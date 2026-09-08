package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa/normalize"
)

// reproject looks again at messages this build did not understand when they
// arrived.
//
// Classification happens once, on the way in, so a message that reached the
// archive before its type was supported stays "unsupported" for good — the row
// is written and nothing revisits it. That is survivable only because the
// protobuf that produced it was sealed and kept, which is exactly what makes
// this command possible.
//
// It runs here, in the server, rather than in the browser, and takes the key on
// the command line. Three reasons, in order of how much they matter:
//
//   - raw_sealed never crosses the wire, so no client can fetch it. Adding it
//     to the protocol would double the size of every message frame to serve a
//     command run once.
//   - The classifier is this one. A reprojection written in the browser would
//     be a second implementation of what a message IS, and the archive would
//     end up holding two kinds of row for one kind of message with only the
//     date to say which produced it. The repository already refuses that trade
//     for the sealing format, for the same reason.
//   - The server cannot open its own archive, by design. So the key has to be
//     handed in, and it is held in memory for the run and never written down —
//     the same posture, deliberate and already documented, as media retry.
//
// Read-only unless -apply is given. The dry run is the default because the
// alternative is a command that rewrites a thousand rows on a typo.
func reproject(args []string) error {
	fs := flag.NewFlagSet("reproject", flag.ContinueOnError)
	deviceID := fs.String("device", "", "device id (a unique prefix is enough)")
	keyIn := fs.String("key", "", "device archive private key, base64; or set WS_ARCHIVE_KEY")
	apply := fs.Bool("apply", false, "write the reclassified rows; without it nothing is changed")
	limit := fs.Int("limit", 5000, "how many rows to look at")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *deviceID == "" {
		return errors.New("-device is required")
	}
	raw := *keyIn
	if raw == "" {
		raw = os.Getenv("WS_ARCHIVE_KEY")
	}
	if raw == "" {
		return errors.New("the device archive private key is required: -key or WS_ARCHIVE_KEY")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("archive key is not base64: %w", err)
	}
	priv, err := seal.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("archive key: %w", err)
	}

	ctx := context.Background()
	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	// The tenant has to be discovered before the row can be read: every table
	// is under row-level security and the scope must be set before the query.
	dev, tenant, err := resolveDeviceAnywhere(ctx, a, *deviceID)
	if err != nil {
		return err
	}
	device, err := uuid.Parse(dev.ID)
	if err != nil {
		return err
	}

	rows, err := a.messages.Unsupported(ctx, tenant, device, 0, *limit)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("nothing filed as unsupported")
		return nil
	}

	// One sealer for the run, so every rewritten row shares one fresh content
	// key rather than allocating one apiece.
	pub, epoch, err := a.keys.ArchiveKey(ctx, tenant, device)
	if err != nil {
		return err
	}
	sealer, err := seal.NewSealer(tenant, device, pub, epoch, a.keys)
	if err != nil {
		return err
	}

	own := domain.Address{LID: dev.Identity.LID, PN: dev.Identity.PN}

	ring := newKeyring(priv, tenant, device, a.keys)

	var opened, changed, skipped, failed int
	byType := map[string]int{}
	for _, r := range rows {
		env, ok := reclassify(ctx, ring, tenant, r, own)
		if !ok {
			failed++
			continue
		}
		opened++
		if env.Type == domain.TypeUnsupported {
			// Still not understood. Ordinary, and the whole reason the row
			// keeps its raw protobuf: the next build gets another try.
			continue
		}
		if env.Content.Media != nil {
			// The attachment pipeline is a separate machine — a download
			// queue, object storage, a retry ladder — and inserting a media
			// row from here would fabricate the half of it that records what
			// was actually fetched. Reported rather than half-done.
			fmt.Printf("  skip %s: %s carries an attachment; reprojection does not "+
				"reach the media pipeline\n", r.WAID, env.Type)
			skipped++
			continue
		}
		byType[string(env.Type)]++
		if !*apply {
			continue
		}
		if err := writeReprojection(ctx, a, sealer, tenant, device, r, env); err != nil {
			fmt.Printf("  fail %s: %v\n", r.WAID, err)
			failed++
			continue
		}
		changed++
	}

	fmt.Printf("looked at %d, opened %d, could not open %d\n", len(rows), opened, failed)
	for t, n := range byType {
		fmt.Printf("  %-16s %d\n", t, n)
	}
	if skipped > 0 {
		fmt.Printf("  skipped (attachments) %d\n", skipped)
	}
	if *apply {
		fmt.Printf("rewrote %d rows\n", changed)
	} else {
		fmt.Println("dry run; nothing was written. Add -apply to rewrite.")
	}
	return nil
}

// reclassify opens one stored protobuf and runs it through the ingest
// classifier.
func reclassify(ctx context.Context, ring *keyring, tenant uuid.UUID,
	r store.Reprojection, own domain.Address) (domain.Envelope, bool) {
	plaintext, err := ring.open(ctx, r.ContentKeyID, seal.KindRawProto, r.UID, r.RawSealed)
	if err != nil {
		return domain.Envelope{}, false
	}
	var msg waE2E.Message
	if err := proto.Unmarshal(plaintext, &msg); err != nil {
		return domain.Envelope{}, false
	}

	chat, err := types.ParseJID(r.ChatKey)
	if err != nil {
		return domain.Envelope{}, false
	}
	sender := chat
	if r.SenderKey != "" {
		if j, err := types.ParseJID(r.SenderKey); err == nil {
			sender = j
		}
	}
	info := types.MessageInfo{
		ID: r.WAID,
		MessageSource: types.MessageSource{
			Chat: chat, Sender: sender,
			IsFromMe: r.IsFromMe, IsGroup: r.IsGroup,
		},
	}
	env, err := normalize.FromRaw(info, &msg, normalize.Options{
		TenantID: tenant.String(), Own: own,
	})
	if err != nil {
		return domain.Envelope{}, false
	}
	return env, true
}

// keyring unwraps content keys once each, with the device key.
//
// Cached because a run touches a thousand rows that share a handful of keys,
// and each unwrap is an HPKE open. The private key stays in this process for
// the length of the command and is never written down.
type keyring struct {
	priv   seal.PrivateKey
	tenant uuid.UUID
	device uuid.UUID
	store  *store.Keys
	keys   map[uint32]*seal.ContentKey
}

func newKeyring(priv seal.PrivateKey, tenant, device uuid.UUID, ks *store.Keys) *keyring {
	return &keyring{priv: priv, tenant: tenant, device: device, store: ks,
		keys: map[uint32]*seal.ContentKey{}}
}

func (k *keyring) open(ctx context.Context, id uint32, kind seal.Kind,
	row uuid.UUID, envelope []byte) ([]byte, error) {
	if id == 0 {
		// Sealed straight to the device key, with no content key in between.
		return seal.OpenDirect(k.priv, kind, k.tenant, row, envelope)
	}
	ck, ok := k.keys[id]
	if !ok {
		sealed, err := k.store.SealedContentKey(ctx, k.tenant, k.device, id)
		if err != nil {
			return nil, err
		}
		ck, err = seal.OpenContentKey(k.priv, k.tenant, k.device, id, sealed)
		if err != nil {
			return nil, err
		}
		k.keys[id] = ck
	}
	return ck.Open(kind, k.tenant, row, envelope)
}

func writeReprojection(ctx context.Context, a *app, sealer *seal.Sealer,
	tenant, device uuid.UUID, r store.Reprojection, env domain.Envelope) error {
	values := map[seal.Kind][]byte{}
	if env.Content.Body != "" {
		values[seal.KindBody] = []byte(env.Content.Body)
	}
	if p := env.Content.Payload(); !p.Empty() {
		blob, err := p.Marshal()
		if err != nil {
			return err
		}
		values[seal.KindPayload] = blob
	}
	if len(env.Content.Raw) > 0 {
		values[seal.KindRawProto] = env.Content.Raw
	}
	sealed, keyID, err := sealer.SealAll(ctx, r.UID, values)
	if err != nil {
		return err
	}
	// The command-line path does not attach media: the browser path is the one
	// that is used, and duplicating the sealing of a media key here would be a
	// second place for it to be got wrong. A row with an attachment is left
	// for it and reported.
	return a.messages.Reproject(ctx, tenant, device, r.UID, env.Type, keyID,
		sealed[seal.KindBody], sealed[seal.KindPayload], sealed[seal.KindRawProto], nil)
}
