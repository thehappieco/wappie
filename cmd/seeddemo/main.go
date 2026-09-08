// Command seeddemo fills a tenant with a conversation to look at.
//
// Temporary scaffolding for developing the web client: pairing a phone to see
// whether a bubble renders is a slow loop, and doing it against a real archive
// means testing on someone's actual messages. This writes a small, obviously
// fake conversation through the real ingest pipeline, so what the client meets
// is sealed exactly like anything else.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/blob"
	"whatserver2/internal/config"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/crypto/wamedia"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/media"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "seeddemo:", err)
		os.Exit(1)
	}
}

func run() error {
	tenantArg := flag.String("tenant", "", "tenant id (required)")
	label := flag.String("label", "demo", "device label")
	flag.Parse()
	if *tenantArg == "" {
		return errors.New("-tenant is required")
	}
	tenant, err := uuid.Parse(*tenantArg)
	if err != nil {
		return err
	}

	if err := config.LoadDotEnv(".env"); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pools, err := pg.Open(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pools.Close()

	keys := store.NewKeys(pools.API)
	devices := store.NewDevices(pools.API)
	dev, err := devices.Create(ctx, tenant.String(), *label, wa.ModePassive)
	if err != nil {
		return err
	}
	deviceID := uuid.MustParse(dev.ID)

	// The archive key is generated here and printed, because a demo device has
	// nobody to grant it to. A real device gets its key at pairing time and it
	// is sealed straight to the accounts that may read it.
	const epoch = 1
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		return err
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		return err
	}
	if err := keys.CreateArchiveKey(ctx, tenant, deviceID, epoch, pub); err != nil {
		return err
	}

	// Sealed to every account of the tenant, the way pairing does it, so the
	// demo exercises the path a real device takes rather than a shortcut.
	users := store.NewUsers(pools.API)
	accounts, err := users.List(ctx, tenant)
	if err != nil {
		return err
	}
	for _, u := range accounts {
		userPub, err := seal.ParsePublicKey(u.PublicKey)
		if err != nil {
			return fmt.Errorf("account %s has an unusable public key: %w", u.Email, err)
		}
		sealed, err := seal.SealDirect(userPub, seal.KindDeviceGrant, tenant,
			seal.GrantRow(tenant, deviceID, u.ID, epoch), epoch, privBytes)
		if err != nil {
			return err
		}
		if err := keys.PutGrant(ctx, store.Grant{
			TenantID: tenant, DeviceID: deviceID, UserID: u.ID,
			Epoch: epoch, SealedDSK: sealed,
		}, nil); err != nil {
			return err
		}
	}
	sealer, err := seal.NewSealer(tenant, deviceID, pub, epoch, keys)
	if err != nil {
		return err
	}

	messages := store.NewMessages(pools.Live)
	pipe, err := ingest.New(ingest.Config{
		Tenant: tenant, Sealer: sealer, Messages: messages,
		Log: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return err
	}

	if err := seedContacts(ctx, sealer, store.NewContacts(pools.API), tenant, deviceID); err != nil {
		return err
	}
	if err := seedChats(ctx, sealer, messages, tenant, deviceID); err != nil {
		return err
	}
	n, err := seedMessages(ctx, pipe, tenant.String(), dev.ID)
	if err != nil {
		return err
	}

	// Attachments need object storage. Without it the rest is still worth
	// having, so this reports and carries on rather than failing the run.
	bucket, err := blob.New(cfg.Storage)
	switch {
	case err != nil:
		return err
	case !bucket.Configured():
		fmt.Println("object storage is not configured; skipping the attachments")
	default:
		attached, err := seedMedia(ctx, pipe, bucket, store.NewMedia(pools.API),
			tenant, dev.ID)
		if err != nil {
			return err
		}
		n += attached
	}

	fmt.Printf("device %s\n%d rows written for tenant %s\n", dev.ID, n, tenant)
	if len(accounts) > 0 {
		fmt.Printf("archive key sealed to %d account(s); sign in to read it\n", len(accounts))
	} else {
		fmt.Printf("no account to grant to, so the key is printed once:\narchive key  %s\n",
			base64.RawURLEncoding.EncodeToString(privBytes))
	}
	return nil
}

// seedMedia writes attachments the way the real path leaves them: the object
// store holds WhatsApp's own ciphertext, and only the 32-byte key is sealed.
//
// Encrypting locally is exactly what the archive stores, because
// wamedia.Encrypt is deterministic — the IV comes from the HKDF expansion, not
// from a fresh draw — so these bytes are byte-identical to what a CDN would
// have served for the same key.
func seedMedia(ctx context.Context, pipe *ingest.Pipeline, bucket *blob.Store,
	rows *store.Media, tenant uuid.UUID, device string) (int, error) {
	at := time.Now().Add(-30 * time.Minute).Truncate(time.Second)

	photo, err := gradientPNG(640, 400)
	if err != nil {
		return 0, err
	}
	thumb, err := gradientJPEG(120, 75)
	if err != nil {
		return 0, err
	}
	document := []byte("ORÇAMENTO\n\nMão de obra .... 8.500\nMaterial ....... 4.000\n")

	attachments := []struct {
		id, caption, fileName, mime string
		typ                         domain.Type
		waType                      wamedia.Type
		payload, thumbnail          []byte
		width, height               uint32
	}{
		{
			id: "DEMO0020", caption: "a fachada depois da pintura",
			mime: "image/png", typ: domain.TypeImage, waType: wamedia.Image,
			payload: photo, thumbnail: thumb, width: 640, height: 400,
		},
		{
			id: "DEMO0021", fileName: "orçamento.txt", mime: "text/plain",
			typ: domain.TypeDocument, waType: wamedia.Document, payload: document,
		},
	}

	written := 0
	for i, a := range attachments {
		key := make([]byte, wamedia.KeyLen)
		for j := range key {
			key[j] = byte((i+11)*17 + j)
		}
		enc, err := wamedia.Encrypt(a.payload, key, a.waType)
		if err != nil {
			return written, err
		}
		sum := sha256.Sum256(enc)
		plainSum := sha256.Sum256(a.payload)

		env := domain.Envelope{
			TenantID: tenant.String(), DeviceID: device, MessageID: a.id,
			Chat: mustAddr(ana), Sender: mustAddr(ana),
			Timestamp: at.Add(time.Duration(i) * time.Minute),
			Kind:      domain.KindMessage, Type: a.typ, Source: domain.SourceLive,
		}
		env.Content.Body = a.caption
		env.Content.Media = &domain.Media{
			MimeType: a.mime, FileLength: uint64(len(a.payload)),
			FileSHA256: plainSum[:], FileEncSHA256: sum[:],
			MediaKey: key, Thumbnail: a.thumbnail, FileName: a.fileName,
			Width: a.width, Height: a.height,
		}

		res, err := pipe.Ingest(ctx, env)
		if err != nil {
			return written, err
		}

		objectKey := media.ObjectKey(tenant, sum[:])
		if err := bucket.Put(ctx, objectKey, bytes.NewReader(enc), int64(len(enc))); err != nil {
			return written, err
		}
		if err := rows.MarkDone(ctx, tenant, res.UID, objectKey, int64(len(enc))); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func mustAddr(jid string) domain.Address {
	parsed, err := types.ParseJID(jid)
	if err != nil {
		panic(err)
	}
	return domain.Address{PN: parsed}
}

// gradientPNG draws something recognisable, so a picture that decrypts wrong
// looks wrong rather than looking like a picture nobody can judge.
func gradientPNG(w, h int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{
				R: uint8(255 * x / w),
				G: uint8(255 * y / h),
				B: uint8(160),
				A: 255,
			})
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func gradientJPEG(w, h int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{R: uint8(255 * x / w), G: uint8(255 * y / h), B: 160, A: 255})
		}
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 70}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

const (
	ana   = "5511911111111@s.whatsapp.net"
	bruno = "5511922222222@s.whatsapp.net"
	group = "120363111111111111@g.us"
)

func seal1(ctx context.Context, s *seal.Sealer, row uuid.UUID, kind seal.Kind, v string) ([]byte, uint32, error) {
	out, keyID, err := s.SealAll(ctx, row, map[seal.Kind][]byte{kind: []byte(v)})
	if err != nil {
		return nil, 0, err
	}
	return out[kind], keyID, nil
}

func seedContacts(ctx context.Context, s *seal.Sealer, contacts *store.Contacts,
	tenant, device uuid.UUID) error {
	people := []struct {
		key, full, push string
		isGroup         bool
	}{
		{ana, "Ana Ribeiro", "Ana", false},
		{bruno, "Bruno Sales", "bru", false},
		{group, "", "", true},
	}
	for _, p := range people {
		uid := store.ContactUID(device, p.key)
		in := store.ContactName{
			TenantID: tenant, DeviceID: device,
			ContactKey: p.key, ContactPN: p.key, IsGroup: p.isGroup,
		}
		if p.full != "" {
			values := map[seal.Kind][]byte{
				seal.KindFullName: []byte(p.full),
				seal.KindPushName: []byte(p.push),
			}
			sealed, keyID, err := s.SealAll(ctx, uid, values)
			if err != nil {
				return err
			}
			in.FullNameSealed = sealed[seal.KindFullName]
			in.PushNameSealed = sealed[seal.KindPushName]
			in.ContentKeyID = keyID
		}
		if err := contacts.Upsert(ctx, in); err != nil {
			return err
		}
		// A one-pixel PNG stands in for a profile picture: enough to prove the
		// sealed-avatar path end to end without shipping an image into the repo.
		png := []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
			0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
			0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
			0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
			0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
		}
		sealedPic, keyID, err := s.SealAll(ctx, uid, map[seal.Kind][]byte{seal.KindAvatar: png})
		if err != nil {
			return err
		}
		if err := contacts.SetAvatar(ctx, tenant, device, p.key, "demo",
			sealedPic[seal.KindAvatar], keyID); err != nil {
			return err
		}
	}
	return nil
}

func seedChats(ctx context.Context, s *seal.Sealer, messages *store.Messages,
	tenant, device uuid.UUID) error {
	chats := []struct {
		key, name string
		isGroup   bool
	}{
		{ana, "Ana Ribeiro", false},
		{group, "Obras da serra", true},
	}
	for _, c := range chats {
		uid := store.ChatUID(device, c.key)
		sealed, keyID, err := seal1(ctx, s, uid, seal.KindContactName, c.name)
		if err != nil {
			return err
		}
		if err := messages.UpsertChatMeta(ctx, store.ChatMeta{
			TenantID: tenant, DeviceID: device, ChatKey: c.key, ChatPN: c.key,
			IsGroup: c.isGroup, NameSealed: sealed, NameKeyID: keyID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func seedMessages(ctx context.Context, pipe *ingest.Pipeline, tenant, device string) (int, error) {
	base := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	at := func(minutes int) time.Time { return base.Add(time.Duration(minutes) * time.Minute) }

	addr := func(jid string) domain.Address {
		parsed, err := types.ParseJID(jid)
		if err != nil {
			panic(err)
		}
		return domain.Address{PN: parsed}
	}

	base9 := func(id string, chat string, sender string, fromMe bool, minutes int) domain.Envelope {
		env := domain.Envelope{
			TenantID: tenant, DeviceID: device, MessageID: id,
			Chat: addr(chat), Timestamp: at(minutes), IsFromMe: fromMe,
			Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive,
		}
		if sender != "" {
			env.Sender = addr(sender)
		}
		if chat == group {
			env.IsGroup = true
		}
		return env
	}

	envelopes := []domain.Envelope{}

	// A plain exchange.
	m1 := base9("DEMO0001", ana, ana, false, 0)
	m1.Content.Body = "oi! consegue olhar o orçamento hoje?"
	envelopes = append(envelopes, m1)

	m2 := base9("DEMO0002", ana, "", true, 2)
	m2.Content.Body = "consigo sim, me manda"
	envelopes = append(envelopes, m2)

	// An edited message: the original, then two edits. All three survive.
	m3 := base9("DEMO0003", ana, ana, false, 5)
	m3.Content.Body = "o valor ficou em 12 mil"
	envelopes = append(envelopes, m3)

	e1 := base9("DEMO0004", ana, ana, false, 6)
	e1.Kind, e1.TargetID, e1.TargetRel = domain.KindEdit, "DEMO0003", domain.TargetMessage
	e1.Content.Body = "o valor ficou em 12.500"
	envelopes = append(envelopes, e1)

	e2 := base9("DEMO0005", ana, ana, false, 8)
	e2.Kind, e2.TargetID, e2.TargetRel = domain.KindEdit, "DEMO0003", domain.TargetMessage
	e2.Content.Body = "o valor ficou em 12.500 já com a mão de obra"
	envelopes = append(envelopes, e2)

	// A deleted message. WhatsApp removes it; the archive keeps the text.
	m4 := base9("DEMO0006", ana, ana, false, 10)
	m4.Content.Body = "esquece, falei besteira — era do outro cliente"
	envelopes = append(envelopes, m4)

	d1 := base9("DEMO0007", ana, ana, false, 11)
	d1.Kind, d1.TargetID, d1.TargetRel = domain.KindDelete, "DEMO0006", domain.TargetMessage
	envelopes = append(envelopes, d1)

	// Reactions, one of them replaced by a later one from the same person.
	r1 := base9("DEMO0008", ana, "", true, 12)
	r1.Kind, r1.Type = domain.KindReaction, domain.TypeReaction
	r1.TargetID, r1.TargetRel = "DEMO0003", domain.TargetMessage
	r1.Content.Body = "👍"
	envelopes = append(envelopes, r1)

	r2 := base9("DEMO0009", ana, "", true, 13)
	r2.Kind, r2.Type = domain.KindReaction, domain.TypeReaction
	r2.TargetID, r2.TargetRel = "DEMO0003", domain.TargetMessage
	r2.Content.Body = "🎉"
	envelopes = append(envelopes, r2)

	// A location.
	loc := base9("DEMO0010", ana, ana, false, 15)
	loc.Type = domain.TypeLocation
	loc.Content.Location = &domain.Location{
		Latitude: -23.5505, Longitude: -46.6333, Name: "Obra — São Paulo",
		Address: "Av. Paulista, 1000",
	}
	envelopes = append(envelopes, loc)

	// A poll in the group.
	poll := base9("DEMO0011", group, bruno, false, 20)
	poll.Type = domain.TypePoll
	poll.Content.Poll = &domain.Poll{
		Question: "Quando fazemos a vistoria?", Options: []string{"quinta", "sexta", "sábado"},
		SelectableCount: 1,
	}
	envelopes = append(envelopes, poll)

	// A group message with a mention, plus one from us.
	g1 := base9("DEMO0012", group, ana, false, 22)
	g1.Content.Body = "@5511922222222 leva a trena"
	g1.Content.Mentions = []string{bruno}
	envelopes = append(envelopes, g1)

	g2 := base9("DEMO0013", group, "", true, 24)
	g2.Content.Body = "combinado, saio 7h"
	g2.IsForwarded, g2.ForwardingScore = true, 6
	envelopes = append(envelopes, g2)

	// A view-once, disappearing message: two flags a reader has to be able to
	// tell apart from an ordinary one.
	vo := base9("DEMO0014", ana, ana, false, 26)
	vo.ViewOnce, vo.Ephemeral, vo.Expiration = true, true, 86400
	vo.Content.Body = "print do contrato (só desta vez)"
	envelopes = append(envelopes, vo)

	for i, env := range envelopes {
		if _, err := pipe.Ingest(ctx, env); err != nil {
			return i, fmt.Errorf("row %d (%s): %w", i, env.MessageID, err)
		}
	}
	return len(envelopes), nil
}
