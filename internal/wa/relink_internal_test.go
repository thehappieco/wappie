package wa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/pgtest"
)

// Fictional accounts only: no real phone number or LID appears here.
var (
	ownPN    = types.JID{User: "155501000001", Device: 3, Server: types.DefaultUserServer}
	ownLID   = types.JID{User: "100000000000001", Device: 3, Server: types.HiddenUserServer}
	otherPN  = types.NewJID("155501000002", types.DefaultUserServer)
	otherLID = types.NewJID("100000000000002", types.HiddenUserServer)
	// The new link of the number's own account: other device numbers.
	newPN  = types.JID{User: ownPN.User, Device: 7, Server: types.DefaultUserServer}
	newLID = types.JID{User: ownLID.User, Device: 7, Server: types.HiddenUserServer}
)

// recordingContainer is a session store that records what reaches it.
type recordingContainer struct {
	mu      sync.Mutex
	puts    int
	deletes int
}

func (c *recordingContainer) PutDevice(context.Context, *store.Device) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	return nil
}

func (c *recordingContainer) DeleteDevice(context.Context, *store.Device) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deletes++
	return nil
}

func (c *recordingContainer) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts, c.deletes
}

func withLink(pn, lid types.JID) *store.Device {
	return &store.Device{ID: &pn, LID: lid}
}

// The account check refuses before anything reaches the session store, by
// the user parts of both halves, and never compares device numbers.
func TestRelinkContainerRefusals(t *testing.T) {
	ctx := context.Background()
	expect := Identity{PN: ownPN, LID: ownLID}
	staleRow := errors.New("the number changed")
	for name, tc := range map[string]struct {
		pn, lid types.JID
		recheck error
		want    error
		half    string
	}{
		"another phone":        {pn: otherPN, lid: ownLID, want: ErrOtherAccount, half: "phone"},
		"same phone, new LID":  {pn: newPN, lid: otherLID, want: ErrOtherAccount, half: "lid"},
		"no LID":               {pn: newPN, want: ErrLinkFailed},
		"a LID on a phone JID": {pn: newPN, lid: otherPN, want: ErrLinkFailed},
		"the row changed":      {pn: newPN, lid: newLID, recheck: staleRow, want: staleRow},
	} {
		t.Run(name, func(t *testing.T) {
			inner := &recordingContainer{}
			c := newRelinkContainer(inner, &Relink{Expect: expect, Recheck: func(context.Context) error { return tc.recheck }})
			err := c.PutDevice(ctx, withLink(tc.pn, tc.lid))
			if !errors.Is(err, tc.want) {
				t.Fatalf("PutDevice = %v, want %v", err, tc.want)
			}
			var other *OtherAccount
			if tc.half != "" && (!errors.As(err, &other) || other.Half != tc.half) {
				t.Fatalf("refusal %v, want half %q", err, tc.half)
			}
			// Refused once, refused again, and a delete reaches nothing.
			if again := c.PutDevice(ctx, withLink(newPN, newLID)); !errors.Is(again, tc.want) {
				t.Fatalf("a second PutDevice after a refusal = %v", again)
			}
			if err := c.DeleteDevice(ctx, withLink(newPN, newLID)); err != nil {
				t.Fatal(err)
			}
			if puts, deletes := inner.counts(); puts != 0 || deletes != 0 {
				t.Fatalf("the session store got %d writes and %d deletes after a refusal", puts, deletes)
			}
		})
	}

	t.Run("the number's own account", func(t *testing.T) {
		inner := &recordingContainer{}
		c := newRelinkContainer(inner, &Relink{Expect: expect})
		if err := c.PutDevice(ctx, withLink(newPN, newLID)); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteDevice(ctx, withLink(newPN, newLID)); err != nil {
			t.Fatal(err)
		}
		if puts, deletes := inner.counts(); puts != 1 || deletes != 1 {
			t.Fatalf("the session store got %d writes and %d deletes, want 1 and 1", puts, deletes)
		}
	})

	t.Run("no JID yet", func(t *testing.T) {
		c := newRelinkContainer(&sqlstore.Container{}, &Relink{Expect: expect})
		if err := c.PutDevice(ctx, &store.Device{}); !errors.Is(err, sqlstore.ErrDeviceIDMustBeSet) {
			t.Fatalf("PutDevice with no JID = %v, want whatsmeow's own error", err)
		}
	})

	t.Run("the callback", func(t *testing.T) {
		c := newRelinkContainer(&recordingContainer{}, &Relink{Expect: expect})
		if !c.prePair(newPN, "smba", "") {
			t.Fatal("the callback refused the number's own phone")
		}
		if c.prePair(otherPN, "smba", "") {
			t.Fatal("the callback let another phone through")
		}
		if err := c.PutDevice(ctx, withLink(newPN, newLID)); !errors.Is(err, ErrOtherAccount) {
			t.Fatalf("PutDevice after the callback refused = %v", err)
		}
	})
}

// lineRecorder is a whatsmeow logger that keeps every line.
type lineRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (l *lineRecorder) add(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(msg, args...))
}
func (l *lineRecorder) Warnf(msg string, args ...any)  { l.add("WARN", msg, args...) }
func (l *lineRecorder) Errorf(msg string, args ...any) { l.add("ERROR", msg, args...) }
func (l *lineRecorder) Infof(msg string, args ...any)  { l.add("INFO", msg, args...) }
func (l *lineRecorder) Debugf(msg string, args ...any) { l.add("DEBUG", msg, args...) }
func (l *lineRecorder) Sub(string) waLog.Logger        { return l }

func (l *lineRecorder) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// sessionStore is a real whatsmeow session store in the test's own schema.
func sessionStore(t *testing.T) (*sqlstore.Container, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Empty(t)
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(pgtest.DSN())
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	db, err := sql.Open("pgx", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	container := sqlstore.NewWithDB(db, "postgres", waLog.Noop)
	if err := container.Upgrade(ctx); err != nil {
		t.Fatal(err)
	}
	return container, db
}

// signedIdentity is WhatsApp's pair-success device identity for ds, made
// with a test account key: HMAC'd with the link's ADV secret and signed for
// its identity key, so whatsmeow's checks before the callback pass.
func signedIdentity(t *testing.T, ds *store.Device) []byte {
	t.Helper()
	account := keys.NewKeyPair()
	details, err := proto.Marshal(&waAdv.ADVDeviceIdentity{
		RawID: proto.Uint32(1), Timestamp: proto.Uint64(uint64(time.Now().Unix())), KeyIndex: proto.Uint32(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	message := append(append(append([]byte{}, whatsmeow.AdvAccountSignaturePrefix...), details...), ds.IdentityKey.Pub[:]...)
	signature := ecc.CalculateSignature(ecc.NewDjbECPrivateKey(*account.Priv), message)
	signed, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentity{
		Details: details, AccountSignatureKey: account.Pub[:], AccountSignature: signature[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, ds.AdvSecretKey)
	mac.Write(signed)
	out, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentityHMAC{Details: signed, HMAC: mac.Sum(nil)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A refused scan stores nothing, in whatsmeow's own order at core's pin:
// the callback refuses another phone before whatsmeow sets anything, and the
// session store's first write refuses the number's phone under another LID.
// Either way there is no session row, no LID pair, no identity key, and the
// only node whatsmeow tries to send is the pair error, never
// pair-device-sign. The control case, the number's own account, gets past
// both and fails only at the send, which this test cannot make: so the test
// identity is valid, and the refusal is what stopped the other two. A
// whatsmeow upgrade that moves the first write fails here.
func TestRelinkRefusedPairStoresNothing(t *testing.T) {
	ctx := context.Background()
	container, db := sessionStore(t)
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	stored := func(pn, lid types.JID) (devices, lids, identities int) {
		return count(`SELECT count(*) FROM whatsmeow_device WHERE jid = $1`, pn.String()),
			count(`SELECT count(*) FROM whatsmeow_lid_map WHERE lid = $1 OR pn = $2`, lid.User, pn.User),
			count(`SELECT count(*) FROM whatsmeow_identity_keys WHERE our_jid = $1`, pn.String())
	}

	pair := func(t *testing.T, pn, lid types.JID) (*lineRecorder, *relinkContainer, *store.Device, error) {
		t.Helper()
		ds := container.NewDevice()
		log := &lineRecorder{}
		client := whatsmeow.NewClient(ds, log)
		guard := armRelink(ds, client, &Relink{Expect: Identity{PN: ownPN, LID: ownLID}})
		//nolint:staticcheck // SA1019: whatsmeow's own handlePair, with no network, is what this pins
		err := client.DangerousInternals().HandlePair(ctx, signedIdentity(t, ds), "pair-1", "", "smba", pn, lid)
		return log, guard, ds, err
	}

	for name, tc := range map[string]struct {
		pn, lid types.JID
		half    string
	}{
		"another account (the callback)":          {pn: otherPN, lid: otherLID, half: "phone"},
		"the same phone, another LID (the write)": {pn: newPN, lid: otherLID, half: "lid"},
	} {
		t.Run(name, func(t *testing.T) {
			log, guard, ds, err := pair(t, tc.pn, tc.lid)
			var dbErr *whatsmeow.PairDatabaseError
			switch tc.half {
			case "phone":
				if !errors.Is(err, whatsmeow.ErrPairRejectedLocally) {
					t.Fatalf("HandlePair = %v, want the callback's refusal", err)
				}
			case "lid":
				if !errors.As(err, &dbErr) || !errors.Is(err, ErrOtherAccount) {
					t.Fatalf("HandlePair = %v, want the session store's refusal", err)
				}
			}
			refused, _ := guard.verdict.get()
			var other *OtherAccount
			if !errors.As(refused, &other) || other.Half != tc.half {
				t.Fatalf("verdict = %v, want other_account on the %s", refused, tc.half)
			}
			if d, l, i := stored(tc.pn, tc.lid); d != 0 || l != 0 || i != 0 {
				t.Fatalf("a refused scan stored %d sessions, %d LID pairs and %d identity keys", d, l, i)
			}
			if ds.Initialized {
				t.Fatal("the refused link's device was initialized by the session store")
			}
			if n := log.count("Failed to send pair error node"); n != 1 {
				t.Fatalf("%d pair error sends, want 1: %q", n, log.lines)
			}
			if n := log.count("failed to send pairing confirmation"); n != 0 {
				t.Fatalf("whatsmeow tried pair-device-sign after a refusal: %q", log.lines)
			}
		})
	}

	t.Run("the number's own account", func(t *testing.T) {
		log, guard, ds, err := pair(t, newPN, newLID)
		if err == nil || !strings.Contains(err.Error(), "failed to send pairing confirmation") {
			t.Fatalf("HandlePair = %v, want it to fail only at the send of pair-device-sign", err)
		}
		if refused, accepted := guard.verdict.get(); refused != nil || !accepted {
			t.Fatalf("verdict = %v, accepted %v", refused, accepted)
		}
		if _, ok := ds.Container.(*sqlstore.Container); !ok {
			t.Fatalf("after the first write the device's container is %T, want the session store again", ds.Container)
		}
		// whatsmeow deleted the session after the failed send; the LID pair
		// it wrote before the send stays.
		if _, l, _ := stored(newPN, newLID); l != 1 {
			t.Fatalf("LID pairs = %d, want the one whatsmeow writes after the first write", l)
		}
		if n := log.count("Failed to send pair error node"); n != 0 {
			t.Fatalf("the number's own account got a pair error: %q", log.lines)
		}
	})
}

// The QR whatsmeow makes at core's pin is a linked-devices URL with five
// comma-separated parts, in the alphabet of spec 14.13: 175 characters plus
// WhatsApp's reference. Built from a fake reference, never a real QR.
func TestPairingQRShape(t *testing.T) {
	ds := (&sqlstore.Container{}).NewDevice()
	client := whatsmeow.NewClient(ds, waLog.Noop)
	ref := "2@test-ref-not-real"
	//nolint:staticcheck // SA1019: whatsmeow's QR builder is unexported; a fake reference only
	qr := client.DangerousInternals().MakeQRData([]byte(ref), whatsmeow.PairClientOtherWebClient)
	const prefix = "https://wa.me/settings/linked_devices#"
	if !strings.HasPrefix(qr, prefix) {
		t.Fatalf("the QR does not start with %q", prefix)
	}
	if parts := strings.Split(strings.TrimPrefix(qr, prefix), ","); len(parts) != 5 || parts[0] != ref {
		t.Fatalf("the QR has %d parts, want 5 with the reference first", len(parts))
	}
	if len(qr) != 175+len(ref) {
		t.Fatalf("the QR is %d characters, want %d", len(qr), 175+len(ref))
	}
	allowed := func(r rune) bool {
		return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("+/=,@._:#-", r)
	}
	for _, r := range qr {
		if !allowed(r) {
			t.Fatalf("the QR holds %q, outside spec 14.13's alphabet", r)
		}
	}
}

// whatsmeow's "Successfully paired" line names the new link's JID, which is
// its phone number. The pairing's logger prints the server only.
func TestPairingLoggerRedactsJIDs(t *testing.T) {
	var buf strings.Builder
	r := &Registry{log: slog.New(slog.NewTextHandler(&buf, nil))}
	log := r.pairLogger("pair/test").Sub("QRChannel")
	log.Infof("Successfully paired %s", &newPN)
	log.Warnf("pair of %s and %v", newLID, newPN)
	out := buf.String()
	if strings.Contains(out, ownPN.User) || strings.Contains(out, ownLID.User) {
		t.Fatalf("a pairing log line carries a phone number or a LID: %s", out)
	}
	if !strings.Contains(out, "<redacted>@s.whatsapp.net") || !strings.Contains(out, "<redacted>@lid") {
		t.Fatalf("the redacted JIDs lost their server: %s", out)
	}
}
