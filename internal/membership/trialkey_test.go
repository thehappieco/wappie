package membership

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/kms"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Slice 19's K_app, codes and events in the leader (E0): the key opened
// only by wappie-api, under the purpose trial-codes, never on the retired
// list; codes made at send time from the number's own identity; the rows
// with no code settled not_sent; the catch-up when a key becomes usable;
// and nothing of a key or a code in a log.

// trialTimes are the trial key's timings for the tests.
func trialTimes() TrialTimings {
	return TrialTimings{Retry: 200 * time.Millisecond, Poll: 100 * time.Millisecond, Daily: time.Hour, Pace: 5 * time.Millisecond}
}

// trialKMS gives w's members a fake KMS for K_app, retired as given.
func (w *world) trialKMS(t *testing.T, retired ...string) *membershiptest.KMS {
	t.Helper()
	k := membershiptest.NewKMS(t)
	w.members.Trial = TrialKeyConfig{Open: k.Open, Region: "eu-west-1",
		KeyARN: "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", Retired: retired}
	return k
}

// installKey seals a new K_app under k and installs it, as contract
// trial-key init does; it returns the envelope.
func (w *world) installKey(t *testing.T, k *membershiptest.KMS) []byte {
	t.Helper()
	envelope, err := SealTrialKey(context.Background(), k, rand.Read)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.contract.InitTrialKey(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

// linkNumber is a new number of ws linked by actor with identity n, as the
// pairing's hook records it (RecordLinked only).
func (w *world) linkNumber(t *testing.T, ws uuid.UUID, actor *uuid.UUID, n int) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	d, err := store.NewDevices(w.pool).Create(ctx, ws.String(), "Loja", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	if _, err := w.contract.RecordLinked(ctx, ws, device, actor, testIdentity(n)); err != nil {
		t.Fatal(err)
	}
	return device
}

// testIdentity is a synthetic identity of the fictional 555 range.
func testIdentity(n int) wa.Identity {
	return wa.Identity{PN: types.JID{User: fmt.Sprintf("1555010%04d", n), Server: types.DefaultUserServer, Device: 7},
		LID: types.JID{User: fmt.Sprintf("10000000000%04d", n), Server: types.HiddenUserServer, Device: 7}}
}

// rowsOf are ws's rows of device of type kind: their outcome ("" for
// none yet).
func (w *world) rowsOf(t *testing.T, ws, device uuid.UUID, kind string) []string {
	t.Helper()
	ctx := context.Background()
	var out []string
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT coalesce(outcome, '') FROM item_events WHERE item_id = $1 AND type = $2 ORDER BY seq`, device, kind)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// sentCodes are the codes of the events of type kind the fake accepted
// for item.
func (w *world) sentCodes(kind string, item uuid.UUID) []kc.TrialCodes {
	var out []kc.TrialCodes
	for _, e := range w.fake.Events(App) {
		if e.Type == kind && e.Item.ID == item.String() {
			out = append(out, e.Codes)
		}
	}
	return out
}

// TestTrialCodeVectors: trial-codes.json's Wappie cases through trialCodes,
// from the JIDs a paired session holds (a device part included): each code
// as recorded, the phone number with and without Brazil's ninth digit
// apart, and every identifier that makes none dropped.
func TestTrialCodeVectors(t *testing.T) {
	var v struct {
		KeyHex string `json:"key_hex"`
		Codes  []struct {
			Name, App, Kind, Input, Code string
		} `json:"codes"`
		Differ []struct {
			Name string
			A, B struct{ App, Kind, Input string }
		} `json:"differ"`
		NoCode []struct {
			Name, App, Kind, Input string
		} `json:"no_code"`
	}
	readVectors(t, "trial-codes.json", &v)
	raw, err := hex.DecodeString(v.KeyHex)
	if err != nil || !strings.HasPrefix(v.KeyHex, "000102") {
		t.Fatalf("the vectors' key: %v", err)
	}
	key, err := kc.NewTrialKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	jid := func(kind, input string) (pn, lid string) {
		if kind == kc.TrialKindE164 {
			return strings.TrimPrefix(input, "+") + ":7@s.whatsapp.net", ""
		}
		return "", input + ":7@lid"
	}
	codesOf := func(kind, input string) kc.TrialCodes {
		pn, lid := jid(kind, input)
		return trialCodes(key, App, pn, lid)
	}
	seen := 0
	for _, c := range v.Codes {
		if c.App != App {
			continue
		}
		seen++
		got := codesOf(c.Kind, c.Input)
		if len(got) != 1 || got[0] != c.Code {
			t.Errorf("%s: %d codes, want %s", c.Name, len(got), c.Code)
		}
	}
	if seen < 2 {
		t.Fatalf("%d Wappie codes in the vectors", seen)
	}
	for _, c := range v.Differ {
		if c.A.App != App || c.B.App != App {
			continue
		}
		a, b := codesOf(c.A.Kind, c.A.Input), codesOf(c.B.Kind, c.B.Input)
		if len(a) != 1 || len(b) != 1 || a[0] == b[0] {
			t.Errorf("%s: %v and %v", c.Name, a, b)
		}
	}
	// "+551188887777 vs +5511988887777": never reformatted.
	short, long := trialCodes(key, App, "551188887777@s.whatsapp.net", ""), trialCodes(key, App, "5511988887777@s.whatsapp.net", "")
	if len(short) != 1 || len(long) != 1 || short[0] == long[0] {
		t.Fatal("a Brazilian ninth digit makes the same code")
	}
	for _, c := range v.NoCode {
		if c.App != App {
			continue
		}
		// Through the kit, which trialCodes calls: an ErrNoCode drops the
		// kind. And a JID that does not parse makes none either.
		if _, err := kc.TrialCode(key, App, c.Kind, c.Input); !errors.Is(err, kc.ErrNoCode) {
			t.Errorf("%s: %v", c.Name, err)
		}
		if got := codesOf(c.Kind, c.Input); len(got) != 0 && c.Input != strings.TrimSpace(c.Input) {
			t.Errorf("%s: %d codes", c.Name, len(got))
		}
	}
	if got := trialCodes(key, App, "", ""); len(got) != 0 {
		t.Fatal("a number with no identity has a code")
	}
}

// TestTrialKeyLoad: wappie-api opens the installed envelope once, under
// trial-codes, and records the open; a second load opens nothing; codes
// suspended make no code, and resumed make them again.
func TestTrialKeyLoad(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	k := w.trialKMS(t)
	if got, err := w.members.LoadTrialKey(ctx); err != nil || got.Usable || got.Why != trialNoKey {
		t.Fatalf("with no key: %+v %v", got, err)
	}
	envelope := w.installKey(t, k)
	if k.Decrypts() != 0 {
		t.Fatalf("init opened the key: %d decrypts", k.Decrypts())
	}
	got, err := w.members.LoadTrialKey(ctx)
	if err != nil || !got.Usable || !got.Became {
		t.Fatalf("the first load: %+v %v", got, err)
	}
	if got, err := w.members.LoadTrialKey(ctx); err != nil || !got.Usable || got.Became || k.Decrypts() != 1 {
		t.Fatalf("a second load: %+v %v, %d decrypts", got, err, k.Decrypts())
	}
	for _, p := range k.Purposes() {
		if p != "trial-codes" {
			t.Fatalf("a KMS call under %q", p)
		}
	}
	st, err := w.contract.TrialKeyState(ctx)
	sum := sha256.Sum256(envelope)
	if err != nil || st.OpenedAt == nil || !bytes.Equal(st.EnvelopeSHA256, sum[:]) || st.OpenError != "" {
		t.Fatalf("the open recorded: %+v %v", st, err)
	}
	if codes, why := w.members.trialCodesNow("15550100001:7@s.whatsapp.net", "100000000000001:7@lid"); len(codes) != 2 || why != "" {
		t.Fatalf("codes: %d %q", len(codes), why)
	}
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil {
		t.Fatal(err)
	}
	if got, err := w.members.LoadTrialKey(ctx); err != nil || got.Usable || got.Why != trialSuspended {
		t.Fatalf("suspended: %+v %v", got, err)
	}
	if codes, why := w.members.trialCodesNow("15550100001@s.whatsapp.net", ""); len(codes) != 0 || why != trialSuspended {
		t.Fatalf("suspended codes: %d %q", len(codes), why)
	}
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesOn); err != nil {
		t.Fatal(err)
	}
	if got, err := w.members.LoadTrialKey(ctx); err != nil || !got.Usable || !got.Became || k.Decrypts() != 1 {
		t.Fatalf("resumed: %+v %v, %d decrypts", got, err, k.Decrypts())
	}
}

// TestTrialKeyRetiredEnvelopeNeverOpened: an envelope on the retired list
// is never opened, its class recorded; another KMS's envelope does not
// open, and says decrypt.
func TestTrialKeyRetiredEnvelopeNeverOpened(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	other := membershiptest.NewKMS(t)
	envelope := w.installKey(t, other)
	sum := sha256.Sum256(envelope)
	k := w.trialKMS(t, hex.EncodeToString(sum[:]))
	got, err := w.members.LoadTrialKey(ctx)
	if err != nil || got.Usable || got.Why != trialRetired || k.Decrypts() != 0 {
		t.Fatalf("a retired envelope: %+v %v, %d decrypts", got, err, k.Decrypts())
	}
	if st, err := w.contract.TrialKeyState(ctx); err != nil || st.OpenError != trialRetired || st.OpenedAt != nil {
		t.Fatalf("the state: %+v %v", st, err)
	}
	if st, err := w.contract.State(ctx); err != nil || st.ErrorClass != store.ContractErrorTrialKey {
		t.Fatalf("the ERROR: %q %v", st.ErrorClass, err)
	}
	if len(w.logs.Lines("contract: trial key not used; links go with no code", "class=retired")) != 1 {
		t.Fatalf("the log:\n%s", w.logs.String())
	}
	w.trialKMS(t)
	got, err = w.members.LoadTrialKey(ctx)
	if err != nil || got.Usable || got.Why != trialOpenFailing {
		t.Fatalf("another KMS's envelope: %+v %v", got, err)
	}
	if st, err := w.contract.TrialKeyState(ctx); err != nil || st.OpenError != "decrypt" {
		t.Fatalf("its class: %+v %v", st, err)
	}
}

// TestTrialKeySuspendStopsCodes: with the key, a link's item.linked goes
// with both codes; suspended, the next link's settles not_sent and goes
// nowhere; resumed, the catch-up sends that number's codes once, as an
// item.identity_updated.
func TestTrialKeySuspendStopsCodes(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.installKey(t, w.trialKMS(t))
	logs := w.logs
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Trial = trialTimes()
	run(t, l)
	eventually(t, soon, "the key opened", func() bool { return len(logs.Lines("contract: trial key opened")) == 1 })
	first := w.linkNumber(t, w.team, &w.owner, 1)
	eventually(t, soon, "item.linked delivered with its codes", func() bool {
		c := w.sentCodes(kc.EventLinked, first)
		return len(c) == 1 && len(c[0]) == 2
	})
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the suspension seen", func() bool { return len(logs.Lines("contract: trial codes suspended")) == 1 })
	second := w.linkNumber(t, w.team, &w.owner, 2)
	eventually(t, soon, "item.linked settled with no code", func() bool {
		r := w.rowsOf(t, w.team, second, "linked")
		return len(r) == 1 && r[0] == "not_sent"
	})
	if len(w.sentCodes(kc.EventLinked, second)) != 0 {
		t.Fatal("a suspended link was sent")
	}
	if len(logs.Lines("contract: an event goes with no code; not sent", "reason=suspended")) == 0 {
		t.Fatalf("the not_sent line:\n%s", logs.String())
	}
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesOn); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the catch-up's item.identity_updated delivered", func() bool {
		c := w.sentCodes(kc.EventIdentityUpdated, second)
		return len(c) == 1 && len(c[0]) == 2
	})
	if c := w.sentCodes(kc.EventIdentityUpdated, first); len(c) != 0 {
		t.Fatalf("a number delivered under this key caught up again: %d", len(c))
	}
	assertNoKeyMaterial(t, logs.String())
}

// TestCodesCatchUpOnKeyLoad (P2): a number linked with no key (its row
// settled not_sent) and one linked before slice 19 (no row) each get one
// item.identity_updated at the key's first load; one whose row is still
// owed gets none; a second load records none.
func TestCodesCatchUpOnKeyLoad(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	k := w.trialKMS(t)
	logs := w.logs
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Trial = trialTimes()
	l.EventBackoffMin, l.EventBackoffMax = time.Hour, time.Hour
	run(t, l)
	noKey := w.linkNumber(t, w.team, &w.owner, 3)
	eventually(t, soon, "the link with no key settled", func() bool {
		r := w.rowsOf(t, w.team, noKey, "linked")
		return len(r) == 1 && r[0] == "not_sent"
	})
	before := w.device // linked before slice 19: its phone number, no row
	w.fake.RefuseAlways(contracttest.CallEvents, kc.CodeUnavailable)
	owed := w.linkNumber(t, w.team, &w.owner, 4)
	w.installKey(t, k)
	eventually(t, soon, "the catch-up", func() bool {
		return len(w.rowsOf(t, w.team, noKey, "identity_updated")) == 1 && len(w.rowsOf(t, w.team, before, "identity_updated")) == 1
	})
	if n := len(w.rowsOf(t, w.team, owed, "identity_updated")); n != 0 {
		t.Fatalf("a number with an owed row caught up: %d", n)
	}
	// Another load, a resume's: nothing new (the rows are owed).
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil {
		t.Fatal(err)
	}
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesOn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	for _, d := range []uuid.UUID{noKey, before} {
		if n := len(w.rowsOf(t, w.team, d, "identity_updated")); n != 1 {
			t.Fatalf("%s: %d item.identity_updated after a second load", d, n)
		}
	}
	if len(logs.Lines("contract: codes caught up", "workspace="+w.team.String(), "count=2")) != 1 {
		t.Fatalf("the catch-up's line:\n%s", logs.String())
	}
}

// named waits until the leader has named ws (its rows are owed from then).
func (w *snapshotWorld) named(t *testing.T, ws uuid.UUID) {
	t.Helper()
	eventually(t, soon, "the workspace named", func() bool {
		var ok bool
		err := w.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM contract_workspaces WHERE workspace_id = $1)`, ws).Scan(&ok)
		return err == nil && ok
	})
}

// TestEventsHeldUntilKeyLoaded: at a leader's start the event sender waits
// for the first load of the trial key, so an item.linked owed at a restart
// is neither sent nor settled not_sent while KMS is slow, and goes with
// its codes once the key opens. A leader that stops forgets the key: until
// the next load a number has no code, and a send then holds its row.
func TestEventsHeldUntilKeyLoaded(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	k := w.trialKMS(t)
	gate := make(chan struct{})
	w.members.Trial.Open = func(ctx context.Context, region, arn string) (kms.Wrapper, error) {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return k.Open(ctx, region, arn)
	}
	logs := w.logs
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Trial = trialTimes()
	stop := run(t, l)
	w.named(t, w.team)
	stop()
	if _, why := w.members.trialCodesNow("15550100001@s.whatsapp.net", ""); why != trialNotLoaded {
		t.Fatalf("after the leader stopped: %q", why)
	}
	device := w.linkNumber(t, w.team, &w.owner, 41)
	// Not leading, not loaded: a send holds the row.
	s := newEventSender(l)
	if _, ok := s.send(ctx, w.team); ok {
		t.Fatal("a batch held for the key reported done")
	}
	if r := w.rowsOf(t, w.team, device, "linked"); len(r) != 1 || r[0] != "" {
		t.Fatalf("the held row: %v", r)
	}
	// A restart with the key installed and KMS slow: nothing settles.
	w.installKey(t, k)
	l2 := w.leader(w.members, logs, lockKeyOf(w.world))
	l2.Trial = trialTimes()
	run(t, l2)
	time.Sleep(500 * time.Millisecond)
	if r := w.rowsOf(t, w.team, device, "linked"); len(r) != 1 || r[0] != "" {
		t.Fatalf("settled before the key loaded: %v", r)
	}
	close(gate)
	eventually(t, soon, "item.linked delivered with its codes", func() bool {
		c := w.sentCodes(kc.EventLinked, device)
		return len(c) == 1 && len(c[0]) == 2
	})
	if n := len(logs.Lines("contract: an event goes with no code; not sent")); n != 0 {
		t.Fatalf("%d events settled with no code:\n%s", n, logs.String())
	}
}

// TestCatchUpStopsOnSuspension: a suspension during a catch-up stops it at
// the next number (spec 15.10 exposure step 1: no code anywhere), and the
// catch-up reports it did not finish.
func TestCatchUpStopsOnSuspension(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.installKey(t, w.trialKMS(t))
	l := w.leader(w.members, w.logs, lockKeyOf(w.world))
	l.Trial = TrialTimings{Poll: 20 * time.Millisecond, Pace: 300 * time.Millisecond, Retry: time.Hour, Daily: time.Hour}
	stop := run(t, l)
	w.named(t, w.team)
	stop()
	// Numbers linked before slice 19: an identity, no row; each owed.
	devices := store.NewDevices(w.pool)
	for n := 50; n < 55; n++ {
		d, err := devices.Create(ctx, w.team.String(), "Loja", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		if err := devices.SetIdentity(ctx, w.team.String(), d.ID, testIdentity(n)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.members.LoadTrialKey(ctx)
	if err != nil || !got.Usable {
		t.Fatalf("the load: %+v %v", got, err)
	}
	owed, err := w.contract.CodesCatchUp(ctx, got.Made)
	if err != nil || len(owed) < 5 {
		t.Fatalf("owed: %d %v", len(owed), err)
	}
	tw := newTrialWork(l)
	done := make(chan bool, 1)
	go func() { done <- tw.catchUp(ctx, got.Made) }()
	recorded := func() int {
		n := 0
		for _, it := range owed {
			if it.Workspace == w.team {
				n += len(w.rowsOf(t, w.team, it.Device, "identity_updated"))
			}
		}
		return n
	}
	eventually(t, soon, "the first number caught up", func() bool { return recorded() >= 1 })
	if _, err := w.contract.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil {
		t.Fatal(err)
	}
	select {
	case finished := <-done:
		if finished {
			t.Fatal("the catch-up went through the list after a suspension")
		}
	case <-time.After(soon):
		t.Fatal("the catch-up did not stop")
	}
	if n := recorded(); n >= len(owed) || n > 2 {
		t.Fatalf("%d of %d numbers caught up after the suspension", n, len(owed))
	}
	if _, why := w.members.trialCodesNow("15550100001@s.whatsapp.net", ""); why != trialSuspended {
		t.Fatalf("after the catch-up stopped: %q", why)
	}
}

// TestNoEventsWithoutCode: with no K_app, a link's item.linked settles
// not_sent (reason no_key); with a key, a number with neither its phone
// number nor its LID makes none either (no_identity).
func TestNoEventsWithoutCode(t *testing.T) {
	w := newSnapshotWorld(t)
	logs := w.logs
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Trial = trialTimes()
	run(t, l)
	device := w.linkNumber(t, w.team, &w.owner, 5)
	eventually(t, soon, "settled with no key", func() bool {
		r := w.rowsOf(t, w.team, device, "linked")
		return len(r) == 1 && r[0] == "not_sent"
	})
	if len(logs.Lines("contract: an event goes with no code; not sent", "reason=no_key", "event=")) == 0 {
		t.Fatalf("the line:\n%s", logs.String())
	}
	w.members.Trial = TrialKeyConfig{}
	k := w.trialKMS(t)
	w.installKey(t, k)
	eventually(t, soon, "the key opened", func() bool { return len(logs.Lines("contract: trial key opened")) == 1 })
	if codes, why := w.members.trialCodesNow("", ""); len(codes) != 0 || why != trialNoIdentity {
		t.Fatalf("no identity: %d %q", len(codes), why)
	}
	if codes, _ := w.members.trialCodesNow("not a jid", "@lid"); len(codes) != 0 {
		t.Fatalf("an identity that makes no code: %d", len(codes))
	}
}

// TestKeyPairingLinkedActorNull's sender half: a full key's item.linked
// goes as person with actor null, and logs no unknown actor.
func TestKeyPairingLinkedActorNull(t *testing.T) {
	w := newSnapshotWorld(t)
	w.installKey(t, w.trialKMS(t))
	logs := w.logs
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Trial = trialTimes()
	run(t, l)
	device := w.linkNumber(t, w.team, nil, 6)
	eventually(t, soon, "item.linked delivered", func() bool { return len(w.sentCodes(kc.EventLinked, device)) == 1 })
	for _, e := range w.fake.Events(App) {
		if e.Type == kc.EventLinked && e.Item.ID == device.String() && (e.Actor != nil || e.ActorKind != kc.ActorPerson) {
			t.Fatalf("the key's link: actor %v, kind %s", e.Actor, e.ActorKind)
		}
	}
	if lines := logs.Lines("an event's actor has no platform sub"); len(lines) != 0 {
		t.Fatalf("a key's link logged as a fault: %v", lines)
	}
}

// TestEventCodesVectors: wire-events-codes.json, decoded strictly and
// validated as recorded; and each valid number's event, rendered by
// EventOf from the row it would come from with its codes, is the
// vector's event, member for member.
func TestEventCodesVectors(t *testing.T) {
	var v struct {
		Events []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"events"`
	}
	readVectors(t, "wire-events-codes.json", &v)
	types := map[string]string{kc.EventLinked: "linked", kc.EventIdentityUpdated: "identity_updated"}
	rendered := 0
	for _, c := range v.Events {
		var ev kc.Event
		valid := kc.DecodeStrict(c.Value, &ev) == nil && ev.Validate() == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
			continue
		}
		kind, ok := types[ev.Type]
		if !valid || !ok || ev.Item.Kind != kc.ItemNumber {
			continue
		}
		e := store.ContractEvent{EventID: uuid.MustParse(ev.EventID), Type: kind, ItemID: uuid.MustParse(ev.Item.ID),
			OccurredAt: ev.OccurredAt.Time, ActorKind: ev.ActorKind, Readers: []uuid.UUID{}, Label: ev.Item.Label, Hint: ev.Item.Hint}
		if ev.Actor != nil {
			sub := uuid.MustParse(*ev.Actor)
			e.ActorSub = &sub
		}
		got := EventOf(uuid.MustParse(ev.WorkspaceID), e)
		got.Codes = ev.Codes
		if err := got.Validate(); err != nil {
			t.Errorf("%s: EventOf's event: %v", c.Name, err)
			continue
		}
		a, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if ca, cb := canonical(t, a), canonical(t, c.Value); ca != cb {
			t.Errorf("%s: EventOf gives\n%s\nwant\n%s", c.Name, ca, cb)
		}
		rendered++
	}
	if rendered == 0 {
		t.Fatal("no number's event rendered")
	}
}

// TestTrialKeyNeverLogged: what a load, a link and its delivery log holds
// no key byte, no envelope and no code.
func TestTrialKeyNeverLogged(t *testing.T) {
	w := newSnapshotWorld(t)
	k := w.trialKMS(t)
	envelope := w.installKey(t, k)
	logs := w.logs
	l := w.leader(w.members, logs, lockKeyOf(w.world))
	l.Trial = trialTimes()
	run(t, l)
	device := w.linkNumber(t, w.team, &w.owner, 7)
	eventually(t, soon, "item.linked delivered", func() bool { return len(w.sentCodes(kc.EventLinked, device)) == 1 })
	all := logs.String()
	for _, codes := range w.sentCodes(kc.EventLinked, device) {
		for _, code := range codes {
			if strings.Contains(all, code) {
				t.Fatal("a code is in the log")
			}
		}
	}
	for _, s := range []string{hex.EncodeToString(envelope), base64.StdEncoding.EncodeToString(envelope)} {
		if strings.Contains(all, s) {
			t.Fatal("the envelope is in the log")
		}
	}
	assertNoKeyMaterial(t, all)
}

// assertNoKeyMaterial fails when s holds a phone number of the tests'
// range or a LID: the logs carry ids, enums and times only.
func assertNoKeyMaterial(t *testing.T, s string) {
	t.Helper()
	for _, part := range []string{"1555010", "10000000000"} {
		if strings.Contains(s, part) {
			t.Fatalf("an identifier is in the log: %q", part)
		}
	}
}
