package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	cryptoseal "whatserver2/internal/crypto/seal"
	"whatserver2/internal/label"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The access snapshots (README 8; the plan's 4.10, TB5, TB27 to TB30 and
// TB2's snapshot part) on a real database and the fake platform.

var updateGolden = flag.Bool("update", false, "regenerate testdata/snapshots/*.json and testdata/events/*.json")

// The fixture's ids, fixed so that its snapshot is a golden file.
func fixed(kind string, n int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("0199%s-0000-7000-8000-%012x", kind, n))
}

// snapshotFixture is TB5's workspace: a team of the platform's that Wappie
// holds, with numbers in each state and people in each standing.
type snapshotFixture struct {
	team uuid.UUID
	// users and subs by name; unlinked people and service accounts have
	// no sub.
	users, subs map[string]uuid.UUID
	devices     map[string]uuid.UUID
}

// The numbers, by name: their labels, phone numbers ("" for none), LIDs
// ("" for none), and whether they ever connected.
var fixtureNumbers = []struct {
	name, label, pn, lid string
	connected            bool
}{
	{"live", "Vendas", "5511912345678", "", true},
	{"paused", "Suporte", "5511900001111", "", true},
	{"moving", "Número do WhatsApp", "5511900002222", "", true},
	{"moved_back", "+55 11 90000-3333", "5511900003333", "", true},
	{"logged_out", "Entregas", "5511900004444", "", true},
	{"deleted", "Financeiro antigo", "5511900005555", "", true},
	{"disabled_holder", "Cobrança", "5511900006666", "", true},
	{"lid_only", "", "", "190000000000001@lid", false},
	{"connected_only", "0199e000", "", "", true},
	{"rotated", "Recepção", "5511900007777", "", true},
}

// The fixture's label counts by class (its labels in turn: five names, a
// placeholder, the number itself, nothing, the start of its own id, a
// name).
var fixtureLabels = map[label.Class]int{
	label.ClassNamed: 6, label.ClassPlaceholder: 1, label.ClassPhone: 1, label.ClassEmpty: 1, label.ClassLegacyID: 1,
}

// newSnapshotFixture builds it in w, all but the deletion (deleteFixture):
//   - live: owner reads and sends; member waits for the key, and a person
//     whose account is disabled may read it but does not wait; a standing
//     service account reads (a backup without a sub); an assistant's
//     service account reads (never a backup, never listed); nobody is the
//     last holder;
//   - paused: stopped by the owner, its only reader (protected);
//   - moving: paused for a move; a member holds its key without Read, the
//     only holder (protected);
//   - moved_back: paused for a move, stopped by the owner meanwhile, the
//     move's pause undone: a person's pause (TB12's snapshot clause); the
//     second owner its only reader;
//   - logged_out: the owner reads it, and a local person who never linked
//     (a backup without a sub);
//   - deleted: the owner reads, sends and manages it, the only holder;
//   - disabled_holder: the only holder is a person whose account is
//     disabled, their membership standing: a suspended sole holder, both
//     protected and refused (the plan's 19);
//   - lid_only: a LID and nothing else, and connected_only: a past
//     connection and nothing else, each a number of the workspace's (the
//     owner its only holder);
//   - rotated: its key at epoch 3, epoch 2 not retired, epoch 1 retired;
//     the owner holds the current key, a member only epoch 2's (holds a
//     key, does not read, waits; the only holder of that epoch, so
//     protected by Wappie's rule) and another only epoch 1's (no key held,
//     waits);
//   - on live, besides: a member whose membership's deadline has passed
//     and one whose membership is disabled, each with Read and the current
//     key (neither reads nor waits);
//   - on logged_out, besides: holders without a sub that are no backup: a
//     service account with a deadline and no connection, a disabled local
//     person, and a local person without Read;
//   - and a pending registration, which is no number of the workspace's.
func newSnapshotFixture(t *testing.T, w *world) *snapshotFixture {
	t.Helper()
	ctx := context.Background()
	f := &snapshotFixture{users: map[string]uuid.UUID{}, subs: map[string]uuid.UUID{}, devices: map[string]uuid.UUID{}}
	people := []struct {
		name, role string
		linked     bool
	}{
		{"owner", "owner", true}, {"second_owner", "owner", true}, {"member", "member", true},
		{"holder", "member", true}, {"disabled", "member", true}, {"unlinked", "member", false},
		{"standing_service", "service", false}, {"assistant_service", "service", false},
		{"old_key", "member", true}, {"retired_key", "member", true}, {"expired", "member", true}, {"suspended", "member", true},
		{"deadline_service", "service", false}, {"disabled_local", "member", false}, {"keyonly_local", "member", false},
	}
	for i, p := range people {
		f.users[p.name] = fixed("b0c2", i+1)
		if p.linked {
			f.subs[p.name] = fixed("a0c2", i+1)
			if _, err := w.fake.AddAccount(f.subs[p.name].String()); err != nil {
				t.Fatal(err)
			}
		}
	}
	team, err := w.fake.AddTeam("Equipe", f.subs["owner"].String())
	if err != nil {
		t.Fatal(err)
	}
	f.team = uuid.MustParse(team)
	w.exec(ctx, t, `INSERT INTO tenants (id, name) VALUES ($1, 'Equipe')`, f.team)
	in := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := pg.InTenantTx(ctx, w.pool, f.team.String(), fn); err != nil {
			t.Fatal(err)
		}
	}
	in(func(tx pgx.Tx) error {
		for _, p := range people {
			// A person signs in through the platform, with no password; a
			// service account has none either.
			q := `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source) VALUES ($1, $2, $3, $4, $5, 'platform')`
			if p.role == "service" {
				q = `INSERT INTO users (id, tenant_id, email, public_key, role) VALUES ($1, $2, $3, $4, $5)`
			}
			if _, err := tx.Exec(ctx, q, f.users[p.name], f.team, p.name+"@fixture.test", random(t, 32), p.role); err != nil {
				return err
			}
		}
		return nil
	})
	for _, p := range people {
		if p.linked {
			w.exec(ctx, t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`,
				f.subs[p.name], f.users[p.name], p.name+"@id.test")
		}
	}
	devices, keys := store.NewDevices(w.pool), store.NewKeys(w.pool)
	for i, n := range fixtureNumbers {
		id := fixed("e000", i+1)
		f.devices[n.name] = id
		if _, err := devices.CreateWithID(ctx, f.team.String(), id.String(), n.label, wa.ModePassive); err != nil {
			t.Fatal(err)
		}
		in(func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE devices SET pn = nullif($2, '') || '@s.whatsapp.net', lid = nullif($3, ''),
				status = CASE WHEN $4 THEN 'online' ELSE 'offline' END, last_connected_at = CASE WHEN $4 THEN clock_timestamp() END
				WHERE id = $1`, id, n.pn, n.lid, n.connected)
			return err
		})
		epochs := []uint16{1}
		if n.name == "rotated" {
			epochs = []uint16{1, 2, 3}
		}
		for _, epoch := range epochs {
			pub, _, err := cryptoseal.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.CreateArchiveKey(ctx, f.team, id, epoch, pub); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := devices.CreateWithID(ctx, f.team.String(), fixed("e000", 99).String(), "pendente", wa.ModePassive); err != nil {
		t.Fatal(err)
	}
	var apiKey uuid.UUID
	if err := w.pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, created_by)
		VALUES ($1, 'fixture1', 'hash', 'assistant', $2) RETURNING id`, f.team, f.users["owner"]).Scan(&apiKey); err != nil {
		t.Fatal(err)
	}
	in(func(tx pgx.Tx) error {
		grant := func(number, person string, epoch int) error {
			// A grant brings Read and Send, as 0023's trigger gives them.
			_, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk)
				VALUES ($1, $2, $3, $4, 'grant')`, f.team, f.devices[number], f.users[person], epoch)
			return err
		}
		for _, g := range []struct {
			number, person string
			epoch          int
		}{
			{"live", "owner", 1}, {"live", "standing_service", 1}, {"live", "assistant_service", 1},
			{"paused", "owner", 1}, {"moving", "holder", 1}, {"moved_back", "second_owner", 1},
			{"logged_out", "owner", 1}, {"logged_out", "unlinked", 1}, {"deleted", "owner", 1}, {"disabled_holder", "disabled", 1},
			{"lid_only", "owner", 1}, {"connected_only", "owner", 1},
			{"rotated", "owner", 3}, {"rotated", "old_key", 2}, {"rotated", "retired_key", 1},
			{"live", "expired", 1}, {"live", "suspended", 1},
			{"logged_out", "deadline_service", 1}, {"logged_out", "disabled_local", 1}, {"logged_out", "keyonly_local", 1},
		} {
			if err := grant(g.number, g.person, g.epoch); err != nil {
				return err
			}
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read) VALUES ($1, $2, $3, true)`,
				[]any{f.team, f.devices["live"], f.users["member"]}},
			// Allowed to read, but not waiting: their account is disabled.
			{`INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read) VALUES ($1, $2, $3, true)`,
				[]any{f.team, f.devices["live"], f.users["disabled"]}},
			{`UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`,
				[]any{f.devices["moving"], f.users["holder"]}},
			{`UPDATE device_permissions SET can_manage = true WHERE device_id = $1 AND user_id = $2`,
				[]any{f.devices["deleted"], f.users["owner"]}},
			{`UPDATE workspace_memberships SET expires_at = clock_timestamp() + interval '1 day' WHERE tenant_id = $1 AND user_id = $2`,
				[]any{f.team, f.users["assistant_service"]}},
			{`INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host, device_count,
				reader_kid, status, expires_at, kind, service_user_id, key_mode, consent_version, reader)
				VALUES ($1, 'req-fixture', $2, $3, 'Claude', 'claude.ai', 1, 'kid', 'active', clock_timestamp() + interval '1 day',
				'content', $4, 'ephemeral', 1, 'enclave')`,
				[]any{f.team, apiKey, f.users["owner"], f.users["assistant_service"]}},
			{`UPDATE devices SET status = 'logged_out' WHERE id = $1`, []any{f.devices["logged_out"]}},
			{`UPDATE device_archive_keys SET retired_at = clock_timestamp() WHERE device_id = $1 AND epoch = 1`, []any{f.devices["rotated"]}},
			{`UPDATE workspace_memberships SET expires_at = clock_timestamp() - interval '1 day' WHERE tenant_id = $1 AND user_id = $2`,
				[]any{f.team, f.users["expired"]}},
			{`UPDATE workspace_memberships SET status = 'disabled' WHERE tenant_id = $1 AND user_id = $2`, []any{f.team, f.users["suspended"]}},
			{`UPDATE workspace_memberships SET expires_at = clock_timestamp() + interval '1 day' WHERE tenant_id = $1 AND user_id = $2`,
				[]any{f.team, f.users["deadline_service"]}},
			{`UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`,
				[]any{f.devices["logged_out"], f.users["keyonly_local"]}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return fmt.Errorf("%s: %w", q.sql, err)
			}
		}
		return nil
	})
	in(func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = ANY ($1)`,
			[]uuid.UUID{f.users["disabled"], f.users["disabled_local"]})
		if err == nil && tag.RowsAffected() != 2 {
			err = errors.New("the disabled people were not disabled")
		}
		return err
	})

	owner := store.PauseActor{User: f.users["owner"]}
	if _, err := devices.Pause(ctx, f.team, f.devices["paused"], owner); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.PauseForMove(ctx, f.team, f.devices["moving"]); err != nil {
		t.Fatal(err)
	}
	move, err := devices.PauseForMove(ctx, f.team, f.devices["moved_back"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Pause(ctx, f.team, f.devices["moved_back"], owner); err != nil {
		t.Fatal(err)
	}
	if undone, err := devices.UndoMovePause(ctx, f.team, f.devices["moved_back"], move); err != nil || undone {
		t.Fatalf("the move's pause undone over a person's stop: %v %v", undone, err)
	}
	return f
}

// deleteFixture deletes the fixture's deleted number, by its owner, and
// gives it a fixed purge date for the golden file.
func deleteFixture(t *testing.T, w *world, f *snapshotFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, f.team, f.users["owner"], f.devices["deleted"], nil); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, w.pool, f.team.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET purge_after = '2026-11-14T12:00:00Z' WHERE id = $1`, f.devices["deleted"])
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (w *world) snapshotOf(t *testing.T, ws uuid.UUID) (store.ContractSnapshot, kc.Snapshot) {
	t.Helper()
	read, err := w.contract.Snapshot(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	return read, SnapshotOf(read, 1)
}

func itemOf(snap kc.Snapshot, id uuid.UUID) (kc.Item, bool) {
	for _, it := range snap.Items {
		if it.ID == id.String() {
			return it, true
		}
	}
	return kc.Item{}, false
}

// TB5: the fixture's snapshot, rendered, validated and compared byte for
// byte with its golden file; the platform's strict intake accepts it; the
// deleted number lists the same people and protects the same person after
// its deletion as just before it, its reader still reads (the platform's
// answer, the plan's 14); and the number whose move's pause was undone
// over a person's stop is that person's pause.
func TestSnapshotGolden(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	f := newSnapshotFixture(t, w)
	_, before := w.snapshotOf(t, f.team)
	deleteFixture(t, w, f)
	read, snap := w.snapshotOf(t, f.team)
	if !read.Local || len(snap.Items) != len(fixtureNumbers) {
		t.Fatalf("%d items of %d numbers (local %v)", len(snap.Items), len(fixtureNumbers), read.Local)
	}
	if why := checkSnapshot(snap); why != "" {
		t.Fatalf("Wappie would not send its own snapshot: %s", why)
	}

	was, _ := itemOf(before, f.devices["deleted"])
	now, _ := itemOf(snap, f.devices["deleted"])
	if was.State != kc.StateActive || now.State != kc.StateDeleted || now.PurgeAt == nil || now.Reason != nil {
		t.Fatalf("the deleted number: %+v, before %+v", now, was)
	}
	if !reflect.DeepEqual(was.People, now.People) || !reflect.DeepEqual(was.Protected, now.Protected) ||
		len(now.People) != 1 || !now.People[0].Reads || !slices.Equal(now.Protected, []string{f.subs["owner"].String()}) {
		t.Fatalf("the deleted number's people and protected: %+v %v, before %+v %v", now.People, now.Protected, was.People, was.Protected)
	}
	if it, _ := itemOf(snap, f.devices["moved_back"]); it.State != kc.StateSyncPaused || it.Reason == nil || *it.Reason != "by_person" {
		t.Fatalf("a move's pause undone over a person's stop: %+v", it)
	}
	if _, listed := itemOf(snap, fixed("e000", 99)); listed {
		t.Fatal("a pending registration is listed")
	}
	// The read model's predicates, each case by name (the golden file pins
	// them too, but an -update would not tell them apart).
	person := func(number, name string) kc.Person {
		t.Helper()
		it, ok := itemOf(snap, f.devices[number])
		if !ok {
			t.Fatalf("%s is not listed", number)
		}
		for _, p := range it.People {
			if p.Sub == f.subs[name].String() {
				return p
			}
		}
		t.Fatalf("%s is not listed on %s", name, number)
		return kc.Person{}
	}
	for _, c := range []struct {
		number, name             string
		reads, waiting, holdsKey bool
	}{
		{"rotated", "owner", true, false, true},
		{"rotated", "old_key", false, true, true},
		{"rotated", "retired_key", false, true, false},
		{"live", "expired", false, false, true},
		{"live", "suspended", false, false, true},
		{"live", "disabled", false, false, false},
		{"live", "member", false, true, false},
		{"lid_only", "owner", true, false, true},
		{"connected_only", "owner", true, false, true},
	} {
		if p := person(c.number, c.name); p.Reads != c.reads || p.Waiting != c.waiting || p.HoldsKey != c.holdsKey {
			t.Errorf("%s on %s: reads %v waiting %v holds_key %v, want %v %v %v", c.name, c.number, p.Reads, p.Waiting, p.HoldsKey,
				c.reads, c.waiting, c.holdsKey)
		}
	}
	for number, want := range map[string]int{"live": 1, "logged_out": 1, "rotated": 0} {
		if it, _ := itemOf(snap, f.devices[number]); it.OtherBackups != want {
			t.Errorf("%s: %d backups without a sub, want %d", number, it.OtherBackups, want)
		}
	}
	if it, _ := itemOf(snap, f.devices["rotated"]); !slices.Equal(it.Protected, []string{f.subs["old_key"].String(), f.subs["owner"].String()}) &&
		!slices.Equal(it.Protected, []string{f.subs["owner"].String(), f.subs["old_key"].String()}) {
		t.Errorf("rotated: protected %v, want the owner and the only holder of epoch 2", it.Protected)
	}
	if !reflect.DeepEqual(read.Labels, fixtureLabels) {
		t.Errorf("the label counts: %v, want %v", read.Labels, fixtureLabels)
	}
	for _, it := range snap.Items {
		for _, p := range it.People {
			for _, name := range []string{"unlinked", "standing_service", "assistant_service", "deadline_service", "disabled_local", "keyonly_local"} {
				if p.Sub == f.users[name].String() {
					t.Fatalf("%s is listed on %s", name, it.ID)
				}
			}
		}
	}

	// An assistant's service account is never a backup, by its connection
	// as by its deadline (sole_key_holders' two conditions): without the
	// deadline, the live number still counts one backup, and protects
	// nobody.
	if err := pg.InTenantTx(ctx, w.pool, f.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at = NULL WHERE tenant_id = $1 AND user_id = $2`,
			f.team, f.users["assistant_service"])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, again := w.snapshotOf(t, f.team); !reflect.DeepEqual(again.Items, snap.Items) {
		t.Fatalf("an assistant's service account with no deadline changed the snapshot: %+v", again.Items)
	}

	// The platform's strict intake, once the team is named to the app.
	if _, err := w.members.Client.Subscribe(ctx, f.subs["owner"].String()); err != nil {
		t.Fatal(err)
	}
	snap.SnapshotSeq = time.Now().UnixMilli()
	if err := w.members.Client.PutAccess(ctx, f.team.String(), snap); err != nil {
		t.Fatalf("the fake platform with StrictLabels: %v", err)
	}
	if kept, ok := w.fake.Snapshot("wappie", f.team.String()); !ok || kept.SnapshotSeq != snap.SnapshotSeq {
		t.Fatalf("the platform kept %+v", kept)
	}

	snap.SnapshotSeq = 1
	got, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "snapshots", "fixture.json")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the fixture's snapshot differs from %s:\n%s", golden, got)
	}
}

// TB30: for each member of the fixture with a sub, protected lists them
// exactly when removing them is refused with last_device_reader or
// last_reader_of_deleted, by Wappie's own rule (one function, read by
// both); a sole holder whose account is disabled is in both (a suspended
// sole holder stays protected, the plan's 19). Each removal is tried and
// taken back: a trigger refuses the membership's delete, the last write a
// removal makes once its checks pass.
func TestSnapshotProtectedMatchesRefusal(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	f := newSnapshotFixture(t, w)
	deleteFixture(t, w, f)
	_, snap := w.snapshotOf(t, f.team)
	protected := map[string]bool{}
	for _, it := range snap.Items {
		for _, sub := range it.Protected {
			protected[sub] = true
		}
	}
	w.exec(ctx, t, `CREATE FUNCTION probe_removal() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'removable' USING ERRCODE = 'P0001'; END $$`)
	w.exec(ctx, t, `CREATE TRIGGER probe_removal BEFORE DELETE ON workspace_memberships FOR EACH ROW EXECUTE FUNCTION probe_removal()`)
	users := store.NewUsers(w.pool)
	seen := map[bool]int{}
	for name, sub := range f.subs {
		actor := f.users["second_owner"]
		if name == "second_owner" {
			actor = f.users["owner"]
		}
		err := users.RemoveMember(ctx, f.team, actor, f.users[name])
		var deleted *store.ErrLastReaderOfDeleted
		refused := errors.Is(err, store.ErrLastDeviceReader) || errors.As(err, &deleted)
		if !refused && (err == nil || !strings.Contains(err.Error(), "removable")) {
			t.Fatalf("removing %s: %v", name, err)
		}
		if refused != protected[sub.String()] {
			t.Errorf("%s: refused %v (%v), protected %v", name, refused, err, protected[sub.String()])
		}
		seen[refused]++
	}
	if seen[true] != 5 || seen[false] != 4 {
		t.Fatalf("the fixture's members: %d protected, %d not; want 5 and 4", seen[true], seen[false])
	}
	if !protected[f.subs["disabled"].String()] {
		t.Fatal("a suspended sole holder is not protected")
	}
}

// fromWire is the read model a vector's snapshot would come from, false
// when Wappie's would never hold it (a mailbox, the act flag, someone not
// enrolled).
func fromWire(t *testing.T, s kc.Snapshot) (store.ContractSnapshot, bool) {
	t.Helper()
	out := store.ContractSnapshot{Local: true}
	for _, it := range s.Items {
		id, err := uuid.Parse(it.ID)
		if err != nil || it.Kind != kc.ItemNumber {
			return out, false
		}
		item := store.ContractSnapshotItem{ID: id, Label: it.Label, Hint: it.Hint, State: it.State, OtherBackups: it.OtherBackups}
		if it.Reason != nil {
			item.Reason = *it.Reason
		}
		if it.PurgeAt != nil {
			at := it.PurgeAt.Time
			item.PurgeAt = &at
		}
		for _, p := range it.People {
			sub, err := uuid.Parse(p.Sub)
			if err != nil || !p.Enrolled || slices.Contains(p.Can, kc.CanAct) {
				return out, false
			}
			item.People = append(item.People, store.ContractSnapshotPerson{Sub: sub, Read: slices.Contains(p.Can, kc.CanRead),
				Send: slices.Contains(p.Can, kc.CanSend), Manage: slices.Contains(p.Can, kc.CanManage),
				Reads: p.Reads, Waiting: p.Waiting, HoldsKey: p.HoldsKey})
		}
		for _, p := range it.Protected {
			item.Protected = append(item.Protected, uuid.MustParse(p))
		}
		out.Items = append(out.Items, item)
	}
	return out, true
}

// TB2's snapshot part: every snapshot of wire.json and wire-item-ids.json
// through Wappie's own check before a send, which takes exactly the valid
// ones; and each valid one Wappie's read model can hold, through Wappie's
// own encoder, comes back as the vector.
func TestSnapshotWireVectors(t *testing.T) {
	trips := 0
	for _, file := range []string{"wire.json", "wire-item-ids.json"} {
		var w wireVectors
		readVectors(t, file, &w)
		if len(w.Snapshots) == 0 {
			t.Fatalf("%s: no snapshots", file)
		}
		for _, c := range w.Snapshots {
			var s kc.Snapshot
			if err := json.Unmarshal(c.Value, &s); err != nil {
				t.Fatalf("%s: %s: %v", file, c.Name, err)
			}
			if got := checkSnapshot(s) == ""; got != c.Valid {
				t.Errorf("%s: %s: Wappie would send it %v, valid %v (%q)", file, c.Name, got, c.Valid, checkSnapshot(s))
			}
			read, ok := fromWire(t, s)
			if !c.Valid || !ok {
				continue
			}
			got, err := json.Marshal(SnapshotOf(read, s.SnapshotSeq))
			if err != nil {
				t.Fatal(err)
			}
			var a, b any
			if err := json.Unmarshal(got, &a); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(c.Value, &b); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(a, b) {
				t.Errorf("%s: %s: Wappie's encoder gives\n%s\nwant\n%s", file, c.Name, got, c.Value)
			}
			trips++
		}
	}
	if trips < 3 {
		t.Fatalf("only %d vectors went through the encoder", trips)
	}
	// Beyond README 8's limits, and the call's.
	many := kc.Snapshot{V: 1, SnapshotSeq: 1, Items: make([]kc.Item, kc.MaxItems+1)}
	if why := checkSnapshot(many); why != "items" {
		t.Errorf("1001 items: %q", why)
	}
	crowd := kc.Snapshot{V: 1, SnapshotSeq: 1, Items: []kc.Item{{People: make([]kc.Person, kc.MaxPeople+1)}}}
	if why := checkSnapshot(crowd); why != "people" {
		t.Errorf("5001 people: %q", why)
	}
	// Within README 8's counts, but over the call's 1 MiB body: two items of
	// 5000 people each; one of them is under it.
	big := kc.Snapshot{V: kc.SnapshotV, SnapshotSeq: 1, Items: []kc.Item{}}
	for range 2 {
		it := kc.Item{ID: uuid.NewString(), Kind: kc.ItemNumber, State: kc.StateActive, People: []kc.Person{}, Protected: []string{}}
		for range kc.MaxPeople {
			it.People = append(it.People, kc.Person{Sub: uuid.NewString(), Can: []string{kc.CanRead}, Reads: true, Enrolled: true, HoldsKey: true})
		}
		big.Items = append(big.Items, it)
	}
	if body, err := json.Marshal(big); err != nil || len(body) <= 1<<20 || len(body) > 2<<20 {
		t.Fatalf("the big snapshot is %d bytes (%v), want just over 1 MiB", len(body), err)
	}
	if why := checkSnapshot(big); why != "too_large" {
		t.Errorf("a body over 1 MiB: %q", why)
	}
	big.Items = big.Items[:1]
	if why := checkSnapshot(big); why != "" {
		t.Errorf("a body under 1 MiB: %q", why)
	}
}

// snapshotResult sorts PutAccess's answer as README 8's "The answer" does:
// a signed accepted; a signed not_found, retried for a day, then parked; a
// signed invalid_request, parked; anything else retried with the backoff,
// an unverified answer and no answer included, neither being the
// platform's word.
func TestSnapshotResult(t *testing.T) {
	refusal := func(status int, code string) error { return &kc.Refusal{Status: status, Code: code, Message: "m"} }
	for _, c := range []struct {
		what    string
		err     error
		outcome store.ContractSnapshotOutcome
		class   string
	}{
		{"accepted", nil, store.SnapshotAccepted, ""},
		{"a signed not_found", refusal(404, kc.CodeNotFound), store.SnapshotNotFound, "refused:not_found"},
		{"a signed not_found, wrapped", fmt.Errorf("put: %w", refusal(404, kc.CodeNotFound)), store.SnapshotNotFound, "refused:not_found"},
		{"a signed invalid_request", refusal(400, kc.CodeInvalid), store.SnapshotRefused, "refused:invalid_request"},
		{"a signed unavailable", refusal(503, kc.CodeUnavailable), store.SnapshotFailed, "refused:unavailable"},
		{"a signed rate_limited", refusal(429, kc.CodeRateLimited), store.SnapshotFailed, "refused:rate_limited"},
		{"a signed replay", refusal(409, kc.CodeReplay), store.SnapshotFailed, "refused:replay"},
		{"an unverified answer", fmt.Errorf("%w: the signature", kc.ErrUnverified), store.SnapshotFailed, "unverified"},
		{"no answer: a timeout", fmt.Errorf("put: %w", context.DeadlineExceeded), store.SnapshotFailed, "timeout"},
		{"no answer: no transport", ErrUnavailable, store.SnapshotFailed, "no_transport"},
		{"no answer: no secret", ErrNoSecret, store.SnapshotFailed, "no_secret"},
	} {
		if outcome, class := snapshotResult(c.err); outcome != c.outcome || class != c.class {
			t.Errorf("%s: %d %q, want %d %q", c.what, outcome, class, c.outcome, c.class)
		}
	}
}

// The sender's bounds, pinned with literals (P3a's lesson: a test that
// reads a constant cannot pin it): README 8's cadence, and the worst age a
// snapshot reaches at the platform in steady state, across a leader's
// handover, well under the 60 minutes after which contract status --check
// warns and the platform's 90.
func TestSnapshotBounds(t *testing.T) {
	for name, c := range map[string]struct{ got, want time.Duration }{
		"the next after one accepted": {snapshotEvery, 55 * time.Minute},
		"the debounce":                {snapshotDebounce, 2 * time.Second},
		"the first backoff":           {snapshotBackoffMin, 5 * time.Second},
		"the longest backoff":         {snapshotBackoffMax, time.Hour},
		"the longest idle":            {snapshotIdle, time.Minute},
		"the label counts' interval":  {labelsEvery, time.Hour},
		"a not_found's day":           {store.SnapshotNotFoundFor, 24 * time.Hour},
	} {
		if c.got != c.want {
			t.Errorf("%s: %v, want %v", name, c.got, c.want)
		}
	}
	if snapshotBodyLimit != 1<<20 {
		t.Errorf("the call's body limit: %d, want 1 MiB (README 3)", snapshotBodyLimit)
	}
	worst := snapshotEvery + kc.CallTimeout + 2*pg.HoldHeartbeat + leaderRetry
	if worst >= 60*time.Minute {
		t.Errorf("a snapshot may be %v old before the next, past --check's 60 minutes", worst)
	}
}

// snapshotWorld is a leader's world for the cadence: a person Wappie holds
// at the platform's personal workspace, owner of a team of the platform's
// that Wappie holds too, with a number, its archive key and the owner's
// key, both workspaces recorded by the owner's sign-in.
type snapshotWorld struct {
	*world
	owner, sub, home, team, device uuid.UUID
}

func newSnapshotWorld(t *testing.T) *snapshotWorld {
	t.Helper()
	ctx := context.Background()
	w := &snapshotWorld{world: newWorld(t)}
	w.owner, w.sub, w.home = w.heldAtHome(t)
	team, err := w.fake.AddTeam("Equipe", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	w.team = uuid.MustParse(team)
	w.localTeam(t, w.team, "Equipe", member{w.owner, "owner", "active"})
	d, err := store.NewDevices(w.pool).Create(ctx, w.team.String(), "Vendas", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	w.device = uuid.MustParse(d.ID)
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511912345678@s.whatsapp.net' WHERE id = $1`, w.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pub, _, err := cryptoseal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(w.pool).CreateArchiveKey(ctx, w.team, w.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(w.pool).PutGrant(ctx, store.Grant{TenantID: w.team, DeviceID: w.device, UserID: w.owner, Epoch: 1,
		SealedDSK: []byte("grant")}, &w.owner); err != nil {
		t.Fatal(err)
	}
	w.members.SignIn(ctx, w.sub)
	for _, ws := range []uuid.UUID{w.home, w.team} {
		if _, ok, err := w.contract.Workspace(ctx, ws); err != nil || !ok {
			t.Fatalf("%s not recorded: %v %v", ws, ok, err)
		}
	}
	return w
}

// accepted counts the snapshots of ws the fake accepted.
func (w *world) accepted(ws uuid.UUID) int { return len(w.fake.Accepted(ws.String())) }

// settle waits until nothing is pending for the workspaces wss: Wappie has
// recorded each one's last outcome, and its next snapshot is the hourly
// one (the platform answers before Wappie records the answer).
func (w *world) settle(t *testing.T, wss ...uuid.UUID) {
	t.Helper()
	eventually(t, 10*time.Second, "the snapshots settled", func() bool {
		for _, ws := range wss {
			var quiet bool
			if err := w.pool.QueryRow(context.Background(), `SELECT snapshot_due_at > clock_timestamp() + interval '10 minutes'
				AND snapshot_tries = 0 FROM contract_workspaces WHERE workspace_id = $1`, ws).Scan(&quiet); err != nil || !quiet {
				return false
			}
		}
		return true
	})
}

// oneMore makes change once nothing is pending for ws, and waits for one
// snapshot of it within 3 s, and none more once it has settled again.
func (w *world) oneMore(t *testing.T, what string, ws uuid.UUID, change func() error) {
	t.Helper()
	w.settle(t, ws)
	n := w.accepted(ws)
	if err := change(); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	eventually(t, 3*time.Second, what+": a snapshot within 3 s", func() bool { return w.accepted(ws) > n })
	w.settle(t, ws)
	if got := w.accepted(ws) - n; got != 1 {
		t.Fatalf("%s: %d snapshots, want one", what, got)
	}
}

// TB27: the cadence (README 8). At the leader's start every recorded
// workspace's snapshot, an empty one for a workspace Wappie has no tenant
// for; one snapshot within 3 s of a pause, a grant, a permission, a
// membership, a move (both workspaces) and a storage stop; ten changes in a
// second give one; and the next is due an hour (here: shortened) after the
// last accepted. One sender across two processes, which stops sending when
// its lock goes; and after an hour of the platform refusing (the backoff at
// its cap), the first signed feed answer brings every snapshot back within
// 3 s.
func TestSnapshotCadence(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	key := lockKey(t)
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, key)
	l.SnapshotEvery = time.Hour
	stop := run(t, l)
	// At least one each: the round's PUT and the feed's first page, at the
	// leader's start too, name both before their first snapshot is
	// accepted, which makes them due once more (the plan's 4.7).
	for _, ws := range []uuid.UUID{w.home, w.team} {
		eventually(t, 3*time.Second, "the leader's start: "+ws.String(), func() bool { return w.accepted(ws) >= 1 })
	}
	if s, _ := w.fake.Snapshot("wappie", w.team.String()); len(s.Items) != 1 || s.Items[0].ID != w.device.String() {
		t.Fatalf("the team's snapshot: %+v", s)
	}

	// A workspace Wappie has no tenant for, named to the app: an empty
	// snapshot, right after it is first named.
	outside, err := w.fake.AddTeam("Fora", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the outside team's snapshot", func() bool { return w.accepted(uuid.MustParse(outside)) == 1 })
	if s, _ := w.fake.Snapshot("wappie", outside); s.Items == nil || len(s.Items) != 0 {
		t.Fatalf("the outside team's snapshot: %+v", s)
	}
	w.settle(t, w.home, w.team, uuid.MustParse(outside))

	devices, keys, users := store.NewDevices(w.pool), store.NewKeys(w.pool), store.NewUsers(w.pool)
	other := w.localPerson(t)
	w.oneMore(t, "a member joins", w.team, func() error {
		w.localTeam(t, w.team, "", member{other, "member", "active"})
		return nil
	})
	for _, c := range []struct {
		what   string
		change func() error
	}{
		{"a pause", func() error {
			_, err := devices.Pause(ctx, w.team, w.device, store.PauseActor{User: w.owner})
			return err
		}},
		{"a grant", func() error {
			return keys.PutGrant(ctx, store.Grant{TenantID: w.team, DeviceID: w.device, UserID: other, Epoch: 1, SealedDSK: []byte("g")}, &w.owner)
		}},
		{"a permission", func() error {
			return users.SetDevicePermission(ctx, w.team, w.owner, store.DevicePermission{DeviceID: w.device, UserID: other, Read: true, Manage: true})
		}},
		{"a membership", func() error { return users.UpdateMember(ctx, w.team, w.owner, other, "admin", "active") }},
		{"a storage stop", func() error {
			_, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at = clock_timestamp() WHERE id = $1`, w.team)
			return err
		}},
	} {
		w.oneMore(t, c.what, w.team, c.change)
	}
	if s, _ := w.fake.Snapshot("wappie", w.team.String()); len(s.Items) != 1 || s.Items[0].Reason == nil || *s.Items[0].Reason != "quota" {
		t.Fatalf("after the storage stop: %+v", s.Items)
	}
	w.oneMore(t, "the storage resumed", w.team, func() error {
		_, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at = NULL WHERE id = $1`, w.team)
		return err
	})

	// Ten changes in a second: one snapshot, of the last.
	w.oneMore(t, "ten changes in a second", w.team, func() error {
		for i := range 10 {
			if err := devices.Rename(ctx, w.team.String(), w.device.String(), fmt.Sprintf("Vendas %d", i)); err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	})
	if s, _ := w.fake.Snapshot("wappie", w.team.String()); *s.Items[0].Label != "Vendas 9" {
		t.Fatalf("the debounced snapshot's label: %q", *s.Items[0].Label)
	}

	// A move: the workspace it leaves and the one it reaches. The member
	// leaves first: nobody else may have access.
	w.oneMore(t, "the member removed", w.team, func() error { return users.RemoveMember(ctx, w.team, w.owner, other) })
	w.settle(t, w.home)
	home := w.accepted(w.home)
	w.oneMore(t, "a move, the team", w.team, func() error {
		_, err := devices.TransferPersonal(ctx, w.team, w.owner, w.device, w.home)
		return err
	})
	w.settle(t, w.home)
	if got := w.accepted(w.home) - home; got != 1 {
		t.Fatalf("a move, the personal workspace: %d snapshots", got)
	}
	if s, _ := w.fake.Snapshot("wappie", w.home.String()); len(s.Items) != 1 || s.Items[0].ID != w.device.String() {
		t.Fatalf("the personal workspace after the move: %+v", s.Items)
	}

	// Hourly, here shortened: a leader started again with its next 1.5 s
	// after the last accepted sends one at its start, then on its own.
	w.settle(t, w.team, w.home)
	stop()
	l = w.leader(w.members, logs, key)
	l.SnapshotEvery = 1500 * time.Millisecond
	team := w.accepted(w.team)
	stop = run(t, l)
	eventually(t, 3*time.Second, "the leader's start, again", func() bool { return w.accepted(w.team) == team+1 })
	eventually(t, 5*time.Second, "the next, with no change", func() bool { return w.accepted(w.team) >= team+3 })
	stop()

	// One sender across two processes; it stops with its lock.
	var procs []*counting
	for range 2 {
		c := &counting{}
		client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
		if err := client.Use(w.secret, ""); err != nil {
			t.Fatal(err)
		}
		m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
		run(t, w.leader(m, &membershiptest.Logs{}, key))
		procs = append(procs, c)
	}
	eventually(t, 5*time.Second, "a leader's start", func() bool { return procs[0].access.Load()+procs[1].access.Load() >= 3 })
	time.Sleep(time.Second)
	sending := -1
	for i, p := range procs {
		if p.access.Load() > 0 {
			if sending >= 0 {
				t.Fatal("both processes send snapshots")
			}
			sending = i
		}
	}
	if sending < 0 {
		t.Fatal("no process sends snapshots")
	}
	old, next := procs[sending], procs[1-sending]
	if _, err := w.pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, w.lockHolder(t, key)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the other process's start sends", func() bool { return next.access.Load() >= 3 })
	sent := old.access.Load()
	if err := devices.Rename(ctx, w.home.String(), w.device.String(), "Depois"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "the change, by the new leader", func() bool { return next.access.Load() >= 4 })
	time.Sleep(500 * time.Millisecond)
	if n := old.access.Load(); n != sent {
		t.Fatalf("the old leader sent %d snapshots after its lock went", n-sent)
	}

	// An hour of the platform refusing: the backoff at its cap, then the
	// first signed feed answer brings every snapshot back.
	w.fake.RefuseAlways(contracttest.CallFeed, kc.CodeUnavailable)
	w.fake.RefuseAlways(contracttest.CallAccess, kc.CodeUnavailable)
	w.exec(ctx, t, `SELECT pg_notify($1, 'generation')`, store.ContractModeChannel)
	if err := devices.Rename(ctx, w.home.String(), w.device.String(), "Durante"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "a snapshot refused", func() bool {
		var tries int
		_ = w.pool.QueryRow(ctx, `SELECT snapshot_tries FROM contract_workspaces WHERE workspace_id = $1`, w.home).Scan(&tries) //nolint:errcheck // a test's read
		return tries > 0
	})
	w.exec(ctx, t, `UPDATE contract_workspaces SET snapshot_tries = 10, snapshot_due_at = clock_timestamp() + interval '1 hour'`)
	before := map[uuid.UUID]int{}
	for _, ws := range []uuid.UUID{w.home, w.team, uuid.MustParse(outside)} {
		before[ws] = w.accepted(ws)
	}
	w.fake.RefuseAlways(contracttest.CallAccess, "")
	w.fake.RefuseAlways(contracttest.CallFeed, "")
	reads := len(w.fake.Reads())
	eventually(t, 5*time.Second, "a signed feed answer", func() bool { return len(w.fake.Reads()) > reads })
	answered := time.Now()
	for ws, n := range before {
		eventually(t, 3*time.Second, "after the outage: "+ws.String(), func() bool { return w.accepted(ws) > n })
	}
	if took := time.Since(answered); took > 3*time.Second {
		t.Fatalf("the snapshots came back %v after the feed", took)
	}
}

// TB28: a workspace's snapshot_seq rises strictly, in the order the
// platform receives them, across leaders (a lock lost, a process stopped)
// and a clock stepped back, and the platform keeps the latest.
func TestSnapshotSeqRises(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	key := lockKey(t)
	process := func() (stop func()) {
		client := NewClient(&http.Client{}, w.fake.URL, nil)
		if err := client.Use(w.secret, ""); err != nil {
			t.Fatal(err)
		}
		m := &Members{Client: client, Contract: w.contract, Log: w.logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
		return run(t, w.leader(m, &membershiptest.Logs{}, key))
	}
	stopA := process()
	process()
	devices := store.NewDevices(w.pool)
	change := func(i int) {
		t.Helper()
		n := w.accepted(w.team)
		if err := devices.Rename(ctx, w.team.String(), w.device.String(), fmt.Sprintf("Vendas %d", i)); err != nil {
			t.Fatal(err)
		}
		eventually(t, 5*time.Second, fmt.Sprintf("change %d's snapshot", i), func() bool { return w.accepted(w.team) > n })
	}
	eventually(t, 5*time.Second, "the leader's start", func() bool { return w.accepted(w.team) >= 1 })
	for i := range 8 {
		change(i)
		switch i {
		case 2:
			// A takeover: the leader's lock connection goes.
			if _, err := w.pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, w.lockHolder(t, key)); err != nil {
				t.Fatal(err)
			}
		case 4:
			// The first process stops, whichever leads; a third starts.
			stopA()
			process()
		case 6:
			// The clock steps back an hour: the last seq an hour ahead.
			w.exec(ctx, t, `UPDATE contract_workspaces SET snapshot_seq = (extract(epoch FROM clock_timestamp() + interval '1 hour') * 1000)::bigint
				WHERE workspace_id = $1`, w.team)
		}
	}
	var seqs []int64
	for _, a := range w.fake.Accesses(w.team.String()) {
		seqs = append(seqs, a.Seq)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("snapshot_seq %d after %d (all: %v)", seqs[i], seqs[i-1], seqs)
		}
	}
	var stored int64
	if err := w.pool.QueryRow(ctx, `SELECT snapshot_seq FROM contract_workspaces WHERE workspace_id = $1`, w.team).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	kept, _ := w.fake.Snapshot("wappie", w.team.String())
	if len(seqs) < 9 || kept.SnapshotSeq != seqs[len(seqs)-1] || stored != kept.SnapshotSeq || *kept.Items[0].Label != "Vendas 7" {
		t.Fatalf("%d snapshots; the platform keeps %d (%v), Wappie stored %d, the last sent %d", len(seqs), kept.SnapshotSeq,
			kept.Items, stored, seqs[len(seqs)-1])
	}
	if ahead := time.UnixMilli(kept.SnapshotSeq); time.Until(ahead) < 50*time.Minute {
		t.Fatalf("after the clock stepped back the seq is %v, not past the one an hour ahead", ahead)
	}
}

// TB29: a workspace the platform answers not_found for is retried with the
// backoff, parked once its first not_found is a day old (the clock moved
// in SQL), with an ERROR recorded for contract status --check; a document
// that names it again releases it and its snapshot goes at once. A
// snapshot refused as invalid (a Wappie bug) parks at once, which no
// document releases; a leader's start tries it once more.
func TestSnapshotNotFoundParks(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	key := lockKey(t)
	logs := &membershiptest.Logs{}
	leader := func() *Leader {
		l := w.leader(w.members, logs, key)
		l.SnapshotBackoffMin, l.SnapshotBackoffMax = 50*time.Millisecond, 200*time.Millisecond
		return l
	}
	stop := run(t, leader())
	eventually(t, 5*time.Second, "the leader's start", func() bool { return w.accepted(w.team) == 1 })
	row := func() (tries int, notFound, parked *time.Time, class *string) {
		t.Helper()
		if err := w.pool.QueryRow(ctx, `SELECT snapshot_tries, not_found_since, parked_at, snapshot_error FROM contract_workspaces
			WHERE workspace_id = $1`, w.team).Scan(&tries, &notFound, &parked, &class); err != nil {
			t.Fatal(err)
		}
		return
	}
	sent := func() int { return len(w.fake.Accesses(w.team.String())) }
	devices := store.NewDevices(w.pool)
	rename := func(name string) {
		t.Helper()
		if err := devices.Rename(ctx, w.team.String(), w.device.String(), name); err != nil {
			t.Fatal(err)
		}
	}

	w.fake.RefuseAlways(contracttest.CallAccess, kc.CodeNotFound)
	rename("Vendas 1")
	eventually(t, 5*time.Second, "retried", func() bool {
		tries, notFound, parked, _ := row()
		return tries >= 3 && notFound != nil && parked == nil
	})
	_, first, _, class := row()
	if class == nil || *class != "refused:not_found" {
		t.Fatalf("the failure's class: %v", class)
	}
	w.exec(ctx, t, `UPDATE contract_workspaces SET not_found_since = not_found_since - interval '24 hours' WHERE workspace_id = $1`, w.team)
	eventually(t, 5*time.Second, "parked", func() bool { _, _, parked, _ := row(); return parked != nil })
	eventually(t, 5*time.Second, "the park's ERROR recorded", func() bool {
		return len(logs.Lines("level=ERROR", "a workspace's snapshot is parked")) == 1 && w.state(t).ErrorClass == store.ContractErrorSnapshotParked
	})
	if _, notFound, _, _ := row(); notFound == nil || !notFound.Equal(first.Add(-24*time.Hour)) {
		t.Fatalf("the park lost its first not_found: %v, was %v", notFound, first)
	}
	n := sent()
	rename("Vendas 2")
	time.Sleep(time.Second)
	if got := sent(); got != n {
		t.Fatalf("%d snapshots sent while parked", got-n)
	}

	// A document that names it again: released, and sent at once. The
	// count is taken before the document: the park holds every snapshot
	// until it comes (above), and the one it releases may be accepted
	// before the document's row is seen here.
	w.fake.RefuseAlways(contracttest.CallAccess, "")
	version := w.version(t, w.sub)
	accepted := w.accepted(w.team)
	named := time.Now()
	if err := w.fake.RenameTeam(w.team.String(), "Equipe 2"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the document naming it", func() bool { return w.version(t, w.sub) > version })
	eventually(t, 3*time.Second, "the snapshot after the document", func() bool { return w.accepted(w.team) > accepted })
	if took := time.Since(named); took > 3*time.Second {
		t.Fatalf("the snapshot went %v after the document", took)
	}
	// The platform answers before Wappie records the answer.
	eventually(t, 5*time.Second, "the release recorded", func() bool {
		tries, notFound, parked, class := row()
		return tries == 0 && notFound == nil && parked == nil && class == nil
	})
	if s, _ := w.fake.Snapshot("wappie", w.team.String()); *s.Items[0].Label != "Vendas 2" {
		t.Fatalf("the released snapshot is not the latest: %q", *s.Items[0].Label)
	}

	// invalid_request: parked at once, and a document does not release it.
	w.fake.RefuseAlways(contracttest.CallAccess, kc.CodeInvalid)
	rename("Vendas 3")
	eventually(t, 5*time.Second, "parked as invalid", func() bool { _, _, parked, _ := row(); return parked != nil })
	if tries, notFound, _, class := row(); notFound != nil || class == nil || *class != "refused:invalid_request" || tries != 0 {
		t.Fatalf("an invalid park: tries %d, not_found %v, class %v", tries, notFound, class)
	}
	n = sent()
	version = w.version(t, w.sub)
	if err := w.fake.RenameTeam(w.team.String(), "Equipe 3"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "another document naming it", func() bool { return w.version(t, w.sub) > version })
	time.Sleep(time.Second)
	if got := sent(); got != n {
		t.Fatalf("a document released an invalid park: %d snapshots", got-n)
	}
	// A leader's start tries it once, and it parks again.
	stop()
	stop = run(t, leader())
	eventually(t, 5*time.Second, "the leader's start's one try", func() bool { return sent() == n+1 })
	eventually(t, 5*time.Second, "parked again", func() bool { _, _, parked, _ := row(); return parked != nil })
	time.Sleep(500 * time.Millisecond)
	if got := sent(); got != n+1 {
		t.Fatalf("%d tries after the leader's start, want one", got-n)
	}
	// Fixed: the next leader's start sends it.
	w.fake.RefuseAlways(contracttest.CallAccess, "")
	stop()
	accepted = w.accepted(w.team)
	run(t, leader())
	eventually(t, 5*time.Second, "accepted after the fix", func() bool { return w.accepted(w.team) > accepted })
	eventually(t, 5*time.Second, "the fix recorded", func() bool { _, _, parked, class := row(); return parked == nil && class == nil })
}

// TestSnapshotsNeverStale: on the platform's clock, here 240 times faster
// than the test's (the leader's timings 240 times shorter than their
// defaults), no named workspace goes near the platform's 90 minutes
// without an accepted snapshot (contract_snapshots_stale, the plan's 18),
// nor the 60 minutes after which contract status --check warns: not in
// steady state, where one goes 55 minutes after the last; not across a
// takeover after the lock's connection is killed, nor a restart of the
// leading process; and after an outage of the platform, within minutes of
// its return (the follower's first page after it, a long-poll's wait and
// the feed's backoff later: here 4 minutes for the test's 1 s wait, in
// production up to 85 s). A workspace first named is sent its snapshot at once.
// The platform signs on the real clock (its 60 s window), and its receipts
// are timed on the fast one.
func TestSnapshotsNeverStale(t *testing.T) {
	const scale = 240
	origin := time.Now()
	clock := func() time.Time { return origin.Add(time.Since(origin) * scale) }
	w := newSnapshotWorld(t)
	w.fake.RecordOn(clock)
	key := lockKey(t)
	scaled := func(m *Members) *Leader {
		return &Leader{Members: m, Pool: w.pool, Log: (&membershiptest.Logs{}).Logger(), Key: key,
			Retry: leaderRetry / scale, Heartbeat: pg.HoldHeartbeat / scale, ModeCheck: modeCheck / scale, Wait: 1,
			BackoffMin: feedBackoffMin / scale, BackoffMax: feedBackoffMax / scale, SweepEvery: sweepEvery / scale, RoundEvery: roundEvery / scale,
			SnapshotEvery: snapshotEvery / scale, SnapshotDebounce: snapshotDebounce / scale,
			SnapshotBackoffMin: snapshotBackoffMin / scale, SnapshotBackoffMax: snapshotBackoffMax / scale, ours: w.backends.Has}
	}
	second := func() *Members {
		client := NewClient(&http.Client{}, w.fake.URL, nil)
		if err := client.Use(w.secret, ""); err != nil {
			t.Fatal(err)
		}
		return &Members{Client: client, Contract: w.contract, Log: w.logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	}
	stopA := run(t, scaled(w.members))
	run(t, scaled(second()))
	eventually(t, 5*time.Second, "the first snapshots", func() bool { return w.accepted(w.team) > 0 && w.accepted(w.home) > 0 })

	// Steady state past an hour of the platform's clock.
	time.Sleep(16 * time.Second)
	// A workspace named now.
	outside, err := w.fake.AddTeam("Fora", w.sub.String())
	if err != nil {
		t.Fatal(err)
	}
	named := clock()
	eventually(t, 5*time.Second, "the new workspace's snapshot", func() bool { return w.accepted(uuid.MustParse(outside)) > 0 })
	if first := w.fake.Accepted(outside)[0]; first.Sub(named) > 5*time.Minute {
		t.Fatalf("a workspace first named waited %v of the platform's clock", first.Sub(named))
	}
	// A takeover, then a restart of the first process.
	if _, err := w.pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, w.lockHolder(t, key)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	stopA()
	time.Sleep(2 * time.Second)
	run(t, scaled(second()))
	time.Sleep(3 * time.Second)
	// An outage: the platform answers nothing for half an hour of its
	// clock, then answers again.
	w.fake.SetDown(true)
	down := clock()
	time.Sleep(30 * time.Minute / scale)
	w.fake.SetDown(false)
	up := clock()
	time.Sleep(16 * time.Second)

	for _, ws := range []string{w.team.String(), w.home.String(), outside} {
		got := w.fake.Accepted(ws)
		worst, back := time.Duration(0), time.Duration(-1)
		for i := 1; i < len(got); i++ {
			if got[i-1].Before(up) && got[i].After(down) {
				// The outage is the platform's own: what counts is how soon a
				// snapshot goes once it answers again.
				continue
			}
			worst = max(worst, got[i].Sub(got[i-1]))
		}
		for _, at := range got {
			if at.After(up) {
				back = at.Sub(up)
				break
			}
		}
		last := clock().Sub(got[len(got)-1])
		if worst > 70*time.Minute || worst == 0 || last > 70*time.Minute {
			t.Errorf("%s: the longest gap between accepted snapshots is %v of the platform's clock, the last %v ago (%d snapshots)",
				ws, worst, last, len(got))
		}
		// The first feed page after the outage brings the snapshots back
		// (the follower's recovery): the long-poll's wait, here a second of
		// the test's clock, and the feed's backoff.
		if back < 0 || back > 10*time.Minute {
			t.Errorf("%s: after the outage a snapshot was accepted %v later on the platform's clock", ws, back)
		}
		t.Logf("%s: the longest gap %v, the first after the outage %v later, %d snapshots", ws, worst, back, len(got))
	}
}

// The sender's own refusal (the plan's 4.10): a workspace over README 8's
// 1000 numbers is never sent; one ERROR per run names the rule, never a
// value, and is recorded for contract status --check (snapshot_invalid);
// the workspace keeps local_invalid:items, is never parked, and is tried
// again with the backoff; once a deletion brings it to 1000 it is sent.
func TestSnapshotOverTheLimits(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO devices (tenant_id, label, status, pn)
			SELECT $1, 'n' || g, 'online', '5521' || lpad(g::text, 9, '0') || '@s.whatsapp.net' FROM generate_series(1, 1000) g`, w.team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKey(t))
	l.SnapshotBackoffMin, l.SnapshotBackoffMax = 50*time.Millisecond, 200*time.Millisecond
	run(t, l)
	row := func() (tries int, parked *time.Time, class *string) {
		t.Helper()
		if err := w.pool.QueryRow(ctx, `SELECT snapshot_tries, parked_at, snapshot_error FROM contract_workspaces WHERE workspace_id = $1`,
			w.team).Scan(&tries, &parked, &class); err != nil {
			t.Fatal(err)
		}
		return
	}
	eventually(t, 5*time.Second, "retried with the backoff", func() bool {
		tries, parked, class := row()
		return tries >= 4 && parked == nil && class != nil && *class == "local_invalid:items"
	})
	eventually(t, 5*time.Second, "the ERROR recorded", func() bool { return w.state(t).ErrorClass == store.ContractErrorSnapshotInvalid })
	if n := len(w.fake.Accesses(w.team.String())); n != 0 {
		t.Fatalf("%d snapshots of 1001 numbers sent", n)
	}
	lines := logs.Lines("level=ERROR", "Wappie would not send it")
	if len(lines) != 1 || !strings.Contains(lines[0], "workspace="+w.team.String()) || !strings.Contains(lines[0], "reason=items") ||
		!strings.Contains(lines[0], "items=1001") || strings.Contains(lines[0], "n1") || strings.Contains(lines[0], "5521") {
		t.Fatalf("the ERRORs: %q", lines)
	}
	if w.accepted(w.home) == 0 {
		t.Fatal("the other workspace's snapshot waits on this one")
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1 AND label = 'n1000'`, w.team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "sent at 1000 numbers", func() bool { return w.accepted(w.team) == 1 })
	if s, _ := w.fake.Snapshot("wappie", w.team.String()); len(s.Items) != 1000 {
		t.Fatalf("the snapshot sent has %d items", len(s.Items))
	}
	eventually(t, 5*time.Second, "the run ended", func() bool { tries, parked, class := row(); return tries == 0 && parked == nil && class == nil })
	if n := len(logs.Lines("level=ERROR", "Wappie would not send it")); n != 1 {
		t.Fatalf("%d ERRORs for one run", n)
	}
}

// The snapshots go at the pace, as the round's PUTs (P3a's review: all of
// the app's calls stay well under the platform's 50 a second, one unsigned
// 429 being a new account's failed PUT), even at a leader's start, when
// every workspace is due at once. Each is timed as the client sends it, by
// the turn it went on (counting.pace), not by the clock, which a loaded
// machine moves between a turn and its call; and none goes without a
// turn, nor a turn before its time.
func TestSnapshotsArePaced(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	const pace = 200 * time.Millisecond
	for range 5 {
		w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, uuid.New())
	}
	c := &counting{}
	client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	m := &Members{Client: client, Contract: w.contract, Log: w.logs.Logger(), ModeCache: -1, Pace: pace}
	c.pace(m)
	run(t, w.leader(m, &membershiptest.Logs{}, lockKey(t)))
	eventuallySteps(t, 30*time.Second, "five snapshots", 5, func() int { return int(c.access.Load()) })
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kept(t)
	for i := 1; i < len(c.puts); i++ {
		if gap := c.puts[i].Sub(c.puts[i-1]); gap < pace {
			t.Fatalf("snapshot %d went %v after the one before, under the pace %v", i, gap, pace)
		}
	}
}

// The label counts (the plan's 4.8 and DB22): one INFO line for a
// workspace on its first accepted snapshot, with the counts by class, and
// none more within the hour; no label, hint or phone number anywhere in
// the leader's logs.
func TestSnapshotLabelCounts(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	f := newSnapshotFixture(t, w)
	logs := &membershiptest.Logs{}
	w.members.Log = logs.Logger()
	run(t, w.leader(w.members, logs, lockKey(t)))
	counted := func() []string {
		return logs.Lines("level=INFO", "contract: snapshot labels", "workspace="+f.team.String())
	}
	eventually(t, 10*time.Second, "the team's label counts", func() bool { return len(counted()) > 0 })
	line := counted()[0]
	for _, want := range []string{"items=10", "named=6", "phone=1", "placeholder=1", "legacy_id=1", "empty=1"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the label counts %q lack %s", line, want)
		}
	}
	accepted := w.accepted(f.team)
	if err := store.NewDevices(w.pool).Rename(ctx, f.team.String(), f.devices["live"].String(), "Vendas Sul"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the next snapshot", func() bool { return w.accepted(f.team) > accepted })
	w.settle(t, f.team)
	if n := len(counted()); n != 1 {
		t.Fatalf("%d label count lines within the hour", n)
	}
	values := []string{"Vendas", "Suporte", "WhatsApp", "90000-3333", "Entregas", "Financeiro", "Cobran", "Recep"}
	for _, n := range fixtureNumbers {
		if n.pn != "" {
			values = append(values, n.pn, *label.HintFromPN(n.pn), n.pn[len(n.pn)-7:])
		}
	}
	all := logs.String() + w.logs.String()
	for _, v := range values {
		if strings.Contains(all, v) {
			t.Errorf("the logs hold %q", v)
		}
	}
}
