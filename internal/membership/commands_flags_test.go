package membership

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The flags kinds through the executor (step 12b's F2; the plan's 3.1 and
// 5.2, DS18 to DS23): R1 for the target person, R2 for the target's
// document, a raise's target active locally before R4, R4 per kind, and
// the runners dispatched with the person and the params as the kit read
// them.

// flagsWorld is snapshotWorld's team with a second person Wappie holds, a
// member there and on the platform, who reads the team's number.
type flagsWorld struct {
	*snapshotWorld
	member, memberSub, memberHome uuid.UUID
}

func newFlagsWorld(t *testing.T) *flagsWorld {
	t.Helper()
	ctx := context.Background()
	w := &flagsWorld{snapshotWorld: newSnapshotWorld(t)}
	w.member, w.memberSub, w.memberHome = w.heldAtHome(t)
	if err := w.fake.SetRole(w.team.String(), w.memberSub.String(), kc.RoleMember); err != nil {
		t.Fatal(err)
	}
	w.localTeam(t, w.team, "", member{w.member, "member", "active"})
	// Read and the key; the key's first grant gave send too, taken back.
	w.inTenant(t, w.team, func(tx pgx.Tx) error {
		if err := readsTx(ctx, tx, w.team, w.device, w.member); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE device_permissions SET can_send = false WHERE device_id = $1 AND user_id = $2`, w.device, w.member)
		return err
	})
	w.members.SignIn(ctx, w.memberSub)
	if w.version(t, w.memberSub) == 0 {
		t.Fatal("the member has no document")
	}
	return w
}

// inTenant runs fn in a transaction scoped to ws.
func (w *flagsWorld) inTenant(t *testing.T, ws uuid.UUID, fn func(tx pgx.Tx) error) {
	t.Helper()
	if err := pg.InTenantTx(context.Background(), w.pool, ws.String(), fn); err != nil {
		t.Fatal(err)
	}
}

// sql runs one statement in a transaction scoped to ws.
func (w *flagsWorld) sql(t *testing.T, ws uuid.UUID, sql string, args ...any) {
	t.Helper()
	w.inTenant(t, ws, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
}

// flags is a flags row of kind in ws by the owner, on item for the person
// sub, drawn from both documents as stored.
func (w *flagsWorld) flags(t *testing.T, kind string, ws, item, sub uuid.UUID, before, after string) row {
	t.Helper()
	return row{kind: kind, ws: &ws, actor: w.sub, target: fmt.Sprintf(`{"item":%q,"person":%q}`, item, sub),
		params: fmt.Sprintf(`{"before":{"can":%s},"after":{"can":%s}}`, before, after),
		docs:   map[uuid.UUID]int64{w.sub: w.version(t, w.sub), sub: w.version(t, sub)}}
}

// judge takes r, runs it with sw, and checks its code ("" for ran) and
// that it was judged on a seq.
func (w *flagsWorld) judge(t *testing.T, what string, sw *settingsWork, r row, code string) uuid.UUID {
	t.Helper()
	id := w.take(t, r)
	w.runNext(t, sw)
	got, _ := w.ledgerRow(t, id.String())
	want := store.CommandRan
	if code != "" {
		want = store.CommandRefused
	}
	if got.outcome != want || got.code != code || got.stateSeq == nil {
		t.Fatalf("%s: %+v, want %s %q at a seq", what, got, want, code)
	}
	return id
}

// stored is user's stored flags on device in ws, as Wappie's screen
// reads them.
func (w *flagsWorld) stored(t *testing.T, ws, device, user uuid.UUID) store.DevicePermission {
	t.Helper()
	p, err := w.users.StoredDevicePermission(context.Background(), ws, user, device)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFlagsTargetHeld: R1 for the person a flags kind names (not linked,
// or linked and not followed: not_held, judged on a seq), and R2 for their
// document (memberships_behind, retry_after 5), each before any change.
func TestFlagsTargetHeld(t *testing.T) {
	w := newFlagsWorld(t)
	ctx := context.Background()
	on := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})

	stranger := uuid.New()
	r := w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, stranger, `["read","send"]`, `["send"]`)
	w.judge(t, "a target Wappie does not hold", on, r, kc.CodeNotHeld)

	local, err := w.users.Create(ctx, store.NewUser{TenantID: w.team, Email: "unfollowed@example.com", Role: "member", AuthKey: "x",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("w")})
	if err != nil {
		t.Fatal(err)
	}
	unfollowed := uuid.New()
	w.exec(ctx, t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, 'u@id.test', 'new')`, unfollowed, local.ID)
	r = w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, unfollowed, `[]`, `["send"]`)
	w.judge(t, "a linked target Wappie does not follow", on, r, kc.CodeNotHeld)
	// A target the console did not name in based_on is read all the same.
	r = w.flags(t, kc.OpItemAccessRemove, w.team, w.device, unfollowed, `["read"]`, `[]`)
	delete(r.docs, unfollowed)
	w.judge(t, "a target not drawn from a document", on, r, kc.CodeNotHeld)

	r = w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, w.memberSub, `["read"]`, `[]`)
	r.docs[w.memberSub]++
	id := w.take(t, r)
	w.runNext(t, on)
	var retry *int
	if err := w.pool.QueryRow(ctx, `SELECT retry_after FROM contract_commands WHERE id = $1 AND code = 'memberships_behind'`, id).
		Scan(&retry); err != nil || retry == nil || *retry != 5 {
		t.Fatalf("the target's document behind: retry_after %v, %v", retry, err)
	}
	if p := w.stored(t, w.team, w.device, w.member); !p.Read || !p.HasKey {
		t.Fatalf("a refused drop changed the flags: %+v", p)
	}
}

// TestFlagsRaiseTargetNotActive: a raise whose target Wappie holds as not
// active locally (a suspended membership, an expired one, a disabled
// account here, a document disabled or closed, or a disablement seen after
// the document's own) is a final not_found judged before R4: with enforce
// on, the target stale and the platform down, R4 would have answered
// memberships_unconfirmed, and no GET is made. An active one is R4's.
func TestFlagsRaiseTargetNotActive(t *testing.T) {
	w := newFlagsWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	on := w.executorOf(t, store.SettingsOn, logs)
	w.members.Enforce = true
	asked := w.asked()
	w.staleBy(ctx, t, w.memberSub, "2 hours")
	w.fake.SetDown(true)

	membership := func(set string) func() {
		return func() {
			w.sql(t, w.team, `UPDATE workspace_memberships SET `+set+` WHERE tenant_id = $1 AND user_id = $2`, w.team, w.member)
		}
	}
	account := func(set string) func() {
		return func() { w.sql(t, w.memberHome, `UPDATE users SET `+set+` WHERE id = $1`, w.member) }
	}
	document := func(set string) func() {
		return func() { w.exec(ctx, t, `UPDATE contract_accounts SET `+set+` WHERE sub = $1`, w.memberSub) }
	}
	for _, c := range []struct {
		what      string
		set, back func()
	}{
		{"a suspended membership", membership(`status = 'disabled'`), membership(`status = 'active'`)},
		{"an expired membership", membership(`expires_at = now() - interval '1 minute'`), membership(`expires_at = NULL`)},
		{"a disabled local account", account(`status = 'disabled'`), account(`status = 'active'`)},
		{"a disabled document", document(`status = 'disabled'`), document(`status = 'active'`)},
		{"a closed document", document(`status = 'closed'`), document(`status = 'active'`)},
		{"a disablement seen after the document", document(`disabled_at = clock_timestamp()`), document(`disabled_at = NULL`)},
	} {
		c.set()
		r := w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, w.memberSub, `["read"]`, `["read","send"]`)
		w.judge(t, c.what, on, r, kc.CodeNotFound)
		c.back()
	}
	if asked.of(w.memberSub) != 0 {
		t.Fatalf("the target was asked for %d times before a not_found", asked.of(w.memberSub))
	}
	if len(logs.Lines("contract: a command was refused", "code=not_found", "at=target")) != 6 {
		t.Fatalf("the log:\n%s", logs.String())
	}

	// Active, stale, and the platform down: R4 refuses, a retry.
	r := w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, w.memberSub, `["read"]`, `["read","send"]`)
	w.judge(t, "an active target, stale", on, r, kc.CodeMembershipsUnconfirmed)
	if p := w.stored(t, w.team, w.device, w.member); p.Send {
		t.Fatalf("a refused raise wrote: %+v", p)
	}
	// The platform back: it runs.
	w.fake.SetDown(false)
	w.judge(t, "an active target, confirmed", on, r, "")
	if p := w.stored(t, w.team, w.device, w.member); !p.Read || !p.Send || p.Manage {
		t.Fatalf("after the raise: %+v", p)
	}
}

// TestFlagsFreshness: R4 per kind with enforce on and the platform down:
// a raise asks the actor and the target in a team, and only the actor's
// stored status in a personal workspace (it runs); a drop of read, and an
// access_remove, of someone who reads asks the minute rule (refused, and a
// drop delivered again waits rather than be answered a retry); a drop of
// send asks nothing; a drop of read of someone who neither reads nor holds
// the key asks nothing.
func TestFlagsFreshness(t *testing.T) {
	w := newFlagsWorld(t)
	ctx := context.Background()
	on := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})
	w.members.Enforce = true
	home := w.number(t, w.home, "Casa", 77, w.owner)
	// A member who neither reads nor holds the key.
	other, otherSub, _ := w.heldAtHome(t)
	if err := w.fake.SetRole(w.team.String(), otherSub.String(), kc.RoleMember); err != nil {
		t.Fatal(err)
	}
	w.localTeam(t, w.team, "", member{other, "member", "active"})
	w.members.SignIn(ctx, otherSub)
	// Every document over a minute old, and the platform down: no backup
	// is confirmed, and no GET answers.
	w.staleBy(ctx, t, w.sub, "2 minutes")
	w.staleBy(ctx, t, w.memberSub, "2 minutes")
	w.fake.SetDown(true)

	// A drop of read: refused, nothing changed.
	drop := w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, w.memberSub, `["read"]`, `[]`)
	w.judge(t, "a drop of read, no confirmed backup", on, drop, kc.CodeMembershipsUnconfirmed)
	remove := w.flags(t, kc.OpItemAccessRemove, w.team, w.device, w.memberSub, `["read"]`, `[]`)
	w.judge(t, "an access_remove, no confirmed backup", on, remove, kc.CodeMembershipsUnconfirmed)
	if p := w.stored(t, w.team, w.device, w.member); !p.Read || !p.HasKey {
		t.Fatalf("a refused tightening changed the flags: %+v", p)
	}
	// Delivered again, it waits.
	again := drop
	again.again = true
	id := w.take(t, again)
	w.runNext(t, on)
	if r, _ := w.ledgerRow(t, id.String()); r.outcome != "" {
		t.Fatalf("a drop delivered again was answered: %+v", r)
	}
	if tries, class, waiting := w.wait(t, id); tries != 1 || class != "again_"+kc.CodeMembershipsUnconfirmed || !waiting {
		t.Fatalf("a drop delivered again: %d tries, %q, waiting %v", tries, class, waiting)
	}
	w.exec(ctx, t, `DELETE FROM contract_commands WHERE id = $1`, id)

	// A drop of send asks nothing.
	if err := w.users.SetDevicePermission(ctx, w.team, w.owner, store.DevicePermission{DeviceID: w.device, UserID: w.member, Read: true,
		Send: true}); err != nil {
		t.Fatal(err)
	}
	send := w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, w.memberSub, `["read","send"]`, `["read"]`)
	w.judge(t, "a drop of send", on, send, "")
	if p := w.stored(t, w.team, w.device, w.member); !p.Read || p.Send || !p.HasKey {
		t.Fatalf("after a drop of send: %+v", p)
	}

	// A raise in the team asks both, so it is refused.
	raise := w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, w.memberSub, `["read"]`, `["read","send"]`)
	w.staleBy(ctx, t, w.memberSub, "2 hours")
	w.judge(t, "a raise in a team, the target stale", on, raise, kc.CodeMembershipsUnconfirmed)
	// In a personal workspace, only the actor's stored status: it runs.
	w.staleBy(ctx, t, w.sub, "2 hours")
	own := w.flags(t, kc.OpItemFlagsRaise, w.home, home, w.sub, `["read","send"]`, `["read","send","manage"]`)
	w.judge(t, "a raise in a personal workspace", on, own, "")
	if p := w.stored(t, w.home, home, w.owner); !p.Manage {
		t.Fatalf("the personal raise: %+v", p)
	}

	// Someone who neither reads nor holds the key: no gate.
	nothing := w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, otherSub, `["read"]`, `[]`)
	w.judge(t, "a drop of read from someone who holds nothing", on, nothing, "")
}

// TestFlagsRunThroughTheExecutor: in on, the three kinds run with the
// person and the params the console sent: a raise, a stale raise
// (state_changed), a drop of read that takes the key, the last reader's
// drop (last_reader), a remove that keeps the row; each result posts.
func TestFlagsRunThroughTheExecutor(t *testing.T) {
	w := newFlagsWorld(t)
	on := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})
	var ids []uuid.UUID

	ids = append(ids, w.judge(t, "a raise of send and manage", on,
		w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, w.memberSub, `["read"]`, `["manage","read","send"]`), ""))
	if p := w.stored(t, w.team, w.device, w.member); !p.Read || !p.Send || !p.Manage {
		t.Fatalf("after the raise: %+v", p)
	}
	ids = append(ids, w.judge(t, "a stale raise", on,
		w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, w.memberSub, `["read"]`, `["read","send"]`), kc.CodeStateChanged))
	ids = append(ids, w.judge(t, "a drop of read", on,
		w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, w.memberSub, `["read","send"]`, `["send"]`), ""))
	if p := w.stored(t, w.team, w.device, w.member); p.Read || !p.Send || !p.Manage || p.HasKey {
		t.Fatalf("after the drop of read: %+v", p)
	}
	ids = append(ids, w.judge(t, "the last reader's drop", on,
		w.flags(t, kc.OpItemFlagsDrop, w.team, w.device, w.sub, `["read","send"]`, `["send"]`), kc.CodeLastReader))
	ids = append(ids, w.judge(t, "a remove", on,
		w.flags(t, kc.OpItemAccessRemove, w.team, w.device, w.memberSub, `["send","manage"]`, `[]`), ""))
	if p := w.stored(t, w.team, w.device, w.member); p.Read || p.Send || p.Manage || p.HasKey {
		t.Fatalf("after the remove: %+v", p)
	}
	var kept int
	w.inTenant(t, w.team, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM device_permissions WHERE device_id = $1 AND user_id = $2`,
			w.device, w.member).Scan(&kept)
	})
	if kept != 1 {
		t.Fatalf("the row after a remove: %d", kept)
	}
	// A number that is none of Wappie's, and params the kit refuses.
	w.judge(t, "another workspace's number", on,
		w.flags(t, kc.OpItemFlagsDrop, w.team, w.number(t, w.home, "Casa", 77, w.owner), w.memberSub, `["send"]`, `[]`), kc.CodeNotFound)
	bad := w.flags(t, kc.OpItemFlagsRaise, w.team, w.device, w.memberSub, `[]`, `["read"]`)
	id := w.take(t, bad)
	w.runNext(t, on)
	if r, _ := w.ledgerRow(t, id.String()); r.code != kc.CodeInvalidCommand || r.stateSeq != nil {
		t.Fatalf("a raise of read: %+v", r)
	}

	rows, err := w.contract.UndeliveredResults(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if !slices.Contains(ids, r.ID) {
			continue
		}
		if _, why := resultOf(r); why != "" {
			t.Errorf("the result of a %s (%s %s) would not post: %s", r.Kind, r.Outcome, r.Code, why)
		}
	}
}

// TestFlagsVectorsRun: the kit's three flags vectors (wire-commands.json),
// their ids made the world's and signed again, go through the take's
// decisions and the executor: the raise, the drop and the remove each run
// on the member's line as their params say.
func TestFlagsVectorsRun(t *testing.T) {
	var v commandVectors
	readVectors(t, "wire-commands.json", &v)
	w := newFlagsWorld(t)
	ctx := context.Background()
	sw := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})
	gen := w.generation(t)
	secret := membershiptest.Secret(t)
	verify := func(raw json.RawMessage) (kc.Command, error) { return kc.VerifyCommand(raw, App, []string{secret}) }
	vectors := map[string]json.RawMessage{}
	for _, c := range v.Commands {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(c.Value, &head); err != nil {
			t.Fatal(err)
		}
		if c.App == App && c.Valid && slices.Contains([]string{kc.OpItemFlagsRaise, kc.OpItemFlagsDrop, kc.OpItemAccessRemove}, head.Kind) {
			vectors[head.Kind] = c.Value
		}
	}
	if len(vectors) != 3 {
		t.Fatalf("%d flags vectors", len(vectors))
	}
	for i, kind := range []string{kc.OpItemFlagsRaise, kc.OpItemFlagsDrop, kc.OpItemAccessRemove} {
		var m map[string]any
		if err := json.Unmarshal(vectors[kind], &m); err != nil {
			t.Fatal(err)
		}
		id, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		st, err := w.contract.SettingsState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		m["id"], m["generation"], m["cseq"], m["wseq"] = id.String(), gen.String(), st.FeedCursor+1, 2000+i
		m["actor"], m["workspace_id"] = w.sub.String(), w.team.String()
		m["target"] = map[string]string{"item": w.device.String(), "person": w.memberSub.String()}
		m["based_on"] = map[string]any{"state_seq": 1, "docs": map[string]int64{w.sub.String(): w.version(t, w.sub),
			w.memberSub.String(): w.version(t, w.memberSub)}}
		m["issued_at"], m["first_issued_at"] = now.Format(time.RFC3339), now.Format(time.RFC3339)
		if m["expires_at"] != nil {
			m["expires_at"] = now.Add(5 * time.Minute).Format(time.RFC3339)
		}
		delete(m, "mac")
		unsigned, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := kc.SignCommand(unsigned, App, secret)
		if err != nil {
			t.Fatal(err)
		}
		take, unreadable, err := decideCommand(App, verify, gen.String(), now, kc.CommandFeedItem{CSeq: st.FeedCursor + 1, Command: signed},
			func(uuid.UUID) (string, error) { return kc.KindTeam, nil })
		if err != nil || unreadable != nil || take.Verdict != "" || take.Decoded == nil {
			t.Fatalf("%s: the take's decision: %+v %v %v", kind, take, unreadable, err)
		}
		res, err := w.contract.TakeCommands(ctx, store.ContractCommandPage{SeenGeneration: gen, After: st.FeedCursor, NextAfter: st.FeedCursor + 1,
			SignedAt: now, Items: []store.ContractCommandTake{take}})
		if err != nil || !res.Committed || res.New != 1 {
			t.Fatalf("%s: the take: %+v %v", kind, res, err)
		}
		w.runNext(t, sw)
		if r, _ := w.ledgerRow(t, id.String()); r.outcome != store.CommandRan {
			t.Fatalf("%s: %+v", kind, r)
		}
		p := w.stored(t, w.team, w.device, w.member)
		switch kind {
		case kc.OpItemFlagsRaise:
			// read to read and send.
			if !p.Read || !p.Send || p.Manage || !p.HasKey {
				t.Fatalf("after the raise: %+v", p)
			}
		case kc.OpItemFlagsDrop:
			// read, send and manage to send: read goes, with the key.
			if p.Read || !p.Send || p.Manage || p.HasKey {
				t.Fatalf("after the drop: %+v", p)
			}
		case kc.OpItemAccessRemove:
			if p.Read || p.Send || p.Manage || p.HasKey {
				t.Fatalf("after the remove: %+v", p)
			}
		}
	}
}

// TestAcceptsFlags: in on, numbers lists the three flags kinds beside
// 12a's five, each a kit v0.10.1 Wappie kind of the numbers section; in
// read, none.
func TestAcceptsFlags(t *testing.T) {
	got := accepts(store.SettingsOn, kc.SectionNumbers)
	for _, kind := range []string{kc.OpItemFlagsRaise, kc.OpItemFlagsDrop, kc.OpItemAccessRemove} {
		if !slices.Contains(got, kind) {
			t.Errorf("on: %s is not listed: %v", kind, got)
		}
	}
	for _, kind := range got {
		if k, ok := kc.CommandKindOf(App, kind); !ok || k.Section != kc.SectionNumbers {
			t.Errorf("%s is not a numbers kind of the kit: %+v", kind, k)
		}
	}
	if len(got) != 8 {
		t.Errorf("on lists %d kinds: %v", len(got), got)
	}
	if r := accepts(store.SettingsRead, kc.SectionNumbers); r == nil || len(r) != 0 {
		t.Errorf("read lists %v", r)
	}
}
