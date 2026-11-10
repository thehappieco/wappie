package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// Step 7's snapshot items and events (the plan's 6.2, 6.3 and 10.5): an
// item's ordinal and tokens, and a pause's stop, sent only while the token
// mode is on; a token's expiry, which writes nothing, makes a snapshot
// due; and a token's pause folds by its creator.

// TestTheNewMembersWaitForTheTokenGate (the plan's 10.5): before tokens
// on, the snapshot carries no ordinal and no tokens, and a pause no stop;
// with tokens on, every item has both (a deleted one no token), the
// platform's strict intake takes it, and every pause has its stop; off
// again, everything is as it was, byte for byte (the golden files, with
// the gate off, are TestSnapshotGolden's and TestEventGoldenFiles').
func TestTheNewMembersWaitForTheTokenGate(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	f := newSnapshotFixture(t, w)
	deleteFixture(t, w, f)
	live := f.devices["live"]
	tok := w.sqlToken(t, f.team, live, f.subs["owner"], "1 day", "read", "send")
	w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind, named_at) VALUES ($1, 'team', clock_timestamp() - interval '1 minute')
		ON CONFLICT (workspace_id) DO UPDATE SET named_at = excluded.named_at`, f.team)
	owner := f.subs["owner"]
	pause := w.event(t, f.team, eventRow{kind: "sync_paused", item: live, actorKind: "key", actor: &owner,
		readers: []uuid.UUID{owner, f.subs["member"]}, label: ptr("Vendas"), hint: ptr("…5678")})
	if _, err := w.members.Client.Subscribe(ctx, owner.String()); err != nil {
		t.Fatal(err)
	}

	measure := func(mode string) (kc.Snapshot, []byte, kc.Event) {
		t.Helper()
		w.exec(ctx, t, `UPDATE contract_token_state SET mode = $1`, mode)
		read, err := w.contract.Snapshot(ctx, f.team)
		if err != nil {
			t.Fatal(err)
		}
		snap := SnapshotOf(read, 1)
		body, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		if why := checkSnapshot(snap); why != "" {
			t.Fatalf("tokens %s: Wappie would not send its snapshot: %s", mode, why)
		}
		// The queue: the fixture's deletion, which never has a stop, and
		// the pause.
		batch, err := w.contract.EventBatch(ctx, f.team, kc.MaxEvents)
		if err != nil || len(batch.Events) != 2 {
			t.Fatalf("tokens %s: the queue %+v %v", mode, batch, err)
		}
		var paused kc.Event
		for _, e := range batch.Events {
			ev := EventOf(f.team, e)
			if err := ev.Validate(); err != nil {
				t.Fatalf("tokens %s: %s: %v", mode, ev.Type, err)
			}
			switch {
			case e.EventID == pause:
				paused = ev
			case ev.Stop != "":
				t.Fatalf("tokens %s: %s has a stop", mode, ev.Type)
			}
		}
		if paused.EventID != pause.String() {
			t.Fatalf("tokens %s: the pause is not in the queue", mode)
		}
		return snap, body, paused
	}

	off, offBody, offPause := measure(store.TokensOff)
	if bytes.Contains(offBody, []byte(`"ordinal"`)) || bytes.Contains(offBody, []byte(`"tokens"`)) || offPause.Stop != "" {
		t.Fatalf("tokens off: %s, the pause's stop %q", offBody, offPause.Stop)
	}

	on, _, onPause := measure(store.TokensOn)
	if onPause.Stop != kc.StopPause {
		t.Fatalf("tokens on: the pause's stop %q", onPause.Stop)
	}
	if len(on.Items) != len(off.Items) {
		t.Fatalf("tokens on: %d items, off %d", len(on.Items), len(off.Items))
	}
	ordinals := map[kc.Ordinal]bool{}
	for _, it := range on.Items {
		if it.Ordinal < 1 || it.Ordinal > kc.MaxOrdinal || ordinals[it.Ordinal] || it.Tokens == nil {
			t.Fatalf("tokens on, %s: ordinal %d, tokens %v", it.ID, it.Ordinal, it.Tokens)
		}
		ordinals[it.Ordinal] = true
		switch it.ID {
		case live.String():
			want := kc.ItemTokens{{ID: tok.String(), Can: []string{kc.CanRead, kc.CanSend}, Waiting: true}}
			if b, _ := json.Marshal(it.Tokens); !bytes.Equal(b, mustJSON(t, want)) {
				t.Fatalf("tokens on, the live number's tokens: %s", b)
			}
		case f.devices["deleted"].String():
			if it.State != kc.StateDeleted || len(it.Tokens) != 0 {
				t.Fatalf("tokens on, the deleted number: %+v", it)
			}
		default:
			if len(it.Tokens) != 0 {
				t.Fatalf("tokens on, %s: %v", it.ID, it.Tokens)
			}
		}
	}
	// The platform's strict intake takes it.
	on.SnapshotSeq = time.Now().UnixMilli()
	if err := w.members.Client.PutAccess(ctx, f.team.String(), on); err != nil {
		t.Fatalf("the fake platform's intake: %v", err)
	}
	if kept, ok := w.fake.Snapshot("wappie", f.team.String()); !ok || len(kept.Items) != len(on.Items) {
		t.Fatalf("the platform kept %+v", kept)
	}

	_, again, againPause := measure(store.TokensOff)
	if !bytes.Equal(again, offBody) || againPause.Stop != "" {
		t.Fatalf("tokens off again: %s, was %s; the pause's stop %q", again, offBody, againPause.Stop)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSnapshotTokensOverTheLimits (the plan's 6.2 and 10.5, note N2): with
// 100 tokens on every number, the most numbers whose snapshot fits the
// call's 1 MiB goes, and one more is refused as too_large, never sent; an
// item holds at most 1000 tokens, and 1001 are refused by the kit's rule.
func TestSnapshotTokensOverTheLimits(t *testing.T) {
	item := func(n, tokens int) store.ContractSnapshotItem {
		o := n
		it := store.ContractSnapshotItem{ID: uuid.New(), State: store.SnapshotActive, Ordinal: &o, Tokens: []store.ContractSnapshotToken{}}
		for range tokens {
			it.Tokens = append(it.Tokens, store.ContractSnapshotToken{ID: uuid.New(), Read: true, Send: true, Manage: true, Reads: true})
		}
		return it
	}
	read := store.ContractSnapshot{Local: true, TokenMode: true}
	fits := 0
	for n := 1; n <= kc.MaxItems; n++ {
		read.Items = append(read.Items, item(n, 100))
		snap := SnapshotOf(read, 1)
		body, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		why := checkSnapshot(snap)
		if len(body) <= snapshotBodyLimit {
			if why != "" {
				t.Fatalf("%d numbers, %d bytes: %q", n, len(body), why)
			}
			fits = n
			continue
		}
		if why != "too_large" || n != fits+1 {
			t.Fatalf("%d numbers, %d bytes: %q, want too_large one past %d", n, len(body), why, fits)
		}
		break
	}
	if fits < 90 || fits >= kc.MaxItems {
		t.Fatalf("%d numbers with 100 tokens each fit in 1 MiB", fits)
	}
	t.Logf("%d numbers with 100 tokens each fit in 1 MiB", fits)

	one := store.ContractSnapshot{Local: true, TokenMode: true, Items: []store.ContractSnapshotItem{item(1, kc.MaxItemTokens)}}
	if why := checkSnapshot(SnapshotOf(one, 1)); why != "" {
		t.Fatalf("1000 tokens on an item: %q", why)
	}
	one.Items[0].Tokens = append(one.Items[0].Tokens, item(2, 1).Tokens...)
	if why := checkSnapshot(SnapshotOf(one, 1)); why != "invalid" {
		t.Fatalf("1001 tokens on an item: %q", why)
	}
}

// TestATokensExpiryMakesTheSnapshotDue (the plan's 6.2): an expiry writes
// nothing, so the snapshot that lists a token makes the next one due at
// its expiry, far sooner than the hourly one, and that one leaves it out.
// The token sends only: an expiry that drops an identity would wake the
// sender through its grants.
func TestATokensExpiryMakesTheSnapshotDue(t *testing.T) {
	w := newTokenWorld(t)
	logs := &membershiptest.Logs{}
	l := w.tokenLeader(w.members, logs, lockKey(t))
	l.SnapshotEvery = time.Hour
	run(t, l)
	w.settle(t, w.home)
	id, _, err := w.fake.AddToken(w.home.String(), w.sub.String(), "Nightly", time.Now().Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	w.grant(t, id, kc.CanSend)
	held := func(want bool) func() bool {
		return func() bool {
			s, ok := w.fake.Snapshot("wappie", w.home.String())
			if !ok || len(s.Items) != 1 || s.Items[0].Tokens == nil {
				return false
			}
			listed := len(s.Items[0].Tokens) == 1 && s.Items[0].Tokens[0].ID == id
			return listed == want && (listed || len(s.Items[0].Tokens) == 0)
		}
	}
	eventually(t, soon, "a snapshot that lists the token", held(true))
	eventually(t, soon, "a snapshot after its expiry, without it", held(false))
}
