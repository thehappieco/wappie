package membership

import (
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
