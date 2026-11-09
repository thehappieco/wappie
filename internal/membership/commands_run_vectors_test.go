package membership

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// The kit's command vectors through the commands release's executor, and
// every result the executor and the acts write through the poster's own
// check: each is one the platform keeps (the kit's ValidateFor).

// TestVectorsThroughTheExecutor: every command of wire-commands.json that
// Wappie takes (Wappie's, valid for Wappie), and every actions case that
// runs, is taken into the ledger and judged by the executor in the mode
// on: each ends with a result, and every result posts.
func TestVectorsThroughTheExecutor(t *testing.T) {
	var v commandVectors
	readVectors(t, "wire-commands.json", &v)
	w := newSnapshotWorld(t)
	ctx := context.Background()
	sw := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})
	gen := w.generation(t)
	verify := func(raw json.RawMessage) (kc.Command, error) {
		return kc.VerifyCommand(raw, App, []string{vectorSecretA})
	}
	var bodies []json.RawMessage
	for _, c := range v.Commands {
		if c.App == App && c.Valid {
			bodies = append(bodies, c.Value)
		}
	}
	for _, a := range v.Actions {
		if a.App == App && a.Action == "run" {
			bodies = append(bodies, a.Value)
		}
	}
	taken := 0
	for i, raw := range bodies {
		var head struct {
			Generation string `json:"generation"`
			CSeq       int64  `json:"cseq"`
			IssuedAt   string `json:"issued_at"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatal(err)
		}
		signed, err := time.Parse(time.RFC3339Nano, head.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		take, unreadable, err := decideCommand(App, verify, head.Generation, signed, kc.CommandFeedItem{CSeq: head.CSeq, Command: raw},
			func(uuid.UUID) (string, error) { return kc.KindTeam, nil })
		if err != nil || unreadable != nil || take.Verdict != "" || take.Decoded == nil {
			continue
		}
		// One id per row, and a wseq past the memory's, so each runs.
		take.ID = uuid.New()
		if take.Decoded.WSeq != nil {
			wseq := int64(1000 + i)
			take.Decoded.WSeq = &wseq
		}
		st, err := w.contract.SettingsState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		res, err := w.contract.TakeCommands(ctx, store.ContractCommandPage{SeenGeneration: gen, After: st.FeedCursor, NextAfter: st.FeedCursor + 1,
			SignedAt: signed, Items: []store.ContractCommandTake{take}})
		if err != nil || !res.Committed || res.New != 1 {
			t.Fatalf("the take of a vector: %+v %v", res, err)
		}
		taken++
	}
	if taken < 40 {
		t.Fatalf("only %d vectors taken", taken)
	}
	for range taken {
		w.runNext(t, sw)
	}
	if _, ok, err := w.contract.NextCommand(ctx); err != nil || ok {
		t.Fatalf("a row left open: %v %v", ok, err)
	}
	rows, err := w.contract.UndeliveredResults(ctx, 500)
	if err != nil || len(rows) != taken {
		t.Fatalf("%d results for %d rows: %v", len(rows), taken, err)
	}
	for _, r := range rows {
		if _, why := resultOf(r); why != "" {
			t.Errorf("the result of a %s (%s %s) would not post: %s", r.Kind, r.Outcome, r.Code, why)
		}
	}
}

// TestRunResultsPost: every result the commands release's executor and
// acts write, kind by kind, passes the poster's check, the kit's
// ValidateFor, with its seq where the kind's code needs one.
func TestRunResultsPost(t *testing.T) {
	seq := int64(1794000000000)
	refused := func(code string, retry int, judged bool) store.ContractResult {
		r := store.ContractResult{ID: uuid.New(), Outcome: store.CommandRefused, Code: code, At: time.Now()}
		if retry > 0 {
			r.RetryAfter = &retry
		}
		if judged {
			r.StateSeq = &seq
		}
		return r
	}
	ran := func(detail string) store.ContractResult {
		r := store.ContractResult{ID: uuid.New(), Outcome: store.CommandRan, StateSeq: &seq, At: time.Now()}
		if detail != "" {
			r.Detail = json.RawMessage(detail)
		}
		return r
	}
	every := func(person bool) []store.ContractResult {
		out := []store.ContractResult{
			refused(kc.CodeKindNotAccepted, 0, true), refused(kc.CodeNotHeld, 0, !person),
			refused(kc.CodeMembershipsBehind, int(behindRetry/time.Second), true), refused(kc.CodeInvalidCommand, 0, false),
			refused(kc.CodeRateLimited, store.CommandStuckRetryAfter, true), refused(kc.CodeExpired, 0, false),
		}
		if !person {
			out = append(out, refused(kc.CodeNotFound, 0, true), refused(kc.CodeTeamClosed, 0, true),
				refused(kc.CodeMembershipsUnconfirmed, 0, true), refused(kc.CodeNotAuthorized, 0, true))
		}
		return out
	}
	cleaned := refused(kc.CodeLabelChanged, 0, true)
	cleaned.Detail = json.RawMessage(`{"cleaned": "Café"}`)
	for kind, own := range map[string][]store.ContractResult{
		kc.OpItemRename:              {ran(""), refused(kc.CodeStateChanged, 0, true), cleaned},
		kc.OpItemSyncStop:            {ran("")},
		kc.OpItemSyncResume:          {ran(""), refused(kc.CodeStateChanged, 0, true)},
		kc.OpItemRegistrationDelete:  {ran(""), refused(kc.CodeStateChanged, 0, true)},
		kc.OpPersonSignOutEverywhere: {ran(`{"sessions_ended": 3}`)},
		kc.OpPersonNoticesDismiss:    {ran(""), refused(kc.CodeStateChanged, 0, true)},
		kc.OpItemSyncNow: {ran(""), refused(kc.CodePaused, 0, true), refused(kc.CodeStoragePaused, 0, true), refused(kc.CodeNotLinked, 0, true),
			refused(kc.CodeReadOnly, 0, true), refused(kc.CodeItemBusy, 42, true), refused(kc.CodeConnectFailed, 0, true)},
	} {
		person := kind == kc.OpPersonSignOutEverywhere || kind == kc.OpPersonNoticesDismiss
		for _, r := range append(own, every(person)...) {
			r.Kind = kind
			if _, why := resultOf(r); why != "" {
				t.Errorf("%s %s %s: %s", kind, r.Outcome, r.Code, why)
			}
		}
	}
}
