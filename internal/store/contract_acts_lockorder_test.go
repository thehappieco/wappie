package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestActsLockOrder (the plan's 3.4, DS14): every act of the commands
// release, run through its own store call, at the same time as a reset
// (Restart, from the command feed), a take, a numbers read, a person's
// read, a new sub's document, the frames' own pause, resume mark and
// notices seen, a session's start and end, the repair of lost marks, a
// refusal, a failed run, a results post and a mode switch, many rounds:
// nothing deadlocks (no 40P01, not even one retried), every call ends
// without an error, and an act that read the old generation leaves a
// result the poster drops.
func TestActsLockOrder(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	reader, readerSub := w.actor(t, "member", "member")
	u, err := w.users.Get(ctx, w.tenant, reader)
	if err != nil {
		t.Fatal(err)
	}
	renamed, stopped, resumed, synced := w.number(t, "Vendas"), w.number(t, "Stop"), w.number(t, "Resume"), w.number(t, "Now")
	framed := w.number(t, "Frame")
	for _, d := range []uuid.UUID{renamed, stopped, resumed, synced, framed} {
		w.reads(t, reader, d)
		w.reads(t, admin, d)
	}
	logs := &syncBuffer{}
	lctx := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(logs, nil)))
	label := "Vendas"
	for round := range 20 {
		var cur uuid.UUID
		if err := w.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&cur); err != nil {
			t.Fatal(err)
		}
		// A reset forgets the documents' generation: each actor's document
		// of the new one is stored again, as the round would.
		w.gen = cur
		w.docRole(t, adminSub, "admin", "active")
		w.docRole(t, readerSub, "member", "active")
		rename := w.command(t, kc.OpItemRename, admin, adminSub)
		stop := w.command(t, kc.OpItemSyncStop, admin, adminSub)
		resume := w.command(t, kc.OpItemSyncResume, admin, adminSub)
		now := w.command(t, kc.OpItemSyncNow, reader, readerSub)
		del := w.command(t, kc.OpItemRegistrationDelete, admin, adminSub)
		signOut := w.command(t, kc.OpPersonSignOutEverywhere, reader, readerSub)
		dismiss := w.command(t, kc.OpPersonNoticesDismiss, reader, readerSub)
		refused := w.command(t, kc.OpItemRename, admin, adminSub)
		failing := w.command(t, kc.OpItemRename, admin, adminSub)
		pending, err := w.devices.Create(ctx, w.tenant.String(), "device", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		w.execOne(t, `UPDATE devices SET paused = true WHERE id = $1`, resumed)
		token, _, err := w.users.StartSession(ctx, u, "round")
		if err != nil {
			t.Fatal(err)
		}
		var notices []store.NoticeRef
		for _, n := range w.notices(t, reader) {
			notices = append(notices, store.NoticeRef{ID: strconv.FormatInt(n.ID, 10), Version: int64(n.Pauses)})
		}
		if len(notices) == 0 {
			notices = []store.NoticeRef{{ID: "1", Version: 1}}
		}
		next := uuid.New()
		after := fmt.Sprintf("Vendas %d", round)
		mode := store.SettingsRead
		if round%2 == 1 {
			mode = store.SettingsOn
		}
		calls := map[string]func() error{
			"a reset": func() error {
				_, err := w.c.RestartFromCommands(lctx, cur, &next)
				return err
			},
			"a rename": func() error {
				_, err := w.c.RunRename(lctx, rename, renamed, &label, after)
				return err
			},
			"a stop": func() error {
				_, _, err := w.c.RunSyncStop(lctx, stop, stopped)
				return err
			},
			"a resume": func() error {
				_, _, err := w.c.RunSyncResume(lctx, resume, resumed)
				return err
			},
			"a sync now": func() error {
				act, _, err := w.c.JudgeSyncNow(lctx, now, synced, nil)
				if err != nil || !act.Open {
					return err
				}
				_, err = w.c.FinishSyncNow(lctx, now, store.CommandResult{Outcome: store.CommandRan})
				return err
			},
			"a registration's delete": func() error {
				act, err := w.c.JudgeRegistrationDelete(lctx, del, uuid.MustParse(pending.ID))
				if err != nil || !act.Open {
					return err
				}
				_, err = w.c.RunRegistrationDelete(lctx, del, uuid.MustParse(pending.ID))
				return err
			},
			"a sign-out everywhere": func() error {
				_, err := w.c.RunSignOutEverywhere(lctx, signOut, time.Now())
				return err
			},
			"a dismissal": func() error {
				_, err := w.c.RunNoticesDismiss(lctx, dismiss, notices)
				return err
			},
			"a take": func() error {
				st, err := w.c.SettingsState(lctx)
				if err != nil {
					return err
				}
				_, err = w.c.TakeCommands(lctx, store.ContractCommandPage{SeenGeneration: cur, After: st.FeedCursor, NextAfter: st.FeedCursor + 1,
					SignedAt: time.Now(), Unreadable: []store.ContractUnreadable{{Cseq: st.FeedCursor + 1, Why: "test"}}})
				return err
			},
			"a numbers read": func() error {
				_, _, err := w.c.NumbersOf(lctx, w.tenant)
				return err
			},
			"a person read": func() error {
				_, _, err := w.c.PersonOf(lctx, readerSub)
				return err
			},
			"a new sub's document": func() error {
				sub := uuid.New()
				doc := store.ContractDoc{Sub: sub, Generation: cur, Version: 1, Status: "active",
					Workspaces: []store.ContractDocWorkspace{{ID: w.tenant, Kind: "team", Role: "member", Status: "open", WVersion: 1}}}
				doc.Raw, _ = json.Marshal(map[string]any{"v": 1, "sub": sub})
				_, err := w.c.StoreDocuments(lctx, store.ContractAnswer, doc)
				return err
			},
			"the frame's pause": func() error {
				_, err := w.devices.Pause(lctx, w.tenant, framed, store.PauseActor{User: admin})
				return err
			},
			"the frame's resume": func() error {
				if err := w.devices.SetPaused(lctx, w.tenant.String(), framed.String(), false); err != nil {
					return err
				}
				return w.devices.MarkResumed(lctx, w.tenant, framed)
			},
			"notices seen": func() error {
				_, err := w.devices.SeeNotices(lctx, w.tenant, reader, []store.SeenNotice{{ID: 1, Pauses: 1}})
				return err
			},
			"a session's start": func() error {
				_, _, err := w.users.StartSession(lctx, u, "start")
				return err
			},
			"a session's end": func() error {
				return w.users.EndSessionFamily(lctx, token)
			},
			"the repair": func() error {
				_, err := w.c.ResumeLostMarks(lctx)
				return err
			},
			"a refusal": func() error {
				return w.c.RefuseCommand(lctx, refused.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
			},
			"a failed run": func() error {
				_, err := w.c.CommandRunFailed(lctx, failing.ID, "store")
				return err
			},
			"a results post": func() error {
				results, err := w.c.UndeliveredResults(lctx, 100)
				if err != nil {
					return err
				}
				var answers []store.ContractResultOutcome
				for _, r := range results {
					answers = append(answers, store.ContractResultOutcome{ID: r.ID, Answer: store.DeliveryAccepted})
				}
				return w.c.ResultsPosted(lctx, answers)
			},
			"a mode switch": func() error {
				_, err := w.c.SetSettingsMode(lctx, mode, true)
				return err
			},
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(calls))
		start := make(chan struct{})
		for name, call := range calls {
			wg.Go(func() {
				<-start
				err := call()
				// A document's REPEATABLE READ measuring transaction that
				// ran out of its retries under this many writers is a
				// failed send the sender backs off from, never a deadlock.
				if (name == "a numbers read" || name == "a person read") && sqlState(err) == "40001" {
					err = nil
				}
				if err != nil {
					errs <- fmt.Errorf("round %d, %s: %w", round, name, err)
				}
			})
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
		if _, err := w.c.UndeliveredResults(ctx, 100); err != nil {
			t.Fatal(err)
		}
		var stale int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM contract_commands c WHERE c.outcome IS NOT NULL
			AND c.generation IS DISTINCT FROM (SELECT generation FROM contract_state) AND c.delivery IS NULL`).Scan(&stale); err != nil {
			t.Fatal(err)
		}
		if stale != 0 {
			t.Fatalf("round %d: %d results of an old generation not dropped", round, stale)
		}
		// The rename ran, or the reset came first: its actor's document
		// was of the old generation then, and counts as none.
		got, l := w.device(t, renamed).Label, w.ledger(t, rename.ID)
		if (l.outcome != "ran" || got != after) && (l.code != kc.CodeNotAuthorized || got != label) {
			t.Fatalf("round %d: the rename left %q: %+v", round, got, l)
		}
		label = got
	}
	if strings.Contains(logs.String(), "deadlocked") {
		t.Fatalf("a deadlock, retried:\n%s", logs.String())
	}
}
