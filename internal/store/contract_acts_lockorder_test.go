package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
// result the poster drops. A drop of read whose person has a connection
// and an integration on the number races them too (DS47).
func TestActsLockOrder(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	reader, readerSub := w.actor(t, "member", "member")
	own := ownOf(w)
	consenter, _ := w.actor(t, "admin", "admin")
	dropped := w.number(t, "Dropped")
	w.reads(t, admin, dropped)
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
	// The consenter reads every number their integration names (DS47).
	w.reads(t, consenter, framed)
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
		// The consenter reads the number again, with a connection on it
		// alone and an integration on it and another, which the drop
		// ends whole, both (DS47).
		w.reads(t, consenter, dropped)
		own.connect(t, consenter, store.KindContent, dropped)
		own.connect(t, consenter, store.KindAI, dropped, framed)
		dropRead := w.command(t, kc.OpItemFlagsDrop, admin, adminSub)
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
			"a drop of read": func() error {
				_, _, _, err := w.c.RunFlagsDrop(lctx, dropRead, dropped, consenter, []string{kc.CanRead}, []string{})
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
		// A drop answered from an old generation left the connections:
		// they go before the next round (the workspace's cap).
		own.endAll(t)
	}
	if strings.Contains(logs.String(), "deadlocked") {
		t.Fatalf("a deadlock, retried:\n%s", logs.String())
	}
}

// TestFlagsActsLockOrder (the plan's 3.2 and 5.1): the three flags acts at
// the same time as Wappie's own writers of the same rows (a permission
// change, a key shared and one revoked, a member disabled and enabled
// again, a member removed), the account follower's apply, a reset, a
// numbers read and a numbered snapshot, many rounds: nothing deadlocks
// (no 40P01, not even one retried), and every call ends without an error
// but the refusals a race may answer.
func TestFlagsActsLockOrder(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	target, targetSub := w.actor(t, "member", "member")
	raised, _ := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, admin, device)
	w.reads(t, raised, device)
	logs := &syncBuffer{}
	lctx := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(logs, nil)))
	for round := range 20 {
		var cur uuid.UUID
		if err := w.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&cur); err != nil {
			t.Fatal(err)
		}
		w.gen = cur
		w.docRole(t, adminSub, "admin", "active")
		w.docRole(t, targetSub, "member", "active")
		// The raise's person has read and send again, the drop's reads again
		// (the disable races it), and a fresh person reads, for the remove
		// and the removal to race on.
		if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: raised, Read: true,
			Send: true}); err != nil {
			t.Fatal(err)
		}
		if err := w.users.UpdateMember(ctx, w.tenant, w.owner, target, "member", "active"); err != nil {
			t.Fatal(err)
		}
		if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: target, Epoch: 1, SealedDSK: []byte("grant")}, &w.owner); err != nil {
			t.Fatal(err)
		}
		if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: target, Read: true, Send: true}); err != nil {
			t.Fatal(err)
		}
		other, _ := w.actor(t, "member", "member")
		w.reads(t, other, device)
		raise := w.command(t, kc.OpItemFlagsRaise, admin, adminSub)
		drop := w.command(t, kc.OpItemFlagsDrop, admin, adminSub)
		remove := w.command(t, kc.OpItemAccessRemove, admin, adminSub)
		next := uuid.New()
		calls := map[string]func() error{
			"a raise": func() error {
				_, _, err := w.c.RunFlagsRaise(lctx, raise, device, raised, []string{kc.CanRead, kc.CanSend},
					[]string{kc.CanRead, kc.CanSend, kc.CanManage})
				return err
			},
			"a drop": func() error {
				_, _, _, err := w.c.RunFlagsDrop(lctx, drop, device, target, []string{kc.CanRead, kc.CanSend}, []string{kc.CanSend})
				return err
			},
			"a remove": func() error {
				_, _, _, err := w.c.RunAccessRemove(lctx, remove, device, other)
				return err
			},
			"a permission change": func() error {
				return w.users.SetDevicePermission(lctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: raised, Read: true,
					Send: true})
			},
			"the drop's person's permission change": func() error {
				err := w.users.SetDevicePermission(lctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: target, Read: true,
					Send: true})
				if errors.Is(err, store.ErrNotFound) {
					// The member's disable came first.
					return nil
				}
				return err
			},
			"a key shared": func() error {
				err := w.keys.PutGrant(lctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: target, Epoch: 1, SealedDSK: []byte("grant")},
					&w.owner)
				if errors.Is(err, store.ErrNotFound) {
					return nil
				}
				return err
			},
			"a key revoked": func() error {
				return w.keys.RevokeGrant(lctx, w.tenant, device, other)
			},
			"a member disabled": func() error {
				return w.users.UpdateMember(lctx, w.tenant, w.owner, target, "member", "disabled")
			},
			"a member removed": func() error {
				return w.users.RemoveMember(lctx, w.tenant, w.owner, other)
			},
			"the follower's apply": func() error {
				doc := store.ContractDoc{Sub: targetSub, Generation: cur, Version: int64(round) + 2, Status: "active",
					Workspaces: []store.ContractDocWorkspace{{ID: w.tenant, Kind: "team", Role: "member", Status: "open", WVersion: 1}}}
				doc.Raw, _ = json.Marshal(map[string]any{"v": 1, "sub": targetSub})
				_, err := w.c.StoreDocuments(lctx, store.ContractAnswer, doc)
				return err
			},
			"a reset": func() error {
				_, err := w.c.RestartFromCommands(lctx, cur, &next)
				return err
			},
			"a numbers read": func() error {
				_, _, err := w.c.NumbersOf(lctx, w.tenant)
				return err
			},
			"a snapshot": func() error {
				_, _, err := w.c.SnapshotNumbered(lctx, w.tenant)
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
				if (name == "a numbers read" || name == "a snapshot") && sqlState(err) == "40001" {
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
		// Each act wrote a result, whatever came first.
		for name, id := range map[string]uuid.UUID{"raise": raise.ID, "drop": drop.ID, "remove": remove.ID} {
			if l := w.ledger(t, id); l.outcome == "" {
				t.Fatalf("round %d: the %s has no result", round, name)
			}
		}
	}
	if strings.Contains(logs.String(), "deadlocked") {
		t.Fatalf("a deadlock, retried:\n%s", logs.String())
	}
}

// TestOwnConnectionsLockOrder (the plan's 3.2 and 5.4, DS47, the
// platform's 0061): a drop of read and a remove whose people have
// connections and integrations of every kind on the number and another (a
// media one among them), which end whole, and Wappie's own screen without
// Read, at the same time as every writer of those connections' rows (a
// revoke, an integration paused and one revoked, a reader's question, a
// notice raised, the person disabled, another removed, the number deleted,
// a key shared, a content and a metadata consent prepared before the drop
// recorded), the account follower's apply, a reset, a numbers read and a
// numbered snapshot, many rounds: nothing deadlocks (no 40P01, not even
// one retried), every call ends without an error but the answers a race
// may give, and none of the people's connections made before the round
// is left live.
func TestOwnConnectionsLockOrder(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	dropped, droppedSub := w.actor(t, "admin", "admin")
	screened, _ := w.actor(t, "admin", "admin")
	logs := &syncBuffer{}
	lctx := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(logs, nil)))
	allowed := store.StatusAllowed{Content: func(uuid.UUID) bool { return true }, AI: func(uuid.UUID) bool { return true }}
	paused := true
	// what a race may answer: the row ended, the person or the number gone.
	raced := func(err error) error {
		if errors.Is(err, store.ErrMCPConnectionState) || errors.Is(err, store.ErrMCPConnectionNotFound) ||
			errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrNumberGone) {
			return nil
		}
		return err
	}
	for round := range 10 {
		var cur uuid.UUID
		if err := w.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&cur); err != nil {
			t.Fatal(err)
		}
		w.gen = cur
		w.docRole(t, adminSub, "admin", "active")
		w.docRole(t, droppedSub, "admin", "active")
		if err := w.users.UpdateMember(ctx, w.tenant, w.owner, dropped, "admin", "active"); err != nil {
			t.Fatal(err)
		}
		removed, _ := w.actor(t, "admin", "admin")
		device := w.number(t, fmt.Sprintf("Round %d", round))
		w.reads(t, w.owner, device)
		type made struct{ both, ai, meta string }
		mine := map[uuid.UUID]made{}
		for _, p := range []uuid.UUID{dropped, removed, screened} {
			w.reads(t, p, device)
			w.reads(t, p, w.shared)
			var m made
			m.both, _ = w.connect(t, p, store.KindContent, device, w.shared)
			m.ai, _ = w.connect(t, p, store.KindAI, device, w.shared)
			m.meta, _ = w.connect(t, p, store.KindMetadata, device, w.shared)
			mine[p] = m
		}
		theirs, _ := w.connect(t, w.owner, store.KindContent, device)
		media := w.connectMedia(t, removed, device, w.shared)
		before := []string{media.ID}
		for _, m := range mine {
			before = append(before, m.both, m.ai, m.meta)
		}
		prepared := w.prepare(t, dropped, store.KindContent, device)
		preparedMeta := w.prepare(t, screened, store.KindMetadata, device, w.shared)
		var everyone []uuid.UUID
		w.scoped(t, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT user_id FROM workspace_memberships WHERE tenant_id = $1`, w.tenant)
			if err != nil {
				return err
			}
			everyone, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			return err
		})
		drop := w.command(t, kc.OpItemFlagsDrop, admin, adminSub)
		remove := w.command(t, kc.OpItemAccessRemove, admin, adminSub)
		next := uuid.New()
		calls := map[string]func() error{
			"a drop of read": func() error {
				_, _, _, err := w.c.RunFlagsDrop(lctx, drop, device, dropped, []string{kc.CanRead}, []string{})
				return err
			},
			"a remove": func() error {
				_, _, _, err := w.c.RunAccessRemove(lctx, remove, device, removed)
				return err
			},
			"the screen without read": func() error {
				_, err := w.users.SetDevicePermissionEnded(lctx, w.tenant, admin, store.DevicePermission{DeviceID: device, UserID: screened})
				return raced(err)
			},
			// A lone grant.revoke on the same person, and the upgrade's
			// sweep, take the same locks in the same order (DS48).
			"a grant revoked": func() error {
				_, err := w.keys.RevokeGrantEnded(lctx, w.tenant, device, screened)
				return raced(err)
			},
			"the upgrade's sweep": func() error {
				_, err := store.EndConnectionsWithoutRead(lctx, w.pool)
				return err
			},
			"a connection revoked": func() error {
				_, err := w.conns.Revoke(lctx, w.tenant, w.owner, mine[dropped].both)
				return err
			},
			"an integration paused": func() error {
				_, err := w.conns.SetAIControls(lctx, w.tenant, w.owner, mine[removed].ai, store.AIControls{Paused: &paused})
				return raced(err)
			},
			"an integration revoked": func() error {
				_, _, err := w.conns.RevokeAI(lctx, w.tenant, w.owner, mine[screened].ai, false)
				return err
			},
			"a reader's question": func() error {
				_, err := w.conns.StatusFor(lctx, "enclave", mine[removed].both, allowed)
				return err
			},
			"another person's reader's question": func() error {
				_, err := w.conns.StatusFor(lctx, "enclave", theirs, allowed)
				return err
			},
			"a notice raised": func() error {
				_, err := w.conns.RaiseNotice(lctx, store.HostedReader, mine[screened].meta, "daily_messages")
				return raced(err)
			},
			"the person disabled": func() error {
				return w.users.UpdateMember(lctx, w.tenant, w.owner, dropped, "admin", "disabled")
			},
			"a member removed": func() error {
				return w.users.RemoveMember(lctx, w.tenant, w.owner, removed)
			},
			"the number deleted": func() error {
				_, err := w.devices.Quarantine(lctx, w.tenant, w.owner, device, everyone)
				return err
			},
			"a consent recorded": func() error {
				// Refused once the drop, the disabling or the deletion
				// came first (DS47).
				_, err := w.conns.Create(lctx, w.tenant, dropped, prepared)
				if errors.Is(err, store.ErrMCPKeyUnsuitable) || errors.Is(err, store.ErrMembershipForbidden) {
					return nil
				}
				return err
			},
			"a metadata consent recorded": func() error {
				// Refused once the screen took Read first (the platform's
				// 0061); after the deletion it names the shared number
				// alone, which the person still reads.
				_, err := w.conns.Create(lctx, w.tenant, screened, preparedMeta)
				if errors.Is(err, store.ErrMCPKeyUnsuitable) {
					return nil
				}
				return err
			},
			"a key shared": func() error {
				return raced(w.keys.PutGrant(lctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: screened, Epoch: 1,
					SealedDSK: []byte("grant")}, &w.owner))
			},
			"the follower's apply": func() error {
				doc := store.ContractDoc{Sub: droppedSub, Generation: cur, Version: int64(round) + 2, Status: "active",
					Workspaces: []store.ContractDocWorkspace{{ID: w.tenant, Kind: "team", Role: "admin", Status: "open", WVersion: 1}}}
				doc.Raw, _ = json.Marshal(map[string]any{"v": 1, "sub": droppedSub})
				_, err := w.c.StoreDocuments(lctx, store.ContractAnswer, doc)
				return err
			},
			"a reset": func() error {
				_, err := w.c.RestartFromCommands(lctx, cur, &next)
				return err
			},
			"a numbers read": func() error {
				_, _, err := w.c.NumbersOf(lctx, w.tenant)
				return err
			},
			"a snapshot": func() error {
				_, _, err := w.c.SnapshotNumbered(lctx, w.tenant)
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
				if (name == "a numbers read" || name == "a snapshot") && sqlState(err) == "40001" {
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
		for name, id := range map[string]uuid.UUID{"drop": drop.ID, "remove": remove.ID} {
			if l := w.ledger(t, id); l.outcome == "" {
				t.Fatalf("round %d: the %s has no result", round, name)
			}
		}
		// Whatever came first, nothing reaches the deleted number, and the
		// live ones go before the next round (the workspace's cap).
		if n := w.count(t, `SELECT count(*) FROM mcp_connections c JOIN api_key_devices x ON x.api_key_id = c.api_key_id
			WHERE x.device_id = $1 AND c.status IN ('pending', 'active', 'reseal')`, device); n != 0 {
			t.Fatalf("round %d: %d live connections still reach the deleted number", round, n)
		}
		if n := w.count(t, `SELECT count(*) FROM mcp_connections WHERE id::text = ANY($1) AND status IN ('pending', 'active', 'reseal')`,
			before); n != 0 {
			t.Fatalf("round %d: %d of the people's connections made before it are live", round, n)
		}
		w.endAll(t)
	}
	if strings.Contains(logs.String(), "deadlocked") {
		t.Fatalf("a deadlock, retried:\n%s", logs.String())
	}
}
