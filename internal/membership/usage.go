package membership

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// The usage report in the leader (E0 slice 18; the platform's spec,
// section 15.8; docs/contract.md, "Entitlements and usage"): every
// recorded platform workspace's bytes per hosted number, measured from one
// consistent snapshot (store.MeasureUsage) and sent with
// PUT /contract/v1/workspaces/{id}/usage, one workspace at a time, at the
// leader's pace. It runs while the entitlements part observes and its own
// switch is on (contract_ent_state.usage). No figure of a report is ever
// logged: its lines carry the workspace, the usage_seq, the rule, kept, a
// trigger or a class.
//
// When a workspace is due, its earliest deadline first: a crossing of its
// document's allowance_bytes or cap_bytes, either way (within a minute); a
// requests.usage_after later than the last report (within 10 minutes); a
// deletion, recovery, purge or move out of one of its numbers; a move of
// its total by 1 % of its quota, at least 100 MB, coalesced to one report
// every 15 minutes; and at least every 6 hours. A report sent past its
// trigger's deadline is logged late and is a --check finding for a day:
// the scan's cost is unmeasured on the pilot, and slice 20's counters are
// what guarantee the deadlines.

// The usage sender's defaults.
const (
	// usageEvery is how often each workspace's triggers are looked at.
	usageEvery = time.Minute
	// usageFloor is the longest between two reports of a workspace.
	usageFloor = 6 * time.Hour
	// usageCoalesce is the 1 % trigger's least time between two reports.
	usageCoalesce = 15 * time.Minute
	// usageBackoffMin and usageBackoffMax bound the wait after a report
	// that got no answer.
	usageBackoffMin = 5 * time.Second
	usageBackoffMax = time.Hour
	// usageInvalidRetry is how long a report refused invalid_request waits.
	usageInvalidRetry = time.Hour
	// usageCrossingDeadline and usageAfterDeadline are the spec's two
	// deadlines: within a minute of a crossing, within 10 minutes of a
	// usage_after.
	usageCrossingDeadline = time.Minute
	usageAfterDeadline    = 10 * time.Minute
	// usagePercentFloor is the 1 % trigger's least move: 100 MB.
	usagePercentFloor = 100_000_000
)

// UsageConfig is the usage sender's timings, the defaults above when zero;
// tests shorten them.
type UsageConfig struct {
	Every, Floor, Coalesce          time.Duration
	BackoffMin, BackoffMax          time.Duration
	InvalidRetry                    time.Duration
	CrossingDeadline, AfterDeadline time.Duration
}

// usageWork is the usage sender: its loop while usage is on, and the
// workspaces the usage channel's notices named.
type usageWork struct {
	w   *entitlementsWork
	cfg UsageConfig

	mu    sync.Mutex
	marks map[uuid.UUID]bool
	wake  chan struct{}
	stop  context.CancelFunc
	wg    sync.WaitGroup
}

func newUsageWork(w *entitlementsWork) *usageWork {
	return &usageWork{w: w, cfg: w.cfg.Usage, marks: map[uuid.UUID]bool{}, wake: make(chan struct{}, 1)}
}

// set starts the loop under ctx for on when it does not run, or stops it
// and waits for it for off.
func (u *usageWork) set(ctx context.Context, usage string) {
	u.mu.Lock()
	running := u.stop != nil
	switch {
	case usage == store.UsageOn && !running:
		run, stop := context.WithCancel(obs.WithLogger(ctx, u.w.l.log()))
		u.stop = stop
		u.mu.Unlock()
		u.w.l.log().Info("contract: usage started")
		u.wg.Go(func() { u.run(run) })
	case usage != store.UsageOn && running:
		stop := u.stop
		u.stop = nil
		u.mu.Unlock()
		stop()
		u.wg.Wait()
		u.w.l.log().Info("contract: usage stopped")
	default:
		u.mu.Unlock()
	}
}

// notice takes a usage channel notice: a workspace whose number was
// deleted, recovered, purged or moved out.
func (u *usageWork) notice(payload string) {
	id, err := uuid.Parse(payload)
	if err != nil {
		return
	}
	u.mu.Lock()
	u.marks[id] = true
	u.mu.Unlock()
	kick(u.wake)
}

// take returns and forgets the workspaces the notices named.
func (u *usageWork) take() []uuid.UUID {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]uuid.UUID, 0, len(u.marks))
	for id := range u.marks {
		out = append(out, id)
	}
	u.marks = map[uuid.UUID]bool{}
	return out
}

// run looks at the triggers every Every and sends the reports due, until
// ctx ends.
func (u *usageWork) run(ctx context.Context) {
	every := or(u.cfg.Every, usageEvery)
	var checked time.Time
	for ctx.Err() == nil {
		for _, ws := range u.take() {
			if err := u.w.l.Members.Contract.UsageMark(ctx, ws, store.UsageEvent, time.Time{}); err != nil && ctx.Err() == nil {
				u.w.l.log().Warn("contract: could not make a usage report due", "error", err)
			}
		}
		if time.Since(checked) >= every {
			checked = time.Now()
			u.check(ctx)
		}
		for ctx.Err() == nil {
			due, err := u.w.l.Members.Contract.UsageDue(ctx, 1)
			if err != nil || len(due) == 0 {
				break
			}
			if !u.send(ctx, due[0]) {
				return
			}
			for _, ws := range u.take() {
				if err := u.w.l.Members.Contract.UsageMark(ctx, ws, store.UsageEvent, time.Time{}); err != nil && ctx.Err() == nil {
					u.w.l.log().Warn("contract: could not make a usage report due", "error", err)
				}
			}
		}
		if !pause(ctx, max(every-time.Since(checked), time.Millisecond), u.wake) {
			return
		}
	}
}

// check makes due each recorded workspace one of whose triggers holds,
// once a minute: a crossing, the 1 % move (of its document's quota, or of
// usagePercentFloor while it holds none), a usage_after, an event a notice
// was lost for, and the floor; and stops or resumes a workspace on its
// document's not_found. A mark "now" is on the database's clock (a zero
// time), the one measured_at is read on; one made while a report backs off
// waits its backoff (UsageMark).
func (u *usageWork) check(ctx context.Context) {
	c, log := u.w.l.Members.Contract, u.w.l.log()
	rows, err := c.UsageRows(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("contract: could not read the usage cadence", "error", err)
		}
		return
	}
	_, ents, err := c.EntRows(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("contract: could not read the entitlements documents", "error", err)
		}
		return
	}
	docs := map[uuid.UUID]*kc.EntitlementsDoc{}
	for _, r := range ents {
		if r.Doc == nil {
			continue
		}
		var d kc.EntitlementsDoc
		if json.Unmarshal(r.Doc, &d) == nil {
			docs[r.Workspace] = &d
		}
	}
	now := time.Now()
	mark := func(ws uuid.UUID, trigger string, at time.Time) {
		if err := c.UsageMark(ctx, ws, trigger, at); err != nil && ctx.Err() == nil {
			log.Warn("contract: could not make a usage report due", "error", err)
		}
	}
	for _, r := range rows {
		switch {
		case r.NotFoundSince != nil:
			if r.StoppedSince == nil {
				if err := c.UsageStopped(ctx, r.Workspace); err != nil && ctx.Err() == nil {
					log.Warn("contract: could not stop a workspace's usage", "error", err)
				}
			}
			continue
		case r.StoppedSince != nil:
			// A document of it reached the feed again.
			if err := c.UsageResumed(ctx, r.Workspace); err != nil && ctx.Err() == nil {
				log.Warn("contract: could not resume a workspace's usage", "error", err)
			}
			continue
		}
		d := docs[r.Workspace]
		if d != nil && d.Requests.UsageAfter != nil && (r.LastMeasuredAt == nil || d.Requests.UsageAfter.After(*r.LastMeasuredAt)) {
			mark(r.Workspace, store.UsageAfter, time.Time{})
		}
		if r.LastMeasuredAt == nil {
			continue
		}
		if r.LastTotal != nil {
			if total, ok, err := c.EntTotal(ctx, r.Workspace); err == nil && ok {
				last := *r.LastTotal
				var quota int64
				if d != nil {
					quota = d.Storage.QuotaBytes
					for _, line := range []int64{d.Storage.AllowanceBytes, d.Storage.CapBytes} {
						if (last > line) != (total > line) {
							mark(r.Workspace, store.UsageCrossing, time.Time{})
						}
					}
				}
				if moved := abs64(total - last); moved >= max(quota/100, usagePercentFloor) {
					var at time.Time
					if r.PctAfter != nil && r.PctAfter.After(now) {
						at = *r.PctAfter
					}
					mark(r.Workspace, store.UsagePercent, at)
				}
			}
		}
		if found, err := c.UsageEventsSince(ctx, r.Workspace, *r.LastMeasuredAt, r.LastEvents); err == nil && found {
			mark(r.Workspace, store.UsageEvent, time.Time{})
		}
		mark(r.Workspace, store.UsageFloor, r.LastMeasuredAt.Add(or(u.cfg.Floor, usageFloor)))
	}
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// usageClass is a measurement's failure as its log line names it.
func usageClass(err error) string {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrUsageMismatch):
		return "mismatch"
	case errors.As(err, &pgErr) && pgErr.Code == "57014":
		return "timeout"
	}
	return "store"
}

// usageReport is the wire's report of m (the spec's 15.8): an empty one
// where Wappie has no such workspace.
func usageReport(m store.UsageMeasure) kc.Usage {
	u := kc.Usage{V: kc.UsageV, Type: kc.UsageType, App: App, WorkspaceID: m.Workspace.String(), UsageSeq: m.Seq,
		RuleVersion: store.UsageRule, MeasuredAt: kc.T(m.MeasuredAt), Items: make([]kc.UsageItem, 0, len(m.Items))}
	if !m.Local {
		return u
	}
	u.TotalBytes, u.SharedBytes = m.Total, m.Shared
	for _, it := range m.Items {
		item := kc.UsageItem{ID: it.Device.String(), State: it.State, Bytes: it.Bytes, RecentBytes: it.Recent,
			UndatedBytes: it.Undated, FixedBytes: it.Fixed}
		if it.PurgeAt != nil {
			at := kc.T(*it.PurgeAt)
			item.PurgeAt = &at
		}
		u.Items = append(u.Items, item)
	}
	return u
}

// send measures and sends r's report, and records the outcome; false when
// ctx ended.
func (u *usageWork) send(ctx context.Context, r store.UsageRow) bool {
	l, m := u.w.l, u.w.l.Members
	c, log := m.Contract, l.log()
	backoff := min(or(u.cfg.BackoffMin, usageBackoffMin)<<min(r.Tries, 20), or(u.cfg.BackoffMax, usageBackoffMax))
	failed := func(class string, wait time.Duration) {
		if err := c.UsageFailed(ctx, r.Workspace, class, wait); err != nil && ctx.Err() == nil {
			log.Warn("contract: could not record a usage report's failure", "error", err)
		}
	}
	if r.NotFoundSince != nil {
		if err := c.UsageStopped(ctx, r.Workspace); err != nil && ctx.Err() == nil {
			log.Warn("contract: could not stop a workspace's usage", "error", err)
		}
		return true
	}
	measure, err := c.MeasureUsage(ctx, r.Workspace)
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		class := usageClass(err)
		log.Warn("contract: usage not measured", "workspace", r.Workspace, "class", class)
		if class == "mismatch" {
			if err := c.RecordError(ctx, store.ContractErrorUsageMismatch); err != nil && ctx.Err() == nil {
				log.Warn("contract: could not record an ERROR", "error", err)
			}
		}
		failed(class, backoff)
		return true
	}
	report := usageReport(measure)
	if err := report.Validate(); err != nil {
		log.Warn("contract: usage not measured", "workspace", r.Workspace, "class", "invalid")
		failed("invalid", or(u.cfg.InvalidRetry, usageInvalidRetry))
		return true
	}
	body, err := json.Marshal(report)
	if err != nil {
		failed("store", backoff)
		return true
	}
	// Kept before the PUT goes: an answer lost after the platform took the
	// report leaves it kept all the same (the spec's 15.8).
	if err := c.UsageSending(ctx, measure, body); err != nil {
		if ctx.Err() != nil {
			return false
		}
		log.Warn("contract: usage not measured", "workspace", r.Workspace, "class", "store")
		failed("store", backoff)
		return true
	}
	if err := m.paced(ctx); err != nil {
		return false
	}
	kept, err := m.Client.PutUsage(ctx, r.Workspace.String(), report)
	if ctx.Err() != nil {
		return false
	}
	switch code := RefusalCode(err); {
	case err == nil:
	case code == kc.CodeInvalid:
		log.Warn("contract: usage refused", "workspace", r.Workspace, "usage_seq", report.UsageSeq, "code", code)
		if err := c.RecordError(ctx, store.ContractErrorUsageInvalid); err != nil && ctx.Err() == nil {
			log.Warn("contract: could not record an ERROR", "error", err)
		}
		failed(code, or(u.cfg.InvalidRetry, usageInvalidRetry))
		return true
	case code != "":
		log.Warn("contract: usage refused", "workspace", r.Workspace, "usage_seq", report.UsageSeq, "code", code)
		if code == kc.CodeNotFound {
			// A workspace the platform keeps no document of: its GET says
			// whether to stop (the spec's 15.1).
			if err := c.EntGetDueNow(ctx, r.Workspace); err == nil {
				kick(u.w.gets)
			}
		}
		failed(code, backoff)
		return true
	default:
		failed(feedClass(err), backoff)
		return true
	}
	late := ""
	// Lateness counts from when the trigger first made the report due,
	// never from a backoff's due_at.
	first := r.DueFirstAt
	if first == nil {
		first = r.DueAt
	}
	if first != nil {
		deadline := map[string]time.Duration{store.UsageCrossing: or(u.cfg.CrossingDeadline, usageCrossingDeadline),
			store.UsageAfter: or(u.cfg.AfterDeadline, usageAfterDeadline)}[r.DueTrigger]
		if deadline > 0 && time.Since(*first) > deadline {
			late = r.DueTrigger
			log.Warn("contract: usage report late", "workspace", r.Workspace, "trigger", late)
		}
	}
	if err := c.UsageSent(ctx, measure, body, kept, or(u.cfg.Floor, usageFloor), or(u.cfg.Coalesce, usageCoalesce), late); err != nil && ctx.Err() == nil {
		log.Warn("contract: could not record a usage report sent", "error", err)
	}
	log.Info("contract: usage sent", "workspace", r.Workspace, "usage_seq", report.UsageSeq, "rule_version", report.RuleVersion, "kept", kept)
	// A closed workspace's document, or that of one no account document
	// names any more, is asked again with each report, until a signed
	// not_found stops its reports (the spec's 15.8).
	if ask, err := c.UsageAsksGet(ctx, r.Workspace); err == nil && ask {
		if err := c.EntGetDueNow(ctx, r.Workspace); err == nil {
			kick(u.w.gets)
		}
	}
	return true
}
