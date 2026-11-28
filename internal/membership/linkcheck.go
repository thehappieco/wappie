package membership

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// A link, a relink and a move into a workspace (the platform's spec,
// sections 15.5, 15.6, 15.11 and 15.12; E0 slice 19; Q57). A new pairing
// records item.linked and the number's placed_at, whatever the
// entitlements mode says (Linked). While the workspace is named and the
// entitlements part observes, the link check goes right after it, with the
// number's codes, and a GET beside it when no document is held or its
// freshness is over an hour; Wappie logs the answer, and what an enforcing
// release would refuse, and holds nothing back: history sync goes on
// (Q57: "do not hold sync"). A relink and a move are judged likewise, a
// relink by the last applied document's new_links alone, a move before its
// transaction opens, in one 5 s budget. Nothing here ever refuses, delays
// or undoes a link, a relink or a move. No line carries a code, a JID or a
// figure.

// The link check's timings, the defaults when zero.
const (
	// linkGetWait bounds the wait for a link's GET.
	linkGetWait = 10 * time.Second
	// linkMoveBudget bounds a move's GET and check together.
	linkMoveBudget = 5 * time.Second
	// linkPoll is how often a GET's row is read while it is awaited.
	linkPoll = 200 * time.Millisecond
	// linkFreshFor is the freshness past which a link asks the GET.
	linkFreshFor = time.Hour
)

// linkedRetries are the waits before RecordLinked's retries: three, at 1,
// 5 and 30 seconds.
var linkedRetries = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

// LinkTimings are the link check's timings; tests shorten them.
type LinkTimings struct {
	GetWait, MoveBudget, Poll time.Duration
	// Retries are RecordLinked's waits (linkedRetries when nil).
	Retries []time.Duration
}

// The reasons an enforcing release would refuse a link, a relink or a
// move, as the log names them (spec 15.5, 15.6, 15.11).
const (
	refuseStale       = "stale"
	refuseNoDocument  = "no_document"
	refuseNotFound    = "not_found"
	refuseNewLinksOff = "new_links_off"
	refuseNoPlace     = "no_place"
	refuseAllowance   = "allowance"
	refuseUsedUp      = "used_up"
)

// The acts a judge is made for.
const (
	actLink   = store.LinkActLink
	actRelink = "relink"
	actMove   = store.LinkActMove
)

// linkJudge is what a link's judge reads, after any GET.
type linkJudge struct {
	// Doc is the document held then (nil: none).
	Doc *kc.EntitlementsDoc
	// NoDocument: none held and the GET gave no answer; Stale: one held,
	// its freshness over an hour and the GET gave no answer; NotFound: the
	// GET or the check answered a signed not_found.
	NoDocument, Stale, NotFound bool
	// Answer is the check's signed answer, nil for none.
	Answer *kc.LinkCheckAnswer
	// Others is Wappie's own count of the workspace's places taken by
	// other numbers (spec 15.5; hosted only in E0), nil when not counted.
	Others *int64
	// OverAllowance: a move's bytes would take the destination past its
	// allowance_bytes.
	OverAllowance bool
}

// wouldRefuse is the first reason an enforcing release would refuse act,
// "" for none.
func (j linkJudge) wouldRefuse(act string) string {
	newLinksOff := (j.Doc != nil && j.Doc.Switches.NewLinks == kc.SwitchOff) ||
		(j.Answer != nil && j.Answer.Switches.NewLinks == kc.SwitchOff)
	switch {
	case j.NotFound:
		return refuseNotFound
	case j.NoDocument:
		return refuseNoDocument
	case j.Stale:
		return refuseStale
	case newLinksOff:
		return refuseNewLinksOff
	case act == actMove && j.OverAllowance:
		return refuseAllowance
	case j.Doc != nil && j.Others != nil && *j.Others >= j.Doc.Places.Total:
		return refuseNoPlace
	case act == actLink && j.Answer != nil && j.Answer.Trial == kc.TrialUsedUp && j.Doc != nil && j.Doc.State.TrialEndsAt != nil:
		return refuseUsedUp
	}
	return ""
}

// enforcing reports whether the workspace would enforce by the document
// held: E0 holds such a workspace at observe (its brake).
func (j linkJudge) enforcing() bool { return j.Doc != nil && j.Doc.Mode == kc.ModeEnforce }

// Linked is the pairing's hook (wa.PairOptions.OnLinked): a new link of
// device in tenant, by actor (nil: a full key's), with the paired
// session's identity. It returns at once and never fails the pairing,
// which WhatsApp has completed: in the background it records the link
// (RecordLinked: placed_at and item.linked), with three retries, then
// checks it (AfterPairing). A last failure logs ERROR with ids only and is
// recorded; the daily catch-up then covers the number.
func (m *Members) Linked(ctx context.Context, tenant, device uuid.UUID, actor *uuid.UUID, id wa.Identity) {
	ctx = context.WithoutCancel(ctx)
	go func() {
		retries := m.LinkTimings.Retries
		if retries == nil {
			retries = linkedRetries
		}
		for i := 0; ; i++ {
			_, err := m.Contract.RecordLinked(ctx, tenant, device, actor, id)
			if err == nil {
				break
			}
			if i == len(retries) {
				m.log().Error("contract: an item.linked could not be written; the catch-up covers the number",
					"workspace", tenant, "device", device, "tries", i+1)
				if err := m.Contract.RecordError(ctx, store.ContractErrorEventRecord); err != nil {
					m.log().Warn("contract: could not record an ERROR", "error", err)
				}
				break
			}
			time.Sleep(retries[i])
		}
		m.AfterPairing(ctx, tenant, device, id)
	}()
}

// observing reports whether ws's links are checked: the platform callable,
// the contract on, ws named, and the entitlements part observing.
func (m *Members) observing(ctx context.Context, ws uuid.UUID) bool {
	if m.Client == nil || !m.on(ctx) {
		return false
	}
	if _, named, err := m.Contract.Workspace(ctx, ws); err != nil || !named {
		return false
	}
	st, err := m.Contract.EntState(ctx)
	return err == nil && st.Effective() == store.EntObserve
}

// AfterPairing checks a new link of device in ws (spec 15.11, observe;
// Q57): the link check at once with the number's codes (none without a
// usable K_app: the place alone), and beside it, when no document is held
// or its freshness is over an hour, the GET computed now, waited for up to
// GetWait. It logs the answer and what an enforcing release would refuse,
// and holds nothing back.
func (m *Members) AfterPairing(ctx context.Context, ws, device uuid.UUID, id wa.Identity) {
	if !m.observing(ctx, ws) {
		return
	}
	codes, _ := m.trialCodesNow(identityStrings(id))
	type checked struct {
		a   kc.LinkCheckAnswer
		err error
	}
	answer := make(chan checked, 1)
	go func() {
		a, err := m.Client.LinkCheck(ctx, ws.String(), kc.LinkCheck{Kind: kc.ItemNumber, Codes: codes})
		answer <- checked{a, err}
	}()
	row, held, err := m.Contract.EntRow(ctx, ws)
	if err != nil {
		m.log().Warn("contract: could not read a workspace's entitlements for a link", "workspace", ws, "error", err)
	}
	j := m.linkGet(ctx, ws, row, held, or(m.LinkTimings.GetWait, linkGetWait))
	got := <-answer
	m.judged(ctx, ws, device, actLink, j, &got.a, got.err)
}

// identityStrings are id's two halves as devices stores them.
func identityStrings(id wa.Identity) (pn, lid string) {
	if !id.PN.IsEmpty() {
		pn = id.PN.String()
	}
	if !id.LID.IsEmpty() {
		lid = id.LID.String()
	}
	return pn, lid
}

// linkGet is the judge's document: the one held, or, when none is held or
// its freshness is over an hour, the GET computed now (slice 17's, made due
// at once), waited for up to wait.
func (m *Members) linkGet(ctx context.Context, ws uuid.UUID, row store.EntRow, held bool, wait time.Duration) linkJudge {
	var j linkJudge
	hasDoc := held && row.Doc != nil
	if hasDoc && row.Fresh != nil && time.Since(*row.Fresh) <= linkFreshFor {
		j.Doc = decodeDoc(row.Doc)
		return j
	}
	before := row
	if err := m.Contract.EntGetNow(ctx, ws); err != nil {
		m.log().Warn("contract: could not ask a link's GET", "workspace", ws, "error", err)
	}
	deadline := time.Now().Add(wait)
	answered, notFound := false, false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		time.Sleep(or(m.LinkTimings.Poll, linkPoll))
		r, ok, err := m.Contract.EntRow(ctx, ws)
		if err != nil || !ok {
			continue
		}
		row = r
		if r.GetFreshAt != nil && (before.GetFreshAt == nil || r.GetFreshAt.After(*before.GetFreshAt)) {
			answered = true
			break
		}
		if r.NotFoundSince != nil && r.GetDueAt == nil {
			notFound = true
			break
		}
		if r.GetErrorAt != nil && (before.GetErrorAt == nil || r.GetTries != before.GetTries) {
			break
		}
	}
	switch {
	case answered:
		j.Doc = decodeDoc(row.Doc)
	case notFound:
		j.NotFound = true
		j.Doc = decodeDoc(row.Doc)
	case hasDoc:
		j.Stale = true
		j.Doc = decodeDoc(row.Doc)
	default:
		j.NoDocument = true
	}
	return j
}

// decodeDoc is a stored document, nil for none or one that does not read.
func decodeDoc(raw []byte) *kc.EntitlementsDoc {
	if raw == nil {
		return nil
	}
	var d kc.EntitlementsDoc
	if json.Unmarshal(raw, &d) != nil {
		return nil
	}
	return &d
}

// judged logs a check's answer (or its failure, never retried) and what an
// enforcing release would refuse, counts the workspace's places, and keeps
// the check for contract status.
func (m *Members) judged(ctx context.Context, ws, device uuid.UUID, act string, j linkJudge, a *kc.LinkCheckAnswer, err error) {
	answered := err == nil
	if err == nil {
		j.Answer = a
		place := "null"
		if a.Place != nil {
			place = *a.Place
		}
		m.log().Info("contract: link check", "workspace", ws, "device", device, "act", act, "place", place, "trial", a.Trial,
			"trial_ends_at_set", a.TrialEndsAt != nil, "new_links", a.Switches.NewLinks,
			"computed_at", a.ComputedAt.UTC().Format(time.RFC3339))
	} else {
		if RefusalCode(err) == kc.CodeNotFound {
			j.NotFound = true
		}
		// A rate_limited answer or a transport's failure: logged, not
		// retried.
		m.log().Warn("contract: link check failed", "workspace", ws, "device", device, "act", act, "class", feedClass(err))
	}
	if j.Doc != nil {
		var others int64
		n, cerr := m.Contract.HostedNumbers(ctx, ws)
		if cerr == nil {
			// The number linked is counted already; a move's is not yet.
			if others = n; act == actLink {
				others = n - 1
			}
			j.Others = &others
		}
	}
	reason := j.wouldRefuse(act)
	m.wouldRefuse(ctx, ws, device, act, reason, j)
	if rerr := m.Contract.RecordLinkCheck(ctx, ws, act, answered, reason); rerr != nil && ctx.Err() == nil {
		m.log().Warn("contract: could not keep a link check", "workspace", ws, "error", rerr)
	}
}

// wouldRefuse logs what an enforcing release would refuse: ids and enums
// only. A workspace held at observe (a brake, or a document that says
// enforce, which E0 holds) says so.
func (m *Members) wouldRefuse(ctx context.Context, ws, device uuid.UUID, act, reason string, j linkJudge) {
	if reason == "" {
		return
	}
	attrs := []any{"workspace", ws, "device", device, "act", act, "reason", reason}
	if reason == refuseNoPlace {
		attrs = append(attrs, "count", "hosted_only")
	}
	if j.enforcing() {
		attrs = append(attrs, "held_at_observe", true)
	} else if row, ok, err := m.Contract.EntRow(ctx, ws); err == nil && ok && row.BrakeKind != "" {
		attrs = append(attrs, "held_at_observe", true)
	}
	m.log().Info("contract: link would be refused (observe)", attrs...)
}

// Relinked is a relink's hook (relink.Service): a relink is no link (spec
// 15.11), and follows the last applied document's new_links alone, with no
// GET and no check. With new_links off it logs what an enforcing release
// would refuse.
func (m *Members) Relinked(ctx context.Context, ws, device uuid.UUID) {
	if !m.observing(ctx, ws) {
		return
	}
	row, ok, err := m.Contract.EntRow(ctx, ws)
	if err != nil || !ok || row.AppliedAt == nil {
		return
	}
	j := linkJudge{Doc: decodeDoc(row.Doc)}
	if j.Doc != nil && j.Doc.Switches.NewLinks == kc.SwitchOff {
		m.wouldRefuse(ctx, ws, device, actRelink, refuseNewLinksOff, j)
	}
}

// BeforeMove checks a move of device from source into target before the
// move's transaction opens (spec 15.11, "A number moved into the
// workspace"), so no call runs while it holds both workspaces: in one
// MoveBudget, the GET when the destination's freshness is over an hour,
// then the link check with the number's codes. It logs what an enforcing
// release would refuse (new_links off, the moved bytes past the
// allowance, no place by Wappie's own count, stale, not_found), and never
// blocks or delays the move beyond the budget. moved is the preview's
// bytes, which may count a shared object twice: the line errs towards
// "would refuse". Never logged.
func (m *Members) BeforeMove(ctx context.Context, source, target, device uuid.UUID, moved int64) {
	ctx, cancel := context.WithTimeout(ctx, or(m.LinkTimings.MoveBudget, linkMoveBudget))
	defer cancel()
	if !m.observing(ctx, target) {
		return
	}
	pn, lid, err := m.Contract.NumberIdentity(ctx, source, device)
	if err != nil {
		m.log().Warn("contract: could not read a moved number's identity", "device", device, "error", err)
	}
	codes, _ := m.trialCodesNow(pn, lid)
	row, held, err := m.Contract.EntRow(ctx, target)
	if err != nil {
		m.log().Warn("contract: could not read a workspace's entitlements for a move", "workspace", target, "error", err)
	}
	wait := time.Until(deadlineOf(ctx)) / 2
	j := m.linkGet(ctx, target, row, held, wait)
	if j.Doc != nil {
		if total, ok, err := m.Contract.EntTotal(ctx, target); err == nil && ok {
			j.OverAllowance = total+moved > j.Doc.Storage.AllowanceBytes
		}
	}
	a, err := m.Client.LinkCheck(ctx, target.String(), kc.LinkCheck{Kind: kc.ItemNumber, Codes: codes})
	m.judged(context.WithoutCancel(ctx), target, device, actMove, j, &a, err)
}

// deadlineOf is ctx's deadline, now plus the default budget without one.
func deadlineOf(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(linkMoveBudget)
}
