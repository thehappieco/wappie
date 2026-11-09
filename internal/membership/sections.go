package membership

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The sections' sender (the spec's 14.2, "Cadence"; the plan's 5.2): the
// leader's one sender of every recorded workspace's numbers section, and
// of every followed person's document (person.go), as the snapshots'
// (snapshots.go): at the leader's start, within
// sectionDebounce of a change it shows (a dirty notice of the snapshot's,
// members included, or 0052's own), within connectionDebounce of a
// connection that only flipped between online and offline, at once after
// an act or a reset (their transactions make it due now), when the pairing
// look finds a pending row's pairing changed, and sectionEvery after its
// last accepted one; in the order they are due, at the round's pace. Each
// takes its state_seq first, in its own measuring transaction, so a
// section at or above an act's seq shows it (DS3).

// sectionSender is one leader's sender of the settings sections, and of
// the persons' documents (person.go), as one sender.
type sectionSender struct {
	sw *settingsWork
	// pending is what each workspace's last section sent said of its
	// registrations: the pairing look compares the process's view with it.
	pending map[uuid.UUID]pendingSent
	// leftOut is how many notices each person's last document left out,
	// for its ERROR once.
	leftOut map[uuid.UUID]int
	// warned spaces the WARNs of failed sends.
	warned time.Time
	// dropped is, per workspace, the rows its last section left out because
	// the wire refuses them: their ERROR is logged once per run.
	dropped map[uuid.UUID]string
}

// run sends sections until ctx ends.
func (s *sectionSender) run(ctx context.Context) {
	sw := s.sw
	l, c := sw.l, sw.l.Members.Contract
	cfg := sw.cfg
	minBack := or(l.BackoffMin, feedBackoffMin)
	wake := sw.sections.wake
	for {
		err := c.SectionsDue(ctx)
		if err == nil {
			err = c.PersonsDue(ctx)
		}
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		l.log().Warn("contract: could not make the sections due at the settings' start", "error", err)
		if !pause(ctx, minBack, wake) {
			return
		}
	}
	lookAt := time.Now().Add(or(cfg.PairingLook, pairingLook))
	for ctx.Err() == nil {
		if !time.Now().Before(lookAt) {
			s.lookPairings()
			lookAt = time.Now().Add(or(cfg.PairingLook, pairingLook))
		}
		if !s.applyNotices(ctx) {
			if ctx.Err() != nil || !pause(ctx, minBack, wake) {
				return
			}
			continue
		}
		next, ok, err := c.NextSection(ctx)
		var person store.ContractPersonDue
		var pok bool
		if err == nil {
			person, pok, err = c.NextPerson(ctx)
		}
		// The one due first goes first, a section before a person's
		// document due at the same time.
		personFirst := pok && person.Due && (!ok || !next.Due || person.DueAt.Before(next.DueAt))
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			l.log().Warn("contract: could not read the sections due", "error", err)
			if !pause(ctx, minBack, wake) {
				return
			}
		case personFirst:
			if err := l.Members.paced(ctx); err != nil {
				return
			}
			if !s.sendPerson(ctx, person) && !pause(ctx, minBack, wake) {
				return
			}
		case ok && next.Due:
			if err := l.Members.paced(ctx); err != nil {
				return
			}
			if !s.send(ctx, next) && !pause(ctx, minBack, wake) {
				return
			}
		default:
			wait := min(snapshotIdle, max(time.Until(lookAt), 0))
			if ok {
				wait = min(wait, next.Wait)
			}
			if pok {
				wait = min(wait, person.Wait)
			}
			if !pause(ctx, wait, wake) {
				return
			}
		}
	}
}

// applyNotices makes the workspaces the notices named due within their
// debounce, and the persons' documents they may change; false when that
// could not be written (the notices are kept).
func (s *sectionSender) applyNotices(ctx context.Context) bool {
	return s.applySectionNotices(ctx) && s.applyPersonNotices(ctx)
}

// applyPersonNotices makes due within the section debounce the documents
// of the users whose notices changed (a "u:" payload: a notice raised,
// changed, seen or deleted), of those with an unseen notice in a workspace
// a change touched (a reader who lost Read, or a number deleted, hides a
// pause notice; a membership disabled hides them all), and of everyone on
// an "all" (an account's status shows or hides the pause notices it
// raised for others).
func (s *sectionSender) applyPersonNotices(ctx context.Context) bool {
	sw := s.sw
	c := sw.l.Members.Contract
	users, workspaces, all := sw.sections.takePersons()
	if len(users) == 0 && len(workspaces) == 0 && !all {
		return true
	}
	debounce := or(sw.cfg.SectionDebounce, sectionDebounce)
	var subs []uuid.UUID
	var err error
	if all {
		err = c.PersonsDirtyAll(ctx, debounce)
	}
	for _, ws := range workspaces {
		if err != nil {
			break
		}
		var of []uuid.UUID
		if of, err = c.PersonsOfWorkspace(ctx, ws); err != nil {
			break
		}
		subs = append(subs, of...)
	}
	if err == nil {
		err = c.PersonsDirty(ctx, subs, users, debounce)
	}
	if err != nil {
		sw.sections.givePersons(users, workspaces, all)
		if ctx.Err() == nil {
			sw.l.log().Warn("contract: could not make the changed persons' documents due", "error", err)
		}
		return false
	}
	return true
}

// applySectionNotices makes the workspaces the notices named due within
// their debounce.
func (s *sectionSender) applySectionNotices(ctx context.Context) bool {
	sw := s.sw
	c := sw.l.Members.Contract
	ids, flips, all := sw.sections.take()
	if !all && len(ids) == 0 && len(flips) == 0 {
		return true
	}
	err := c.SectionsDirty(ctx, ids, all, or(sw.cfg.SectionDebounce, sectionDebounce))
	if err == nil {
		err = c.SectionsDirty(ctx, flips, false, or(sw.cfg.ConnectionDebounce, connectionDebounce))
	}
	if err != nil {
		sw.sections.give(ids, flips, all)
		if ctx.Err() == nil {
			sw.l.log().Warn("contract: could not make the changed workspaces' sections due", "error", err)
		}
		return false
	}
	return true
}

// lookPairings makes due, within the debounce, each workspace whose last
// section sent a pending row the process now sees otherwise: a pairing
// that started or ended, or a retry that became possible or not.
func (s *sectionSender) lookPairings() {
	looks := s.sw.cfg.Numbers
	if looks == nil {
		return
	}
	for ws, sent := range s.pending {
		for id, row := range sent {
			now := pendingOf(store.ContractPending{ID: id, Epoch: row.epoch}, looks)
			if now.Pairing != row.pairing || now.CanRetry != row.canRetry {
				s.sw.sections.dirty(ws.String())
				break
			}
		}
	}
}

// send measures one workspace's numbers section, renders it, checks it,
// sends it and records what the platform answered. It reports false when
// no outcome could be stored, and the section is due as it was.
func (s *sectionSender) send(ctx context.Context, next store.ContractSectionDue) bool {
	sw := s.sw
	l, m := sw.l, sw.l.Members
	c, ws := m.Contract, next.Workspace
	read, ok, err := c.NumbersOf(ctx, ws)
	switch {
	case err != nil:
		if ctx.Err() != nil {
			return true
		}
		l.log().Warn("contract: could not read a workspace's numbers section", "workspace", ws, "error", err)
		_, stored := s.record(ctx, ws, next.Seq, next.DueAt, store.SnapshotFailed, "database")
		return stored
	case !ok:
		// Parked meanwhile, or no snapshot numbered yet (NextSection skips
		// both): nothing goes.
		return true
	}
	doc, dropped, why, rule := numbersSection(read, sw.mode(), sw.cfg.Numbers)
	if why != "" {
		class := "local_invalid:" + why
		rec, stored := s.record(ctx, ws, read.Seq, read.MeasuredAt, store.SnapshotFailed, class)
		// Once per run, whichever leader, however many tries a change or a
		// restart asks for in between (which count none), as the snapshot's.
		if stored && rec.Recorded && rec.Before != class {
			attrs := []any{"workspace", ws, "reason", why, "items", len(read.Items), "pending", len(read.Pending)}
			if rule != nil {
				attrs = append(attrs, "rule", rule.Error())
			}
			l.log().Error("contract: a workspace's numbers section is not sent: Wappie would not send it", attrs...)
			if err := c.RecordError(ctx, store.ContractErrorSectionInvalid); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
		}
		return stored
	}
	s.droppedRows(ctx, ws, dropped)
	err = m.Client.PutSettings(ctx, doc)
	if ctx.Err() != nil {
		// The leader is stopping: the next sends again at its start.
		return true
	}
	s.remember(ws, read, doc)
	outcome, class := snapshotResult(err)
	rec, stored := s.record(ctx, ws, read.Seq, read.MeasuredAt, outcome, class)
	switch {
	case !rec.Recorded:
	case outcome == store.SnapshotAccepted:
		l.log().Debug("contract: numbers section accepted", "workspace", ws, "seq", read.Seq, "items", len(read.Items))
	case rec.Parked:
		attrs := []any{"workspace", ws, "class", class}
		if rec.NotFoundSince != nil {
			attrs = append(attrs, "not_found_since", rec.NotFoundSince.UTC().Format(time.RFC3339))
		}
		l.log().Error("contract: a workspace's numbers section is parked", attrs...)
		if err := c.RecordError(ctx, store.ContractErrorSectionParked); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an ERROR", "error", err)
		}
	default:
		if time.Since(s.warned) >= warnEvery {
			s.warned = time.Now()
			l.log().Warn("contract: a numbers section was not accepted", append([]any{"workspace", ws, "tries", rec.Tries}, callAttrs(err)...)...)
		}
	}
	return stored
}

// droppedRows logs at ERROR, once per run for the same rows, and records
// for --check, the rows a section of ws leaves out because the wire refuses
// them: a bug of Wappie's, never a row of the database (numbersSection).
func (s *sectionSender) droppedRows(ctx context.Context, ws uuid.UUID, dropped []uuid.UUID) {
	if len(dropped) == 0 {
		delete(s.dropped, ws)
		return
	}
	key := fmt.Sprint(dropped)
	if s.dropped[ws] == key {
		return
	}
	if s.dropped == nil {
		s.dropped = map[uuid.UUID]string{}
	}
	s.dropped[ws] = key
	l := s.sw.l
	l.log().Error("contract: a workspace's numbers section leaves out rows the wire refuses: it goes truncated",
		"workspace", ws, "rows", len(dropped), "first", dropped[0])
	if err := l.Members.Contract.RecordError(ctx, store.ContractErrorSectionInvalid); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not record an ERROR", "error", err)
	}
}

// remember keeps what a section sent of its pending rows, with each one's
// epoch as read, for the pairing look.
func (s *sectionSender) remember(ws uuid.UUID, read store.ContractNumbers, doc kc.SettingsDoc) {
	var data struct {
		Pending []kc.PendingRegistration `json:"pending"`
	}
	if json.Unmarshal(doc.Data, &data) != nil || len(data.Pending) == 0 {
		delete(s.pending, ws)
		return
	}
	epochs := map[string]int{}
	for _, p := range read.Pending {
		epochs[p.ID.String()] = p.Epoch
	}
	sent := pendingSent{}
	for _, p := range data.Pending {
		if id, err := uuid.Parse(p.ID); err == nil {
			sent[id] = pendingRow{epoch: epochs[p.ID], pairing: p.Pairing, canRetry: p.CanRetry}
		}
	}
	s.pending[ws] = sent
}

// sectionRule says why Wappie would not send doc, or "": a document the
// kit's Validate refuses (the platform reads it as strictly), or a body
// over the call's limit. Its words name a rule, never a value; the kit's
// refusal names the member that failed.
func sectionRule(doc kc.SettingsDoc) (string, error) {
	if err := doc.Validate(); err != nil {
		return "invalid", err
	}
	body, err := encodeData(doc)
	if err != nil {
		return "encode", err
	}
	if len(body) > kc.SettingsBodyLimit {
		return "too_large", fmt.Errorf("%d bytes", len(body))
	}
	return "", nil
}

// record stores an outcome, and logs a failure to store it (false): the
// section is then due as it was, and sent again.
func (s *sectionSender) record(ctx context.Context, ws uuid.UUID, seq int64, measured time.Time,
	outcome store.ContractSnapshotOutcome, class string) (store.ContractSnapshotRecord, bool) {
	sw := s.sw
	rec, err := sw.l.Members.Contract.SectionSent(ctx, ws, store.SectionNumbers, seq, measured, outcome, class, sw.cfg.sectionTimes())
	if err != nil {
		if ctx.Err() == nil {
			sw.l.log().Warn("contract: could not record a numbers section's outcome", "workspace", ws, "error", err)
		}
		return rec, false
	}
	return rec, true
}
