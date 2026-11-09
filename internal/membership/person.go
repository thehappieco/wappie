package membership

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/label"
	"whatserver2/internal/store"
)

// The person's document (the spec's 14.3 and 14.5; the plan's 6.6, DS12):
// one person's own settings in Wappie, for each sub Wappie follows with a
// document that is not closed (PUT /contract/v1/accounts/{sub}/settings,
// the kit's WappiePersonSettings), sent by the section sender as a
// section is, on the person's own clock (contract_persons.seq, DS3):
//
//   - signed_out_everywhere_at, the latest person.sign_out_everywhere that
//     ran;
//   - notices, the person's unseen ones of platform workspaces (never a
//     local-only workspace's), the newest kc.MaxNotices, each as Wappie's
//     own page lists it: version the pauses folded in for sync_paused (as
//     SeenNotice acknowledges it), else 1; the label stored with it, but
//     one stored before 0052 (the label cutover) only when today's rule
//     gives the same text now; params with the actor's sub, never a name.
//
// A row the wire refuses (a label or a hint the kit refuses, a
// number_deleted with no purge date) is left out and the document marked
// truncated, with an ERROR once (the spec's 14.2): every row sent is whole.
// A person with more notices than kc.MaxNotices gets the newest, and the
// document is marked truncated too (14.2: "a list cut to fit"), with no
// ERROR: the cut is the spec's own bound, no fault of Wappie's.

// personDoc is read's document as the settings mode lets it be sent, and
// how many notices the wire would refuse and were left out. A notice past
// the newest kc.MaxNotices it sends is cut, and the document truncated,
// but it is not counted among those.
func personDoc(read store.ContractPerson, mode string) (kc.PersonSettingsDoc, int, error) {
	data := kc.WappiePersonSettings{Notices: []kc.Notice{}}
	if at := read.SignedOutEverywhereAt; at != nil {
		t := kc.T(*at)
		data.SignedOutEverywhereAt = &t
	}
	left, cut := 0, false
	for _, n := range read.Notices {
		if len(data.Notices) == kc.MaxNotices {
			cut = true
			break
		}
		row, err := noticeRow(n, read.LabelCutoverAt)
		if err != nil || !noticeSendable(read.Sub, row) {
			left++
			continue
		}
		data.Notices = append(data.Notices, row)
	}
	raw, err := encodeData(data)
	if err != nil {
		return kc.PersonSettingsDoc{}, left, err
	}
	return kc.PersonSettingsDoc{V: kc.SettingsV, Type: kc.PersonSettingsType, App: App, Producer: kc.ProducerWappie,
		Sub: read.Sub.String(), StateSeq: read.Seq, MeasuredAt: kc.T(read.MeasuredAt), Truncated: left > 0 || cut,
		Accepts: accepts(mode, kc.SectionPerson), Data: raw}, left, nil
}

// noticeRow is one notice as the wire carries it.
func noticeRow(n store.ContractNotice, cutover time.Time) (kc.Notice, error) {
	ws, item := n.Workspace.String(), n.Device.String()
	row := kc.Notice{ID: strconv.FormatInt(n.ID, 10), Code: n.Kind, WorkspaceID: &ws, Item: &item, At: kc.T(n.At()), Version: 1,
		Label: noticeLabel(n, cutover), Hint: n.Hint}
	var actor *string
	if n.ActorSub != nil {
		sub := n.ActorSub.String()
		actor = &sub
	}
	var params any
	switch n.Kind {
	case store.NoticeSyncPaused:
		row.Version = int64(n.Pauses)
		params = kc.SyncPausedParams{Actor: actor, ActorKind: n.ActorKind, SeveralActors: n.SeveralActors, FirstAt: kc.T(n.RaisedAt),
			ResumedAt: wireTime(n.ResumedAt)}
	case store.NoticeNumberDeleted:
		var until kc.Time
		if n.Until != nil {
			until = kc.T(*n.Until)
		}
		params = kc.NumberDeletedParams{Actor: actor, Until: until, PurgedAt: wireTime(n.PurgedAt)}
	case store.NoticeNumberStranded:
		params = kc.NumberStrandedParams{Actor: actor, Until: wireTime(n.Until)}
	case store.NoticeNumberMovedOut:
		params = kc.NumberMovedOutParams{Actor: actor}
	default:
		return row, fmt.Errorf("membership: a notice of kind %q", n.Kind)
	}
	var err error
	row.Params, err = encodeData(params)
	return row, err
}

// noticeLabel is the label a notice is sent with (DS12): the one stored
// with it, but one stored before the label cutover only when the rule
// Wappie applies now gives the same text of the number as it is now
// (label.Contract), else none: before 0052 a number nobody named was
// labelled with its push name.
func noticeLabel(n store.ContractNotice, cutover time.Time) *string {
	if n.Label == nil || !n.At().Before(cutover) {
		return n.Label
	}
	if n.DeviceLabel == nil {
		return nil
	}
	pn := ""
	if n.DevicePN != nil {
		pn = *n.DevicePN
	}
	if now := label.Contract(*n.DeviceLabel, pn, n.Device.String()); now != nil && *now == *n.Label {
		return n.Label
	}
	return nil
}

func wireTime(t *time.Time) *kc.Time {
	if t == nil {
		return nil
	}
	w := kc.T(*t)
	return &w
}

// noticeSendable reports whether the wire takes row: a document of it
// alone passes the kit's Validate, as the platform reads every row.
func noticeSendable(sub uuid.UUID, row kc.Notice) bool {
	raw, err := encodeData(kc.WappiePersonSettings{Notices: []kc.Notice{row}})
	if err != nil {
		return false
	}
	return kc.PersonSettingsDoc{V: kc.SettingsV, Type: kc.PersonSettingsType, App: App, Producer: kc.ProducerWappie,
		Sub: sub.String(), StateSeq: 1, MeasuredAt: kc.T(time.Unix(1, 0)), Accepts: []string{}, Data: raw}.Validate() == nil
}

// personRule says why Wappie would not send doc, or "", as sectionRule.
func personRule(doc kc.PersonSettingsDoc) (string, error) {
	if err := doc.Validate(); err != nil {
		return "invalid", err
	}
	body, err := encodeData(doc)
	if err != nil {
		return "encode", err
	}
	if len(body) > kc.PersonSettingsBodyLimit {
		return "too_large", fmt.Errorf("%d bytes", len(body))
	}
	return "", nil
}

// sendPerson measures one person's document, renders it, checks it, sends
// it and records what the platform answered, as send does a section. A
// pause notice whose resume lost its mark is repaired first (DS17). It
// reports false when no outcome could be stored.
func (s *sectionSender) sendPerson(ctx context.Context, next store.ContractPersonDue) bool {
	sw := s.sw
	l, m := sw.l, sw.l.Members
	c, sub := m.Contract, next.Sub
	if _, err := c.ResumeLostMarks(ctx, sub); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not repair a person's pause notices", "error", err)
	}
	read, ok, err := c.PersonOf(ctx, sub)
	switch {
	case err != nil:
		if ctx.Err() != nil {
			return true
		}
		l.log().Warn("contract: could not read a person's document", "error", err)
		_, stored := s.recordPerson(ctx, sub, next.Seq, next.DueAt, store.SnapshotFailed, "database")
		return stored
	case !ok:
		return true
	}
	doc, left, err := personDoc(read, sw.mode())
	why, rule := "encode", err
	if err == nil {
		why, rule = personRule(doc)
	}
	if why != "" {
		class := "local_invalid:" + why
		rec, stored := s.recordPerson(ctx, sub, read.Seq, read.MeasuredAt, store.SnapshotFailed, class)
		if stored && rec.Recorded && rec.Before != class {
			attrs := []any{"sub", sub, "reason", why, "notices", len(read.Notices)}
			if rule != nil {
				attrs = append(attrs, "rule", rule.Error())
			}
			l.log().Error("contract: a person's document is not sent: Wappie would not send it", attrs...)
			s.recordError(ctx, store.ContractErrorPersonInvalid)
		}
		return stored
	}
	if s.leftOut == nil {
		s.leftOut = map[uuid.UUID]int{}
	}
	if left > 0 && s.leftOut[sub] != left {
		l.log().Error("contract: a person's notices are left out: the wire refuses them", "sub", sub, "left_out", left, "notices", len(read.Notices))
		s.recordError(ctx, store.ContractErrorPersonInvalid)
	}
	s.leftOut[sub] = left
	err = m.Client.PutPersonSettings(ctx, doc)
	if ctx.Err() != nil {
		return true
	}
	outcome, class := snapshotResult(err)
	rec, stored := s.recordPerson(ctx, sub, read.Seq, read.MeasuredAt, outcome, class)
	switch {
	case !rec.Recorded:
	case outcome == store.SnapshotAccepted:
		l.log().Debug("contract: a person's document accepted", "seq", read.Seq, "notices", len(read.Notices))
	case rec.Parked:
		l.log().Error("contract: a person's document is parked", "sub", sub, "class", class)
	default:
		if time.Since(s.warned) >= warnEvery {
			s.warned = time.Now()
			l.log().Warn("contract: a person's document was not accepted", append([]any{"tries", rec.Tries}, callAttrs(err)...)...)
		}
	}
	return stored
}

// recordPerson stores a person's document's outcome, as record a
// section's.
func (s *sectionSender) recordPerson(ctx context.Context, sub uuid.UUID, seq int64, measured time.Time,
	outcome store.ContractSnapshotOutcome, class string) (store.ContractSnapshotRecord, bool) {
	sw := s.sw
	rec, err := sw.l.Members.Contract.PersonSent(ctx, sub, seq, measured, outcome, class, sw.cfg.sectionTimes())
	if err != nil {
		if ctx.Err() == nil {
			sw.l.log().Warn("contract: could not record a person's document's outcome", "error", err)
		}
		return rec, false
	}
	return rec, true
}

// recordError keeps an ERROR's class for --check.
func (s *sectionSender) recordError(ctx context.Context, class string) {
	if err := s.sw.l.Members.Contract.RecordError(ctx, class); err != nil && ctx.Err() == nil {
		s.sw.l.log().Warn("contract: could not record an ERROR", "error", err)
	}
}
