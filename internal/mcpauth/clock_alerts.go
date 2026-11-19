package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"whatserver2/internal/mailer"
)

// Mailing the operator when an attested reader cannot vouch for its clock
// (docs/mcp-enclave.md §5.1).
//
// From 0.6.1 a reader that cannot vouch for its clock says so on its health
// check, and from the reader's own TLS, not the parent's word. This server
// already asks every minute, so it is the one that mails. The parent only
// restarts the enclave (its watchdog), and this server infers the restart
// from the boot id changing under the same image.
//
// Each answer is OK (clock_ok true), BAD (clock_ok false or state
// clock_unknown, or a 503 clock_unknown with or without its health object)
// or DOWN (anything else). A reader that never sent clock_ok (0.6.0) is
// never tracked. An episode opens at the first BAD and closes only at an
// OK; DOWN, and a new boot that has not yet answered OK, keep it open.
//
// The mail goes out under one of four words, never a word the reader sent:
//   - cap_exceeded: a BAD answer whose clock_code is cap_exceeded, once per
//     boot, before the watchdog's restart wipes it;
//   - nsm_kms_disagree: clock_disagree_kms above 0 and other than the last
//     value seen for this boot (a Node restart resets the count);
//   - clock_unknown: an episode still open clockUnknownAfter after it began,
//     again each alertWindow while it stays open;
//   - watchdog_restart: the first answer from a new boot with the same PCR0,
//     when the boot before last answered BAD within watchdogBadWithin. A
//     new PCR0 is a deploy or a rollback and is not mailed.
//
// Each word goes at most once per alertWindow, across restarts and across
// processes, claimed in a state file under a file lock before the mail is
// sent: two processes never both send, and a crash between the claim and
// the send loses that window's mail rather than sending it twice. A send
// that fails gives the claim back, if it is still this one's, and is tried
// again at most every alertRetry. The same file keeps what each reader last
// said, so a restart of this server does not lose the restart inference.

const (
	// clockUnknownAfter is how long an episode stays open before
	// clock_unknown is mailed. A fault the watchdog fixes is back in about
	// twelve minutes (five to trigger, one to restart, up to three of clock
	// wait, KMS and ACME), so only a fault it does not fix reaches it. The
	// owner may change it.
	clockUnknownAfter = 25 * time.Minute
	// alertWindow is how long one word's claim stands: each word is mailed
	// at most once in it.
	alertWindow = ReaderAlertWindow
	// alertRetry is how often a word whose mail failed is tried again.
	alertRetry = 10 * time.Minute
	// watchdogBadWithin is how recent the last BAD answer of the boot before
	// must be for a new boot to be a watchdog restart.
	watchdogBadWithin = 30 * time.Minute
	// alertStateVersion is the state file's version.
	alertStateVersion = 1
	// alertStateWarnEvery bounds the warning that the state file cannot be
	// kept.
	alertStateWarnEvery = 10 * time.Minute
)

// ReaderAlertWindow is how long one alert word's claim stands, the test
// alert's included: each is mailed at most once in it.
const ReaderAlertWindow = 23 * time.Hour

// The state files, in the API unit's state directory (the deletion
// ledger's): the alerts', and the test alert's (whatserverd
// reader-alert-test), each with its lock beside it.
const (
	ReaderAlertsFile     = "reader-alerts.json"
	ReaderAlertsTestFile = "reader-alerts-test.json"
)

// The outcomes a decision is logged with.
const (
	alertSent       = "sent"
	alertSuppressed = "suppressed"
	alertFailed     = "failed"
)

// ClockAlerts mails the operator about attested readers' clocks. Built only
// when an operator address and a mail server are configured; a nil
// *ClockAlerts does nothing.
type ClockAlerts struct {
	// Dir is the directory the state file and its lock are in.
	Dir string
	// Mail sends one alert: one of the four fault words of package mailer
	// and its numbers. It is never given mailer.ReaderAlertTest.
	Mail func(ctx context.Context, word string, nums []mailer.ReaderAlertNum) error
	Log  *slog.Logger

	// mu guards stateWarned, when the state file last could not be kept:
	// every reader's checks call Observe.
	mu          sync.Mutex
	stateWarned time.Time
}

// answerClass is what one health check said about the reader's clock.
type answerClass string

const (
	// classNone is a reader that does not report its clock (0.6.0).
	classNone answerClass = ""
	classOK   answerClass = "ok"
	classBad  answerClass = "bad"
	classDown answerClass = "down"
)

// classify reads one health check: its class and, when the reader sent
// one, its health object.
func classify(health ReaderHealth, err error) (answerClass, *ReaderHealth) {
	if err != nil {
		var status *HealthStatusError
		if errors.As(err, &status) && status.Status == 503 && status.Code == ReaderCodeClockUnknown {
			return classBad, status.Health
		}
		return classDown, nil
	}
	switch {
	case health.ClockOK != nil && !*health.ClockOK, health.State == ReaderCodeClockUnknown:
		return classBad, &health
	case health.ClockOK != nil:
		return classOK, &health
	}
	return classNone, nil
}

// alertState is the state file.
type alertState struct {
	V int `json:"v"`
	// Sent is when each word was last claimed.
	Sent map[string]time.Time `json:"sent,omitempty"`
	// Readers is what each tracked reader last said, by reader id.
	Readers map[string]*alertTrack `json:"readers,omitempty"`
}

// alertTrack is one reader as the alerts know it.
type alertTrack struct {
	// BootID and PCR0 are the boot the reader last answered from.
	BootID string `json:"boot_id,omitempty"`
	PCR0   string `json:"pcr0,omitempty"`
	// Class is the last classified answer (ok or bad) and ClassAt when it
	// came; AnsweredAt is when the reader last answered at all (not DOWN).
	Class      answerClass `json:"class,omitempty"`
	ClassAt    time.Time   `json:"class_at,omitzero"`
	AnsweredAt time.Time   `json:"answered_at,omitzero"`
	// EpisodeStart is when the open episode began, zero with none open.
	EpisodeStart time.Time `json:"episode_start,omitzero"`
	// UncMS and NSMSkewMS are the last the reader reported, for a
	// clock_unknown sent while it does not answer.
	UncMS     *int64 `json:"clock_unc_ms,omitempty"`
	NSMSkewMS *int64 `json:"nsm_skew_ms,omitempty"`

	// What has been decided, so that each fault is decided once:
	// CapBoot is the boot cap_exceeded was decided for; Disagree the last
	// clock_disagree_kms seen for BootID; UnknownFor the episode
	// clock_unknown was last decided for, and UnknownAt when; Restart a
	// watchdog_restart not yet decided.
	CapBoot    string          `json:"cap_boot,omitempty"`
	Disagree   *int64          `json:"disagree_kms,omitempty"`
	UnknownFor time.Time       `json:"unknown_for,omitzero"`
	UnknownAt  time.Time       `json:"unknown_at,omitzero"`
	Restart    *pendingRestart `json:"restart,omitempty"`
	// Failed is when each word's mail last failed for this reader.
	Failed map[string]time.Time `json:"failed,omitempty"`
}

// pendingRestart is a watchdog_restart inferred and not yet decided.
type pendingRestart struct {
	BootID            string `json:"boot_id"`
	MinutesBadBefore  int64  `json:"minutes_bad_before"`
	MinutesUnanswered int64  `json:"minutes_unanswered"`
	ClockOKNow        int64  `json:"clock_ok_now"`
	UncMS             *int64 `json:"clock_unc_ms,omitempty"`
}

// dueAlert is one word to decide: its numbers, and what deciding it marks
// on the reader's track.
type dueAlert struct {
	word string
	nums []mailer.ReaderAlertNum
	mark func(*alertTrack)
}

// claimed is a word claimed for sending: when, and the claim it replaced.
type claimed struct {
	dueAlert
	at, prev time.Time
}

// Observe takes one health check of one reader, its answer or its error, at
// now, and mails what it calls for. It blocks while a mail is sent.
func (c *ClockAlerts) Observe(ctx context.Context, readerID string, health ReaderHealth, err error, now time.Time) {
	if c == nil || c.Mail == nil {
		return
	}
	class, h := classify(health, err)
	store := alertStore{path: filepath.Join(c.Dir, ReaderAlertsFile)}
	var claims []claimed
	updateErr := store.update(func(st *alertState) error {
		tr := st.Readers[readerID]
		switch {
		case class == classNone:
			// A reader that does not report its clock is not tracked; one
			// that stopped (a rollback to 0.6.0) is forgotten.
			delete(st.Readers, readerID)
			return nil
		case class == classDown && tr == nil:
			return nil
		case tr == nil:
			tr = &alertTrack{}
			st.Readers[readerID] = tr
		}
		for _, d := range observe(tr, class, h, now) {
			if at, ok := tr.Failed[d.word]; ok && now.Sub(at) < alertRetry {
				continue
			}
			if last, ok := st.Sent[d.word]; ok && within(now, last, alertWindow) {
				d.mark(tr)
				delete(tr.Failed, d.word)
				c.logDecision(d.word, alertSuppressed, nil)
				continue
			}
			claims = append(claims, claimed{dueAlert: d, at: now, prev: st.Sent[d.word]})
			st.Sent[d.word] = now
		}
		return nil
	})
	if updateErr != nil {
		c.warnState(updateErr, now)
		return
	}
	for _, cl := range claims {
		sendErr := c.Mail(ctx, cl.word, cl.nums)
		finishErr := store.update(func(st *alertState) error {
			if sendErr != nil {
				// Give the claim back, unless another has taken it since.
				if last, ok := st.Sent[cl.word]; ok && last.Equal(cl.at) {
					if cl.prev.IsZero() {
						delete(st.Sent, cl.word)
					} else {
						st.Sent[cl.word] = cl.prev
					}
				}
			}
			tr := st.Readers[readerID]
			if tr == nil {
				return nil
			}
			if sendErr != nil {
				if tr.Failed == nil {
					tr.Failed = map[string]time.Time{}
				}
				tr.Failed[cl.word] = now
				return nil
			}
			cl.mark(tr)
			delete(tr.Failed, cl.word)
			return nil
		})
		if sendErr != nil {
			c.logDecision(cl.word, alertFailed, sendErr)
		} else {
			c.logDecision(cl.word, alertSent, nil)
		}
		if finishErr != nil {
			c.warnState(finishErr, now)
		}
	}
}

// observe moves one reader's track on by one answer and returns the words
// due.
func observe(tr *alertTrack, class answerClass, h *ReaderHealth, now time.Time) []dueAlert {
	var due []dueAlert
	if class == classOK || class == classBad {
		if h != nil && h.BootID != "" {
			if tr.BootID != "" && h.BootID != tr.BootID {
				// A new boot. The same image after a recent BAD is a
				// restart for the clock, most likely the watchdog's.
				if h.PCR0 == tr.PCR0 && tr.Class == classBad && now.Sub(tr.ClassAt) <= watchdogBadWithin {
					okNow := int64(0)
					if class == classOK {
						okNow = 1
					}
					tr.Restart = &pendingRestart{
						BootID:            h.BootID,
						MinutesBadBefore:  minutes(tr.ClassAt.Sub(tr.EpisodeStart)),
						MinutesUnanswered: minutes(now.Sub(tr.AnsweredAt)),
						ClockOKNow:        okNow,
						UncMS:             h.ClockUncMS,
					}
				}
				tr.Disagree = nil
			}
			tr.BootID, tr.PCR0 = h.BootID, h.PCR0
		}
		tr.Class, tr.ClassAt, tr.AnsweredAt = class, now, now
		if h != nil {
			tr.UncMS, tr.NSMSkewMS = h.ClockUncMS, h.NSMSkewMS
		}
		if class == classOK {
			tr.EpisodeStart = time.Time{}
		} else if tr.EpisodeStart.IsZero() {
			tr.EpisodeStart = now
		}
	}

	if r := tr.Restart; r != nil {
		nums := []mailer.ReaderAlertNum{
			{Key: "minutes_bad_before", Value: r.MinutesBadBefore},
			{Key: "minutes_unanswered", Value: r.MinutesUnanswered},
			{Key: "clock_ok_now", Value: r.ClockOKNow},
		}
		nums = appendNum(nums, "clock_unc_ms", r.UncMS)
		boot := r.BootID
		due = append(due, dueAlert{word: mailer.ReaderAlertWatchdogRestart, nums: nums, mark: func(tr *alertTrack) {
			if tr.Restart != nil && tr.Restart.BootID == boot {
				tr.Restart = nil
			}
		}})
	}

	if class == classBad && h != nil && h.ClockCode != nil && *h.ClockCode == "cap_exceeded" && tr.CapBoot != tr.BootID {
		var nums []mailer.ReaderAlertNum
		nums = appendNum(nums, "clock_corr_hour_ms", h.ClockCorrHourMS)
		nums = appendNum(nums, "clock_corr_day_ms", h.ClockCorrDayMS)
		nums = appendNum(nums, "clock_unc_ms", h.ClockUncMS)
		nums = appendNum(nums, "nsm_skew_ms", h.NSMSkewMS)
		boot := tr.BootID
		due = append(due, dueAlert{word: mailer.ReaderAlertCapExceeded, nums: nums, mark: func(tr *alertTrack) { tr.CapBoot = boot }})
	}

	if h != nil && h.ClockDisagreeKMS != nil {
		v := *h.ClockDisagreeKMS
		switch {
		case v == 0:
			tr.Disagree = &v
		case tr.Disagree == nil || *tr.Disagree != v:
			var nums []mailer.ReaderAlertNum
			nums = appendNum(nums, "kms_skew_lo_ms", h.KMSSkewLoMS)
			nums = appendNum(nums, "kms_skew_hi_ms", h.KMSSkewHiMS)
			nums = appendNum(nums, "nsm_skew_ms", h.NSMSkewMS)
			nums = appendNum(nums, "clock_unc_ms", h.ClockUncMS)
			due = append(due, dueAlert{word: mailer.ReaderAlertNSMKMSDisagree, nums: nums, mark: func(tr *alertTrack) { tr.Disagree = &v }})
		}
	}

	if start := tr.EpisodeStart; !start.IsZero() && now.Sub(start) >= clockUnknownAfter &&
		(!tr.UnknownFor.Equal(start) || now.Sub(tr.UnknownAt) >= alertWindow) {
		answering := int64(0)
		if class != classDown {
			answering = 1
		}
		nums := []mailer.ReaderAlertNum{
			{Key: "minutes_unknown", Value: minutes(now.Sub(start))},
			{Key: "minutes_unanswered", Value: minutes(now.Sub(tr.AnsweredAt))},
		}
		nums = appendNum(nums, "clock_unc_ms", tr.UncMS)
		nums = appendNum(nums, "nsm_skew_ms", tr.NSMSkewMS)
		nums = append(nums, mailer.ReaderAlertNum{Key: "answering", Value: answering})
		due = append(due, dueAlert{word: mailer.ReaderAlertClockUnknown, nums: nums, mark: func(tr *alertTrack) {
			tr.UnknownFor, tr.UnknownAt = start, now
		}})
	}
	return due
}

// within reports whether now and then are less than d apart either way. A
// claim stamped ahead of now counts too, so that this server's clock going
// back never sends a word twice; one more than d ahead is ignored, so that a
// clock once far ahead does not silence a word for ever.
func within(now, then time.Time, d time.Duration) bool {
	gap := now.Sub(then)
	return gap < d && gap > -d
}

// minutes is a duration in whole minutes, 0 for a negative one.
func minutes(d time.Duration) int64 {
	if d < 0 {
		return 0
	}
	return int64(d / time.Minute)
}

// appendNum adds a number the reader reported, when it did.
func appendNum(nums []mailer.ReaderAlertNum, key string, v *int64) []mailer.ReaderAlertNum {
	if v == nil {
		return nums
	}
	return append(nums, mailer.ReaderAlertNum{Key: key, Value: *v})
}

func (c *ClockAlerts) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// logDecision logs one word's decision.
func (c *ClockAlerts) logDecision(word, outcome string, err error) {
	attrs := []any{"event", "reader_alert", "cause", word, "outcome", outcome}
	if err != nil {
		c.log().Warn("reader clock alert", append(attrs, "error", err)...)
		return
	}
	c.log().Info("reader clock alert", attrs...)
}

// warnState warns, at most every alertStateWarnEvery, that the state file
// cannot be kept: no alert is mailed without its claim.
func (c *ClockAlerts) warnState(err error, now time.Time) {
	c.mu.Lock()
	quiet := !c.stateWarned.IsZero() && within(now, c.stateWarned, alertStateWarnEvery)
	if !quiet {
		c.stateWarned = now
	}
	c.mu.Unlock()
	if quiet {
		return
	}
	c.log().Warn("reader clock alerts cannot keep their state; nothing is mailed without it",
		"event", "reader_alert", "file", filepath.Join(c.Dir, ReaderAlertsFile), "error", err)
}

// AlertTooSoonError is a test alert refused because the last one is less
// than alertWindow old.
type AlertTooSoonError struct {
	// Next is when the next test alert is allowed.
	Next time.Time
}

func (e *AlertTooSoonError) Error() string {
	return "a test alert went less than " + alertWindow.String() + " ago; the next is allowed after " + e.Next.UTC().Format(time.RFC3339)
}

// SendReaderAlertTest claims the test alert's own window in
// ReaderAlertsTestFile in dir and sends it with send: at most one test
// alert per alertWindow, whatever the real words' claims. Within the
// window it sends nothing and returns *AlertTooSoonError. A send that fails
// gives the claim back, if it is still this one's.
func SendReaderAlertTest(ctx context.Context, dir string, now time.Time, send func(context.Context) error) error {
	store := alertStore{path: filepath.Join(dir, ReaderAlertsTestFile)}
	var prev time.Time
	err := store.update(func(st *alertState) error {
		if last, ok := st.Sent[mailer.ReaderAlertTest]; ok && within(now, last, alertWindow) {
			return &AlertTooSoonError{Next: last.Add(alertWindow)}
		}
		prev = st.Sent[mailer.ReaderAlertTest]
		st.Sent[mailer.ReaderAlertTest] = now
		return nil
	})
	if err != nil {
		return err
	}
	sendErr := send(ctx)
	if sendErr == nil {
		return nil
	}
	if err := store.update(func(st *alertState) error {
		if last, ok := st.Sent[mailer.ReaderAlertTest]; ok && last.Equal(now) {
			if prev.IsZero() {
				delete(st.Sent, mailer.ReaderAlertTest)
			} else {
				st.Sent[mailer.ReaderAlertTest] = prev
			}
		}
		return nil
	}); err != nil {
		return errors.Join(sendErr, fmt.Errorf("the claim was not given back: %w", err))
	}
	return sendErr
}

// alertStore is one state file and its lock beside it.
type alertStore struct{ path string }

func (s alertStore) lockPath() string { return strings.TrimSuffix(s.path, ".json") + ".lock" }

// update runs fn on the file's state under its lock and writes the state
// back when fn returns nil.
func (s alertStore) update(fn func(*alertState) error) error {
	unlock, err := lockAlerts(s.lockPath())
	if err != nil {
		return err
	}
	defer unlock()
	st, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	return s.save(st)
}

// load reads the state; a missing file is an empty state. A file that is
// not the state is an error, never an empty state: it would forget the
// claims.
func (s alertStore) load() (*alertState, error) {
	st := &alertState{V: alertStateVersion}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, st); err != nil || st.V != alertStateVersion {
			return nil, fmt.Errorf("%s is not version %d of the alerts' state", s.path, alertStateVersion)
		}
	}
	if st.Sent == nil {
		st.Sent = map[string]time.Time{}
	}
	if st.Readers == nil {
		st.Readers = map[string]*alertTrack{}
	}
	return st, nil
}

// save writes the state atomically: a temporary file, synced, renamed over
// the old one, and the directory synced.
func (s alertStore) save(st *alertState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			tmp.Close()           //nolint:errcheck,gosec // abandoned on an error already returned
			os.Remove(tmp.Name()) //nolint:errcheck,gosec // as above
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	done = true
	d, err := os.Open(dir) //nolint:gosec // G304: the state file's own directory
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // read-only
	return d.Sync()
}
