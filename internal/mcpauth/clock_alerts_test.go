package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"whatserver2/internal/mailer"
)

// sentAlert is one mail a test's ClockAlerts sent.
type sentAlert struct {
	word string
	nums map[string]int64
}

// alertRig is a ClockAlerts on a temporary directory whose mail is recorded,
// and whose decisions are read back from its log.
type alertRig struct {
	t    *testing.T
	c    *ClockAlerts
	mu   sync.Mutex
	sent []sentAlert
	logs *lockedCapture
	// fail, when set, is what the next sends return.
	fail error
}

// lockedCapture is a log handler several goroutines may write to.
type lockedCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *lockedCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *lockedCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r)
	return nil
}
func (c *lockedCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *lockedCapture) WithGroup(string) slog.Handler      { return c }

// decisions are the logged decisions, "cause=outcome" each, in order.
func (c *lockedCapture) decisions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.records {
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		if attrs["event"] == "reader_alert" && attrs["cause"] != "" {
			out = append(out, attrs["cause"]+"="+attrs["outcome"])
		}
	}
	return out
}

func newAlertRig(t *testing.T, dir string) *alertRig {
	t.Helper()
	r := &alertRig{t: t, logs: &lockedCapture{}}
	r.c = &ClockAlerts{Dir: dir, Log: slog.New(r.logs)}
	r.c.Mail = func(_ context.Context, word string, nums []mailer.ReaderAlertNum) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if word == mailer.ReaderAlertTest {
			t.Errorf("a cause rule sent the test word")
		}
		if r.fail != nil {
			return r.fail
		}
		m := map[string]int64{}
		for _, n := range nums {
			m[n.Key] = n.Value
		}
		r.sent = append(r.sent, sentAlert{word: word, nums: m})
		return nil
	}
	return r
}

// take returns the mail sent since the last take.
func (r *alertRig) take() []sentAlert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

// words are the words of the mail sent since the last take.
func (r *alertRig) words() string {
	var w []string
	for _, s := range r.take() {
		w = append(w, s.word)
	}
	return strings.Join(w, ",")
}

const (
	pcrA = "aa"
	pcrB = "bb"
)

// check is one health check's answer or error.
type check struct {
	health ReaderHealth
	err    error
}

// answer is a 200 health object of a 0.6.1 reader.
func answer(boot, pcr0 string, ok bool, fields func(*ReaderHealth)) check {
	h := ReaderHealth{OK: true, ReaderID: "enclave", BootID: boot, PCR0: pcr0, State: "ready", ClockOK: &ok}
	if !ok {
		h.State = ReaderCodeClockUnknown
	}
	if fields != nil {
		fields(&h)
	}
	return check{health: h}
}

// stale is a 503 clock_unknown, with the health object when h is not nil.
func stale(h *ReaderHealth) check {
	return check{err: &HealthStatusError{Status: http.StatusServiceUnavailable, Code: ReaderCodeClockUnknown, Health: h}}
}

// down is a health check that got no answer.
func down() check {
	return check{err: ErrReaderUnavailable}
}

func (r *alertRig) observe(at time.Time, c check) {
	r.c.Observe(context.Background(), "enclave", c.health, c.err, at)
}

var t0 = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func code(c string) func(*ReaderHealth) {
	return func(h *ReaderHealth) { h.ClockCode = &c }
}

// cap_exceeded goes on the first BAD answer that names it, with its numbers,
// and once per boot.
func TestClockAlertCapOnFirstAnswer(t *testing.T) {
	r := newAlertRig(t, t.TempDir())
	r.observe(at(0), answer("b1", pcrA, true, nil))
	r.observe(at(1), answer("b1", pcrA, false, func(h *ReaderHealth) {
		code("cap_exceeded")(h)
		h.ClockCorrHourMS, h.ClockCorrDayMS, h.ClockUncMS, h.NSMSkewMS = ms(3100), ms(4200), ms(90500), ms(90000)
	}))
	got := r.take()
	if len(got) != 1 || got[0].word != mailer.ReaderAlertCapExceeded {
		t.Fatalf("sent %+v", got)
	}
	want := map[string]int64{"clock_corr_hour_ms": 3100, "clock_corr_day_ms": 4200, "clock_unc_ms": 90500, "nsm_skew_ms": 90000}
	if len(got[0].nums) != len(want) {
		t.Fatalf("numbers %v", got[0].nums)
	}
	for k, v := range want {
		if got[0].nums[k] != v {
			t.Fatalf("numbers %v", got[0].nums)
		}
	}
	for m := 2; m < 10; m++ {
		r.observe(at(m), answer("b1", pcrA, false, code("cap_exceeded")))
	}
	if w := r.words(); w != "" {
		t.Fatalf("sent again: %s", w)
	}
	if d := strings.Join(r.logs.decisions(), " "); d != "cap_exceeded=sent" {
		t.Fatalf("decisions %s", d)
	}
}

// nsm_kms_disagree is decided on the first count above 0 and on each
// change, a Node restart's reset included, and never on 0.
func TestClockAlertDisagree(t *testing.T) {
	r := newAlertRig(t, t.TempDir())
	count := func(n int64) func(*ReaderHealth) {
		return func(h *ReaderHealth) {
			h.ClockDisagreeKMS, h.KMSSkewLoMS, h.KMSSkewHiMS, h.ClockUncMS, h.NSMSkewMS = &n, ms(-3000), ms(-2000), ms(40), ms(5)
		}
	}
	r.observe(at(0), answer("b1", pcrA, true, count(0)))
	if w := r.words(); w != "" {
		t.Fatalf("0 sent %s", w)
	}
	r.observe(at(1), answer("b1", pcrA, true, count(1)))
	got := r.take()
	if len(got) != 1 || got[0].word != mailer.ReaderAlertNSMKMSDisagree || got[0].nums["kms_skew_lo_ms"] != -3000 ||
		got[0].nums["kms_skew_hi_ms"] != -2000 || got[0].nums["nsm_skew_ms"] != 5 || got[0].nums["clock_unc_ms"] != 40 {
		t.Fatalf("first sight: %+v", got)
	}
	r.observe(at(2), answer("b1", pcrA, true, count(1)))
	r.observe(at(3), answer("b1", pcrA, true, count(2))) // a change
	r.observe(at(4), answer("b1", pcrA, true, count(0))) // Node restarted
	r.observe(at(5), answer("b1", pcrA, true, count(1))) // and saw it again
	want := "nsm_kms_disagree=sent nsm_kms_disagree=suppressed nsm_kms_disagree=suppressed"
	if d := strings.Join(r.logs.decisions(), " "); d != want {
		t.Fatalf("decisions %q, want %q", d, want)
	}
	// After the window, a change mails again.
	r.observe(at(1+23*60), answer("b1", pcrA, true, count(3)))
	if w := r.words(); w != mailer.ReaderAlertNSMKMSDisagree {
		t.Fatalf("after the window: %q", w)
	}
}

// clock_unknown goes when the episode is clockUnknownAfter old, however it
// is made of BAD, DOWN and a new boot's BAD, and not before; it says
// whether the reader answers.
func TestClockAlertUnknownAcrossDownAndNewBoot(t *testing.T) {
	r := newAlertRig(t, t.TempDir())
	r.observe(at(0), answer("b1", pcrA, true, nil))
	r.observe(at(1), answer("b1", pcrA, false, func(h *ReaderHealth) { h.ClockUncMS, h.NSMSkewMS = ms(6000), ms(5500) }))
	for m := 2; m <= 6; m++ {
		r.observe(at(m), down())
	}
	// The new boot is a restart, still BAD: watchdog_restart, the episode
	// stays open.
	r.observe(at(8), answer("b2", pcrA, false, nil))
	got := r.take()
	if len(got) != 1 || got[0].word != mailer.ReaderAlertWatchdogRestart || got[0].nums["minutes_bad_before"] != 0 ||
		got[0].nums["minutes_unanswered"] != 7 || got[0].nums["clock_ok_now"] != 0 {
		t.Fatalf("restart: %+v", got)
	}
	r.observe(at(25), answer("b2", pcrA, false, func(h *ReaderHealth) { h.ClockUncMS, h.NSMSkewMS = ms(6000), ms(5500) }))
	if w := r.words(); w != "" {
		t.Fatalf("before %s: %s", clockUnknownAfter, w)
	}
	r.observe(at(26), down())
	got = r.take()
	if len(got) != 1 || got[0].word != mailer.ReaderAlertClockUnknown {
		t.Fatalf("at %s: %+v", clockUnknownAfter, got)
	}
	want := map[string]int64{"minutes_unknown": 25, "minutes_unanswered": 1, "clock_unc_ms": 6000, "nsm_skew_ms": 5500, "answering": 0}
	for k, v := range want {
		if n, ok := got[0].nums[k]; !ok || n != v {
			t.Fatalf("numbers %v, want %v", got[0].nums, want)
		}
	}
	// Once per episode, then again only after the window while it lasts.
	r.observe(at(30), answer("b2", pcrA, false, nil))
	r.observe(at(25+23*60), answer("b2", pcrA, false, nil))
	if d := strings.Join(r.logs.decisions(), " "); d != "watchdog_restart=sent clock_unknown=sent" {
		t.Fatalf("decisions %s", d)
	}
	r.observe(at(26+23*60), answer("b2", pcrA, false, nil))
	got = r.take()
	if len(got) != 1 || got[0].word != mailer.ReaderAlertClockUnknown || got[0].nums["answering"] != 1 {
		t.Fatalf("a day on: %+v", got)
	}
	// An OK closes the episode; a new BAD starts its own count.
	r.observe(at(27+23*60), answer("b2", pcrA, true, nil))
	r.observe(at(28+23*60), answer("b2", pcrA, false, nil))
	r.observe(at(28+23*60+24), answer("b2", pcrA, false, nil))
	if w := r.words(); w != "" {
		t.Fatalf("a new episode mailed early: %s", w)
	}
}

// watchdog_restart is the same image's new boot after a recent BAD; not a
// new image, not after an OK, not after an old BAD, not the first boot seen.
func TestClockAlertWatchdogRestart(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(r *alertRig)
		want string
	}{
		{"same image after BAD", func(r *alertRig) {
			r.observe(at(0), answer("b1", pcrA, false, nil))
			r.observe(at(5), answer("b2", pcrA, true, nil))
		}, "watchdog_restart"},
		{"after the bare 503", func(r *alertRig) {
			r.observe(at(0), answer("b1", pcrA, true, nil))
			r.observe(at(1), stale(nil))
			r.observe(at(10), answer("b2", pcrA, true, nil))
		}, "watchdog_restart"},
		{"a new image is a deploy", func(r *alertRig) {
			r.observe(at(0), answer("b1", pcrA, false, nil))
			r.observe(at(5), answer("b2", pcrB, true, nil))
		}, ""},
		{"after an OK", func(r *alertRig) {
			r.observe(at(0), answer("b1", pcrA, false, nil))
			r.observe(at(1), answer("b1", pcrA, true, nil))
			r.observe(at(5), answer("b2", pcrA, true, nil))
		}, ""},
		{"BAD too long ago", func(r *alertRig) {
			r.observe(at(0), answer("b1", pcrA, false, nil))
			for m := 1; m <= 31; m++ {
				r.observe(at(m), down())
			}
			r.observe(at(31), answer("b2", pcrA, true, nil))
		}, "clock_unknown"},
		{"the first boot seen", func(r *alertRig) {
			r.observe(at(0), answer("b2", pcrA, true, nil))
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newAlertRig(t, t.TempDir())
			tc.run(r)
			if w := r.words(); w != tc.want {
				t.Fatalf("sent %q, want %q", w, tc.want)
			}
		})
	}
}

// A 0.6.0 reader, which sends no clock_ok, is never tracked: nothing in the
// file, nothing sent, and its misses are not an episode. A 0.6.1 reader
// rolled back to 0.6.0 is forgotten.
func TestClockAlertOlderReaderNeverTracked(t *testing.T) {
	dir := t.TempDir()
	r := newAlertRig(t, dir)
	old := ReaderHealth{OK: true, ReaderID: "enclave", BootID: "b1", PCR0: pcrA, State: "ready"}
	r.observe(at(0), check{health: old})
	for m := 1; m < 60; m++ {
		r.observe(at(m), down())
	}
	r.observe(at(60), check{health: old})
	if w := r.words(); w != "" {
		t.Fatalf("sent %s", w)
	}
	st := readAlertState(t, dir)
	if len(st.Readers) != 0 {
		t.Fatalf("tracked: %+v", st.Readers)
	}
	r.observe(at(61), answer("b2", pcrB, false, nil))
	r.observe(at(62), check{health: old})
	if st := readAlertState(t, dir); len(st.Readers) != 0 {
		t.Fatalf("not forgotten: %+v", st.Readers)
	}
}

// The 503 clock_unknown is BAD with its health object (whose cause it names)
// and without it.
func TestClockAlertStale503(t *testing.T) {
	r := newAlertRig(t, t.TempDir())
	h := &ReaderHealth{OK: true, ReaderID: "enclave", BootID: "b1", PCR0: pcrA, State: ReaderCodeClockUnknown, ClockOK: new(bool)}
	h.ClockCode = str("cap_exceeded")
	r.observe(at(0), stale(h))
	if w := r.words(); w != mailer.ReaderAlertCapExceeded {
		t.Fatalf("with health: %q", w)
	}

	r = newAlertRig(t, t.TempDir())
	for m := 0; m <= 25; m++ {
		r.observe(at(m), stale(nil))
	}
	got := r.take()
	if len(got) != 1 || got[0].word != mailer.ReaderAlertClockUnknown || got[0].nums["answering"] != 1 {
		t.Fatalf("bare: %+v", got)
	}
	if _, ok := got[0].nums["clock_unc_ms"]; ok {
		t.Fatalf("a number the bare 503 did not carry: %v", got[0].nums)
	}
}

// The window survives a new process on the same file, and so does the
// restart inference.
func TestClockAlertStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	r := newAlertRig(t, dir)
	r.observe(at(0), answer("b1", pcrA, false, code("cap_exceeded")))
	if w := r.words(); w != mailer.ReaderAlertCapExceeded {
		t.Fatalf("first: %q", w)
	}
	// This server restarts; the reader is restarted too, and comes back
	// with the cap hit again.
	r = newAlertRig(t, dir)
	r.observe(at(6), answer("b2", pcrA, false, code("cap_exceeded")))
	if w := r.words(); w != mailer.ReaderAlertWatchdogRestart {
		t.Fatalf("after a restart: %q", w)
	}
	if d := strings.Join(r.logs.decisions(), " "); d != "cap_exceeded=suppressed watchdog_restart=sent" {
		t.Fatalf("decisions %s", d)
	}
	r.observe(at(7), answer("b2", pcrA, true, nil))
	st := readAlertState(t, dir)
	if !st.Sent[mailer.ReaderAlertCapExceeded].Equal(at(0)) {
		t.Fatalf("claim %v", st.Sent)
	}
	info, err := os.Stat(filepath.Join(dir, ReaderAlertsFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v %v", info, err)
	}
	// After the window, a new boot's cap goes again.
	r = newAlertRig(t, dir)
	r.observe(at(23*60), answer("b3", pcrB, false, code("cap_exceeded")))
	if w := r.words(); w != mailer.ReaderAlertCapExceeded {
		t.Fatalf("after the window: %q", w)
	}
}

// Two processes claiming the same word at once send it once: the other is
// suppressed while the first is still sending.
func TestClockAlertConcurrentClaimers(t *testing.T) {
	dir := t.TempDir()
	first, second := newAlertRig(t, dir), newAlertRig(t, dir)
	entered, release := make(chan struct{}), make(chan struct{})
	mail := first.c.Mail
	first.c.Mail = func(ctx context.Context, word string, nums []mailer.ReaderAlertNum) error {
		close(entered)
		<-release
		return mail(ctx, word, nums)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		first.observe(at(0), stale(&ReaderHealth{OK: true, ReaderID: "enclave", BootID: "b1", PCR0: pcrA, ClockOK: new(bool), ClockCode: str("cap_exceeded")}))
	}()
	<-entered
	second.observe(at(0), stale(&ReaderHealth{OK: true, ReaderID: "enclave", BootID: "b1", PCR0: pcrA, ClockOK: new(bool), ClockCode: str("cap_exceeded")}))
	close(release)
	<-done
	if a, b := first.words(), second.words(); a != mailer.ReaderAlertCapExceeded || b != "" {
		t.Fatalf("first %q, second %q", a, b)
	}
	if d := strings.Join(second.logs.decisions(), " "); d != "cap_exceeded=suppressed" {
		t.Fatalf("second decided %s", d)
	}

	// And many at once, each with its own lock: one mail.
	dir = t.TempDir()
	var wg sync.WaitGroup
	rigs := make([]*alertRig, 8)
	for i := range rigs {
		rigs[i] = newAlertRig(t, dir)
	}
	for _, r := range rigs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.observe(at(0), answer("b1", pcrA, false, code("cap_exceeded")))
		}()
	}
	wg.Wait()
	total := 0
	for _, r := range rigs {
		total += len(r.take())
	}
	if total != 1 {
		t.Fatalf("%d mails from %d claimers", total, len(rigs))
	}
}

// A send that fails gives the claim back and is tried again after
// alertRetry, not before; a claim another took meanwhile is not undone.
func TestClockAlertSendFailure(t *testing.T) {
	dir := t.TempDir()
	r := newAlertRig(t, dir)
	r.fail = errors.New("mailer: SMTP connection failed")
	r.observe(at(0), answer("b1", pcrA, false, code("cap_exceeded")))
	if st := readAlertState(t, dir); len(st.Sent) != 0 {
		t.Fatalf("the claim was kept: %v", st.Sent)
	}
	r.fail = nil
	r.observe(at(9), answer("b1", pcrA, false, code("cap_exceeded")))
	if w := r.words(); w != "" {
		t.Fatalf("retried before %s: %s", alertRetry, w)
	}
	r.observe(at(10), answer("b1", pcrA, false, code("cap_exceeded")))
	if w := r.words(); w != mailer.ReaderAlertCapExceeded {
		t.Fatalf("not retried: %q", w)
	}
	if d := strings.Join(r.logs.decisions(), " "); d != "cap_exceeded=failed cap_exceeded=sent" {
		t.Fatalf("decisions %s", d)
	}

	// While a failing send is out, another process takes the word: the
	// failure does not give that claim back.
	dir = t.TempDir()
	r = newAlertRig(t, dir)
	other := at(1)
	r.c.Mail = func(context.Context, string, []mailer.ReaderAlertNum) error {
		st := readAlertState(t, dir)
		st.Sent[mailer.ReaderAlertCapExceeded] = other
		writeAlertState(t, dir, st)
		return errors.New("mailer: SMTP connection failed")
	}
	r.observe(at(0), answer("b1", pcrA, false, code("cap_exceeded")))
	if st := readAlertState(t, dir); !st.Sent[mailer.ReaderAlertCapExceeded].Equal(other) {
		t.Fatalf("another's claim was undone: %v", st.Sent)
	}
}

// A crash between the claim and the send loses that window's mail and
// never sends it twice.
func TestClockAlertCrashBetweenClaimAndSend(t *testing.T) {
	dir := t.TempDir()
	r := newAlertRig(t, dir)
	r.c.Mail = func(context.Context, string, []mailer.ReaderAlertNum) error {
		runtime.Goexit() // the process dies with the claim written
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.observe(at(0), answer("b1", pcrA, false, code("cap_exceeded")))
	}()
	<-done
	if st := readAlertState(t, dir); !st.Sent[mailer.ReaderAlertCapExceeded].Equal(at(0)) {
		t.Fatalf("no claim: %v", st.Sent)
	}
	r = newAlertRig(t, dir)
	for m := 1; m < 20; m++ {
		r.observe(at(m), answer("b1", pcrA, false, code("cap_exceeded")))
	}
	if w := r.words(); w != "" {
		t.Fatalf("sent after the crash: %s", w)
	}
	if d := strings.Join(r.logs.decisions(), " "); d != "cap_exceeded=suppressed" {
		t.Fatalf("decisions %s", d)
	}
}

// A state file that is not the state stops the mail, with a warning at most
// every alertStateWarnEvery, and is not overwritten.
func TestClockAlertUnreadableState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ReaderAlertsFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newAlertRig(t, dir)
	for m := range 12 {
		r.observe(at(m), answer("b1", pcrA, false, code("cap_exceeded")))
	}
	if w := r.words(); w != "" {
		t.Fatalf("sent without the state: %s", w)
	}
	warned := 0
	for _, rec := range r.logs.records {
		if strings.Contains(rec.Message, "cannot keep their state") {
			warned++
		}
	}
	if warned != 2 {
		t.Fatalf("%d warnings in 12 minutes", warned)
	}
	if b, _ := os.ReadFile(path); string(b) != "{not json" {
		t.Fatalf("overwritten: %s", b)
	}
}

// The test alert has its own file and window: a second run inside it is
// refused with when the next is allowed, the real words' claims are not
// touched, and a failed send gives the window back.
func TestReaderAlertTestWindow(t *testing.T) {
	dir := t.TempDir()
	sends := 0
	send := func(context.Context) error { sends++; return nil }
	if err := SendReaderAlertTest(context.Background(), dir, at(0), send); err != nil || sends != 1 {
		t.Fatalf("first: %v (%d)", err, sends)
	}
	err := SendReaderAlertTest(context.Background(), dir, at(60), send)
	var soon *AlertTooSoonError
	if !errors.As(err, &soon) || !soon.Next.Equal(at(23*60)) || sends != 1 ||
		!strings.Contains(err.Error(), "2026-11-20T11:00:00Z") {
		t.Fatalf("second: %v (%d)", err, sends)
	}
	if _, err := os.Stat(filepath.Join(dir, ReaderAlertsFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the real alerts' file was touched: %v", err)
	}
	if err := SendReaderAlertTest(context.Background(), dir, at(23*60), send); err != nil || sends != 2 {
		t.Fatalf("after the window: %v (%d)", err, sends)
	}

	dir = t.TempDir()
	failing := errors.New("mailer: SMTP connection failed")
	if err := SendReaderAlertTest(context.Background(), dir, at(0), func(context.Context) error { return failing }); !errors.Is(err, failing) {
		t.Fatalf("failed send: %v", err)
	}
	if err := SendReaderAlertTest(context.Background(), dir, at(1), send); err != nil {
		t.Fatalf("after a failed send: %v", err)
	}

	// A real alert's claim does not spend the test's window, nor the
	// test's a real word's.
	dir = t.TempDir()
	r := newAlertRig(t, dir)
	r.observe(at(0), answer("b1", pcrA, false, code("cap_exceeded")))
	if err := SendReaderAlertTest(context.Background(), dir, at(1), send); err != nil {
		t.Fatalf("test after a real alert: %v", err)
	}
	if st := readAlertState(t, dir); len(st.Sent) != 1 {
		t.Fatalf("real claims %v", st.Sent)
	}
}

// The health check feeds the alerts: a reader whose check names the cap is
// mailed about, a nil ClockAlerts does nothing, and the health line is
// logged as before.
func TestCheckReaderFeedsClockAlerts(t *testing.T) {
	status := http.StatusOK
	body := readerHealthWith(t, map[string]any{"state": ReaderCodeClockUnknown, "clock_ok": false, "clock_code": "cap_exceeded"})
	a := healthServer(t, &status, &body)
	logs := &capture{}
	h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
	h.checkReader(context.Background(), a, 0) // nil ClockAlerts
	r := newAlertRig(t, t.TempDir())
	h.ClockAlerts = r.c
	h.checkReader(context.Background(), a, 0)
	if w := r.words(); w != mailer.ReaderAlertCapExceeded {
		t.Fatalf("sent %q", w)
	}
	if got := logs.lines(notReadyLine); len(got) != 2 || got[1].attrs["clock_code"] != "cap_exceeded" {
		t.Fatalf("health lines %+v", got)
	}
	status, body = http.StatusBadGateway, `{"code":"kms_failed"}`
	h.checkReader(context.Background(), a, 0)
	if w := r.words(); w != "" {
		t.Fatalf("a miss sent %q", w)
	}
}

func readAlertState(t *testing.T, dir string) *alertState {
	t.Helper()
	st, err := alertStore{path: filepath.Join(dir, ReaderAlertsFile)}.load()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func writeAlertState(t *testing.T, dir string, st *alertState) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ReaderAlertsFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
