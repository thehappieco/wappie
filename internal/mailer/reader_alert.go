package mailer

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The reader clock alert (docs/mcp-enclave.md §5.1): the attested reader
// cannot vouch for its clock, or was restarted for it, told to the
// operator's address alone.
//
// What it may carry decides its shape. The reader and the parent are not
// trusted with the words of a mail sent from Wappie's domain, so nothing in
// it comes from them as text: the subject is one of five fixed words, the
// body a fixed paragraph per fault word, then whole numbers under fixed keys,
// each word with its own list of keys, then the time. No reader id, no boot
// id, no code the reader sent, no link. The test alert is a fault word's
// body under its own subject word, with test: 1 first.

// The words a reader clock alert's subject may carry. The first four are
// faults; ReaderAlertTest is only ever sent by whatserverd
// reader-alert-test (ReaderClockAlertTest), never for a fault.
const (
	ReaderAlertCapExceeded     = "cap_exceeded"
	ReaderAlertNSMKMSDisagree  = "nsm_kms_disagree"
	ReaderAlertClockUnknown    = "clock_unknown"
	ReaderAlertWatchdogRestart = "watchdog_restart"
	ReaderAlertTest            = "test"
)

// ReaderAlertNum is one number of a reader clock alert: Key must be on its
// word's list.
type ReaderAlertNum struct {
	Key   string
	Value int64
}

// readerAlertWord is one word's paragraph and the keys it may carry, in the
// order the body shows them.
type readerAlertWord struct {
	text string
	keys []string
}

// readerAlertWords are the four fault words. The texts are drafts for the
// owner. The test alert has no entry: it is readerAlertTestBody's.
var readerAlertWords = map[string]readerAlertWord{
	ReaderAlertCapExceeded: {
		text: "The attested Wappie reader's clock helper had to correct the enclave clock by more than its cap allows, so the reader stopped vouching for its clock and refuses the work that needs it. The parent's watchdog restarts the enclave to clear this. The numbers are the corrections and the uncertainty the reader reported.",
		keys: []string{"clock_corr_hour_ms", "clock_corr_day_ms", "clock_unc_ms", "nsm_skew_ms"},
	},
	ReaderAlertNSMKMSDisagree: {
		text: "The attested Wappie reader found its clock outside the range that AWS KMS's answers allow, while its clock helper reported the clock as good: its two time sources disagree. The reader stops vouching for its clock until they agree again. The numbers are the KMS range and the helper's reading.",
		keys: []string{"kms_skew_lo_ms", "kms_skew_hi_ms", "nsm_skew_ms", "clock_unc_ms"},
	},
	ReaderAlertClockUnknown: {
		text: "The attested Wappie reader has not vouched for its clock for minutes_unknown minutes, and refuses the work that needs it until it does. answering is 1 when it still answers its health check and 0 when it has not answered for minutes_unanswered minutes. The parent's watchdog has stopped restarting it (a second fault within 24 hours) or is not running. Look at the reader's log on the parent.",
		keys: []string{"minutes_unknown", "minutes_unanswered", "clock_unc_ms", "nsm_skew_ms", "answering"},
	},
	ReaderAlertWatchdogRestart: {
		text: "The attested Wappie reader came back from a restart with the same image after it could not vouch for its clock, most likely restarted by the parent's watchdog. A console renewal round follows: content connections must be renewed in the console. If the clock fails again within 24 hours, the watchdog stops restarting the reader, and the cause is then mailed at most once a day.",
		keys: []string{"minutes_bad_before", "minutes_unanswered", "clock_ok_now", "clock_unc_ms"},
	},
}

// readerAlertTestBody is the fault word whose body the test alert carries,
// so that the test shows a real alert's body as it is delivered.
const readerAlertTestBody = ReaderAlertClockUnknown

// readerAlertTestLine is the test alert's first line.
const readerAlertTestLine = "test: 1"

// readerAlertFooter ends every reader clock alert.
const readerAlertFooter = "Times are UTC. This mail names no reader, boot or workspace, and carries no text from the reader."

// ReaderClockAlert sends the alert for one of the four fault words to one
// address. A key that is not on the word's list, or given twice, is refused,
// and so is ReaderAlertTest: only ReaderClockAlertTest sends that.
func (s Sender) ReaderClockAlert(ctx context.Context, to, word string, nums []ReaderAlertNum) error {
	if word == ReaderAlertTest {
		return errors.New("mailer: the test word is only for the test alert")
	}
	model, err := readerAlertEmail(word, nums, time.Now())
	if err != nil {
		return err
	}
	return s.send(ctx, to, model)
}

// ReaderClockAlertTest sends the test alert to one address: the subject word
// ReaderAlertTest over a real alert's body (readerAlertTestBody's paragraph
// and its keys, each 0), with test: 1 as its first line.
func (s Sender) ReaderClockAlertTest(ctx context.Context, to string) error {
	model, err := readerAlertTestEmail(time.Now())
	if err != nil {
		return err
	}
	return s.send(ctx, to, model)
}

// readerAlert is one reader clock alert, ready to render.
type readerAlert struct {
	Word, Text, Footer, Time string
	Lines                    []string
	test                     bool
}

func (m readerAlert) subject() string { return "Wappie reader alert: " + m.Word }

var readerAlertHTML = template.Must(template.New("reader-alert").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Wappie reader alert: {{.Word}}</title></head>
<body style="font-family:sans-serif;color:#111">
{{if .Test}}<pre style="font-size:14px">{{.TestLine}}</pre>
{{end}}<p>{{.Text}}</p>
<pre style="font-size:14px">{{range .Body}}{{.}}
{{end}}time: {{.Time}}</pre>
<p style="color:#555;font-size:12px">{{.Footer}}</p>
</body></html>
`))

func (m readerAlert) render() (string, string, error) {
	var plain strings.Builder
	if m.test {
		// The test's line goes first, before the paragraph.
		plain.WriteString(readerAlertTestLine + "\n\n")
	}
	plain.WriteString(m.Text + "\n\n")
	for _, l := range m.Lines {
		plain.WriteString(l + "\n")
	}
	plain.WriteString("time: " + m.Time + "\n\n" + m.Footer + "\n")
	var html bytes.Buffer
	err := readerAlertHTML.Execute(&html, struct {
		Word, Text, Footer, Time, TestLine string
		Body                               []string
		Test                               bool
	}{m.Word, m.Text, m.Footer, m.Time, readerAlertTestLine, m.Lines, m.test})
	if err != nil {
		return "", "", err
	}
	return plain.String(), html.String(), nil
}

// readerAlertEmail builds the alert for a fault word with nums at at. Every
// key must be on the word's list, once; the lines follow the list's order,
// whatever the order given, and a key not given is left out. The test word
// is not one: readerAlertTestEmail builds that.
func readerAlertEmail(word string, nums []ReaderAlertNum, at time.Time) (readerAlert, error) {
	w, ok := readerAlertWords[word]
	if !ok {
		return readerAlert{}, errors.New("mailer: not a reader alert word")
	}
	values := map[string]int64{}
	for _, n := range nums {
		if !slices.Contains(w.keys, n.Key) {
			return readerAlert{}, errors.New("mailer: not a key of this reader alert")
		}
		if _, dup := values[n.Key]; dup {
			return readerAlert{}, errors.New("mailer: a reader alert key given twice")
		}
		values[n.Key] = n.Value
	}
	m := readerAlert{Word: word, Text: w.text, Footer: readerAlertFooter, Time: at.UTC().Format(time.RFC3339)}
	for _, k := range w.keys {
		if v, ok := values[k]; ok {
			m.Lines = append(m.Lines, k+": "+strconv.FormatInt(v, 10))
		}
	}
	return m, nil
}

// readerAlertTestEmail builds the test alert at at: readerAlertTestBody's
// alert with every key at 0, under the subject word ReaderAlertTest, with
// readerAlertTestLine first.
func readerAlertTestEmail(at time.Time) (readerAlert, error) {
	keys := readerAlertWords[readerAlertTestBody].keys
	nums := make([]ReaderAlertNum, 0, len(keys))
	for _, k := range keys {
		nums = append(nums, ReaderAlertNum{Key: k})
	}
	m, err := readerAlertEmail(readerAlertTestBody, nums, at)
	if err != nil {
		return readerAlert{}, err
	}
	m.Word, m.test = ReaderAlertTest, true
	return m, nil
}
