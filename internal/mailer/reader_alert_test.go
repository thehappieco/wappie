package mailer

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// readerAlertParts reads a built alert back: its subject and its plain and
// HTML bodies.
func readerAlertParts(t *testing.T, model readerAlert) (string, string, string) {
	t.Helper()
	data, _, _, err := message("Wappie <alerts@example.test>", "ops@example.test", model)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	related := multipart.NewReader(msg.Body, params["boundary"])
	alt, err := related.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	_, params, err = mime.ParseMediaType(alt.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(alt, params["boundary"])
	var bodies []string
	for range 2 {
		p, err := parts.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, strings.ReplaceAll(string(b), "\r\n", "\n"))
	}
	return subject, bodies[0], bodies[1]
}

// Every word's alert has its fixed subject, its paragraph, its numbers under
// its keys in the list's order whatever the order given, the time in UTC and
// the footer, and nothing else: every plain line is one of those.
func TestReaderAlertEmail(t *testing.T) {
	at := time.Date(2026, 11, 19, 12, 34, 56, 0, time.FixedZone("x", -3*3600))
	for word, w := range readerAlertWords {
		t.Run(word, func(t *testing.T) {
			var nums []ReaderAlertNum
			for i := len(w.keys) - 1; i >= 0; i-- {
				nums = append(nums, ReaderAlertNum{Key: w.keys[i], Value: int64(i) - 2})
			}
			model, err := readerAlertEmail(word, nums, at)
			if err != nil {
				t.Fatal(err)
			}
			subject, plain, html := readerAlertParts(t, model)
			if subject != "Wappie reader alert: "+word {
				t.Fatalf("subject = %q", subject)
			}
			lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")
			var numbers []string
			for _, l := range lines {
				switch {
				case l == "" || l == w.text || l == readerAlertFooter || l == "time: 2026-11-19T15:34:56Z":
				case regexp.MustCompile(`^[a-z_]+: -?[0-9]+$`).MatchString(l):
					numbers = append(numbers, l)
				default:
					t.Fatalf("a line the template does not have: %q", l)
				}
			}
			var want []string
			for i, k := range w.keys {
				want = append(want, k+": "+itoa(int64(i)-2))
			}
			if strings.Join(numbers, "|") != strings.Join(want, "|") {
				t.Fatalf("numbers = %v, want %v", numbers, want)
			}
			for _, s := range append(want, "2026-11-19T15:34:56Z", readerAlertFooter) {
				if !strings.Contains(html, s) {
					t.Fatalf("the HTML lacks %q", s)
				}
			}
			if strings.Contains(html, "<a ") || strings.Contains(html, "http") {
				t.Fatal("a link in a reader alert")
			}
		})
	}
}

// The test alert is the real clock_unknown alert under the subject word
// test: test: 1 as its first line, then clock_unknown's paragraph and every
// one of its keys (at 0) in their order, the time and the footer, in both
// bodies, and nothing else.
func TestReaderAlertTestEmail(t *testing.T) {
	at := time.Date(2026, 11, 19, 12, 34, 56, 0, time.UTC)
	model, err := readerAlertTestEmail(at)
	if err != nil {
		t.Fatal(err)
	}
	subject, plain, html := readerAlertParts(t, model)
	if subject != "Wappie reader alert: test" {
		t.Fatalf("subject = %q", subject)
	}
	real := readerAlertWords[ReaderAlertClockUnknown]
	want := []string{"test: 1", "", real.text, ""}
	for _, k := range real.keys {
		want = append(want, k+": 0")
	}
	want = append(want, "time: 2026-11-19T12:34:56Z", "", readerAlertFooter)
	if got := strings.Split(strings.TrimRight(plain, "\n"), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("plain body:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The HTML has the same, test: 1 before the paragraph.
	last := -1
	for _, s := range []string{"test: 1", template.HTMLEscapeString(real.text)} {
		i := strings.Index(html, s)
		if i < 0 || i < last {
			t.Fatalf("the HTML lacks %q or has it out of order", s)
		}
		last = i
	}
	for _, s := range append(want[4:], readerAlertFooter) {
		if !strings.Contains(html, s) {
			t.Fatalf("the HTML lacks %q", s)
		}
	}
	if strings.Count(plain, "test: 1") != 1 || strings.Count(html, "test: 1") != 1 {
		t.Fatal("test: 1 is not there exactly once")
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// A word not of the four faults, a key not on the word's list (whatever it
// holds), a key given twice and the test word, through the alert builder or
// the fault path, are all refused.
func TestReaderAlertRefusesWhatIsNotOnTheList(t *testing.T) {
	at := time.Now()
	for _, tc := range []struct {
		name string
		word string
		nums []ReaderAlertNum
	}{
		{"unknown word", "other", nil},
		{"a code the reader sent", "helper_stale", nil},
		{"empty word", "", nil},
		{"key of another word", ReaderAlertCapExceeded, []ReaderAlertNum{{Key: "minutes_unknown", Value: 1}}},
		{"key with text", ReaderAlertClockUnknown, []ReaderAlertNum{{Key: "minutes_unknown\r\nBcc: x@example.test", Value: 1}}},
		{"key twice", ReaderAlertClockUnknown, []ReaderAlertNum{{Key: "answering", Value: 1}, {Key: "answering", Value: 0}}},
		{"the test word", ReaderAlertTest, nil},
		{"the test word with its line", ReaderAlertTest, []ReaderAlertNum{{Key: "test", Value: 1}}},
	} {
		if _, err := readerAlertEmail(tc.word, tc.nums, at); err == nil {
			t.Errorf("%s: built", tc.name)
		}
	}
	// The fault path refuses the test word before it dials anything.
	if err := (Sender{}).ReaderClockAlert(context.Background(), "ops@example.test", ReaderAlertTest, []ReaderAlertNum{{Key: "test", Value: 1}}); err == nil ||
		!strings.Contains(err.Error(), "only for the test alert") {
		t.Fatalf("test word through the fault path: %v", err)
	}
}

// A key left out is left out of the body, and nothing stands in for it.
func TestReaderAlertLeavesOutWhatIsUnknown(t *testing.T) {
	model, err := readerAlertEmail(ReaderAlertClockUnknown, []ReaderAlertNum{{Key: "answering", Value: 0}, {Key: "minutes_unknown", Value: 25}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(model.Lines, "|") != "minutes_unknown: 25|answering: 0" {
		t.Fatalf("lines = %v", model.Lines)
	}
}
