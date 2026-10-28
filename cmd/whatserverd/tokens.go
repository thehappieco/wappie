package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// whatserverd tokens suspend|lift|list (step 7's plan, section 8; the
// design's 3.6): the operator's own stop of a token, by its selector, which
// stands over the token feed and every reset until the operator lifts it.
// It writes only to the database, so it works with the platform down: a
// leaked token is stopped at once in every process (token auth reads the
// stops in its own query, and the stops' trigger wakes every open socket).
// Its input is a selector, or the whole token, of which only the selector
// is kept: nothing more is ever stored or printed, and nothing it prints
// says whether Wappie holds a token of that selector.

// tokenStopRecord is one line of a stop record (-record, -replay): a file
// outside the database, which a restore of Wappie's database does not take
// back. The runbook keeps it in /opt/wappie/state/token-stops.jsonl.
type tokenStopRecord struct {
	Selector string    `json:"selector"`
	At       time.Time `json:"at"`
	Note     string    `json:"note,omitempty"`
	// Lift: the stop was lifted at At.
	Lift bool `json:"lift,omitempty"`
}

// tokensFlagOutput is where the flags' usage goes (a test reads it).
var tokensFlagOutput io.Writer = os.Stderr

// tokensCommand is whatserverd tokens.
func tokensCommand(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return usageError{arg: "tokens"}
	}
	var run func(context.Context, *store.Tokens) error
	switch args[0] {
	case "suspend", "lift":
		lift := args[0] == "lift"
		fs := flag.NewFlagSet("tokens "+args[0], flag.ContinueOnError)
		fs.SetOutput(tokensFlagOutput)
		note := new(string)
		if !lift {
			note = fs.String("note", "", "why, kept in Wappie's database and the record only")
		}
		record := fs.String("record", "", "append the stop to this file as well (the runbook's /opt/wappie/state/token-stops.jsonl)")
		replay := new(string)
		if !lift {
			replay = fs.String("replay", "", "apply every stop and lift of this record, in order, after a restore of Wappie's database")
		}
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		switch {
		case *replay != "" && (fs.NArg() != 0 || *record != "" || *note != ""):
			return errors.New("tokens suspend: -replay takes no selector, -record or -note")
		case *replay != "":
			run = func(ctx context.Context, t *store.Tokens) error { return replayTokenStops(ctx, t, *replay, out) }
		case fs.NArg() != 1:
			return fmt.Errorf("tokens %s: give one token's selector (16 lowercase hex digits), the whole token, or - to read it from stdin", args[0])
		default:
			selector, err := tokenSelector(fs.Arg(0), stdin)
			if err != nil {
				return fmt.Errorf("tokens %s: %w", args[0], err)
			}
			run = func(ctx context.Context, t *store.Tokens) error {
				return changeTokenStop(ctx, t, tokenStopRecord{Selector: selector, At: time.Now().UTC(), Note: *note, Lift: lift}, *record, out)
			}
		}
	case "list":
		if len(args) != 1 {
			return usageError{arg: "tokens " + strings.Join(args, " ")}
		}
		run = func(ctx context.Context, t *store.Tokens) error { return listTokenStops(ctx, t, out) }
	default:
		return usageError{arg: "tokens " + strings.Join(args, " ")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	return run(ctx, store.NewTokens(a.pools.API))
}

// tokenSelector is the selector of the text given, a selector or a whole
// token ("-" reads it from stdin's first line, so it is never an argument a
// process listing shows). An error never repeats the text.
func tokenSelector(arg string, stdin io.Reader) (string, error) {
	if arg == "-" {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", errors.New("could not read the token from stdin")
		}
		arg = strings.TrimRight(line, "\r\n")
	}
	if kc.ValidSelector(arg) {
		return arg, nil
	}
	if t, err := kc.ParseToken(arg); err == nil {
		return t.Selector, nil
	}
	return "", errors.New("that is neither a token's selector (16 lowercase hex digits) nor a whole token")
}

// osUser names who ran the command, as the stop records it.
func osUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

// changeTokenStop records the stop or its lift, then appends it to the
// record when one is named: a stop the database holds but the record does
// not is said, since a restore would lose it.
func changeTokenStop(ctx context.Context, t *store.Tokens, r tokenStopRecord, record string, out io.Writer) error {
	w := &lines{w: out}
	if r.Lift {
		lifted, err := t.LiftToken(ctx, r.Selector, r.At)
		if err != nil {
			return err
		}
		if lifted {
			w.f("tokens lift: selector %s: the operator's stop is lifted", r.Selector)
		} else {
			w.f("tokens lift: selector %s: no operator's stop was open; nothing changed", r.Selector)
		}
	} else {
		if err := t.StopToken(ctx, r.Selector, osUser(), r.Note, r.At); err != nil {
			return err
		}
		w.f("tokens suspend: selector %s is stopped here, whether or not Wappie holds its token yet", r.Selector)
	}
	if w.err != nil || record == "" {
		return w.err
	}
	if err := appendTokenStop(record, r); err != nil {
		return fmt.Errorf("tokens: the stop is in the database but not in the record %s (a restore would lose it): %w", record, err)
	}
	w.f("recorded in %s", record)
	return w.err
}

// appendTokenStop appends one line to the record, made 0600 if new.
func appendTokenStop(path string, r tokenStopRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: the operator names the record
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close() //nolint:errcheck // the write's error is the one to say
		return err
	}
	return f.Close()
}

// replayTokenStops applies a record's lines in order: each stop at its own
// time, each lift likewise, so the stops stand as they stood before the
// restore; a line older than what the database holds of its selector's stop
// (a stop or a lift made since without the record) is left, so a replay
// never rewinds a later stop, nor lifts one. A line that is not a record is
// refused before anything changes.
func replayTokenStops(ctx context.Context, t *store.Tokens, path string, out io.Writer) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the record
	if err != nil {
		return err
	}
	var records []tokenStopRecord
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r tokenStopRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil || !kc.ValidSelector(r.Selector) || r.At.IsZero() {
			return fmt.Errorf("tokens suspend -replay: line %d of %s is not a stop's record; nothing changed", i+1, path)
		}
		records = append(records, r)
	}
	by := osUser()
	stops, lifts, left := 0, 0, 0
	for _, r := range records {
		var applied bool
		if r.Lift {
			applied, err = t.ReplayTokenLift(ctx, r.Selector, r.At)
		} else {
			applied, err = t.ReplayTokenStop(ctx, r.Selector, by, r.Note, r.At)
		}
		switch {
		case err != nil:
			return err
		case !applied:
			left++
		case r.Lift:
			lifts++
		default:
			stops++
		}
	}
	w := &lines{w: out}
	w.f("tokens suspend -replay: %d stops and %d lifts applied from %s; %d lines left, older than what the database holds or with nothing to lift",
		stops, lifts, path, left)
	return w.err
}

// listTokenStops prints every stop, open ones first: its selector, cause,
// times and who; never the token a selector maps to.
func listTokenStops(ctx context.Context, t *store.Tokens, out io.Writer) error {
	stops, err := t.TokenStops(ctx)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	for _, s := range stops {
		line := fmt.Sprintf("%s %s stopped %s by %s", s.Selector, s.Cause, stamp(s.StoppedAt), s.StoppedBy)
		if s.LiftedAt != nil {
			line += " lifted " + stamp(*s.LiftedAt)
		} else {
			line += " open"
		}
		if s.Note != "" {
			line += fmt.Sprintf(" note=%q", s.Note)
		}
		w.f("%s", line)
	}
	w.f("%d stops", len(stops))
	return w.err
}
