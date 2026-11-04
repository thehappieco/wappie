package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
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
// back. The runbook keeps it in /opt/wappie/state/token-stops.jsonl. Each
// append drops the lines over 365 days old (the longest retention keeps a
// stop), and a replay leaves them; nothing trims the file between appends.
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
	if err := appendTokenStop(record, r, time.Now()); err != nil {
		return fmt.Errorf("tokens: the stop is in the database but not in the record %s (a restore would lose it): %w", record, err)
	}
	w.f("recorded in %s", record)
	return w.err
}

// appendTokenStop adds one line to the record, made 0600 if new, and drops
// the lines of stops retention has let go by now (store.TokenStopLapsed:
// 365 days old), keeping the others in their order and a line that is no
// stop's record as it is. The file is replaced whole or not at all (a
// temporary file in its directory, with its mode and owner, synced, renamed
// over it, the directory synced), under an exclusive lock of the file, so
// two appends at once never lose a line; a temporary copy that an append
// killed before its rename left goes too.
func appendTokenStop(path string, r tokenStopRecord, now time.Time) (err error) {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := lockStopRecord(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // closing releases the lock; the file was only read
	old, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	held, err := f.Stat()
	if err != nil {
		return err
	}
	var kept []byte
	if text := strings.TrimSuffix(string(old), "\n"); text != "" {
		for _, l := range strings.Split(text, "\n") {
			var rec tokenStopRecord
			if json.Unmarshal([]byte(l), &rec) == nil && kc.ValidSelector(rec.Selector) && !rec.At.IsZero() && store.TokenStopLapsed(rec.At, now) {
				continue
			}
			kept = append(append(kept, l...), '\n')
		}
	}
	kept = append(append(kept, line...), '\n')
	dir, prefix := filepath.Dir(path), "."+filepath.Base(path)+".tmp-"
	// A temporary copy an append left when it was killed before its rename
	// (no defer runs on a signal): every append makes its own under the
	// lock of the file it then replaces, which is the one held here, so no
	// other is in flight.
	if err := removeStaleStopTemps(dir, prefix); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()           //nolint:errcheck // already failing; the temporary file goes below
			_ = os.Remove(tmp.Name()) //nolint:errcheck,gosec // best effort: a leftover temporary is inert; G703: our own temporary beside the record the operator names
		}
	}()
	if _, err = tmp.Write(kept); err != nil {
		return err
	}
	if err = tmp.Chmod(held.Mode().Perm()); err != nil {
		return err
	}
	if want, ok := held.Sys().(*syscall.Stat_t); ok {
		if fi, serr := tmp.Stat(); serr == nil {
			if got, ok := fi.Sys().(*syscall.Stat_t); ok && (got.Uid != want.Uid || got.Gid != want.Gid) {
				if err = tmp.Chown(int(want.Uid), int(want.Gid)); err != nil {
					return err
				}
			}
		}
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil { //nolint:gosec // G703: the operator names the record
		return err
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the record's own directory
	if err != nil {
		return err
	}
	if err = d.Sync(); err != nil {
		_ = d.Close() //nolint:errcheck // the sync's error is the one to say
		return err
	}
	return d.Close()
}

// removeStaleStopTemps removes the record's temporary copies in dir (named
// prefix and more), which hold its lines past the 365 days it keeps them.
func removeStaleStopTemps(dir, prefix string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) { //nolint:gosec // G703: our own temporaries, in the directory of the record the operator names
			return err
		}
	}
	return nil
}

// lockStopRecord opens the record, made 0600 if new, under an exclusive
// flock, waiting for it. An append replaces the file, so one that waited
// for the lock of a file replaced meanwhile locks the new one instead.
func lockStopRecord(path string) (*os.File, error) {
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the operator names the record
		if err != nil {
			return nil, err
		}
		for {
			err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
			if !errors.Is(err, syscall.EINTR) {
				break
			}
		}
		if err != nil {
			_ = f.Close() //nolint:errcheck // the lock was not taken
			return nil, err
		}
		held, herr := f.Stat()
		named, nerr := os.Stat(path) //nolint:gosec // G703: the operator names the record
		if herr == nil && nerr == nil && os.SameFile(held, named) {
			return f, nil
		}
		_ = f.Close() //nolint:errcheck // a file replaced meanwhile; its lock goes with it
		switch {
		case herr != nil:
			return nil, herr
		case nerr != nil && !errors.Is(nerr, fs.ErrNotExist):
			return nil, nerr
		}
	}
}

// replayTokenStops applies a record's lines in order: each stop at its own
// time, each lift likewise, so the stops stand as they stood before the
// restore; a line older than what the database holds of its selector's stop
// (a stop or a lift made since without the record) is left, so a replay
// never rewinds a later stop, nor lifts one, and so is a line 365 days old
// (store.TokenStopLapsed), whose stop retention has let go, so a replay
// never brings one back. A line that is not a record is refused before
// anything changes.
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
	by, now := osUser(), time.Now()
	stops, lifts, left, lapsed := 0, 0, 0, 0
	for _, r := range records {
		if store.TokenStopLapsed(r.At, now) {
			lapsed++
			continue
		}
		var applied bool
		if r.Lift {
			applied, err = t.ReplayTokenLift(ctx, r.Selector, r.At)
		} else {
			applied, err = t.ReplayTokenStop(ctx, r.Selector, by, r.Note, r.At, now)
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
	w.f("tokens suspend -replay: %d stops and %d lifts applied from %s; %d lines left, older than what the database holds or with nothing to lift; %d lines over 365 days old left, their stops let go",
		stops, lifts, path, left, lapsed)
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
