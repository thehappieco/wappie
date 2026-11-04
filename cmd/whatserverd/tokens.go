package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/config"
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

// tokenStopRecord is one line of the stop record (WS_TOKEN_STOP_RECORD,
// or -record; -replay): a file outside the database, which a restore of
// Wappie's database does not take back, so a replay brings back the stops
// made since its snapshot. A line is a stop or a lift the operator made:
// its selector, its time (the database's stopped_at or lifted_at, to the
// microsecond) and whether it was a lift, nothing more; the note, the
// account and Wappie's own apply_failed stops stay in the database. A
// line goes 365 days after its time at the latest (the longest retention
// keeps a stop of a selector Wappie never held), dropped at each append and
// each hourly pass, and earlier, in the hourly pass whose retention deleted
// its stop (trimTokenStops).
type tokenStopRecord struct {
	Selector string    `json:"selector"`
	At       time.Time `json:"at"`
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
	var run func(context.Context, *app) error
	switch args[0] {
	case "suspend", "lift":
		lift := args[0] == "lift"
		fs := flag.NewFlagSet("tokens "+args[0], flag.ContinueOnError)
		fs.SetOutput(tokensFlagOutput)
		note := new(string)
		if !lift {
			note = fs.String("note", "", "why, kept in Wappie's database only")
		}
		record := fs.String("record", "", "append to this file instead of the stop record WS_TOKEN_STOP_RECORD names")
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
			run = func(ctx context.Context, a *app) error {
				return replayTokenStops(ctx, store.NewTokens(a.pools.API), *replay, out)
			}
		case fs.NArg() != 1:
			return fmt.Errorf("tokens %s: give one token's selector (16 lowercase hex digits), the whole token, or - to read it from stdin", args[0])
		default:
			selector, err := tokenSelector(fs.Arg(0), stdin)
			if err != nil {
				return fmt.Errorf("tokens %s: %w", args[0], err)
			}
			run = func(ctx context.Context, a *app) error {
				path := *record
				if path == "" {
					path = a.cfg.TokenStopRecord
				}
				return changeTokenStop(ctx, store.NewTokens(a.pools.API), tokenStopRecord{Selector: selector, At: time.Now(), Lift: lift}, *note, path, out)
			}
		}
	case "list":
		if len(args) != 1 {
			return usageError{arg: "tokens " + strings.Join(args, " ")}
		}
		run = func(ctx context.Context, a *app) error { return listTokenStops(ctx, store.NewTokens(a.pools.API), out) }
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
	return run(ctx, a)
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

// changeTokenStop records the stop (with its note, in the database alone)
// or its lift, at r.At to the microsecond, the database's precision, so the
// line's time is the stop's stopped_at or lifted_at exactly; then appends it
// to the stop record, record. A stop the database holds but the record does
// not is said, since a restore would lose it.
func changeTokenStop(ctx context.Context, t *store.Tokens, r tokenStopRecord, note, record string, out io.Writer) error {
	r.At = r.At.UTC().Truncate(time.Microsecond)
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
		if err := t.StopToken(ctx, r.Selector, osUser(), note, r.At); err != nil {
			return err
		}
		w.f("tokens suspend: selector %s is stopped here, whether or not Wappie holds its token yet", r.Selector)
	}
	if w.err != nil {
		return w.err
	}
	if record == "" {
		w.f("no stop record (WS_TOKEN_STOP_RECORD is empty), so a restore of Wappie's database would lose it")
		return w.err
	}
	if err := appendTokenStop(ctx, record, r, time.Now()); err != nil {
		return fmt.Errorf("tokens: the stop is in the database but not in the record %s (a restore would lose it): %w", record, err)
	}
	w.f("recorded in %s", record)
	return w.err
}

// appendTokenStop adds r's line to the record, made 0600 if new, and drops
// the lines over 365 days old by now (store.TokenStopLapsed), whose stops
// retention has let go.
func appendTokenStop(ctx context.Context, path string, r tokenStopRecord, now time.Time) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = rewriteTokenStops(ctx, path, line, func() (func(tokenStopRecord) bool, error) {
		return func(rec tokenStopRecord) bool { return !store.TokenStopLapsed(rec.At, now) }, nil
	})
	return err
}

// trimTokenStops is the hourly pass's trim of the record, right after
// retention (retainTokens). It drops the lines over 365 days old by now,
// and the lines of each selector whose operator's stop that retention
// deleted (letGo, with the stop's last change: its lift, else its stop) up
// to that change. It never drops a line of a stop the database holds: a
// command writes the database before it locks the record to add its line,
// so made, read under the lock, gives every stop of those selectors made
// again since the delete, and the lines from each one's time on stay,
// whatever the clocks. A stop retention deletes in the milliseconds before
// its command adds its line leaves that line to its 365 days, as a crash
// between retention's commit and the trim leaves the lines it would have
// dropped. It never makes a missing record, and reports how many lines it
// dropped.
//
// A line over 365 days old goes even while its stop stands. Only a stop of
// a selector Wappie holds outlives 365 days, to the selector's until, its
// token's created_at + 365 days, which its expires_at never passes: a stop
// made once its token existed goes by then, in the same pass (the next one
// if the database's clock lags Wappie's). One made before its token's
// created_at (a selector stopped ahead of its token) stands to that until
// with no line, which loses nothing a restore needs: every snapshot one
// can take is under 90 days old (decision 0027), so it holds the stop as
// it stood over 275 days after it was made, and anything since has a
// younger line.
func trimTokenStops(ctx context.Context, path string, now time.Time, letGo map[string]time.Time,
	made func(selectors []string) (map[string]time.Time, error),
) (int, error) {
	return rewriteTokenStops(ctx, path, nil, func() (func(tokenStopRecord) bool, error) {
		var again map[string]time.Time
		if len(letGo) > 0 {
			var err error
			if again, err = made(slices.Sorted(maps.Keys(letGo))); err != nil {
				return nil, err
			}
		}
		return func(rec tokenStopRecord) bool {
			if store.TokenStopLapsed(rec.At, now) {
				return false
			}
			through, gone := letGo[rec.Selector]
			if !gone || rec.At.After(through) {
				return true
			}
			since, stopped := again[rec.Selector]
			return stopped && !rec.At.Before(since)
		}, nil
	})
}

// rewriteTokenStops replaces the record whole, or not at all, under an
// exclusive lock of the file. It keeps, in their order, a line that is no
// stop's record as it is and each stop's line that keeper's filter, made
// under the lock, keeps, written again as its selector, time and lift
// alone (a line an older binary wrote with its note loses it); then adds
// add (a line, without its newline), if any. The new text goes to a
// temporary file in the record's directory, with its mode and owner,
// synced and renamed over it, the directory synced: two rewrites at once
// never lose a line. A temporary copy a rewrite killed before its rename
// left goes too. With add, a missing record is made 0600; without, a
// missing record stays missing, and an unchanged one is not written. It
// reports how many lines it dropped.
func rewriteTokenStops(ctx context.Context, path string, add []byte, keeper func() (func(tokenStopRecord) bool, error)) (dropped int, err error) {
	f, err := lockStopRecord(ctx, path, add != nil)
	if add == nil && errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // closing releases the lock; the file was only read
	keep, err := keeper()
	if err != nil {
		return 0, err
	}
	old, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	held, err := f.Stat()
	if err != nil {
		return 0, err
	}
	var kept []byte
	if text := strings.TrimSuffix(string(old), "\n"); text != "" {
		for _, l := range strings.Split(text, "\n") {
			var rec tokenStopRecord
			if json.Unmarshal([]byte(l), &rec) == nil && kc.ValidSelector(rec.Selector) && !rec.At.IsZero() {
				if !keep(rec) {
					dropped++
					continue
				}
				line, err := json.Marshal(rec)
				if err != nil {
					return 0, err
				}
				l = string(line)
			}
			kept = append(append(kept, l...), '\n')
		}
	}
	if add != nil {
		kept = append(append(kept, add...), '\n')
	}
	dir, prefix := filepath.Dir(path), "."+filepath.Base(path)+".tmp-"
	// A temporary copy a rewrite left when it was killed before its rename
	// (no defer runs on a signal): every rewrite makes its own under the
	// lock of the file it then replaces, which is the one held here, so no
	// other is in flight.
	if err := removeStaleStopTemps(dir, prefix); err != nil {
		return 0, err
	}
	if add == nil && bytes.Equal(kept, old) {
		return 0, nil
	}
	tmp, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()           //nolint:errcheck // already failing; the temporary file goes below
			_ = os.Remove(tmp.Name()) //nolint:errcheck,gosec // best effort: a leftover temporary is inert; G703: our own temporary beside the record the operator names
		}
	}()
	if _, err = tmp.Write(kept); err != nil {
		return 0, err
	}
	if err = tmp.Chmod(held.Mode().Perm()); err != nil {
		return 0, err
	}
	if want, ok := held.Sys().(*syscall.Stat_t); ok {
		if fi, serr := tmp.Stat(); serr == nil {
			if got, ok := fi.Sys().(*syscall.Stat_t); ok && (got.Uid != want.Uid || got.Gid != want.Gid) {
				if err = tmp.Chown(int(want.Uid), int(want.Gid)); err != nil {
					return 0, err
				}
			}
		}
	}
	if err = tmp.Sync(); err != nil {
		return 0, err
	}
	if err = tmp.Close(); err != nil {
		return 0, err
	}
	if err = os.Rename(tmp.Name(), path); err != nil { //nolint:gosec // G703: the operator names the record
		return 0, err
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the record's own directory
	if err != nil {
		return 0, err
	}
	if err = d.Sync(); err != nil {
		_ = d.Close() //nolint:errcheck // the sync's error is the one to say
		return 0, err
	}
	return dropped, d.Close()
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

// lockStopRecord opens the record (made 0600 if new, with create) under an
// exclusive flock, waiting for it until ctx ends: the hourly pass never
// hangs on a command stopped while it holds the lock. A rewrite replaces
// the file, so one that waited for the lock of a file replaced meanwhile
// locks the new one instead.
func lockStopRecord(ctx context.Context, path string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	for {
		f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: the operator names the record
		if err != nil {
			return nil, err
		}
		if err := flockWait(ctx, f); err != nil {
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

// flockWait takes f's exclusive flock, trying again every 20 ms until ctx
// ends; a rewrite holds it for milliseconds.
func flockWait(ctx context.Context, f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the record is locked: %w", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// checkTokenStopRecord says once, at start and in prod, whether the server
// can write its stop record, as checkDeletionLedger says of the ledger:
// it creates the file with mode 0600 when it is missing, and a temporary
// file beside it, as a rewrite does, which it removes. It never stops the
// start: a stop is made in the database whether or not its line can be
// written (the command says when it cannot), and only a restore reads it.
func checkTokenStopRecord(cfg config.Config, log *slog.Logger) {
	if !cfg.Env.IsProd() {
		return
	}
	path := cfg.TokenStopRecord
	if path == "" {
		log.Error("token stop record not writable", "path", "", "error", "WS_TOKEN_STOP_RECORD is empty")
		return
	}
	if err := stopRecordWritable(path); err != nil {
		log.Error("token stop record not writable", "path", path, "error", err)
		return
	}
	log.Info("token stop record writable", "path", path)
}

// stopRecordWritable opens the record for writing, made 0600 when missing,
// and makes and removes a temporary file in its directory.
func stopRecordWritable(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the configured record
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name()) //nolint:errcheck,gosec // best effort: the next rewrite removes it
		return err
	}
	return os.Remove(tmp.Name()) //nolint:gosec // G703: our own temporary beside the configured record
}

// replayTokenStops applies a record's lines in order: each stop at its own
// time, with no note (the record keeps none), each lift likewise, so the
// stops stand as they stood before the restore; a line older than what the
// database holds of its selector's stop (a stop or a lift made since
// without the record) is left, so a replay never rewinds a later stop, nor
// lifts one, and so is a line 365 days old (store.TokenStopLapsed), whose
// stop retention has let go, so a replay never brings one back. A line
// that is not a record is refused before anything changes. It runs before
// the server starts, so no hourly trim runs beside it: one that did could
// drop the line of a stop retention had just deleted and the replay
// brought back.
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
			applied, err = t.ReplayTokenStop(ctx, r.Selector, by, "", r.At, now)
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
