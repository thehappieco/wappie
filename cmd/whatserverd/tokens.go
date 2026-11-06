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
	"os"
	"os/user"
	"path/filepath"
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

// tokenStopRecord is one line of the stop record (WS_TOKEN_STOP_RECORD;
// -replay): a file outside the database, which a restore of Wappie's
// database does not take back, so a replay brings back the stops made
// since its snapshot. A line is a stop or a lift the operator made: its
// selector, its time (the database's stopped_at or lifted_at, to the
// microsecond) and whether it was a lift, nothing more; the note, the
// account and Wappie's own apply_failed stops stay in the database. A
// line goes 365 days after its time, whatever became of its stop: at an
// append, or in the hourly pass (trimTokenStops).
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
		replay := new(string)
		if !lift {
			replay = fs.String("replay", "", "apply every stop and lift of this record, in order, after a restore of Wappie's database")
		}
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		switch {
		case *replay != "" && (fs.NArg() != 0 || *note != ""):
			return errors.New("tokens suspend: -replay takes no selector or -note")
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
				return changeTokenStop(ctx, store.NewTokens(a.pools.API), tokenStopRecord{Selector: selector, At: time.Now(), Lift: lift}, *note, a.cfg.TokenStopRecord, out)
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

// tokenStopLockWait bounds a command's wait for the stop record's lock,
// far below its minute: a holder stopped mid-write never holds up a stop,
// which is made in the database all the same. A test shortens it.
var tokenStopLockWait = 5 * time.Second

// changeTokenStop records the stop (with its note, in the database alone)
// or its lift, at r.At to the microsecond, the database's precision, or
// later (a stop's times only go forward, each change after the last:
// StopToken); then appends it to the stop record, record (the configured
// one), at the time the database holds, so the line's time is the stop's
// stopped_at or lifted_at exactly and a replay brings the stop back as it
// stood. It takes the record's lock first and holds it to the append, so
// the lines of two commands on one selector land in the order of their
// changes in the database, which is their times' order. A lock not taken
// in time leaves the stop made in the database, and the command says the
// record lacks it. A lift of a stop lifted already changes nothing and
// appends that lift again at its own time (so a lift whose append failed
// is recorded by running it again); one with no operator's stop to lift
// records nothing, since no lift happened. A stop the database holds but
// the record does not is said, since a restore would lose it.
func changeTokenStop(ctx context.Context, t *store.Tokens, r tokenStopRecord, note, record string, out io.Writer) error {
	r.At = r.At.UTC().Truncate(time.Microsecond)
	w := &lines{w: out}
	var held *os.File
	var lockErr error
	if record != "" {
		lockCtx, cancel := context.WithTimeout(ctx, tokenStopLockWait)
		held, lockErr = lockStopRecord(lockCtx, record, true)
		cancel()
		if lockErr == nil {
			defer held.Close() //nolint:errcheck // closing releases the lock; the rewrite synced what it wrote
		}
	}
	if r.Lift {
		at, lifted, err := t.LiftToken(ctx, r.Selector, r.At)
		if err != nil {
			return err
		}
		switch {
		case lifted:
			w.f("tokens lift: selector %s: the operator's stop is lifted", r.Selector)
		case !at.IsZero():
			w.f("tokens lift: selector %s: the operator's stop was lifted already; nothing changed", r.Selector)
		default:
			w.f("tokens lift: selector %s: no operator's stop to lift; nothing changed or recorded", r.Selector)
			return w.err
		}
		r.At = at.UTC()
	} else {
		at, err := t.StopToken(ctx, r.Selector, osUser(), note, r.At)
		if err != nil {
			return err
		}
		r.At = at.UTC()
		w.f("tokens suspend: selector %s is stopped here, whether or not Wappie holds its token yet", r.Selector)
	}
	if w.err != nil {
		return w.err
	}
	if record == "" {
		w.f("no stop record (WS_TOKEN_STOP_RECORD is empty), so a restore of Wappie's database would lose it")
		return w.err
	}
	err := lockErr
	if err == nil {
		err = appendHeldTokenStop(held, record, r, time.Now())
	}
	if err != nil {
		return fmt.Errorf("tokens: the stop is in the database but not in the record %s (a restore would lose it): %w", record, err)
	}
	w.f("recorded in %s", record)
	return w.err
}

// appendTokenStop adds r's line to the record, made 0600 if new, and drops
// the lines 365 days old by now, as the hourly trim does.
func appendTokenStop(ctx context.Context, path string, r tokenStopRecord, now time.Time) error {
	f, err := lockStopRecord(ctx, path, true)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // closing releases the lock; the rewrite synced what it wrote
	return appendHeldTokenStop(f, path, r, now)
}

// appendHeldTokenStop is appendTokenStop with the record's lock held, on
// f, the record at path.
func appendHeldTokenStop(f *os.File, path string, r tokenStopRecord, now time.Time) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = rewriteHeldTokenStops(f, path, line, now)
	return err
}

// trimTokenStops is the hourly pass's trim of the record (retainTokens).
// It drops the lines whose time is 365 days old by now, by the comparison
// a replay uses to leave one (store.TokenStopLapsed), so the two agree,
// and nothing else: decision 0056 keeps each line 365 days after it was
// written, and never less than the reach of the backups Wappie may restore
// (90 days), so a line stays to its 365 days whatever became of its stop.
// A line's time is when it was written, the stop's stopped_at or
// lifted_at, but for a lift run again, whose line carries the first
// lift's time and goes as soon as that line would: every snapshot in reach
// was taken after the first lift and holds it. It never makes a missing
// record, and reports how many lines it dropped and how many it kept as
// they are, being no stop's record.
//
// A line 365 days old goes even while its stop stands. Only a stop of a
// selector Wappie holds outlives 365 days, to the selector's until, its
// token's created_at + 365 days, which its expires_at never passes: a stop
// made once its token existed goes by then. One made before its token's
// created_at (a selector stopped ahead of its token) stands to that until
// with no line, which loses nothing a restore needs: every snapshot one
// can take is under 90 days old (decision 0027), so it holds the stop as
// it stood over 275 days after it was made, and anything since has a
// younger line.
func trimTokenStops(ctx context.Context, path string, now time.Time) (stopRecordRewrite, error) {
	f, err := lockStopRecord(ctx, path, false)
	if errors.Is(err, fs.ErrNotExist) {
		return stopRecordRewrite{}, nil
	}
	if err != nil {
		return stopRecordRewrite{}, err
	}
	defer f.Close() //nolint:errcheck // closing releases the lock; the rewrite synced what it wrote
	return rewriteHeldTokenStops(f, path, nil, now)
}

// stopRecordRewrite is what a rewrite of the stop record did: the lines
// it dropped, and those it kept as they are, being no stop's record.
type stopRecordRewrite struct{ dropped, unreadable int }

// rewriteHeldTokenStops replaces the record at path whole, or not at all,
// its exclusive lock held on f, the file opened. It keeps, in their order, a line
// that is no stop's record as it is (counted, unless blank: -replay
// refuses a record that holds one) and each stop's line under 365 days old
// by now, written again as its selector, time and lift alone (a line an
// older binary wrote with its note loses it); then adds add (a line,
// without its newline), if any. The new text goes to a temporary file in
// the record's directory, with its mode and owner, synced and renamed over
// it, the directory synced: two rewrites at once never lose a line. A
// temporary copy a rewrite killed before its rename left goes too. Without
// add, an unchanged record is not written.
func rewriteHeldTokenStops(f *os.File, path string, add []byte, now time.Time) (did stopRecordRewrite, err error) {
	old, err := io.ReadAll(f)
	if err != nil {
		return stopRecordRewrite{}, err
	}
	held, err := f.Stat()
	if err != nil {
		return stopRecordRewrite{}, err
	}
	var kept []byte
	if text := strings.TrimSuffix(string(old), "\n"); text != "" {
		for _, l := range strings.Split(text, "\n") {
			var rec tokenStopRecord
			switch {
			case json.Unmarshal([]byte(l), &rec) == nil && kc.ValidSelector(rec.Selector) && !rec.At.IsZero():
				if store.TokenStopLapsed(rec.At, now) {
					did.dropped++
					continue
				}
				line, err := json.Marshal(rec)
				if err != nil {
					return stopRecordRewrite{}, err
				}
				l = string(line)
			case strings.TrimSpace(l) != "":
				did.unreadable++
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
		return stopRecordRewrite{}, err
	}
	if add == nil && bytes.Equal(kept, old) {
		return did, nil
	}
	tmp, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return stopRecordRewrite{}, err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()           //nolint:errcheck // already failing; the temporary file goes below
			_ = os.Remove(tmp.Name()) //nolint:errcheck,gosec // best effort: a leftover temporary is inert; G703: our own temporary beside the record the operator names
		}
	}()
	if _, err = tmp.Write(kept); err != nil {
		return stopRecordRewrite{}, err
	}
	if err = tmp.Chmod(held.Mode().Perm()); err != nil {
		return stopRecordRewrite{}, err
	}
	if want, ok := held.Sys().(*syscall.Stat_t); ok {
		if fi, serr := tmp.Stat(); serr == nil {
			if got, ok := fi.Sys().(*syscall.Stat_t); ok && (got.Uid != want.Uid || got.Gid != want.Gid) {
				if err = tmp.Chown(int(want.Uid), int(want.Gid)); err != nil {
					return stopRecordRewrite{}, err
				}
			}
		}
	}
	if err = tmp.Sync(); err != nil {
		return stopRecordRewrite{}, err
	}
	if err = tmp.Close(); err != nil {
		return stopRecordRewrite{}, err
	}
	if err = os.Rename(tmp.Name(), path); err != nil { //nolint:gosec // G703: the operator names the record
		return stopRecordRewrite{}, err
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the record's own directory
	if err != nil {
		return stopRecordRewrite{}, err
	}
	if err = d.Sync(); err != nil {
		_ = d.Close() //nolint:errcheck // the sync's error is the one to say
		return stopRecordRewrite{}, err
	}
	return did, d.Close()
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
// stops stand as they stood before the restore. It leaves a line at or
// before the mark of what retention let go (store.TokenStopMarked): the
// restored database holds that stop or lift already, or retention let its
// stop go before the snapshot, so a replay never brings that stop back. It
// leaves a line 365 days old (store.TokenStopLapsed), which the hourly trim
// drops. It leaves a line no later than what the database holds of its
// selector's stop (the same stop, or a stop or a lift made since without
// the record), so a replay never rewinds a later stop, nor lifts one, nor
// rewrites a stop it holds with its note. A line that is not a record is
// refused before anything changes. A restore runs it before the server
// starts, with the token part off (docs/deployment.md), so the stops stand
// again before a token is accepted.
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
	through, err := t.TokenStopsLetGo(ctx)
	if err != nil {
		return err
	}
	by, now := osUser(), time.Now()
	stops, lifts, left, marked, lapsed := 0, 0, 0, 0, 0
	for _, r := range records {
		switch {
		case store.TokenStopLapsed(r.At, now):
			lapsed++
			continue
		case store.TokenStopMarked(r.At, through):
			marked++
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
	w.f("tokens suspend -replay: %d stops and %d lifts applied from %s; %d lines left, no later than what the database holds or with nothing to lift; %d lines left, no later than the last stop retention let go; %d lines over 365 days old left, their stops let go",
		stops, lifts, path, left, marked, lapsed)
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
