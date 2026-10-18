package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// whatserverd contract status, diff and mode (the plan's 4.4, 4.8 and
// 4.13): the operator's view of the contract, as the service user runs it
// (systemd-run with runtime.env as its environment and the release as its
// working directory). None of them calls the platform: status reads the
// database, what the server published of its secrets and the sealed
// files; diff recomputes observe's differences; mode writes the mode.

// The early warnings of contract status --check (the plan's 18): each well
// before the platform's own alert, which mails the operator after 10
// minutes without a read of the feed (contract_feed_silent) and after 90
// minutes without a workspace's snapshot (contract_snapshots_stale).
const (
	// checkFeedRead: the leader's last feed page, while the contract is on.
	checkFeedRead = 5 * time.Minute
	// checkSnapshot: an open platform workspace named this long ago with
	// no snapshot accepted since, or its last one this old.
	checkSnapshot = 60 * time.Minute
	// checkPublished: the last trusted published_through, while on; past
	// it every sub's freshness rests on its own answers (README 7.1).
	checkPublished = time.Hour
	// checkErrors: how far back a contract ERROR the leader recorded is
	// reported.
	checkErrors = 24 * time.Hour
	// checkRound: how long the round's passes may leave held subs with no
	// document, their PUTs failing, while on (the leader's ERROR's bound).
	checkRound = 15 * time.Minute
	// checkParked: how long after the switch to the mode a park from
	// before it is told. The leader's start releases every park for one
	// try, within its retry (30 s) of the switch, twice it after a lost
	// lock; a park since the switch is told at once.
	checkParked = 2 * time.Minute
	// checkEvents: how long a workspace's queue of events may go without
	// a verdict on its batches, while on: an hour is the backoff's cap, so
	// a queue failing this long has been tried at least a dozen times. Its
	// events may stay pending as long, whatever the cause (a sender whose
	// own store calls fail records no failure on the queue).
	checkEvents = 60 * time.Minute
)

// defaultSealedSecret is where the installer seals the current secret
// (contract-secret.sh install): the never-observed finding looks there when
// runtime.env names no file, since a restored runtime.env may lack the
// contract's settings.
var defaultSealedSecret = "/opt/wappie/sealed/" + membership.SecretFileName

// contractStatusCommand is contract status [--check].
func contractStatusCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("contract status", flag.ContinueOnError)
	check := fs.Bool("check", false, "exit 1 with one line per finding (prune-backups' daily list)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract status " + strings.Join(fs.Args(), " ")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	return contractStatus(ctx, store.NewContract(a.pools.API), a.cfg.Contract, *check, out)
}

// contractStatus prints the contract's state and, with check, its findings,
// and then returns exit status 1 when there is any.
func contractStatus(ctx context.Context, c *store.Contract, cfg config.Contract, check bool, out io.Writer) error {
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	s := st.State
	w.f("mode: %s (since %s)", s.Mode, stamp(s.ModeChangedAt))
	w.f("transport: %s", cfg.Transport())
	loaded, published, lerr := readLoaded(cfg.LoadedFile)
	switch {
	case lerr != nil:
		w.f("secrets (server): unreadable: %v", lerr)
	case !published:
		w.f("secrets (server): nothing published")
	default:
		w.f("secrets (server): pid=%d loaded_at=%s reloads=%d current=%s other=%s error=%s",
			loaded.PID, stamp(loaded.LoadedAt), loaded.Reloads, loaded.Current, loaded.Other, loaded.Error)
	}
	files := sealedFiles(cfg)
	w.f("secrets (files): state=%s current=%s other=%s", files.state, files.current, files.other)
	if s.Generation != nil {
		w.f("generation: %s confirmed=%t", s.Generation, s.GenerationConfirmed)
	} else {
		w.f("generation: none")
	}
	w.f("cursor: %d", s.FeedCursor)
	w.f("published_through: %s", ago(st.Now, s.PublishedThrough))
	w.f("feed: last page %s", ago(st.Now, s.FeedReadAt))
	if s.FeedError != "" {
		w.f("feed: failing since %s (%s)", ago(st.Now, s.FeedErrorAt), s.FeedError)
	}
	round := "pending"
	if s.RoundGeneration != nil && s.Generation != nil && *s.RoundGeneration == *s.Generation {
		round = "done"
	}
	w.f("subs: held %d, followed %d, subscriptions %d, round %s", st.Held, st.Followed, st.Accounts, round)
	if s.RoundErrorAt != nil {
		w.f("round: PUTs failing since %s (%s)", ago(st.Now, s.RoundErrorAt), s.RoundError)
	}
	if s.ErrorAt != nil {
		w.f("last error: %s, %s", s.ErrorClass, ago(st.Now, s.ErrorAt))
	} else {
		w.f("last error: none")
	}
	w.f("platform workspaces: %d", len(st.Workspaces))
	for _, ws := range st.Workspaces {
		state := ws.Status
		if state == "" {
			state = "unknown"
		}
		extra := ""
		if !ws.Local {
			extra += " no_local_workspace"
		}
		if ws.NotFoundSince != nil {
			extra += " not_found_since=" + stamp(*ws.NotFoundSince)
		}
		if ws.ParkedAt != nil {
			extra += " parked=" + stamp(*ws.ParkedAt)
		}
		if ws.SnapshotError != "" {
			extra += fmt.Sprintf(" snapshot_failing=%s tries=%d", ws.SnapshotError, ws.SnapshotTries)
		}
		if ws.EventsError != "" {
			extra += fmt.Sprintf(" events_failing=%s since=%s tries=%d", ws.EventsError, stamp(*ws.EventsErrorAt), ws.EventsTries)
		}
		if ws.EventsNotFoundSince != nil {
			extra += " events_not_found_since=" + stamp(*ws.EventsNotFoundSince)
		}
		if ws.Parked > 0 {
			extra += fmt.Sprintf(" events_parked=%s", strings.Join(ws.ParkedCodes, ","))
		}
		if ws.PendingSince != nil {
			extra += " events_pending_since=" + stamp(*ws.PendingSince)
		}
		w.f("  %s %s %s named %s, snapshot %s, events pending %d parked %d coalesced %d%s",
			ws.ID, ws.Kind, state, ago(st.Now, &ws.NamedAt), ago(st.Now, ws.SnapshotOKAt), ws.Pending, ws.Parked, ws.Coalesced, extra)
	}
	if w.err != nil || !check {
		return w.err
	}
	found := statusFindings(st, cfg, loaded, published, lerr, files)
	for _, f := range found {
		w.f("finding: %s", f)
	}
	if w.err != nil {
		return w.err
	}
	if len(found) > 0 {
		return exitError{code: 1}
	}
	return nil
}

// statusFindings are --check's: each a line naming what to look at, never
// a value of the secret or a name.
func statusFindings(st store.ContractStatus, cfg config.Contract, loaded membership.Loaded, published bool, lerr error, files sealed) []string {
	var out []string
	s, now := st.State, st.Now
	older := func(at *time.Time, d time.Duration) bool { return at == nil || now.Sub(*at) > d }
	if s.ErrorAt != nil && now.Sub(*s.ErrorAt) <= checkErrors {
		out = append(out, fmt.Sprintf("a contract ERROR in the last day: %s at %s", s.ErrorClass, stamp(*s.ErrorAt)))
	}
	if s.On() {
		// Each bound counts from the later of its time and the switch to
		// the mode: the leader starts within seconds of it, so a feed never
		// read, or last read before an off period, is a finding only once
		// the switch is older than the bound.
		since := func(at *time.Time) *time.Time {
			if at == nil || at.Before(s.ModeChangedAt) {
				return &s.ModeChangedAt
			}
			return at
		}
		if older(since(s.FeedReadAt), checkFeedRead) {
			out = append(out, fmt.Sprintf("the feed was last read %s (the platform alerts after 10 minutes)", ago(now, s.FeedReadAt)))
		}
		if older(since(s.PublishedThrough), checkPublished) {
			out = append(out, fmt.Sprintf("published_through is %s", ago(now, s.PublishedThrough)))
		}
		if s.RoundErrorAt != nil && st.Held > st.Followed && older(since(s.RoundErrorAt), checkRound) {
			out = append(out, fmt.Sprintf("%d held subs not followed: their PUTs have failed since %s (%s)",
				st.Held-st.Followed, stamp(*s.RoundErrorAt), s.RoundError))
		}
		for _, ws := range st.Workspaces {
			why := ""
			if ws.SnapshotError != "" {
				why = fmt.Sprintf("; the last one sent: %s", ws.SnapshotError)
			}
			// Parked events are told, whatever the workspace's status, while
			// they last (housekeeping drops them 30 days after they were
			// written), counted as a snapshot's park is: at once for one
			// since the switch to the mode, after checkParked for one from
			// before it.
			if ws.Parked > 0 && ws.ParkedLatest != nil &&
				(!ws.ParkedLatest.Before(s.ModeChangedAt) || now.Sub(s.ModeChangedAt) > checkParked) {
				out = append(out, fmt.Sprintf("workspace %s has %d events parked, the last at %s (%s): they are not sent",
					ws.ID, ws.Parked, stamp(*ws.ParkedLatest), strings.Join(ws.ParkedCodes, ",")))
			}
			switch {
			case ws.EventsErrorAt != nil && older(since(ws.EventsErrorAt), checkEvents):
				out = append(out, fmt.Sprintf("workspace %s's events have had no verdict for over 60 minutes, since %s (%s)",
					ws.ID, stamp(*ws.EventsErrorAt), ws.EventsError))
			case ws.PendingSince != nil && older(since(ws.PendingSince), checkEvents):
				// The backstop, whatever the cause: the queue records no
				// failure when the sender's own store calls fail, nor when
				// no leader sends at all.
				out = append(out, fmt.Sprintf("workspace %s has %d events pending for over 60 minutes, the oldest written at %s: they are not delivered",
					ws.ID, ws.Pending, stamp(*ws.PendingSince)))
			}
			if ws.ParkedAt != nil {
				// A park is told whatever the workspace's status: nothing is
				// sent of it until a document names it again (not_found), a
				// restart or a leader's start. One from before the switch,
				// which the leader's start releases, only once the switch
				// is older than checkParked.
				if !ws.ParkedAt.Before(s.ModeChangedAt) || now.Sub(s.ModeChangedAt) > checkParked {
					out = append(out, fmt.Sprintf("workspace %s is parked since %s: its snapshots are not sent%s", ws.ID, stamp(*ws.ParkedAt), why))
				}
				continue
			}
			if ws.Status == "closed" {
				continue
			}
			last := ws.SnapshotOKAt
			if last == nil {
				last = &ws.NamedAt
			}
			if older(since(last), checkSnapshot) {
				out = append(out, fmt.Sprintf("workspace %s has no snapshot accepted for over 60 minutes (the platform alerts after 90)%s", ws.ID, why))
			}
		}
	}
	switch {
	case lerr != nil:
		out = append(out, fmt.Sprintf("the server's published secrets cannot be read: %v", lerr))
	case published && loaded.Error != "none" && loaded.Error != membership.StepMissing:
		out = append(out, fmt.Sprintf("the server's last secret load failed at step %s", loaded.Error))
	case published && files.present && (loaded.Current != files.current || loaded.Other != files.other):
		out = append(out, fmt.Sprintf("the server holds current=%s other=%s, the files are current=%s other=%s",
			loaded.Current, loaded.Other, files.current, files.other))
	case !published && cfg.Configured() && files.present:
		out = append(out, "a secret is installed but the server has published no load")
	}
	if !s.Observed() {
		path := cfg.SecretFile
		if path == "" {
			path = defaultSealedSecret
		}
		if _, err := os.Lstat(path); err == nil {
			out = append(out, "contract never observed but a secret is installed")
		}
	}
	return out
}

// sealed is what the secret's files on disk say.
type sealed struct {
	// present: the current file is there.
	present               bool
	state, current, other string
}

// sealedFiles reads the files' fingerprints as the server would publish
// them, and the installer's state file.
func sealedFiles(cfg config.Contract) sealed {
	out := sealed{state: "none", current: "none", other: "none"}
	fingerprint := func(path string) (string, bool) {
		if path == "" {
			return "none", false
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: the configured secret files
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "none", false
		case err != nil:
			return "unreadable", true
		case !cfg.Sealed():
			return "plaintext", true
		}
		return membership.Fingerprint(b), true
	}
	out.current, out.present = fingerprint(cfg.SecretFile)
	out.other, _ = fingerprint(cfg.SecretOtherFile)
	if cfg.SecretFile != "" {
		state, err := membership.SealDir(filepath.Dir(cfg.SecretFile)).State()
		switch {
		case err != nil:
			out.state = "disagrees"
		case state == membership.StateNone:
			out.state = "none"
		default:
			out.state = string(state)
		}
	}
	return out
}

// readLoaded reads what the server published of its secrets, false when
// it published nothing there.
func readLoaded(path string) (membership.Loaded, bool, error) {
	var l membership.Loaded
	if path == "" {
		return l, false, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the configured published file
	if errors.Is(err, fs.ErrNotExist) {
		return l, false, nil
	}
	if err != nil {
		return l, false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "pid":
			l.PID, _ = strconv.Atoi(v) //nolint:errcheck // a bad pid reads as 0
		case "loaded_at":
			l.LoadedAt, _ = time.Parse(time.RFC3339, v) //nolint:errcheck // a bad time reads as zero
		case "reloads":
			l.Reloads, _ = strconv.Atoi(v) //nolint:errcheck // a bad count reads as 0
		case "current":
			l.Current = v
		case "other":
			l.Other = v
		case "error":
			l.Error = v
		}
	}
	return l, true, sc.Err()
}

// contractDiffCommand is contract diff [--tenant T].
func contractDiffCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("contract diff", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "only the differences that name this workspace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract diff " + strings.Join(fs.Args(), " ")}
	}
	var only uuid.UUID
	if *tenant != "" {
		id, err := uuid.Parse(*tenant)
		if err != nil {
			return errors.New("contract diff: --tenant takes a workspace id")
		}
		only = id
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	return contractDiff(ctx, store.NewContract(a.pools.API), only, out)
}

// contractDiff prints every difference, one line each, by ids, roles and
// counts: what enforce would change, and the local teams no document names.
func contractDiff(ctx context.Context, c *store.Contract, tenant uuid.UUID, out io.Writer) error {
	diffs, err := c.Differences(ctx, tenant)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	for _, d := range diffs {
		attrs := membership.DifferenceAttrs(d)
		var b strings.Builder
		fmt.Fprint(&b, attrs[1])
		for i := 2; i+1 < len(attrs); i += 2 {
			fmt.Fprintf(&b, " %v=%v", attrs[i], attrs[i+1])
		}
		w.f("%s", b.String())
	}
	w.f("%d differences", len(diffs))
	return w.err
}

// contractModeCommand is contract mode off|observe.
func contractModeCommand(args []string, out io.Writer) error {
	if len(args) != 1 || (args[0] != store.ContractOff && args[0] != store.ContractObserve) {
		return usageError{arg: "contract mode " + strings.Join(args, " ")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	return contractMode(ctx, store.NewContract(a.pools.API), args[0], out)
}

// contractMode switches the mode and says what the switch did.
func contractMode(ctx context.Context, c *store.Contract, mode string, out io.Writer) error {
	change, err := c.SetMode(ctx, mode)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	if !change.Changed {
		w.f("contract mode: already %s; nothing changed", change.To)
		return w.err
	}
	w.f("contract mode: %s -> %s", change.From, change.To)
	if change.To == store.ContractObserve {
		w.f("events to send now: %d (undelivered from before the pause, and deletions, recoveries and purges while off)", change.ToSend)
		w.f("events held back for good: %d (pauses, strandings and moves while off)", change.HeldBack)
	}
	return w.err
}

// lines writes one line per call and keeps the first error.
type lines struct {
	w   io.Writer
	err error
}

func (l *lines) f(format string, args ...any) {
	if l.err == nil {
		_, l.err = fmt.Fprintf(l.w, format+"\n", args...)
	}
}

// stamp is a time as status prints it.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ago is how long before now t was, or never.
func ago(now time.Time, t *time.Time) string {
	if t == nil {
		return "never"
	}
	d := now.Sub(*t).Round(time.Second)
	if d < 0 {
		return fmt.Sprintf("%s ahead (%s)", -d, stamp(*t))
	}
	return fmt.Sprintf("%s ago (%s)", d, stamp(*t))
}
