package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"whatserver2/internal/membership"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/store"
)

// whatserverd contract settings (step 12a; docs/contract.md, "Settings and
// commands"): the settings part's mode, which the leader follows, and the
// operator's view of it. None of them calls the platform: they read and
// write the database. --check's settings findings are contract status
// --check's too.

// The settings part's early warnings (--check), each well before the
// platform's own: the console shows Wappie down after 2 minutes without a
// command feed request, the doctor alerts after 10 (contract_commands_silent)
// and for 24 hours after an invalid_command (contract_command_invalid), and
// the console marks a section stale after 90 minutes.
const (
	// checkCommands: the command feed's last page, while settings are read
	// or on.
	checkCommands = 2 * time.Minute
	// checkResults: the oldest result not delivered.
	checkResults = 5 * time.Minute
	// checkTaken: the oldest command taken with no result yet.
	checkTaken = 10 * time.Minute
	// checkSection: a workspace's last accepted numbers section, while
	// settings are read or on.
	checkSection = time.Hour
	// checkPerson: a person's last accepted document, while settings are
	// read or on.
	checkPerson = time.Hour
)

// exitTellPlatform is contract settings' refusal for want of
// --platform-told: nothing changed.
const exitTellPlatform = 4

// contractSettingsCommand is contract settings off|read|on
// [--platform-told] and status [--check].
func contractSettingsCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return usageError{arg: "contract settings"}
	}
	switch args[0] {
	case store.SettingsOff, store.SettingsRead, store.SettingsOn:
		fs := flag.NewFlagSet("contract settings "+args[0], flag.ContinueOnError)
		told := fs.Bool("platform-told", false, "the platform was told: it watches the command feed from its first read on")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError{arg: "contract settings " + strings.Join(args, " ")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a, closeAll, err := setupCurrent(ctx)
		if err != nil {
			return err
		}
		defer closeAll()
		return contractSettingsMode(ctx, store.NewContract(a.pools.API), args[0], *told, out)
	case "status":
		fs := flag.NewFlagSet("contract settings status", flag.ContinueOnError)
		check := fs.Bool("check", false, "exit 1 with one line per finding")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError{arg: "contract settings " + strings.Join(args, " ")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a, closeAll, err := setupCurrent(ctx)
		if err != nil {
			return err
		}
		defer closeAll()
		return contractSettingsStatus(ctx, store.NewContract(a.pools.API), *check, out)
	}
	return usageError{arg: "contract settings " + strings.Join(args, " ")}
}

// contractSettingsMode switches the settings mode and says what the switch
// did, or why it refused: settings ride on the contract (exit
// exitNotReady while it is off), and the first switch that follows the
// command feed, and off once it was read, need --platform-told (exit
// exitTellPlatform). A refusal changes nothing.
func contractSettingsMode(ctx context.Context, c *store.Contract, mode string, told bool, out io.Writer) error {
	change, err := c.SetSettingsMode(ctx, mode, told)
	switch {
	case errors.Is(err, store.ErrSettingsContractOff):
		return exitError{code: exitNotReady,
			err: errors.New("contract settings: the contract is off; settings follow it: run whatserverd contract mode observe first; nothing changed")}
	case errors.Is(err, store.ErrSettingsTellPlatform) && mode == store.SettingsOff && change.FirstReadAt != nil:
		return exitError{code: exitTellPlatform, err: fmt.Errorf("contract settings: the platform has watched the command feed since %s "+
			"and alerts once it goes silent: tell it first, then run this again with --platform-told; nothing changed", stamp(*change.FirstReadAt))}
	case errors.Is(err, store.ErrSettingsTellPlatform):
		return exitError{code: exitTellPlatform, err: errors.New("contract settings: from the first read of the command feed the platform " +
			"watches it for good: tell it first, then run this again with --platform-told; nothing changed")}
	case err != nil:
		return err
	}
	w := &lines{w: out}
	if !change.Changed {
		w.f("contract settings: already %s; nothing changed", change.To)
		return w.err
	}
	w.f("contract settings: %s -> %s", change.From, change.To)
	switch change.To {
	case store.SettingsOn:
		w.f("the console offers the kinds this binary runs within seconds: every section and person document is due now")
	case store.SettingsRead:
		if change.From == store.SettingsOn {
			w.f("the console offers no kind within seconds: every section and person document goes with accepts []")
		}
	}
	switch {
	case change.To != store.SettingsOff && change.FirstReadAt == nil:
		w.f("the leader follows the command feed within seconds: the platform watches it from then on")
	case change.To == store.SettingsOff && change.FirstReadAt != nil:
		w.f("the platform has watched the command feed since %s: it alerts contract_commands_silent after 10 minutes", stamp(*change.FirstReadAt))
	}
	return w.err
}

// contractSettingsStatus prints the settings part's state and, with
// check, its findings, and then returns exit status 1 when there is any.
func contractSettingsStatus(ctx context.Context, c *store.Contract, check bool, out io.Writer) error {
	st, err := c.SettingsStatus(ctx)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	s, now := st.State, st.Now
	mode := s.Mode
	if s.Effective() != s.Mode {
		mode += " (read as " + s.Effective() + ")"
	}
	w.f("settings: %s (since %s)", mode, stamp(s.ModeChangedAt))
	w.f("command feed: cursor %d, first read %s, last page %s", s.FeedCursor, ago(now, s.FirstReadAt), ago(now, s.ReadAt))
	if s.FeedError != "" {
		w.f("command feed: failing since %s (%s)", ago(now, s.FeedErrorAt), s.FeedError)
	}
	if s.ResultsError != "" && st.Undelivered > 0 {
		// Only an answered post clears it: a reset that dropped the results
		// leaves it set with nothing failing.
		w.f("results: posts failing since %s (%s)", ago(now, s.ResultsErrorAt), s.ResultsError)
	}
	w.f("invalid_command: last answered %s", ago(now, s.InvalidAt))
	w.f("label cutover: %s", stamp(s.LabelCutoverAt))
	var counts []string
	for _, r := range st.Results {
		name := r.Outcome
		if r.Code != "" {
			name += ":" + r.Code
		}
		counts = append(counts, fmt.Sprintf("%s %d", name, r.N))
	}
	if len(counts) == 0 {
		counts = []string{"none"}
	}
	w.f("results (30 days): %s", strings.Join(counts, ", "))
	w.f("commands: open %d (oldest taken %s), retrying %d, undelivered %d (oldest %s), parked %d (last %s)",
		st.Open, ago(now, st.OldestOpen), st.Retrying, st.Undelivered, ago(now, st.OldestUndelivered), st.Parked, ago(now, st.LastParked))
	w.f("numbers sections: %d", len(st.Sections))
	for _, sec := range st.Sections {
		state := sec.Status
		if state == "" {
			state = "unknown"
		}
		extra := ""
		if sec.Error != "" {
			extra += fmt.Sprintf(" failing=%s tries=%d", sec.Error, sec.Tries)
		}
		if sec.NotFoundSince != nil {
			extra += " not_found_since=" + stamp(*sec.NotFoundSince)
		}
		if sec.ParkedAt != nil {
			extra += " parked=" + stamp(*sec.ParkedAt)
		}
		w.f("  %s %s %s seq %d, accepted %s, due %s%s", sec.Workspace, sec.Section, state, sec.StateSeq, ago(now, sec.OKAt),
			ago(now, &sec.DueAt), extra)
	}
	accepted, parked := 0, 0
	for _, p := range st.Persons {
		if p.OKAt != nil {
			accepted++
		}
		if p.ParkedAt != nil {
			parked++
		}
	}
	w.f("person documents: %d (%d accepted, %d parked)", len(st.Persons), accepted, parked)
	if w.err != nil || !check {
		return w.err
	}
	found := settingsFindings(st)
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

// settingsFindings are --check's lines of the settings part, each naming
// what to look at, never a value of a command or a name.
func settingsFindings(st store.ContractSettingsStatus) []string {
	var out []string
	s, now := st.State, st.Now
	older := func(at *time.Time, d time.Duration) bool { return at == nil || now.Sub(*at) > d }
	// Each bound counts from the later of its time and the switch to the
	// mode: the leader starts the settings part within seconds of it.
	since := func(at *time.Time) *time.Time {
		if at == nil || at.Before(s.ModeChangedAt) {
			return &s.ModeChangedAt
		}
		return at
	}
	following := s.Following()
	switch {
	case following && older(since(s.ReadAt), checkCommands):
		out = append(out, fmt.Sprintf("settings are %s but the command feed was last read %s "+
			"(the console shows Wappie down after 2 minutes; the platform alerts after 10)", s.Effective(), ago(now, s.ReadAt)))
	case !following && s.FirstReadAt != nil:
		out = append(out, fmt.Sprintf("settings are off, but the platform has watched the command feed since %s: "+
			"it alerts contract_commands_silent", stamp(*s.FirstReadAt)))
	}
	if s.InvalidAt != nil && now.Sub(*s.InvalidAt) <= checkErrors {
		out = append(out, fmt.Sprintf("an invalid_command was answered at %s (the platform alerts for 24 hours)", stamp(*s.InvalidAt)))
	}
	if st.Parked > 0 && st.LastParked != nil {
		out = append(out, fmt.Sprintf("%d results are parked (rejected invalid_request or local_invalid), the last at %s: "+
			"they are not delivered", st.Parked, stamp(*st.LastParked)))
	}
	if st.Undelivered > 0 && st.OldestUndelivered != nil && older(st.OldestUndelivered, checkResults) {
		class := st.UndeliveredError
		if class == "" {
			class = s.ResultsError
		}
		if class == "" {
			class = "no post failed"
		}
		out = append(out, fmt.Sprintf("%d results are not delivered, the oldest for over %d minutes, since %s (%s)",
			st.Undelivered, int(checkResults/time.Minute), stamp(*st.OldestUndelivered), class))
	}
	if st.Open > 0 && st.OldestOpen != nil && older(st.OldestOpen, checkTaken) {
		out = append(out, fmt.Sprintf("%d commands have no result, the oldest taken over %d minutes ago, at %s",
			st.Open, int(checkTaken/time.Minute), stamp(*st.OldestOpen)))
	}
	if st.Retrying > 0 && st.OldestRetrying != nil {
		out = append(out, fmt.Sprintf("%d commands are retrying after store errors, the oldest taken at %s (%s)",
			st.Retrying, stamp(*st.OldestRetrying), st.RetryError))
	}
	if st.StuckAt != nil && now.Sub(*st.StuckAt) <= checkErrors {
		out = append(out, fmt.Sprintf("a command was answered rate_limited after %d failed runs at %s", store.CommandRunTries, stamp(*st.StuckAt)))
	}
	if !following {
		return out
	}
	for _, sec := range st.Sections {
		why := ""
		if sec.Error != "" {
			why = "; the last one sent: " + sec.Error
		}
		if sec.ParkedAt != nil {
			// The leader's start releases a park from before the switch for
			// one try, within its retry of it; one since is told at once.
			if !sec.ParkedAt.Before(s.ModeChangedAt) || now.Sub(s.ModeChangedAt) > checkParked {
				out = append(out, fmt.Sprintf("workspace %s's %s section is parked since %s: it is not sent (%s)",
					sec.Workspace, sec.Section, stamp(*sec.ParkedAt), sec.Error))
			}
			continue
		}
		if sec.Status == "closed" {
			continue
		}
		if older(since(sec.OKAt), checkSection) {
			out = append(out, fmt.Sprintf("workspace %s has no %s section accepted for over %d minutes (the console marks it stale after 90)%s",
				sec.Workspace, sec.Section, int(checkSection/time.Minute), why))
		}
	}
	return append(out, personFindings(st, since)...)
}

// personFindings are --check's lines of the persons' documents, while
// settings are followed: those not accepted for checkPerson (counted from
// the switch, as the sections'), and those parked, with the oldest's time
// and class; never a sub.
func personFindings(st store.ContractSettingsStatus, since func(*time.Time) *time.Time) []string {
	var out []string
	var stale, parked int
	var oldest, lastParked *time.Time
	class := ""
	for _, p := range st.Persons {
		switch {
		case p.ParkedAt != nil:
			parked++
			if lastParked == nil || p.ParkedAt.After(*lastParked) {
				lastParked = p.ParkedAt
			}
		case st.Now.Sub(*since(p.OKAt)) > checkPerson:
			stale++
			if at := since(p.OKAt); oldest == nil || at.Before(*oldest) {
				oldest, class = at, p.Error
			}
		}
	}
	if stale > 0 {
		why := ""
		if class != "" {
			why = " (" + class + ")"
		}
		out = append(out, fmt.Sprintf("%d person documents not accepted for over %d minutes, the oldest since %s%s",
			stale, int(checkPerson/time.Minute), stamp(*oldest), why))
	}
	if parked > 0 {
		out = append(out, fmt.Sprintf("%d person documents parked, the last at %s: they are not sent", parked, stamp(*lastParked)))
	}
	return out
}

// settingsConfig is the leader's settings part as this process wires it:
// the registry tells the pending rows' pairing and retry, and the numbers
// kinds run with it and with the socket server (internal/numberacts).
func (a *app) settingsConfig() membership.SettingsConfig {
	var cfg membership.SettingsConfig
	if a.members == nil {
		return cfg
	}
	acts := &numberacts.Runner{Store: a.members.Contract, Devices: a.devices, Recorder: a.recordReceipt, Log: a.log}
	if a.registry != nil {
		cfg.Numbers = a.registry
		acts.Registry = a.registry
	}
	if a.ws != nil {
		acts.Sockets = a.ws
	}
	cfg.Acts = acts
	return cfg
}
