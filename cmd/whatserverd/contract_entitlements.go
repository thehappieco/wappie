package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// whatserverd contract entitlements (E0; docs/contract.md, "Entitlements
// and usage"): the entitlements part's mode, which the leader follows, the
// usage sender's own switch, the local brake, and the operator's view of
// them. None of them calls the platform: they read and write the database.
// This release observes only: enforce is refused, and nothing a document
// says is enforced. Each change is reported to the platform's chat (Q54).

// The entitlements part's early warnings (--check): the platform's doctor
// alerts on a document left unacknowledged for 10 minutes by an app that
// acknowledged before (contract_entitlements_unapplied).
const (
	// checkEntSilent: the feed's last page, while observing.
	checkEntSilent = 15 * time.Minute
	// checkEntAck: the last acknowledgement accepted, while observing.
	checkEntAck = 10 * time.Minute
	// checkEntGet: a workspace with no document since its GET was due.
	checkEntGet = 10 * time.Minute
	// checkEntFresh: a workspace's document's freshness (the spec's 15.6:
	// past it, steps freeze).
	checkEntFresh = store.EntFreshFor
)

// contractEntitlementsCommand is contract entitlements off|observe
// [--platform-told], usage off|on [--platform-told], hold|release
// -workspace <id> [--platform-told] and status [--check].
func contractEntitlementsCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return usageError{arg: "contract entitlements"}
	}
	verb := args[0]
	fs := flag.NewFlagSet("contract entitlements "+verb, flag.ContinueOnError)
	told := fs.Bool("platform-told", false, "the platform's chat was told of this change (Q54)")
	check := false
	var workspace string
	rest := args[1:]
	switch verb {
	case store.EntOff, store.EntObserve:
	case store.EntEnforce:
		return errors.New("contract entitlements: this release observes only (E0); nothing changed")
	case "usage":
		if len(rest) == 0 || (rest[0] != store.UsageOff && rest[0] != store.UsageOn) {
			return usageError{arg: "contract entitlements " + strings.Join(args, " ")}
		}
		verb, rest = "usage "+rest[0], rest[1:]
	case "hold", "release":
		fs.StringVar(&workspace, "workspace", "", "the platform workspace's id")
	case "status":
		fs = flag.NewFlagSet("contract entitlements status", flag.ContinueOnError)
		fs.BoolVar(&check, "check", false, "exit 1 with one line per finding")
	default:
		return usageError{arg: "contract entitlements " + strings.Join(args, " ")}
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract entitlements " + strings.Join(args, " ")}
	}
	var ws uuid.UUID
	if verb == "hold" || verb == "release" {
		id, err := uuid.Parse(workspace)
		if err != nil {
			return errors.New("contract entitlements: -workspace takes a platform workspace's id")
		}
		ws = id
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	c := store.NewContract(a.pools.API)
	switch verb {
	case "status":
		return contractEntitlementsStatus(ctx, c, check, out)
	case "hold", "release":
		return contractEntitlementsBrake(ctx, c, ws, verb == "hold", *told, out)
	}
	return contractEntitlementsMode(ctx, c, verb, *told, out)
}

// contractEntitlementsMode switches the follower's mode ("off",
// "observe") or the usage sender's ("usage off", "usage on"), and says
// what the switch did or why it refused: both ride on the contract (exit
// exitNotReady while it is off), and off once the feed was read needs
// --platform-told (exit exitTellPlatform). A refusal changes nothing.
func contractEntitlementsMode(ctx context.Context, c *store.Contract, verb string, told bool, out io.Writer) error {
	var change store.EntModeChange
	var err error
	name := "contract entitlements"
	if usage, ok := strings.CutPrefix(verb, "usage "); ok {
		name += " usage"
		change, err = c.SetEntUsage(ctx, usage)
	} else {
		change, err = c.SetEntMode(ctx, verb, told)
	}
	switch {
	case errors.Is(err, store.ErrEntContractOff):
		return exitError{code: exitNotReady,
			err: errors.New(name + ": the contract is off; entitlements follow it: run whatserverd contract mode observe first; nothing changed")}
	case errors.Is(err, store.ErrEntTellPlatform):
		return exitError{code: exitTellPlatform, err: fmt.Errorf("%s: the platform has read Wappie's acknowledgements since %s "+
			"and alerts once documents go unacknowledged: tell it first, then run this again with --platform-told; nothing changed",
			name, stamp(*change.FirstReadAt))}
	case err != nil:
		return err
	}
	w := &lines{w: out}
	if !change.Changed {
		w.f("%s: already %s; nothing changed", name, change.To)
		return w.err
	}
	slog.Info("contract: entitlements mode", "mode", verb, "platform_told", told)
	w.f("%s: %s -> %s", name, change.From, change.To)
	switch {
	case name == "contract entitlements" && change.To == store.EntObserve:
		w.f("the leader follows the entitlements feed within seconds, in observe: it enforces nothing; report the switch to the platform's chat")
	case name == "contract entitlements usage" && change.To == store.UsageOn:
		w.f("the leader sends a usage report of every named workspace within seconds, while entitlements observe")
	}
	return w.err
}

// contractEntitlementsBrake holds a workspace at observe, or releases it,
// and says what it did: the hold E0 set on an enforce document is told to
// the platform with hold --platform-told, and cannot be released while
// the document says enforce.
func contractEntitlementsBrake(ctx context.Context, c *store.Contract, ws uuid.UUID, hold, told bool, out io.Writer) error {
	changed, err := c.EntBrake(ctx, ws, hold, told)
	switch {
	case errors.Is(err, store.ErrEntEnforceHeld):
		return errors.New("contract entitlements: the workspace's document says enforce, which this release never enforces: " +
			"it stays held at observe; nothing changed")
	case errors.Is(err, store.ErrEntNoBrake):
		return errors.New("contract entitlements: the workspace is not held; nothing changed")
	case err != nil:
		return err
	}
	w := &lines{w: out}
	if !changed {
		w.f("contract entitlements: %s already held; nothing changed", ws)
		return w.err
	}
	slog.Info("contract: entitlements brake", "workspace", ws, "held", hold, "platform_told", told)
	if hold {
		w.f("contract entitlements: %s held at observe; report it to the platform's chat", ws)
	} else {
		w.f("contract entitlements: %s released; report it to the platform's chat", ws)
	}
	return w.err
}

// contractEntitlementsStatus prints the entitlements part's state and, with
// check, its findings, then returns exit status 1 when there is any.
func contractEntitlementsStatus(ctx context.Context, c *store.Contract, check bool, out io.Writer) error {
	st, err := c.EntStatus(ctx)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	entitlementsLines(w, st)
	if w.err != nil || !check {
		return w.err
	}
	found := entitlementsFindings(st)
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

// entitlementsLines are the entitlements part's lines of contract status:
// ids, counts, enums and times only, never a figure.
func entitlementsLines(w *lines, st store.ContractEntStatus) {
	s, now := st.State, st.Now
	if s.Effective() == store.EntOff {
		w.f("entitlements: off")
	} else {
		w.f("entitlements: %s (since %s)", s.Effective(), stamp(s.ModeAt))
	}
	if s.Usage == store.UsageOn {
		w.f("entitlements usage: on (since %s)", stamp(s.UsageAt))
	} else {
		w.f("entitlements usage: off")
	}
	through := "none"
	if s.PublishedThrough != nil {
		through = stamp(*s.PublishedThrough)
	}
	w.f("entitlements feed: cursor %d, published_through %s, last page %s", s.FeedCursor, through, ago(now, s.LastPageAt))
	if s.FeedError != "" {
		w.f("entitlements feed: failing since %s (%s)", stamp(*s.FeedErrorAt), s.FeedError)
	}
	acked := "none"
	if s.AckedThrough != nil {
		acked = fmt.Sprintf("%d at %s", *s.AckedThrough, stamp(*s.AckedAt))
	}
	w.f("entitlements ack: through %s, refusals owed %d", acked, st.Owed)
	applied, kept, placeholders := 0, 0, 0
	for _, r := range st.Rows {
		switch {
		case r.Doc == nil:
			placeholders++
		case r.AppliedAt != nil:
			applied++
		default:
			kept++
		}
	}
	w.f("entitlements documents: %d applied, %d kept for workspaces not named, %d placeholders", applied, kept, placeholders)
	for _, r := range st.Rows {
		version := "none"
		if r.Version != nil {
			version = fmt.Sprintf("v%d", *r.Version)
		} else if r.Doc != nil {
			version = "v?"
		}
		mode, state := r.Mode, r.State
		if r.Doc == nil {
			mode, state = "-", "-"
		}
		fresh := "none"
		if r.Fresh != nil {
			fresh = ago(now, r.Fresh)
		}
		extra := ""
		if r.BrakeKind != "" {
			extra += " held at observe"
		}
		if r.NotFoundSince != nil {
			extra += " not_found since " + stamp(*r.NotFoundSince)
		}
		if r.Doc != nil && (r.Fresh == nil || now.Sub(*r.Fresh) >= checkEntFresh) {
			extra += " frozen"
		}
		w.f("  %s: %s %s %s fresh %s%s", r.Workspace, version, mode, state, fresh, extra)
	}
}

// entitlementsFindings are --check's lines of the entitlements part, each
// naming what to look at, never a figure.
func entitlementsFindings(st store.ContractEntStatus) []string {
	var out []string
	s, now := st.State, st.Now
	older := func(at *time.Time, d time.Duration) bool { return at == nil || now.Sub(*at) > d }
	// Each bound counts from the later of its time and the switch: the
	// leader starts the part within seconds of it.
	since := func(at *time.Time) *time.Time {
		if at == nil || at.Before(s.ModeAt) {
			return &s.ModeAt
		}
		return at
	}
	for _, r := range st.Rows {
		if r.BrakeKind == store.BrakeEnforceInE0 && !r.BrakeTold {
			out = append(out, fmt.Sprintf("%s: an enforce document held at observe (E0), not yet reported to the platform "+
				"(report it, then: whatserverd contract entitlements hold -workspace %s --platform-told)", r.Workspace, r.Workspace))
		}
	}
	if st.LastRefused != nil && now.Sub(*st.LastRefused) <= checkErrors {
		out = append(out, fmt.Sprintf("a document refused in the last 24 hours, the last at %s (the platform alerts for 24 hours)",
			stamp(*st.LastRefused)))
	}
	if s.Effective() == store.EntOff {
		return out
	}
	if older(since(s.LastPageAt), checkEntSilent) {
		out = append(out, fmt.Sprintf("entitlements feed silent for over %d minutes, the last page %s",
			int(checkEntSilent/time.Minute), ago(now, s.LastPageAt)))
	}
	if s.FirstReadAt != nil && older(since(s.AckedAt), checkEntAck) {
		out = append(out, fmt.Sprintf("entitlements acknowledgement over %d minutes old, the last %s (the platform alerts after 10 minutes)",
			int(checkEntAck/time.Minute), ago(now, s.AckedAt)))
	}
	for _, r := range st.Rows {
		switch {
		case r.Doc == nil:
			due := r.GetErrorAt
			if due == nil {
				due = r.GetDueAt
			}
			if due != nil && older(since(due), checkEntGet) {
				out = append(out, fmt.Sprintf("%s: no document after a GET was due for over %d minutes, since %s",
					r.Workspace, int(checkEntGet/time.Minute), stamp(*due)))
			}
		case r.AppliedAt != nil && r.NotFoundSince == nil && older(since(r.Fresh), checkEntFresh):
			out = append(out, fmt.Sprintf("%s: freshness over 24 hours, the last %s", r.Workspace, ago(now, r.Fresh)))
		}
	}
	return out
}
