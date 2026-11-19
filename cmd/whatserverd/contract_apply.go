package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// whatserverd contract apply -dry-run [-sub S] | -confirm N (DS54; step
// E1): what applying the stored documents would do, and, at enforce only,
// doing it. The dry run reads in one read-only transaction, in any mode,
// and writes nothing: one line per action, by ids, roles and counts only
// (never an email, a name or a label), then "N actions, M held". -confirm
// N applies every workspace, account and the orphan services' sweep, once
// N is the dry run's count of actions; it refuses unless the contract is
// at enforce, which only E2's migration and switch can make it, so until
// then it changes nothing. Readers of ended connections are told by their
// 30-second re-tell, and sockets close within their one-second check.

// ErrApplyConfirm is a -confirm that is not the count of actions now.
type errApplyConfirm struct{ confirm, actions int }

func (e errApplyConfirm) Error() string {
	return fmt.Sprintf("contract apply: -confirm %d, but %d actions would run now; run -dry-run again; nothing was written",
		e.confirm, e.actions)
}

func contractApplyCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("contract apply", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "list what applying the stored documents would do, and write nothing")
	sub := fs.String("sub", "", "only this sub's document (with -dry-run)")
	confirm := fs.Int("confirm", -1, "apply, at enforce only: the dry run's count of actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract apply " + strings.Join(fs.Args(), " ")}
	}
	var only uuid.UUID
	switch {
	case *dry && *confirm >= 0:
		return errors.New("contract apply: -dry-run and -confirm are exclusive")
	case !*dry && *confirm < 0:
		return errors.New("contract apply: give -dry-run [-sub S], or -confirm N")
	case *sub != "" && !*dry:
		return errors.New("contract apply: -sub goes with -dry-run")
	case *sub != "":
		id, err := uuid.Parse(*sub)
		if err != nil {
			return errors.New("contract apply: -sub takes a sub")
		}
		only = id
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	c := store.NewContract(a.pools.API)
	if *dry {
		return contractApplyDryRun(ctx, c, only, out)
	}
	return contractApplyConfirm(ctx, c, *confirm, out)
}

// contractApplyDryRun prints the plan.
func contractApplyDryRun(ctx context.Context, c *store.Contract, sub uuid.UUID, out io.Writer) error {
	var plan store.ApplyPlan
	var err error
	if sub != uuid.Nil {
		plan, err = c.PlanAccount(ctx, sub)
	} else {
		plan, err = c.PlanAll(ctx)
	}
	if err != nil {
		return fmt.Errorf("contract apply: %w", err)
	}
	printApplyPlan(out, plan)
	return nil
}

// printApplyPlan prints one line per action, then the counts.
func printApplyPlan(out io.Writer, plan store.ApplyPlan) {
	w := &lines{w: out}
	for _, set := range [][]store.ApplyResult{plan.Workspaces, plan.Accounts} {
		for _, r := range set {
			for _, a := range r.Actions {
				w.f("%s", applyActionLine(a))
			}
		}
	}
	for _, a := range plan.Orphans.Actions {
		w.f("%s", applyActionLine(a))
	}
	actions, held := plan.Actions()
	w.f("%d actions, %d held", actions, held)
}

// applyActionLine is one action as the dry run prints it: its kind, then
// the ids and values its kind uses.
func applyActionLine(a store.ApplyAction) string {
	var b strings.Builder
	b.WriteString(a.Kind)
	id := func(key string, v uuid.UUID) {
		if v != uuid.Nil {
			fmt.Fprintf(&b, " %s=%s", key, v)
		}
	}
	id("sub", a.Sub)
	id("user", a.User)
	id("workspace", a.Workspace)
	if a.Local != "" {
		fmt.Fprintf(&b, " local=%s", a.Local)
	}
	if a.Platform != "" {
		fmt.Fprintf(&b, " platform=%s", a.Platform)
	}
	if a.Count != 0 {
		fmt.Fprintf(&b, " count=%d", a.Count)
	}
	if a.Held != "" {
		fmt.Fprintf(&b, " reason=%s", a.Held)
	}
	return b.String()
}

// contractApplyConfirm applies everything at enforce, once confirm is the
// count of actions now; before enforce it refuses and writes nothing.
func contractApplyConfirm(ctx context.Context, c *store.Contract, confirm int, out io.Writer) error {
	state, err := c.State(ctx)
	if err != nil {
		return err
	}
	if state.Mode != store.ContractEnforce {
		return fmt.Errorf("contract apply: refused: %w (the mode is %s); nothing was written", store.ErrApplyNeedsEnforce, state.Mode)
	}
	plan, err := c.PlanAll(ctx)
	if err != nil {
		return fmt.Errorf("contract apply: %w", err)
	}
	if actions, _ := plan.Actions(); actions != confirm {
		return errApplyConfirm{confirm: confirm, actions: actions}
	}
	w := &lines{w: out}
	subs, workspaces, err := c.PendingApply(ctx, 1<<20)
	if err != nil {
		return fmt.Errorf("contract apply: %w", err)
	}
	for _, id := range workspaces {
		if _, err := c.ApplyWorkspace(ctx, id); err != nil {
			return fmt.Errorf("contract apply: workspace %s: %w", id, err)
		}
	}
	for _, sub := range subs {
		if _, err := c.EnsureTeams(ctx, sub); err != nil {
			return fmt.Errorf("contract apply: sub %s: %w", sub, err)
		}
		r, err := c.ApplyAccount(ctx, sub)
		if err != nil {
			return fmt.Errorf("contract apply: sub %s: %w", sub, err)
		}
		for _, a := range r.Actions {
			w.f("%s", applyActionLine(a))
		}
	}
	sweep, err := c.SweepOrphanServices(ctx)
	if err != nil {
		return fmt.Errorf("contract apply: the orphan services: %w", err)
	}
	for _, a := range sweep.Actions {
		w.f("%s", applyActionLine(a))
	}
	w.f("applied %d subs, %d workspaces", len(subs), len(workspaces))
	return w.err
}
