package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"whatserver2/internal/store"
)

// whatserverd tokens retire-keys -dry-run | -apply -confirm N (step 7's
// plan, 7.2): an operator's command, never a migration, since self-hosted
// installations run the same migrations. It refuses unless the contract
// is on and tokens are on. The dry run prints, per workspace, every live
// key (prefix, what it would do, class, origin, scope, name, the service
// it acts as, its creator's sub or address, its last use) and every
// standing service account (remove, or kept and why), and writes nothing;
// the owner reads it, through the platform, before the apply. The apply
// revokes the keys of class rest and cli, and those in an MCP shape that
// no consent issued (origin rest or cli), removes the services, and
// records the run (key_retirements); -confirm must be the dry run's count
// of keys to revoke. Run again, it revokes nothing, and may remove a
// service kept before. Its log line, on the command's stdout with the
// list, holds counts, prefixes and service names only. It holds both
// modes and every workspace's row until it commits, so the contract's
// feeds, the mode switches and captures wait for that fraction of a
// second.

// keptWhy says why a standing service account is kept.
var keptWhy = map[string]string{
	store.KeptNoRetiredKey: "no retired key acted as it, nor a revoked old MCP token",
	store.KeptSparedKey:    "a spared key acts as it",
	store.KeptSoleReader:   "sole reader of a number (no other human holder)",
}

func retireKeys(ctx context.Context, a *app, apply bool, confirm int, out io.Writer) error {
	keys := store.NewAPIKeys(a.pools.API)
	var r store.KeyRetirement
	var err error
	if apply {
		r, err = keys.Retire(ctx, confirm, osUser())
	} else {
		r, err = keys.RetirePlan(ctx)
	}
	var count *store.ErrRetireConfirm
	switch {
	case errors.Is(err, store.ErrRetireNeedsTokens):
		return errors.New("tokens retire-keys: refused: the contract must be on and tokens on (whatserverd contract tokens on); nothing was written")
	case errors.As(err, &count):
		return fmt.Errorf("tokens retire-keys: -confirm %d, but %d keys would be revoked now; run -dry-run again; nothing was written",
			count.Confirm, count.Revoke)
	case err != nil:
		return fmt.Errorf("tokens retire-keys: %w", err)
	}
	printRetirement(out, r, apply)
	if apply && a.log != nil {
		var prefixes, removed, kept []string
		for _, w := range r.Workspaces {
			for _, k := range w.Keys {
				if k.Retire {
					prefixes = append(prefixes, k.Prefix)
				}
			}
			for _, s := range w.Services {
				switch {
				case s.Remove:
					removed = append(removed, s.Name)
				case s.Reason != store.KeptNoRetiredKey:
					kept = append(kept, s.Name)
				}
			}
		}
		a.log.Info("api keys retired", "revoked", r.Revoke, "prefixes", prefixes, "services_removed", removed, "services_kept", kept)
	}
	return nil
}

func printRetirement(out io.Writer, r store.KeyRetirement, apply bool) {
	p := func(format string, args ...any) {
		//nolint:errcheck // the operator's terminal
		fmt.Fprintf(out, format+"\n", args...)
	}
	if apply {
		p("tokens retire-keys: applied at %s", r.AppliedAt.UTC().Format(time.RFC3339Nano))
	} else {
		p("tokens retire-keys: dry run, nothing written")
	}
	revoke, keep := "revoke", "keep"
	if apply {
		revoke, keep = "revoked", "kept"
	}
	for _, w := range r.Workspaces {
		if len(w.Keys) == 0 && len(w.Services) == 0 {
			continue
		}
		p("workspace %s %q", w.ID, w.Name)
		for _, k := range w.Keys {
			did := keep
			if k.Retire {
				did = revoke
			}
			origin, actsAs, creator, used := "-", "-", "-", "never"
			if k.Origin != "" {
				origin = k.Origin
			}
			if k.ActsAs != "" {
				actsAs = k.ActsAs
			}
			if k.Creator != "" {
				creator = k.Creator
			}
			if k.LastUsedAt != nil {
				used = k.LastUsedAt.UTC().Format(time.RFC3339)
			}
			p("  key %s  %s  class %s  origin %s  scope %s  name %q  acts as %s  creator %s  last used %s", k.Prefix, did, k.Class, origin,
				k.Scope, k.Name, actsAs, creator, used)
		}
		for _, s := range w.Services {
			if s.Remove {
				p("  service %s (%s)  %s", s.Name, s.UserID, map[bool]string{true: "removed", false: "remove"}[apply])
				continue
			}
			p("  service %s (%s)  %s: %s", s.Name, s.UserID, keep, keptWhy[s.Reason])
		}
	}
	if apply {
		p("revoked %d keys; removed %d service accounts; kept %d that a retired key acted as", r.Revoke, r.Removed, r.Kept)
		return
	}
	p("keys to revoke: %d; service accounts to remove: %d; kept that a retired key acts as: %d", r.Revoke, r.Removed, r.Kept)
	p("apply with: whatserverd tokens retire-keys -apply -confirm %d", r.Revoke)
}
