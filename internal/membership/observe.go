package membership

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// Observe (decision 0040, "Rollout"; 0005: "receives and sends, does not
// enforce"; the plan's DB3 and 4.8): every document newly stored is
// compared with Wappie's own memberships, read-only, and the differences
// are logged by id. Nothing in users, workspace_memberships, sessions,
// api_keys, grants or tenants changes because of a document: enforce
// applies them, from the same stored documents. The log holds subs, user
// ids, workspace ids, roles, statuses and counts, never an email, a name or
// a label (DB22).

// observe logs sub's stored document's differences: one INFO line for the
// document, "contract observe: differences" with each difference as a
// group of its ids, or "contract observe: matches"; nothing for a sub
// Wappie does not hold (a feed's document of a refused sign-up). A failure
// to compare is a WARN and changes nothing.
func (m *Members) observe(ctx context.Context, sub uuid.UUID, version int64) {
	diffs, compared, err := m.Contract.DifferencesOf(ctx, sub)
	if err != nil {
		if ctx.Err() == nil {
			m.log().Warn("contract observe: could not compare a document", "sub", sub, "error", err)
		}
		return
	}
	if !compared {
		return
	}
	if len(diffs) == 0 {
		m.log().Info("contract observe: matches", "sub", sub, "version", version)
		return
	}
	attrs := []any{"sub", sub, "version", version, "count", len(diffs)}
	for i, d := range diffs {
		attrs = append(attrs, slog.Group(fmt.Sprintf("d%d", i+1), DifferenceAttrs(d)...))
	}
	m.log().Info("contract observe: differences", attrs...)
}

// DifferenceAttrs are a difference's log attributes, its kind first: only
// the ids and values its kind uses (the plan's 4.8 table), never a name.
// contract diff prints the same.
func DifferenceAttrs(d store.ContractDifference) []any {
	attrs := []any{"kind", d.Kind}
	id := func(key string, v uuid.UUID) {
		if v != uuid.Nil {
			attrs = append(attrs, key, v.String())
		}
	}
	switch d.Kind {
	case store.DiffPersonalMismatch:
		id("sub", d.Sub)
		id("user", d.User)
		attrs = append(attrs, "platform", idOrNone(d.Workspace), "local", idOrNone(d.LocalWorkspace), "numbers", d.Count)
	case store.DiffLocalOnly:
		id("sub", d.Sub)
		id("user", d.User)
		id("workspace", d.Workspace)
	case store.DiffNoSub:
		id("user", d.User)
		id("workspace", d.Workspace)
	case store.DiffPlatformOnly:
		id("sub", d.Sub)
		id("workspace", d.Workspace)
		if d.TenantMissing {
			attrs = append(attrs, "tenant_missing", true)
		}
	case store.DiffRole:
		id("sub", d.Sub)
		id("workspace", d.Workspace)
		attrs = append(attrs, "local", d.Local, "platform", d.Platform)
	case store.DiffAccountStatus:
		id("sub", d.Sub)
		id("user", d.User)
		attrs = append(attrs, "local", d.Local, "platform", d.Platform)
	case store.DiffMembershipStatus:
		id("sub", d.Sub)
		id("workspace", d.Workspace)
	case store.DiffTeamClosed, store.DiffName, store.DiffUnnamedTenant:
		id("workspace", d.Workspace)
	case store.DiffSessionsWouldEnd:
		id("sub", d.Sub)
		attrs = append(attrs, "sessions", d.Count)
	case store.DiffCredentialsWouldStop:
		id("sub", d.Sub)
		attrs = append(attrs, "keys", d.Keys, "connections", d.Connections, "services", d.Services)
	}
	return attrs
}

func idOrNone(v uuid.UUID) string {
	if v == uuid.Nil {
		return "none"
	}
	return v.String()
}
