package membership

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// Applying the stored documents at enforce (DS54; step E1). The store
// applies (store.Contract.ApplyAccount and the rest, which refuse unless
// the mode is enforce); this file does what the process does around each
// apply: it tells the readers of the connections it ended (best effort:
// their 30-second re-tell is the backstop), wakes this process's sessions
// to check their access again, and logs by ids, codes and counts only
// (DB22). Nothing calls Apply or ApplyPending yet: observe's two call
// sites (follower.go's page and signin.go's keep) and the leader's loop
// call them in E2, at enforce. Observe never applies.

// ApplyReaders tells a connection's reader it ended (*mcpauth.Handler's
// TellRevoked), as the console's revoke does.
type ApplyReaders interface {
	TellRevoked(ctx context.Context, reader, id string)
}

// ApplySockets wakes the sessions open on this process to check their
// access again (*wsapi.Server's RevalidateAccess).
type ApplySockets interface {
	RevalidateAccess()
}

// applyBatch is how many subs, workspaces and closings one pass of
// ApplyPending takes of each.
const applyBatch = 100

// Apply applies sub's stored document: the teams it lists that Wappie
// lacks are created, the workspaces it names whose wversion is ahead are
// applied, then the account. Before enforce it does nothing and returns
// store.ErrApplyNeedsEnforce.
func (m *Members) Apply(ctx context.Context, sub uuid.UUID) (store.ApplyResult, error) {
	res := store.ApplyResult{Sub: sub}
	created, err := m.Contract.EnsureTeams(ctx, sub)
	if err != nil {
		return res, m.applyFailed(ctx, sub, err)
	}
	for _, id := range created {
		res.Absorb(store.ApplyResult{Actions: []store.ApplyAction{{Kind: store.ApplyTeamCreated, Workspace: id}},
			Counts: store.ApplyCounts{TeamsCreated: 1}})
	}
	ws, err := m.Contract.PendingWorkspacesOf(ctx, sub)
	if err != nil {
		return res, m.applyFailed(ctx, sub, err)
	}
	for _, id := range ws {
		w, err := m.Contract.ApplyWorkspace(ctx, id)
		if err != nil {
			return res, m.applyFailed(ctx, sub, err)
		}
		res.Absorb(w)
	}
	a, err := m.Contract.ApplyAccount(ctx, sub)
	res.Absorb(a)
	res.Version, res.Held, res.OperatorDisable = a.Version, a.Held, a.OperatorDisable
	m.applied(ctx, res)
	if err != nil {
		return res, m.applyFailed(ctx, sub, err)
	}
	m.logApplied(res)
	return res, nil
}

// ApplyPending is the leader's pass at enforce (E2 runs it): the
// workspaces ahead of what was applied, then the subs whose documents
// differ from what was applied or that hold a part (a held part is retried
// each pass, so a loss held for a strand applies once the generation is
// confirmed), then the closings (confirmed by a fresh GET, forgotten after
// their purge, unsubscribed), then the orphan services' sweep. Before
// enforce it does nothing.
func (m *Members) ApplyPending(ctx context.Context) error {
	state, err := m.Contract.State(ctx)
	if err != nil {
		return err
	}
	if state.Mode != store.ContractEnforce {
		return nil
	}
	subs, workspaces, err := m.Contract.PendingApply(ctx, applyBatch)
	if err != nil {
		return err
	}
	for _, id := range workspaces {
		w, err := m.Contract.ApplyWorkspace(ctx, id)
		if err != nil {
			m.applyFailedWorkspace(ctx, id, err)
			continue
		}
		if w.Changed() {
			m.applied(ctx, w)
			m.logApplied(w)
		}
	}
	for _, sub := range subs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Each sub's failure is logged and recorded; the pass goes on.
		_, _ = m.Apply(ctx, sub)
	}
	m.closings(ctx)
	sweep, err := m.Contract.SweepOrphanServices(ctx)
	switch {
	case err != nil:
		m.log().Error("contract orphan services: failed", "class", applyErrorClass(err))
		m.recordApplyError(ctx, store.ContractErrorApplyFailed)
	case sweep.Keys+sweep.Grants+sweep.Keychain > 0:
		m.log().Info("contract orphan services: swept", "keys", sweep.Keys, "grants", sweep.Grants, "keychain", sweep.Keychain,
			"workspaces", len(sweep.Workspaces))
		m.revalidate()
	}
	if _, err := m.Contract.RetainClosings(ctx); err != nil {
		m.log().Warn("contract apply: could not delete old closing records", "error", err)
	}
	return nil
}

// closings moves each closing on: confirmed by a fresh signed GET,
// forgotten once its purge is done, unsubscribed once forgotten.
func (m *Members) closings(ctx context.Context) {
	confirm, forget, unsubscribe, err := m.Contract.PendingClosings(ctx, applyBatch)
	if err != nil {
		m.log().Warn("contract apply: could not read the closings", "error", err)
		return
	}
	for _, sub := range confirm {
		m.confirmClosing(ctx, sub)
	}
	for _, sub := range forget {
		res, done, err := m.Contract.ForgetClosed(ctx, sub)
		switch {
		case err != nil:
			m.log().Error("contract apply: failed", "sub", sub, "step", "forget", "class", applyErrorClass(err))
			m.recordApplyError(ctx, store.ContractErrorApplyFailed)
		case done && !res.Already:
			m.log().Info("contract apply: forgotten", "sub", sub, "workspace", res.Workspace)
			m.revalidate()
		}
	}
	for _, sub := range unsubscribe {
		if !m.connected() {
			return
		}
		call, cancel := context.WithTimeout(ctx, m.bound())
		err := m.Client.Unsubscribe(call, sub.String())
		cancel()
		if err != nil && RefusalCode(err) != kc.CodeNotFound {
			m.log().Warn("contract apply: a forgotten account's unsubscribe failed", append([]any{"sub", sub}, callAttrs(err)...)...)
			continue
		}
		if err := m.Contract.ClosingUnsubscribed(ctx, sub); err != nil {
			m.log().Warn("contract apply: could not record an unsubscribe", "sub", sub, "error", err)
		}
	}
}

// confirmClosing asks the platform, now and bounded, whether sub's account
// is still closed, and confirms the closing only on a signed answer that
// says so, of the confirmed generation. No answer, an unverified one, or
// another status deletes nothing; an active answer is logged at ERROR
// (closing_contradicted).
func (m *Members) confirmClosing(ctx context.Context, sub uuid.UUID) {
	doc, err := m.get(ctx, sub)
	if err != nil {
		return
	}
	res, err := m.Contract.ConfirmClosing(ctx, sub, doc)
	switch {
	case errors.Is(err, store.ErrClosingContradicted):
		m.log().Error("contract apply: closing_contradicted", "sub", sub, "version", doc.Version)
		m.recordApplyError(ctx, store.ContractErrorClosingContradicted)
	case errors.Is(err, store.ErrClosingUnconfirmed):
		m.log().Warn("contract apply: a closing not confirmed", "sub", sub, "version", doc.Version)
	case err != nil:
		m.log().Error("contract apply: failed", "sub", sub, "step", "confirm_closing", "class", applyErrorClass(err))
		m.recordApplyError(ctx, store.ContractErrorApplyFailed)
	case !res.Already:
		m.log().Info("contract apply: closing confirmed", "sub", sub, "workspace", res.Workspace,
			"quarantined", res.Quarantined, "deleted", res.Deleted)
		m.revalidate()
	}
}

// applied tells the readers of the connections res ended, and wakes this
// process's sessions when res changed anything.
func (m *Members) applied(ctx context.Context, res store.ApplyResult) {
	if len(res.Ended) > 0 && m.Readers != nil {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.bound())
		for _, e := range res.Ended {
			m.Readers.TellRevoked(tctx, e.Reader, e.ID)
		}
		cancel()
	}
	for _, e := range res.Ended {
		m.log().Info("mcp connection revoked", "connection", e.ID, "reason", "contract_apply")
	}
	if res.Changed() {
		m.revalidate()
	}
}

func (m *Members) revalidate() {
	if m.Sockets != nil {
		m.Sockets.RevalidateAccess()
	}
}

// logApplied logs an apply by ids and counts (DB22): what it did, a part
// held, an operator's disable that stands.
func (m *Members) logApplied(res store.ApplyResult) {
	c := res.Counts
	if res.Changed() {
		id := []any{"sub", res.Sub}
		if res.Sub == uuid.Nil {
			id = []any{"workspace", res.Workspace}
		}
		m.log().Info("contract apply: applied", append(id, "version", res.Version,
			"added", c.Added, "roles", c.Roles, "enabled", c.Enabled, "lost", c.Lost, "teams_created", c.TeamsCreated,
			"renamed", c.Renamed, "closed", c.Closed, "reopened", c.Reopened, "sessions", c.Sessions, "keys", c.Keys,
			"connections", c.Connections, "keychain", c.Keychain, "services_removed", c.ServicesRemoved,
			"services_kept", c.ServicesKept, "strands", c.Strands)...)
	}
	if res.Held != "" {
		m.log().Warn("contract apply: held", "sub", res.Sub, "reason", res.Held)
	}
	if res.OperatorDisable {
		m.log().Warn("contract apply: operator disable stands", "sub", res.Sub)
	}
}

// applyFailed logs and records an apply's failure; one refused before
// enforce is neither.
func (m *Members) applyFailed(ctx context.Context, sub uuid.UUID, err error) error {
	if errors.Is(err, store.ErrApplyNeedsEnforce) || ctx.Err() != nil {
		return err
	}
	m.log().Error("contract apply: failed", "sub", sub, "class", applyErrorClass(err))
	m.recordApplyError(ctx, store.ContractErrorApplyFailed)
	return err
}

func (m *Members) applyFailedWorkspace(ctx context.Context, id uuid.UUID, err error) {
	if errors.Is(err, store.ErrApplyNeedsEnforce) || ctx.Err() != nil {
		return
	}
	m.log().Error("contract apply: failed", "workspace", id, "class", applyErrorClass(err))
	m.recordApplyError(ctx, store.ContractErrorApplyFailed)
}

func (m *Members) recordApplyError(ctx context.Context, class string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := m.Contract.RecordError(rctx, class); err != nil {
		m.log().Warn("contract: could not record an ERROR", "error", err)
	}
}

// applyErrorClass is a failure's class for a log line: a database error's
// SQLSTATE, a timeout, or other; never a message.
func applyErrorClass(err error) string {
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		return "sqlstate_" + pgErr.Code
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	}
	return "other"
}
