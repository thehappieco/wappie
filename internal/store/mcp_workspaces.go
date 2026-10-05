package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// AssistantSwitches are what a workspace's owner lets assistants do in it
// (0047, docs/mcp-enclave.md §19.30): read message text, open attachments,
// prepare drafts (and notes to the number's own chat), and run AI
// integrations. Nil is the deployment's default for that switch. They only
// narrow what the operator allows: the kill switches, the deny list and the
// enclave's workspaces come first, and each rides on the one before it.
type AssistantSwitches struct {
	Text, Media, Send, AI *bool
	// SwitchedAt and SwitchedBy are when, and by whom, they last changed;
	// nil before the first change, and SwitchedBy also once that account
	// is gone.
	SwitchedAt *time.Time
	SwitchedBy *uuid.UUID
}

// Set reports whether any switch has a value of its own.
func (a AssistantSwitches) Set() bool {
	return a.Text != nil || a.Media != nil || a.Send != nil || a.AI != nil
}

// WorkspaceSwitches returns the assistant switches of every workspace that
// set any, by workspace. tenants carries no policy, so one read sees them all.
func (m *MCPConnections) WorkspaceSwitches(ctx context.Context) (map[uuid.UUID]AssistantSwitches, error) {
	rows, err := m.pool.Query(ctx, `SELECT id, mcp_text, mcp_media, mcp_send, mcp_ai, mcp_switched_at, mcp_switched_by FROM tenants
		WHERE mcp_text IS NOT NULL OR mcp_media IS NOT NULL OR mcp_send IS NOT NULL OR mcp_ai IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("store: read the workspaces' assistant switches: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]AssistantSwitches{}
	for rows.Next() {
		var id uuid.UUID
		var a AssistantSwitches
		if err := rows.Scan(&id, &a.Text, &a.Media, &a.Send, &a.AI, &a.SwitchedAt, &a.SwitchedBy); err != nil {
			return nil, fmt.Errorf("store: read the workspaces' assistant switches: %w", err)
		}
		out[id] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read the workspaces' assistant switches: %w", err)
	}
	return out, nil
}

// WorkspaceSwitchesOf returns one workspace's assistant switches.
func (m *MCPConnections) WorkspaceSwitchesOf(ctx context.Context, tenant uuid.UUID) (AssistantSwitches, error) {
	var a AssistantSwitches
	err := m.pool.QueryRow(ctx, `SELECT mcp_text, mcp_media, mcp_send, mcp_ai, mcp_switched_at, mcp_switched_by FROM tenants WHERE id=$1`, tenant).
		Scan(&a.Text, &a.Media, &a.Send, &a.AI, &a.SwitchedAt, &a.SwitchedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return AssistantSwitches{}, ErrNotFound
	}
	if err != nil {
		return AssistantSwitches{}, fmt.Errorf("store: read a workspace's assistant switches: %w", err)
	}
	return a, nil
}

// SetWorkspaceSwitches records what a workspace's owner lets assistants do
// in it, every switch given. Only an active owner of an active workspace may;
// anyone else is ErrMembershipForbidden. The connections already consented
// keep their consent: the switches answer every status check, so what is
// turned off stops within the readers' minute. The reader drops a key it may
// no longer use, so once text is on again each content connection waits in
// reseal until the person renews it.
func (m *MCPConnections) SetWorkspaceSwitches(ctx context.Context, tenant, actor uuid.UUID, text, media, send, ai bool) (AssistantSwitches, error) {
	var out AssistantSwitches
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := lockWorkspaceManager(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		if role != "owner" {
			return ErrMembershipForbidden
		}
		return tx.QueryRow(ctx, `UPDATE tenants SET mcp_text=$2, mcp_media=$3, mcp_send=$4, mcp_ai=$5, mcp_switched_at=now(), mcp_switched_by=$6
			WHERE id=$1 RETURNING mcp_text, mcp_media, mcp_send, mcp_ai, mcp_switched_at, mcp_switched_by`, tenant, text, media, send, ai, actor).
			Scan(&out.Text, &out.Media, &out.Send, &out.AI, &out.SwitchedAt, &out.SwitchedBy)
	})
	if err != nil {
		return AssistantSwitches{}, err
	}
	return out, nil
}
