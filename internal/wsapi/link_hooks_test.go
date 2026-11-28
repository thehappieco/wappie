package wsapi_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// moveHooks records the contract's move check (E0 slice 19), and whether
// a workspace's row was held while it ran.
type moveHooks struct {
	c *deletionConsole

	mu     sync.Mutex
	order  []string
	moved  int64
	locked bool
}

func (h *moveHooks) Linked(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID, wa.Identity) {}

func (h *moveHooks) BeforeMove(ctx context.Context, source, target, _ uuid.UUID, moved int64) {
	tx, err := h.c.pool.Begin(ctx)
	locked := err != nil
	if err == nil {
		defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // read only
		_, err = tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id IN ($1, $2) FOR UPDATE NOWAIT`, source, target)
		locked = err != nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.order, h.moved, h.locked = append(h.order, "check"), moved, locked
}

// TestMoveCheckRunsBeforeTheTransaction: a move's link check runs after
// the preview and before the move's transaction, holding no workspace's
// row, with the preview's bytes; the move then commits.
func TestMoveCheckRunsBeforeTheTransaction(t *testing.T) {
	hooks := &moveHooks{}
	var c *deletionConsole
	c = newDeletionConsoleWith(t, deletionOptions{links: hooks,
		transfer: func(ctx context.Context, source, actor, device, target uuid.UUID) (store.PersonalTransferPreview, error) {
			hooks.mu.Lock()
			hooks.order = append(hooks.order, "move")
			hooks.mu.Unlock()
			return c.devices.TransferPersonal(ctx, source, actor, device, target)
		}})
	hooks.c = c
	device := c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	personal := c.personalOf(t, c.owner)
	owner := wsapi.Hello{Session: c.token}
	preview := payload[store.PersonalTransferPreview](t, ask(t, c.console, owner, wsapi.TypeDeviceTransferPreview,
		wsapi.DeviceRef{DeviceID: device.String()}))
	if f := ask(t, c.console, owner, wsapi.TypeDeviceTransfer, transferFrame(device, personal)); f.Type != wsapi.TypeDeviceTransferred {
		t.Fatalf("the move: %s %s", f.Type, f.Payload)
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if len(hooks.order) != 2 || hooks.order[0] != "check" || hooks.order[1] != "move" {
		t.Fatalf("the order: %v", hooks.order)
	}
	if hooks.locked {
		t.Fatal("a workspace's row was held during the move's check")
	}
	if hooks.moved != preview.ArchiveBytes+preview.ObjectBytes {
		t.Fatalf("the check had %d bytes, the preview %d", hooks.moved, preview.ArchiveBytes+preview.ObjectBytes)
	}
}
