package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestDeviceRenamePauseAndCleanupRespectWorkspace(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "device owner")
	other := newTenant(t, pool, "other workspace")
	dev, err := devices.Create(ctx, tenant, "Pending", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err = devices.Rename(ctx, other, dev.ID, "wrong"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross workspace rename: %v", err)
	}
	if err = devices.SetPaused(ctx, other, dev.ID, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross workspace pause: %v", err)
	}
	if err = devices.DeleteUnpaired(ctx, other, dev.ID); err != nil {
		t.Fatal(err)
	}
	if err = devices.Rename(ctx, tenant, dev.ID, "   Atendimento   "); err != nil {
		t.Fatal(err)
	}
	if err = devices.Rename(ctx, tenant, dev.ID, strings.Repeat("x", 101)); err == nil {
		t.Fatal("oversized name accepted")
	}
	if err = devices.SetPaused(ctx, tenant, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err := devices.Get(ctx, tenant, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "Atendimento" || !got.Paused {
		t.Fatalf("updated device = %+v", got)
	}
	if err = devices.DeleteUnpaired(ctx, tenant, dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = devices.Get(ctx, tenant, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pending device retained")
	}
}

func TestPairCleanupCannotEraseACompletedConnection(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "paired")
	for _, proof := range []string{"identity", "connection"} {
		dev, err := devices.Create(ctx, tenant, proof, wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		if proof == "identity" {
			err = devices.SetIdentity(ctx, tenant, dev.ID, wa.Identity{PN: types.JID{User: "5511999999999", Server: types.DefaultUserServer}})
		} else {
			err = devices.SetStatus(ctx, tenant, dev.ID, wa.StatusOnline, "")
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = devices.DeleteUnpaired(ctx, tenant, dev.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = devices.Get(ctx, tenant, dev.ID); err != nil {
			t.Fatalf("cleanup erased paired device: %v", err)
		}
	}
}
