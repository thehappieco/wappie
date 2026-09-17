package seal_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

type ownedKeys struct {
	*memKeys
	want uuid.UUID
	t    *testing.T
}

func (k *ownedKeys) CreateContentKey(ctx context.Context, tenant, device uuid.UUID, epoch uint16, fn func(uint32) ([]byte, error)) (uint32, error) {
	if tenant != k.want {
		k.t.Fatalf("key stored in %s, want current owner %s", tenant, k.want)
	}
	return k.memKeys.CreateContentKey(ctx, tenant, device, epoch, fn)
}

func TestArchiveNamespaceSurvivesWorkspaceTransfer(t *testing.T) {
	pub, priv := keys(t)
	archiveTenant, personal := uuid.New(), uuid.New()
	store := &ownedKeys{memKeys: newMemKeys(), want: archiveTenant, t: t}
	old, err := seal.NewSealer(archiveTenant, testDevice, pub, 1, store)
	if err != nil {
		t.Fatal(err)
	}
	before, err := old.Seal(context.Background(), seal.KindBody, rowA, []byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	beforeID := old.CurrentKeyID()
	store.want = personal
	moved, err := seal.NewSealerWithArchiveTenant(personal, archiveTenant, testDevice, pub, 1, store)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Tenant() != personal {
		t.Fatal("sealer authorizes the previous workspace")
	}
	after, err := moved.Seal(context.Background(), seal.KindBody, rowA, []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id   uint32
		blob []byte
		want string
	}{
		{beforeID, before, "before"}, {moved.CurrentKeyID(), after, "after"},
	} {
		key, err := seal.OpenContentKey(priv, archiveTenant, testDevice, tc.id, store.stored[tc.id])
		if err != nil {
			t.Fatal(err)
		}
		text, err := key.Open(seal.KindBody, archiveTenant, rowA, tc.blob)
		if err != nil || string(text) != tc.want {
			t.Fatalf("open: %q, %v", text, err)
		}
		if _, err := key.Open(seal.KindBody, personal, rowA, tc.blob); err == nil {
			t.Fatal("workspace authorization ID bypassed the immutable archive binding")
		}
	}
}
