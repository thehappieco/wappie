package authapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The storage screen shows an owner what a deleted number still stores, and
// an admin, who may not learn that a number is waiting for its purge, the
// same totals with those bytes in the unlabelled line.
func TestStorageScreenShowsExcludedBytesToOwnersOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, ownerToken := memberAccount(t, h, "owner@storage.test", "owner")
	_, adminToken := memberAccount(t, h, "admin@storage.test", "admin")
	device, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "Vendas", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	if _, err := store.NewMessages(h.pool).Insert(ctx, store.InsertMessage{UID: uid, TenantID: h.tenant, DeviceID: uuid.MustParse(device.ID),
		WAID: "photo", ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceLive, TS: time.Now(),
		BodySealed: []byte{1}, Media: &store.InsertMedia{MediaType: "image", FileEncSHA256: []byte("photo")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.NewMedia(h.pool).MarkDone(ctx, h.tenant, uid, "photo/object", 10); err != nil {
		t.Fatal(err)
	}
	type reply struct {
		UsedBytes int64 `json:"used_bytes"`
		Breakdown struct {
			Devices    []json.RawMessage  `json:"devices"`
			Unassigned store.StorageBytes `json:"unassigned"`
			Excluded   store.StorageBytes `json:"excluded"`
		} `json:"breakdown"`
	}
	screen := func(token string) reply {
		t.Helper()
		var out reply
		if code := h.get(t, "/v1/auth/workspaces/storage", &out, token); code != http.StatusOK {
			t.Fatalf("the storage screen answered %d", code)
		}
		return out
	}
	live := screen(ownerToken)
	if len(live.Breakdown.Devices) != 1 || live.Breakdown.Excluded != (store.StorageBytes{}) {
		t.Fatalf("before the deletion: %+v", live.Breakdown)
	}

	// The workspace's one number excluded as the table owner, with the
	// policy lifted: the deletion that does it for real comes with its own
	// handler.
	if _, err := h.pool.Exec(ctx, `ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
		UPDATE devices SET deleted_at=now(), purge_after=now()+interval '30 days', paused=true;
		ALTER TABLE devices ENABLE ROW LEVEL SECURITY; ALTER TABLE devices FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	owner, admin := screen(ownerToken), screen(adminToken)
	if len(owner.Breakdown.Devices) != 0 || owner.Breakdown.Excluded.ObjectBytes != 10 || owner.Breakdown.Excluded.UsedBytes == 0 {
		t.Fatalf("the owner's breakdown: %+v", owner.Breakdown)
	}
	want := owner.Breakdown.Unassigned
	want.ArchiveBytes += owner.Breakdown.Excluded.ArchiveBytes
	want.ObjectBytes += owner.Breakdown.Excluded.ObjectBytes
	want.UsedBytes += owner.Breakdown.Excluded.UsedBytes
	if admin.Breakdown.Excluded != (store.StorageBytes{}) || admin.Breakdown.Unassigned != want || admin.UsedBytes != owner.UsedBytes {
		t.Fatalf("the admin's breakdown %+v, the owner's %+v", admin.Breakdown, owner.Breakdown)
	}
}
