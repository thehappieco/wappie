package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// The owners' number_moved_out notice (the plan's DB14). Only the Team's
// only owner moves a number (decision 0043), so a second owner is one who
// joined between the transfer's check and its moved_out row: a trigger on
// device_transfers, which the transfer inserts just before the row, makes
// a member an owner there. That owner is told, by the Team's notices; the
// mover never is. A purge of the moved number leaves the notice no name.
func TestMovedOutNotice(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	joiner := w.person(t, "joiner", "member")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), true); err != nil {
		t.Fatal(err)
	}
	w.exec(t, `CREATE FUNCTION join_as_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		UPDATE workspace_memberships SET role = 'owner' WHERE tenant_id = NEW.source_workspace_id AND user_id = '`+joiner.String()+`';
		RETURN NEW; END $$;
		CREATE TRIGGER join_as_owner AFTER INSERT ON device_transfers FOR EACH ROW EXECUTE FUNCTION join_as_owner()`)
	if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, device, personal); err != nil {
		t.Fatal(err)
	}
	got := w.noticesOfKind(t, joiner, store.NoticeNumberMovedOut)
	if len(got) != 1 || got[0].DeviceID != device || got[0].Label == nil || *got[0].Label != "Vendas" || got[0].Hint == nil ||
		got[0].RaisedByKind != "person" || got[0].RaisedByName == nil || got[0].Until != nil {
		t.Fatalf("the other owner's notices: %+v", got)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE user_id = $1`, w.owner); n != 0 {
		t.Fatalf("the mover has %d notices", n)
	}
	if n := w.count(t, `SELECT count(*) FROM item_events WHERE item_id = $1 AND type = 'moved_out'`, device); n != 1 {
		t.Fatalf("%d moved_out rows", n)
	}

	// The number goes for good from Personal: the Team's notice keeps no
	// name, and stays until it is seen.
	if _, err := w.devices.Quarantine(ctx, personal, w.owner, device, nil); err != nil {
		t.Fatal(err)
	}
	if res, err := store.PurgeDevice(ctx, w.pool, personal, device, nil, store.PurgeOptions{Now: true}); err != nil || !res.Final {
		t.Fatalf("the purge: %+v %v", res, err)
	}
	got = w.noticesOfKind(t, joiner, store.NoticeNumberMovedOut)
	if len(got) != 1 || got[0].Label != nil || got[0].Hint != nil {
		t.Fatalf("after the purge: %+v", got)
	}
	left, err := w.devices.SeeNotices(ctx, w.tenant, joiner, []store.SeenNotice{{ID: got[0].ID}})
	if err != nil || len(left) != 0 {
		t.Fatalf("seen by its bare id: %+v %v", left, err)
	}
}
