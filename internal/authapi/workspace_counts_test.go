package authapi_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestWorkspaceDeviceCountsRespectVisibilityAndIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, ownerToken := memberAccount(t, h, "owner@counts.test", "owner")
	_, adminToken := memberAccount(t, h, "admin@counts.test", "admin")
	member, memberToken := memberAccount(t, h, "member@counts.test", "member")
	devices := store.NewDevices(h.pool)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// Three visible devices: send, manage and read with the current key. The
	// other three are hidden, read without any key and read with an old key.
	for _, mode := range []string{"hidden", "send", "manage", "read", "read-no-key", "read-old-key"} {
		device, err := devices.Create(ctx, h.tenant.String(), mode, wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(device.ID)
		if err := h.keys.CreateArchiveKey(ctx, h.tenant, id, 1, pub); err != nil {
			t.Fatal(err)
		}
		if mode == "read" || mode == "read-old-key" {
			if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: id, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &owner.ID); err != nil {
				t.Fatal(err)
			}
		}
		permission := store.DevicePermission{DeviceID: id, UserID: member.ID, Send: mode == "send", Manage: mode == "manage", Read: mode == "read" || mode == "read-no-key" || mode == "read-old-key"}
		if mode != "hidden" {
			if err := h.users.SetDevicePermission(ctx, h.tenant, owner.ID, permission); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "read-old-key" {
			if err := h.keys.CreateArchiveKey(ctx, h.tenant, id, 2, pub); err != nil {
				t.Fatal(err)
			}
		}
	}
	var personal uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, member.ID).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Create(ctx, personal.String(), "personal", wa.ModePassive); err != nil {
		t.Fatal(err)
	}
	var disabled, suspended, unrelated uuid.UUID
	for _, target := range []*uuid.UUID{&disabled, &suspended, &unrelated} {
		if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('other') RETURNING id`).Scan(target); err != nil {
			t.Fatal(err)
		}
		if _, err := devices.Create(ctx, target.String(), "other", wa.ModePassive); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []uuid.UUID{disabled, suspended} {
		if err := pg.InTenantTx(ctx, h.pool, target.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO workspace_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'owner',$3)`, target, member.ID, map[bool]string{true: "disabled", false: "active"}[target == disabled])
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.pool.Exec(ctx, `UPDATE tenants SET status='suspended' WHERE id=$1`, suspended); err != nil {
		t.Fatal(err)
	}
	countSessions := func() int {
		t.Helper()
		var count int
		if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&count)
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	before := countSessions()
	for _, tc := range []struct {
		name, token string
		want        int64
	}{{"owner", ownerToken, 6}, {"admin", adminToken, 6}, {"member", memberToken, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			var reply struct {
				Workspaces []struct {
					ID          uuid.UUID `json:"id"`
					Kind        string    `json:"kind"`
					DeviceCount *int64    `json:"device_count"`
				} `json:"workspaces"`
			}
			if code := h.get(t, "/v1/auth/workspaces", &reply, tc.token); code != http.StatusOK {
				t.Fatalf("list: %d", code)
			}
			seenTeam, seenPersonal, seenSuspended := false, false, false
			for _, space := range reply.Workspaces {
				if space.DeviceCount == nil {
					t.Fatalf("workspace %s lacks device_count", space.ID)
				}
				if space.ID == disabled || space.ID == unrelated {
					t.Fatal("disabled or unrelated workspace leaked")
				}
				switch space.ID {
				case h.tenant:
					seenTeam = true
					if *space.DeviceCount != tc.want {
						t.Fatalf("team count=%d, want %d", *space.DeviceCount, tc.want)
					}
				case personal:
					seenPersonal = true
					if *space.DeviceCount != 1 || space.Kind != "personal" {
						t.Fatalf("personal: %+v", space)
					}
				case suspended:
					seenSuspended = true
					if *space.DeviceCount != 0 {
						t.Fatal("suspended workspace exposed device count")
					}
				default:
					if space.Kind != "personal" || *space.DeviceCount != 0 {
						t.Fatalf("empty personal: %+v", space)
					}
				}
			}
			if !seenTeam || (tc.name == "member" && (!seenPersonal || !seenSuspended)) {
				t.Fatalf("missing workspace: team=%v personal=%v suspended=%v", seenTeam, seenPersonal, seenSuspended)
			}
		})
	}
	if after := countSessions(); after != before {
		t.Fatalf("listing issued sessions: before=%d after=%d", before, after)
	}
	_, current, err := h.users.ActiveSession(ctx, memberToken)
	if err != nil || current.TenantID != h.tenant {
		t.Fatalf("listing changed source session: %+v %v", current, err)
	}
}
