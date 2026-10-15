package store

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/wa"
)

// releaseAStrandedQuery is strandedDevicesTx as release A shipped it, kept
// here as the oracle sole_key_holders (0051) must agree with: a target that
// is a connection's service account (a membership with a deadline, or an
// account a connection names) strands nothing; otherwise every number on
// which the target's grant at a live epoch is the last one an active,
// undeadlined, non-connection member with Read holds.
const releaseAStrandedQuery = `SELECT DISTINCT doomed.device_id
	FROM device_key_grants doomed
	JOIN device_archive_keys k ON k.device_id=doomed.device_id AND k.epoch=doomed.epoch AND k.retired_at IS NULL
	JOIN workspace_memberships m ON m.tenant_id=doomed.tenant_id AND m.user_id=doomed.user_id AND m.status='active'
	JOIN users u ON u.id=m.user_id AND u.status='active'
	WHERE doomed.tenant_id=$1 AND doomed.user_id=$2 AND ($3::uuid IS NULL OR doomed.device_id=$3)
	AND NOT EXISTS(
		SELECT 1 FROM device_key_grants backup
		JOIN workspace_memberships bm ON bm.tenant_id=backup.tenant_id AND bm.user_id=backup.user_id AND bm.status='active'
			AND bm.expires_at IS NULL
		JOIN users bu ON bu.id=bm.user_id AND bu.status='active'
		JOIN device_permissions bp ON bp.tenant_id=backup.tenant_id AND bp.device_id=backup.device_id AND bp.user_id=backup.user_id AND bp.can_read
		WHERE backup.tenant_id=doomed.tenant_id AND backup.device_id=doomed.device_id AND backup.epoch=doomed.epoch AND backup.user_id<>$2
		AND NOT EXISTS(SELECT 1 FROM mcp_connections c WHERE c.service_user_id=backup.user_id)
	)
	ORDER BY doomed.device_id`

func releaseAStranded(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) ([]uuid.UUID, error) {
	var connectionService bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND expires_at IS NOT NULL)
		OR EXISTS(SELECT 1 FROM mcp_connections WHERE service_user_id=$2)`, tenant, target).Scan(&connectionService); err != nil {
		return nil, err
	}
	if connectionService {
		return nil, nil
	}
	rows, err := tx.Query(ctx, releaseAStrandedQuery, tenant, target, device)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// TestSoleKeyHoldersAgree is the plan's TB11: strandedDevicesTx, now read
// from sole_key_holders, gives what release A's query gave, for every
// member and every number of a workspace whose shape changes at random
// between rounds through each case of reader_safety_test.go and the
// deletion's test 13: a sole holder, one whose Read was withheld, two
// holders at once, a disabled membership or account, a connection's
// service account (by its deadline, by its connection, or both), a holder
// only at a retired epoch, several unretired epochs, a deleted number, a
// grant of someone who is no member, and a number nobody holds.
func TestSoleKeyHoldersAgree(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	users, keys, devices := NewUsers(pool), NewKeys(pool), NewDevices(pool)
	newTeam := func(name string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	tenant, elsewhere := newTeam("team"), newTeam("elsewhere")
	account := func(in uuid.UUID, role string) uuid.UUID {
		t.Helper()
		u, err := users.Create(ctx, NewUser{TenantID: in, Email: uuid.NewString()[:12] + "@sole.test", Role: role,
			AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	people := []uuid.UUID{account(tenant, "owner"), account(tenant, "admin")}
	for range 5 {
		people = append(people, account(tenant, "member"))
	}
	service := account(tenant, "member")
	// former leaves the team with its grants still there in some rounds;
	// stranger was never in it.
	former := account(tenant, "member")
	stranger := account(elsewhere, "member")
	everyone := append(slices.Clone(people), service, former)

	// Numbers with one to three epochs; a key per epoch.
	epochs := map[uuid.UUID]int{}
	var numbers []uuid.UUID
	for i, n := range []int{1, 2, 1, 3, 1} {
		d, err := devices.Create(ctx, tenant.String(), fmt.Sprintf("n%d", i), wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		device := uuid.MustParse(d.ID)
		for e := 1; e <= n; e++ {
			pub, _, err := seal.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.CreateArchiveKey(ctx, tenant, device, uint16(e), pub); err != nil {
				t.Fatal(err)
			}
		}
		epochs[device] = n
		numbers = append(numbers, device)
	}
	var apiKey uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, created_by)
		VALUES ($1, 'sole0001', 'hash', 'sole', $2) RETURNING id`, tenant, people[0]).Scan(&apiKey); err != nil {
		t.Fatal(err)
	}

	scoped := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
				return err
			}
			return fn(tx)
		}); err != nil {
			t.Fatal(err)
		}
	}
	rng := rand.New(rand.NewPCG(51, 11))
	chance := func(p float64) bool { return rng.Float64() < p }
	compared, stranded := 0, 0
	for round := range 40 {
		scoped(func(tx pgx.Tx) error {
			for _, q := range []string{`DELETE FROM device_key_grants WHERE tenant_id = $1`,
				`DELETE FROM device_permissions WHERE tenant_id = $1`, `DELETE FROM mcp_connections WHERE tenant_id = $1`} {
				if _, err := tx.Exec(ctx, q, tenant); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO workspace_memberships (tenant_id, user_id, role) VALUES ($1, $2, 'member')
				ON CONFLICT DO NOTHING`, tenant, former); err != nil {
				return err
			}
			for _, u := range append(slices.Clone(people), service) {
				status := "active"
				if chance(0.2) {
					status = "disabled"
				}
				var expires *time.Time
				if chance(0.15) || (u == service && chance(0.5)) {
					at := time.Now().Add(time.Hour)
					expires = &at
				}
				if _, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status = $3, expires_at = $4
					WHERE tenant_id = $1 AND user_id = $2`, tenant, u, status, expires); err != nil {
					return err
				}
				userStatus := "active"
				if chance(0.1) {
					userStatus = "disabled"
				}
				if _, err := tx.Exec(ctx, `UPDATE users SET status = $2 WHERE id = $1`, u, userStatus); err != nil {
					return err
				}
			}
			for _, device := range numbers {
				for e := 1; e <= epochs[device]; e++ {
					// The current epoch is never retired; an older one may be.
					retired := e < epochs[device] && chance(0.3)
					if _, err := tx.Exec(ctx, `UPDATE device_archive_keys SET retired_at = CASE WHEN $3 THEN now() END
						WHERE device_id = $1 AND epoch = $2`, device, e, retired); err != nil {
						return err
					}
					for _, u := range everyone {
						if !chance(0.35) {
							continue
						}
						if _, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk)
							VALUES ($1, $2, $3, $4, 'grant')`, tenant, device, u, e); err != nil {
							return err
						}
					}
				}
				for _, u := range append(slices.Clone(people), service) {
					// A grant sets Read and Send; a withheld Read, a row
					// without it, or no row at all replaces that.
					switch rng.IntN(4) {
					case 0:
						if _, err := tx.Exec(ctx, `DELETE FROM device_permissions WHERE tenant_id = $1 AND device_id = $2 AND user_id = $3`,
							tenant, device, u); err != nil {
							return err
						}
					case 1:
						if _, err := tx.Exec(ctx, `INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read)
							VALUES ($1, $2, $3, false) ON CONFLICT (tenant_id, device_id, user_id) DO UPDATE SET can_read = false`,
							tenant, device, u); err != nil {
							return err
						}
					case 2:
						if _, err := tx.Exec(ctx, `INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read)
							VALUES ($1, $2, $3, true) ON CONFLICT (tenant_id, device_id, user_id) DO UPDATE SET can_read = true`,
							tenant, device, u); err != nil {
							return err
						}
					}
				}
			}
			// The service account is a connection's in half the rounds.
			if chance(0.5) {
				if _, err := tx.Exec(ctx, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name,
					redirect_host, device_count, reader_kid, status, expires_at, kind, service_user_id, key_mode, consent_version, reader)
					VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, 'kid', 'active', now() + interval '1 day', 'content', $5,
					        'ephemeral', 1, 'enclave')`, tenant, fmt.Sprintf("req-%d", round), apiKey, people[0], service); err != nil {
					return err
				}
			}
			if chance(0.5) {
				if _, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2`,
					tenant, former); err != nil {
					return err
				}
			}
			// A deleted number is held to the same rule as a live one.
			_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = CASE WHEN $2 THEN now() END,
				purge_after = CASE WHEN $2 THEN now() + interval '30 days' END, paused = $2 OR paused WHERE id = $1`,
				numbers[2], chance(0.5))
			return err
		})

		targets := append(slices.Clone(everyone), stranger, uuid.New())
		devicesToAsk := []*uuid.UUID{nil}
		for i := range numbers {
			devicesToAsk = append(devicesToAsk, &numbers[i])
		}
		nobody := uuid.New()
		devicesToAsk = append(devicesToAsk, &nobody)
		scoped(func(tx pgx.Tx) error {
			for _, target := range targets {
				for _, device := range devicesToAsk {
					want, err := releaseAStranded(ctx, tx, tenant, target, device)
					if err != nil {
						return err
					}
					got, err := strandedDevicesTx(ctx, tx, tenant, target, device)
					if err != nil {
						return err
					}
					if !slices.Equal(got, want) {
						t.Errorf("round %d, target %s, device %v: sole_key_holders gives %v, release A gave %v",
							round, target, device, got, want)
					}
					compared++
					stranded += len(want)
				}
			}
			return nil
		})
	}
	// The rounds reached both answers, not only the empty one.
	if stranded == 0 || compared == 0 {
		t.Fatalf("%d comparisons stranded %d numbers: the fixture never reached a sole holder", compared, stranded)
	}
}
