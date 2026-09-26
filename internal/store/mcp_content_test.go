package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/access"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Content connections read as a service account of their own. These tests
// run as an ordinary role (NOSUPERUSER, NOBYPASSRLS, checked by
// newMCPFixture), so a cascade that forgot its tenant transaction deletes
// nothing and fails here.

type contentFixture struct {
	*mcpFixture
	users  *store.Users
	grants *store.Keys
}

// newContentFixture is the MCP fixture with an archive key on the device
// and the owner holding its grant and read permission, as a workspace that
// reads its archive does.
func newContentFixture(t *testing.T) *contentFixture {
	t.Helper()
	ctx := context.Background()
	f := &contentFixture{mcpFixture: newMCPFixture(t)}
	f.users, f.grants = store.NewUsers(f.pool), store.NewKeys(f.pool)
	f.archiveKey(ctx, t, f.device, 1)
	f.ownerReads(ctx, t, f.owner, f.device)
	return f
}

func (f *contentFixture) archiveKey(ctx context.Context, t *testing.T, device uuid.UUID, epoch uint16) {
	t.Helper()
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.grants.CreateArchiveKey(ctx, f.tenant, device, epoch, pub); err != nil {
		t.Fatal(err)
	}
}

// ownerReads gives a person the device's grant and read permission.
func (f *contentFixture) ownerReads(ctx context.Context, t *testing.T, person, device uuid.UUID) {
	t.Helper()
	if err := f.grants.PutGrant(ctx, store.Grant{TenantID: f.tenant, DeviceID: device, UserID: person, Epoch: 1, SealedDSK: []byte("a person's grant")}, &f.owner); err != nil {
		t.Fatal(err)
	}
	if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: device, UserID: person, Read: true, Send: true}); err != nil {
		t.Fatal(err)
	}
}

// contentConsent is what the console builds before it records a content
// consent: a provisional service account whose public key is the attested
// key, read-only on the key's devices, holding one grant per device, and a
// twenty-minute key acting as it.
type contentConsent struct {
	service    uuid.UUID
	publicKey  []byte
	key        string
	prefix     string
	in         store.CreateMCPConnection
	actor      uuid.UUID
	devices    []uuid.UUID
	grantEpoch uint16
}

type consentOption func(*contentConsent)

func withDevices(devices ...uuid.UUID) consentOption {
	return func(c *contentConsent) { c.devices = devices }
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// provisionalService registers a service account the way a content consent
// does, through a provisional invitation, with the given public key.
func (f *contentFixture) provisionalService(ctx context.Context, t *testing.T, actor uuid.UUID, pub []byte) uuid.UUID {
	t.Helper()
	secret, _, err := f.users.NewProvisionalServiceInvitation(ctx, f.tenant, actor)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := f.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(randomBytes(t, 4)), pub)
	if err != nil {
		t.Fatal(err)
	}
	return svc.ID
}

func (f *contentFixture) prepareContent(ctx context.Context, t *testing.T, actor uuid.UUID, opts ...consentOption) contentConsent {
	t.Helper()
	c := contentConsent{actor: actor, devices: []uuid.UUID{f.device}, grantEpoch: 1, publicKey: randomBytes(t, 32)}
	for _, o := range opts {
		o(&c)
	}
	c.service = f.provisionalService(ctx, t, actor, c.publicKey)
	for _, device := range c.devices {
		if err := f.users.SetDevicePermission(ctx, f.tenant, actor, store.DevicePermission{DeviceID: device, UserID: c.service, Read: true}); err != nil {
			t.Fatal(err)
		}
		if err := f.grants.PutGrant(ctx, store.Grant{TenantID: f.tenant, DeviceID: device, UserID: c.service, Epoch: c.grantEpoch, SealedDSK: []byte("sealed to the attested key")}, &actor); err != nil {
			t.Fatal(err)
		}
	}
	in := time.Now().Add(20 * time.Minute)
	key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "assistant", store.ScopeRead, &actor, &c.service, c.devices, &in)
	if err != nil {
		t.Fatal(err)
	}
	c.key = key
	c.prefix, _, _ = strings.Cut(key, ".")
	c.in = consent(c.prefix)
	c.in.DeviceCount = len(c.devices)
	c.in.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	c.in.Reader, c.in.Kind, c.in.ServiceUserID = "enclave", store.KindContent, c.service
	c.in.KeyMode, c.in.ConsentVersion, c.in.ReaderPublicKey = store.KeyModeEphemeral, store.ContentConsentVersion, c.publicKey
	return c
}

// consentContent records and activates a content connection.
func (f *contentFixture) consentContent(ctx context.Context, t *testing.T, actor uuid.UUID) (store.MCPConnection, contentConsent) {
	t.Helper()
	c := f.prepareContent(ctx, t, actor)
	conn, err := f.conns.Create(ctx, f.tenant, actor, c.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn, c
}

// inTenant runs a read in the workspace's transaction, as the application
// would; outside one, the policy-protected tables show nothing.
func (f *contentFixture) inTenant(ctx context.Context, t *testing.T, fn func(pgx.Tx) error) {
	t.Helper()
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), fn); err != nil {
		t.Fatal(err)
	}
}

// serviceTrace counts what an account holds in the workspace.
type serviceTrace struct{ grants, permissions, memberships, liveKeys int }

func (f *contentFixture) trace(ctx context.Context, t *testing.T, user uuid.UUID) serviceTrace {
	t.Helper()
	var s serviceTrace
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM device_key_grants WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM device_permissions WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM api_keys WHERE tenant_id=$1 AND acts_as=$2 AND revoked_at IS NULL)`, f.tenant, user).
			Scan(&s.grants, &s.permissions, &s.memberships, &s.liveKeys)
	})
	return s
}

func (f *contentFixture) row(ctx context.Context, t *testing.T, id string) store.MCPConnection {
	t.Helper()
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range listed {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("connection %s not listed", id)
	return store.MCPConnection{}
}

func (f *contentFixture) membershipExpiry(ctx context.Context, t *testing.T, user uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT expires_at FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2`, f.tenant, user).Scan(&at)
	})
	return at
}

func allowAll(uuid.UUID) bool { return true }

// ---------------------------------------------------------------------------

func TestCreateContentConnectionInvariants(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()

	t.Run("the consent the console builds", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		// Provisional: the account's membership has the consent's window.
		if at := f.membershipExpiry(ctx, t, c.service); at == nil || time.Until(*at) > store.ProvisionalServiceTTL || time.Until(*at) < 25*time.Minute {
			t.Fatalf("provisional membership expires %v", at)
		}
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, c.in)
		if err != nil {
			t.Fatal(err)
		}
		if conn.Kind != store.KindContent || conn.ServiceUserID == nil || *conn.ServiceUserID != c.service || conn.KeyMode != store.KeyModeEphemeral {
			t.Fatalf("connection = %+v", conn)
		}
		got := f.row(ctx, t, conn.ID)
		if got.Kind != store.KindContent || got.KeyMode != store.KeyModeEphemeral || got.ServiceUserID == nil || *got.ServiceUserID != c.service {
			t.Fatalf("listed = %+v", got)
		}
		// The key and the account now live exactly as long as the consent.
		if at := f.membershipExpiry(ctx, t, c.service); at == nil || at.Sub(c.in.ExpiresAt).Abs() > time.Second {
			t.Fatalf("membership expires %v, consent %v", at, c.in.ExpiresAt)
		}
		keys, _ := f.keys.List(ctx, f.tenant.String())
		for _, k := range keys {
			if k.Prefix == c.prefix && (k.ExpiresAt == nil || k.ExpiresAt.Sub(c.in.ExpiresAt).Abs() > time.Second) {
				t.Fatalf("key expires %v", k.ExpiresAt)
			}
		}
		// A second consent may not name the same account, even with a fresh
		// key acting as it.
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "again", store.ScopeRead, &f.owner, &c.service, []uuid.UUID{f.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		again := c.in
		again.RequestID = uuid.NewString()
		again.KeyPrefix, _, _ = strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, again); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a service account was reused: %v", err)
		}
		if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
			t.Fatal(err)
		}
	})

	refuse := func(t *testing.T, c contentConsent, want error) {
		t.Helper()
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, want) {
			t.Fatalf("err = %v, want %v", err, want)
		}
	}
	t.Run("key acts as nobody", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "plain", store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		c.in.KeyPrefix, _, _ = strings.Cut(key, ".")
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("key acts as another service", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		other := f.prepareContent(ctx, t, f.owner)
		c.in.KeyPrefix = other.prefix
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("public key is not the attested one", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		c.in.ReaderPublicKey = randomBytes(t, 32)
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("service may send", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: f.device, UserID: c.service, Read: true, Send: true}); err != nil {
			t.Fatal(err)
		}
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("service holds no grant", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		f.inTenant(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE tenant_id=$1 AND user_id=$2`, f.tenant, c.service)
			return err
		})
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("permission beyond the key's devices", func(t *testing.T) {
		dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "second", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		c := f.prepareContent(ctx, t, f.owner)
		if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: uuid.MustParse(dev.ID), UserID: c.service, Read: true}); err != nil {
			t.Fatal(err)
		}
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("an ordinary service account", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		// Without a deadline the account is not one a consent made.
		f.inTenant(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at=NULL WHERE tenant_id=$1 AND user_id=$2`, f.tenant, c.service)
			return err
		})
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("an old service account", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		f.inTenant(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE users SET created_at=now()-interval '31 minutes' WHERE id=$1`, c.service)
			return err
		})
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("hosted reader", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		c.in.Reader = ""
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("longer than ninety days", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		c.in.ExpiresAt = time.Now().Add(92 * 24 * time.Hour)
		refuse(t, c, store.ErrInvalidExpiry)
	})
	t.Run("metadata with a service account", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		c.in.Kind = store.KindMetadata
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); err == nil {
			t.Fatal("a metadata connection took a service account")
		}
	})
	t.Run("a grant at a retired epoch", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		// The device moves to epoch 2; the grant sealed at 1 is stale.
		f.archiveKey(ctx, t, f.device, 2)
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	// Nothing refused left a row behind.
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 1 || listed[0].Status != "revoked" {
		t.Fatalf("rows = %+v %v", listed, err)
	}
}

// A provisional account stops authenticating when its window closes, before
// any janitor: the key acting as it is refused with it.
func TestProvisionalServiceMembershipExpires(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	c := f.prepareContent(ctx, t, f.owner)
	if _, err := access.Authenticate(ctx, c.key, f.keys, f.users); err != nil {
		t.Fatalf("the key was refused inside the window: %v", err)
	}
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2`, f.tenant, c.service)
		return err
	})
	if _, err := f.users.Get(ctx, f.tenant, c.service); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired membership was found: %v", err)
	}
	if _, err := access.Authenticate(ctx, c.key, f.keys, f.users); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("a key acting as an expired account authenticated: %v", err)
	}
	// A consent is refused too.
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
		t.Fatalf("an expired account was bound: %v", err)
	}
	// Only a service invitation can be provisional.
	if _, err := f.pool.Exec(ctx, `INSERT INTO invites(id,invite_id,tenant_id,role,created_by,expires_at,provisional)
		VALUES($1,$2,$3,'member',$4,now()+interval '1 hour',true)`, uuid.New(), randomBytes(t, 32), f.tenant, f.owner); err == nil {
		t.Fatal("a provisional invitation for a person was stored")
	}
}

// Every way a content connection ends takes its key and its service
// account's grants, permissions and membership with it, in one transaction,
// under row-level security.
func TestRevokeContentCascadesUnderRLS(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()

	check := func(t *testing.T, conn store.MCPConnection, c contentConsent, status, reason string) {
		t.Helper()
		got := f.row(ctx, t, conn.ID)
		if got.Status != status || got.RevokeReason != reason {
			t.Fatalf("row = %s/%s, want %s/%s", got.Status, got.RevokeReason, status, reason)
		}
		if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the connection's key still works: %v", err)
		}
		if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
			t.Fatalf("the service account kept %+v", tr)
		}
		// The person's own access is untouched.
		if tr := f.trace(ctx, t, f.owner); tr.grants != 1 || tr.permissions != 1 || tr.memberships != 1 {
			t.Fatalf("the owner's access changed: %+v", tr)
		}
	}

	t.Run("console", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		reader, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID)
		if err != nil || reader != "enclave" {
			t.Fatalf("revoke = %q %v", reader, err)
		}
		check(t, conn, c, "revoked", store.ReasonConsole)
	})
	t.Run("reader", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		if err := f.conns.RevokeByID(ctx, "enclave", conn.ID, store.ReasonReader); err != nil {
			t.Fatal(err)
		}
		check(t, conn, c, "revoked", store.ReasonReader)
	})
	t.Run("reuse detected", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		if err := f.conns.RevokeByID(ctx, "enclave", conn.ID, store.ReasonReuseDetected); err != nil {
			t.Fatal(err)
		}
		check(t, conn, c, "revoked", store.ReasonReuseDetected)
		if err := f.conns.RevokeByID(ctx, "enclave", conn.ID, "console"); err == nil {
			t.Fatal("a reader revoked with a console reason")
		}
	})
	t.Run("relay failed", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, c.in)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.conns.DeleteFailed(ctx, conn.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the key survived a failed hand-off: %v", err)
		}
		if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
			t.Fatalf("the service account survived a failed hand-off: %+v", tr)
		}
		listed, _ := f.conns.List(ctx, f.tenant)
		for _, l := range listed {
			if l.ID == conn.ID {
				t.Fatal("the row survived a failed hand-off")
			}
		}
	})
	t.Run("janitor, pending", func(t *testing.T) {
		c := f.prepareContent(ctx, t, f.owner)
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, c.in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET created_at=now()-interval '30 minutes' WHERE id=$1`, conn.ID); err != nil {
			t.Fatal(err)
		}
		if n, err := store.ExpireMCPConnections(ctx, f.pool, 20*time.Minute); err != nil || n != 1 {
			t.Fatalf("settled %d %v", n, err)
		}
		check(t, conn, c, "revoked", store.ReasonPendingExpired)
	})
	t.Run("janitor, expired", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		if err := f.conns.Reseal(ctx, "enclave", conn.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET expires_at=now()-interval '1 minute' WHERE id=$1`, conn.ID); err != nil {
			t.Fatal(err)
		}
		if n, err := store.ExpireMCPConnections(ctx, f.pool, 20*time.Minute); err != nil || n != 1 {
			t.Fatalf("settled %d %v", n, err)
		}
		check(t, conn, c, "expired", store.ReasonExpired)
	})
	t.Run("service removed", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		if err := f.users.RemoveMember(ctx, f.tenant, f.owner, c.service); err != nil {
			t.Fatal(err)
		}
		check(t, conn, c, "revoked", store.ReasonServiceRemoved)
	})
	t.Run("service disabled", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		if err := f.users.UpdateMember(ctx, f.tenant, f.owner, c.service, store.RoleService, "disabled"); err != nil {
			t.Fatal(err)
		}
		check(t, conn, c, "revoked", store.ReasonServiceDisabled)
	})
	for _, removed := range []bool{true, false} {
		name, reason := "consenter disabled", store.ReasonMemberDisabled
		if removed {
			name, reason = "consenter removed", store.ReasonMemberRemoved
		}
		admin, _ := transferOwner(t, f.archive, "admin")
		t.Run(name, func(t *testing.T) {
			conn, c := f.consentContent(ctx, t, admin)
			// Any kind: their metadata connection ends too.
			_, prefix := f.adminKey(ctx, t, admin)
			meta, err := f.conns.Create(ctx, f.tenant, admin, consent(prefix))
			if err != nil {
				t.Fatal(err)
			}
			if removed {
				err = f.users.RemoveMember(ctx, f.tenant, f.owner, admin)
			} else {
				err = f.users.UpdateMember(ctx, f.tenant, f.owner, admin, "admin", "disabled")
			}
			if err != nil {
				t.Fatal(err)
			}
			check(t, conn, c, "revoked", reason)
			if got := f.row(ctx, t, meta.ID); got.Status != "revoked" || got.RevokeReason != reason {
				t.Fatalf("the consenter's metadata connection = %s/%s", got.Status, got.RevokeReason)
			}
		})
	}
	t.Run("access lost", func(t *testing.T) {
		conn, c := f.consentContent(ctx, t, f.owner)
		if err := f.keys.Revoke(ctx, f.tenant.String(), c.prefix); err != nil {
			t.Fatal(err)
		}
		answer, err := f.conns.Status(ctx, "enclave", conn.ID, allowAll)
		if err != nil || answer.Status != "revoked" {
			t.Fatalf("status = %+v %v", answer, err)
		}
		check(t, conn, c, "revoked", store.ReasonAccessLost)
	})
}

// adminKey issues a provisional metadata key for another manager.
func (f *contentFixture) adminKey(ctx context.Context, t *testing.T, admin uuid.UUID) (string, string) {
	t.Helper()
	in := time.Now().Add(20 * time.Minute)
	key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "meta", store.ScopeRead, &admin, nil, []uuid.UUID{f.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	return key, prefix
}

// A connection service account holds a grant sealed to a key that lives
// only in the reader; after a restart nobody can open it. It must never be
// what lets the last person with the archive key give it up.
func TestReaderSafetyIgnoresConnectionService(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	conn, c := f.consentContent(ctx, t, f.owner)
	// An abandoned provisional account does not count either.
	f.prepareContent(ctx, t, f.owner)

	if err := f.grants.RevokeGrant(ctx, f.tenant, f.device, f.owner); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("the owner gave up the last envelope with only a connection service holding a copy: %v", err)
	}
	if err := f.users.SetDevicePermission(ctx, f.tenant, f.owner, store.DevicePermission{DeviceID: f.device, UserID: f.owner}); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("the owner's read was withdrawn: %v", err)
	}
	// The service account itself is never the last reader: removing it
	// needs no backup.
	if err := f.users.RemoveMember(ctx, f.tenant, f.owner, c.service); err != nil {
		t.Fatalf("the connection's service could not be removed: %v", err)
	}
	if got := f.row(ctx, t, conn.ID); got.Status != "revoked" {
		t.Fatalf("status = %s", got.Status)
	}
	// A person with a grant is still a backup.
	member, _ := transferOwner(t, f.archive, "member")
	f.ownerReads(ctx, t, member, f.device)
	if err := f.grants.RevokeGrant(ctx, f.tenant, f.device, f.owner); err != nil {
		t.Fatalf("a person's backup did not count: %v", err)
	}
}

// The reader asks about a content connection every minute. What it hears
// follows the access behind the connection, not only the row.
func TestStatusRevokedWhenServiceGone(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()

	conn, c := f.consentContent(ctx, t, f.owner)
	answer, err := f.conns.Status(ctx, "enclave", conn.ID, allowAll)
	if err != nil || answer.Status != "active" || answer.Kind != store.KindContent || answer.ServiceUserID == nil || *answer.ServiceUserID != c.service {
		t.Fatalf("status = %+v %v", answer, err)
	}
	// Content switched off for the workspace: reseal, computed, not written.
	answer, err = f.conns.Status(ctx, "enclave", conn.ID, func(uuid.UUID) bool { return false })
	if err != nil || answer.Status != "reseal" {
		t.Fatalf("switched off = %+v %v", answer, err)
	}
	if answer, _ = f.conns.Status(ctx, "enclave", conn.ID, nil); answer.Status != "reseal" {
		t.Fatalf("nil policy = %+v", answer)
	}
	if got := f.row(ctx, t, conn.ID); got.Status != "active" {
		t.Fatalf("the computed reseal was written: %s", got.Status)
	}
	// Another reader learns nothing.
	if _, err := f.conns.Status(ctx, store.HostedReader, conn.ID, allowAll); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("hosted status of a content row: %v", err)
	}

	// The service account's membership vanished behind the ledger's back.
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2`, f.tenant, c.service)
		return err
	})
	answer, err = f.conns.Status(ctx, "enclave", conn.ID, allowAll)
	if err != nil || answer.Status != "revoked" {
		t.Fatalf("status without the service = %+v %v", answer, err)
	}
	got := f.row(ctx, t, conn.ID)
	if got.RevokeReason != store.ReasonAccessLost {
		t.Fatalf("reason = %q", got.RevokeReason)
	}
	if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the key survived: %v", err)
	}
	// The reader heard it in the answer; no notice is owed.
	if ids, err := f.conns.Unnotified(ctx, "enclave", 100); err != nil || len(ids) != 0 {
		t.Fatalf("unnotified = %v %v", ids, err)
	}

	// The consenter disabled behind the ledger's back is the same.
	conn, _ = f.consentContent(ctx, t, f.owner)
	admin, _ := transferOwner(t, f.archive, "admin")
	conn2, _ := f.consentContent(ctx, t, admin)
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status='disabled' WHERE tenant_id=$1 AND user_id=$2`, f.tenant, admin)
		return err
	})
	if answer, _ := f.conns.Status(ctx, "enclave", conn2.ID, allowAll); answer.Status != "revoked" {
		t.Fatalf("status with the consenter disabled = %+v", answer)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", conn.ID, allowAll); answer.Status != "active" {
		t.Fatalf("another consenter's connection = %+v", answer)
	}

	// Past its deadline it is expired, not access lost, though the key ran
	// out with it.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET expires_at=now()-interval '1 second' WHERE id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", conn.ID, allowAll); answer.Status != "expired" {
		t.Fatalf("past its deadline = %+v", answer)
	}
	if got := f.row(ctx, t, conn.ID); got.Status != "expired" || got.RevokeReason != store.ReasonExpired {
		t.Fatalf("row = %s/%s", got.Status, got.RevokeReason)
	}
}

// Reseal keeps the consent; only an active or resealed content connection
// may be resealed.
func TestResealKeepsTheConsent(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	conn, c := f.consentContent(ctx, t, f.owner)
	for i := 0; i < 2; i++ {
		if err := f.conns.Reseal(ctx, "enclave", conn.ID); err != nil {
			t.Fatal(err)
		}
	}
	got := f.row(ctx, t, conn.ID)
	if got.Status != "reseal" || got.ResealedAt == nil {
		t.Fatalf("row = %+v", got)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", conn.ID, allowAll); answer.Status != "reseal" {
		t.Fatalf("status = %+v", answer)
	}
	if tr := f.trace(ctx, t, c.service); tr.grants != 1 || tr.memberships != 1 || tr.liveKeys != 1 {
		t.Fatalf("a reseal touched the account: %+v", tr)
	}
	if err := f.conns.Reseal(ctx, store.HostedReader, conn.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("another reader resealed: %v", err)
	}
	_, prefix := f.provisionalKey(ctx, t, "meta")
	in := consent(prefix)
	in.Reader = "enclave"
	meta, err := f.conns.Create(ctx, f.tenant, f.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", meta.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Reseal(ctx, "enclave", meta.ID); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("a metadata connection was resealed: %v", err)
	}
	// A resealed connection still holds a place under the cap.
	for i := 0; i < 3; i++ {
		_, prefix := f.provisionalKey(ctx, t, "live")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); err != nil {
			t.Fatal(err)
		}
	}
	_, prefix = f.provisionalKey(ctx, t, "sixth")
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrTooManyMCPConnections) {
		t.Fatalf("a resealed connection did not count: %v", err)
	}
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Reseal(ctx, "enclave", conn.ID); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("a revoked connection was resealed: %v", err)
	}
}

// A consent abandoned after its account registered leaves an account with a
// deadline and no connection; the janitor removes it and everything it holds.
func TestExpireAbandonedServiceAccounts(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	abandoned := f.prepareContent(ctx, t, f.owner)
	_, live := f.consentContent(ctx, t, f.owner)

	if n, err := store.ExpireServiceAccounts(ctx, f.pool); err != nil || n != 0 {
		t.Fatalf("inside the window: %d %v", n, err)
	}
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at=now()-interval '1 minute' WHERE tenant_id=$1 AND user_id=$2`, f.tenant, abandoned.service)
		return err
	})
	if n, err := store.ExpireServiceAccounts(ctx, f.pool); err != nil || n != 1 {
		t.Fatalf("removed %d %v", n, err)
	}
	if tr := f.trace(ctx, t, abandoned.service); tr != (serviceTrace{}) {
		t.Fatalf("the abandoned account kept %+v", tr)
	}
	if _, err := f.keys.Verify(ctx, abandoned.key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the abandoned key still works: %v", err)
	}
	if tr := f.trace(ctx, t, live.service); tr.grants != 1 || tr.memberships != 1 || tr.liveKeys != 1 {
		t.Fatalf("a live connection's account was touched: %+v", tr)
	}
	if n, err := store.ExpireServiceAccounts(ctx, f.pool); err != nil || n != 0 {
		t.Fatalf("second pass: %d %v", n, err)
	}
}

// Renewal swaps the key and the service account in one transaction and keeps
// the connection: its id, its expiry, its reader.
func TestRenewSwapsKeyAndService(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	conn, old := f.consentContent(ctx, t, f.owner)
	if err := f.conns.Reseal(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}

	if got, err := f.conns.Renewable(ctx, f.tenant, f.owner, conn.ID); err != nil || got.Reader != "enclave" || got.ExpiresAt.Sub(conn.ExpiresAt).Abs() > time.Second {
		t.Fatalf("renewable = %+v %v", got, err)
	}
	admin, _ := transferOwner(t, f.archive, "admin")
	if _, err := f.conns.Renewable(ctx, f.tenant, admin, conn.ID); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("another manager may renew: %v", err)
	}

	next := f.prepareContent(ctx, t, f.owner)
	renewal := store.RenewMCPConnection{
		KeyPrefix: next.prefix, ServiceUserID: next.service, ReaderKID: "abcdefabcdefabcd",
		ReaderMeasurement: "nitro:pcr0=new;doc=new", ReaderPublicKey: next.publicKey,
	}
	// Refusals first: each leaves everything as it was.
	for name, mutate := range map[string]func(*store.RenewMCPConnection){
		"other public key": func(r *store.RenewMCPConnection) { r.ReaderPublicKey = randomBytes(t, 32) },
		"same service":     func(r *store.RenewMCPConnection) { r.ServiceUserID, r.KeyPrefix = old.service, old.prefix },
		"key of another":   func(r *store.RenewMCPConnection) { r.ServiceUserID = old.service },
	} {
		r := renewal
		mutate(&r)
		if _, err := f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, r); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if err := f.conns.CheckRenewal(ctx, f.tenant, f.owner, conn.ID, renewal); err != nil {
		t.Fatalf("check: %v", err)
	}
	if got := f.row(ctx, t, conn.ID); got.Status != "reseal" || *got.ServiceUserID != old.service {
		t.Fatalf("the check changed the row: %+v", got)
	}

	renewed, err := f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, renewal)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ID != conn.ID || renewed.Status != "active" {
		t.Fatalf("renewed = %+v", renewed)
	}
	got := f.row(ctx, t, conn.ID)
	if got.Status != "active" || got.ServiceUserID == nil || *got.ServiceUserID != next.service || got.KeyPrefix != next.prefix ||
		got.ReaderKID != "abcdefabcdefabcd" || got.ReaderMeasurement != "nitro:pcr0=new;doc=new" || got.RenewedAt == nil ||
		got.ExpiresAt.Sub(conn.ExpiresAt).Abs() > time.Second {
		t.Fatalf("row = %+v", got)
	}
	if _, err := f.keys.Verify(ctx, old.key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the old key still works: %v", err)
	}
	if tr := f.trace(ctx, t, old.service); tr != (serviceTrace{}) {
		t.Fatalf("the old account kept %+v", tr)
	}
	if _, err := f.keys.Verify(ctx, next.key); err != nil {
		t.Fatalf("the new key does not work: %v", err)
	}
	if at := f.membershipExpiry(ctx, t, next.service); at == nil || at.Sub(conn.ExpiresAt).Abs() > time.Second {
		t.Fatalf("the new account expires %v", at)
	}
	if answer, _ := f.conns.Status(ctx, "enclave", conn.ID, allowAll); answer.Status != "active" || *answer.ServiceUserID != next.service {
		t.Fatalf("status = %+v", answer)
	}

	// Another device set is refused.
	dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	second := uuid.MustParse(dev.ID)
	f.archiveKey(ctx, t, second, 1)
	f.ownerReads(ctx, t, f.owner, second)
	wider := f.prepareContent(ctx, t, f.owner, withDevices(f.device, second))
	if _, err := f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, store.RenewMCPConnection{
		KeyPrefix: wider.prefix, ServiceUserID: wider.service, ReaderKID: "abcdefabcdefabcd", ReaderPublicKey: wider.publicKey,
	}); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
		t.Fatalf("a renewal widened the devices: %v", err)
	}
	// A renewal that failed at the reader removes its account; one a
	// connection names is not removable that way.
	if err := f.conns.DiscardService(ctx, f.tenant, wider.service); err != nil {
		t.Fatal(err)
	}
	if tr := f.trace(ctx, t, wider.service); tr != (serviceTrace{}) {
		t.Fatalf("the discarded account kept %+v", tr)
	}
	if err := f.conns.DiscardService(ctx, f.tenant, next.service); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
		t.Fatalf("a connection's account was discarded: %v", err)
	}
	// An ended connection cannot be renewed.
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conns.Renewable(ctx, f.tenant, f.owner, conn.ID); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("an ended connection is renewable: %v", err)
	}
}

// The ledger keeps every end an attested reader has not confirmed, for a
// day, until it does; the reader's own ends need no notice.
func TestRevokeNoticeRepeated(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	console, _ := f.consentContent(ctx, t, f.owner)
	byReader, _ := f.consentContent(ctx, t, f.owner)
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, console.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.RevokeByID(ctx, "enclave", byReader.ID, store.ReasonReader); err != nil {
		t.Fatal(err)
	}
	_, prefix := f.provisionalKey(ctx, t, "hosted")
	hosted, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, hosted.ID); err != nil {
		t.Fatal(err)
	}
	ids, err := f.conns.Unnotified(ctx, "enclave", 100)
	if err != nil || len(ids) != 1 || ids[0] != console.ID {
		t.Fatalf("unnotified = %v %v", ids, err)
	}
	// Asking again gives the same answer until the reader confirms.
	if again, _ := f.conns.Unnotified(ctx, "enclave", 100); len(again) != 1 {
		t.Fatalf("unnotified again = %v", again)
	}
	if err := f.conns.MarkNotified(ctx, "enclave", console.ID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := f.conns.Unnotified(ctx, "enclave", 100); len(ids) != 0 {
		t.Fatalf("after confirmation = %v", ids)
	}
	// Older than a day is left alone.
	old, _ := f.consentContent(ctx, t, f.owner)
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET revoked_at=now()-interval '25 hours' WHERE id=$1`, old.ID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := f.conns.Unnotified(ctx, "enclave", 100); len(ids) != 0 {
		t.Fatalf("a day-old end = %v", ids)
	}
}

// 0042's down-step, exactly as its header documents it, run as the table
// owner under FORCE RLS: every content connection revoked with its key,
// every connection service account stripped, the columns gone, version 42
// forgotten; and up again.
func TestMigration0042DownStep(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	conn, c := f.consentContent(ctx, t, f.owner)
	abandoned := f.prepareContent(ctx, t, f.owner)
	metaKey, metaPrefix := f.provisionalKey(ctx, t, "meta")
	meta, err := f.conns.Create(ctx, f.tenant, f.owner, consent(metaPrefix))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 42)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 41 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var columns int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND ((table_name='mcp_connections' AND column_name IN ('kind','service_user_id','key_mode','consent_version','revoke_reason',
		      'reader_notified_at','resealed_at','renewed_at'))
		  OR (table_name='workspace_memberships' AND column_name='expires_at')
		  OR (table_name='invites' AND column_name='provisional'))`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("columns left: %d %v", columns, err)
	}
	for name, key := range map[string]string{"content": c.key, "abandoned": abandoned.key} {
		if _, err := f.keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the %s key survived: %v", name, err)
		}
	}
	if _, err := f.keys.Verify(ctx, metaKey); err != nil {
		t.Fatalf("the metadata key was revoked: %v", err)
	}
	var grants, memberships int
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM device_key_grants WHERE user_id = ANY($1)),
			(SELECT count(*) FROM workspace_memberships WHERE user_id = ANY($1))`,
			[]uuid.UUID{c.service, abandoned.service}).Scan(&grants, &memberships)
	})
	if grants != 0 || memberships != 0 {
		t.Fatalf("service accounts kept %d grants and %d memberships", grants, memberships)
	}
	statuses := map[string]string{}
	rows, err := f.pool.Query(ctx, `SELECT id::text, status FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		statuses[id] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if statuses[conn.ID] != "revoked" || statuses[meta.ID] != "pending" {
		t.Fatalf("statuses = %v", statuses)
	}
	// The person's own access survived.
	if tr := f.trace(ctx, t, f.owner); tr.grants != 1 || tr.memberships != 1 {
		t.Fatalf("the owner's access changed: %+v", tr)
	}

	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0042: %v", err)
	}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list after re-applying = %+v %v", listed, err)
	}
	for _, l := range listed {
		if l.Kind != store.KindMetadata {
			t.Fatalf("row %s came back as %q", l.ID, l.Kind)
		}
	}
}

// 0042's down-step deletes the provisional invitations, used or not: once
// the column is gone an older binary would redeem an unused one as an
// ordinary service invitation, into an account with no deadline. An ordinary
// service invitation is untouched and can still be used.
func TestMigration0042DownStepDropsProvisionalInvites(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	_, pending, err := f.users.NewProvisionalServiceInvitation(ctx, f.tenant, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	usedSecret, used, err := f.users.NewProvisionalServiceInvitation(ctx, f.tenant, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.users.SignupService(ctx, usedSecret, "mcp-"+hex.EncodeToString(randomBytes(t, 4)), randomBytes(t, 32)); err != nil {
		t.Fatal(err)
	}
	_, ordinary, err := f.users.NewMemberInvitation(ctx, f.tenant, f.owner, store.RoleService, "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 42)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	// Usable is what redemption asks of an invitation.
	usable := func(id uuid.UUID) (present, open bool) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT count(*) > 0, coalesce(bool_or(completed_at IS NULL AND revoked_at IS NULL AND expires_at > now()), false)
			FROM invites WHERE id = $1`, id).Scan(&present, &open); err != nil {
			t.Fatal(err)
		}
		return present, open
	}
	if present, open := usable(pending.ID); present || open {
		t.Fatalf("the unused provisional invitation survived (present %v, usable %v)", present, open)
	}
	if present, open := usable(used.ID); present || open {
		t.Fatalf("the used provisional invitation survived (present %v, usable %v)", present, open)
	}
	if present, open := usable(ordinary.ID); !present || !open {
		t.Fatalf("the ordinary service invitation: present %v, usable %v", present, open)
	}

	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0042: %v", err)
	}
}
