// Package tokentest makes platform tokens live through the store's own
// paths, for the tests of the transports that accept them (REST, media and
// upload, the socket). It is imported by tests only.
//
// A World is a workspace of the contract's current generation at observe,
// with tokens on and caught up, and an owner linked to the platform (a sub
// with an account document that names the workspace). A token is minted
// with the kit's layout, committed as a record of the token feed, judged,
// and, for each number it reads, sealed a grant at the number's epoch by
// the owner, as the grant-token page does.
package tokentest

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// Mint returns a fresh token's text, with its selector and its hash, in the
// kit's layout: thc_, 16 lowercase hex, a dot, and 43 base64url characters.
func Mint() (text, selector, hash string) {
	var sel [8]byte
	var secret [kc.TokenSecretBytes]byte
	if _, err := rand.Read(sel[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(secret[:]); err != nil {
		panic(err)
	}
	selector = hex.EncodeToString(sel[:])
	text = kc.TokenPrefix + selector + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	return text, selector, kc.TokenHash(secret)
}

// World is a workspace where tokens are on.
type World struct {
	T        testing.TB
	Pool     *pgxpool.Pool
	Tokens   *store.Tokens
	Users    *store.Users
	Keys     *store.Keys
	Devices  *store.Devices
	Tenant   uuid.UUID
	Gen      uuid.UUID
	Owner    uuid.UUID
	OwnerSub uuid.UUID
	seq      int64
}

// New makes tenant a workspace where tokens are on, in pool: the contract
// at observe with a confirmed generation, tokens on and caught up with a
// fresh published_through, and an owner linked to the platform. A tenant
// of uuid.Nil is a new one. Only one World per pool: the contract's state
// is the database's.
func New(t testing.TB, pool *pgxpool.Pool, tenant uuid.UUID) *World {
	t.Helper()
	w := &World{T: t, Pool: pool, Tokens: store.NewTokens(pool), Users: store.NewUsers(pool), Keys: store.NewKeys(pool),
		Devices: store.NewDevices(pool), Tenant: tenant, Gen: uuid.New(), OwnerSub: uuid.New()}
	if tenant == uuid.Nil {
		w.Tenant = uuid.New()
		w.Exec(`INSERT INTO tenants (id, name) VALUES ($1, 'team')`, w.Tenant)
	}
	w.Exec(`UPDATE contract_state SET generation = $1, generation_confirmed = true, mode = 'observe',
		events_from = coalesce(events_from, clock_timestamp())`, w.Gen)
	w.Owner = w.Linked("owner", "owner", w.OwnerSub)
	w.Exec(`UPDATE contract_token_state SET mode = 'on', caught_up_at = clock_timestamp(), published_through = $1`, time.Now())
	return w
}

// Exec runs sql on the pool, failing the test on an error.
func (w *World) Exec(sql string, args ...any) {
	w.T.Helper()
	if _, err := w.Pool.Exec(context.Background(), sql, args...); err != nil {
		w.T.Fatalf("%s: %v", sql, err)
	}
}

// Scoped runs fn in the workspace.
func (w *World) Scoped(fn func(pgx.Tx) error) {
	w.T.Helper()
	if err := pg.InTenantTx(context.Background(), w.Pool, w.Tenant.String(), fn); err != nil {
		w.T.Fatal(err)
	}
}

// Linked is a person of the workspace with role, linked to the platform
// as sub, with an account document that names the workspace.
func (w *World) Linked(name, role string, sub uuid.UUID) uuid.UUID {
	w.T.Helper()
	u, err := w.Users.Create(context.Background(), store.NewUser{TenantID: w.Tenant, Email: name + "-" + uuid.NewString()[:8] + "@acme.test",
		Role: role, AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32),
		WrappedUSK: []byte("wrapped")})
	if err != nil {
		w.T.Fatal(err)
	}
	w.Exec(`INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'new')`, sub, u.ID, name+"@acme.test")
	w.Exec(`INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active',
		jsonb_build_object('v', 1, 'workspaces', jsonb_build_array(jsonb_build_object('id', $3::text, 'kind', 'team',
			'role', $4::text, 'status', 'open', 'wversion', 1))))`, sub, w.Gen, w.Tenant, role)
	return u.ID
}

// Number is a new number of the workspace with an archive key at epoch 1,
// read by the owner.
func (w *World) Number(label string) uuid.UUID {
	w.T.Helper()
	ctx := context.Background()
	dev, err := w.Devices.CreateWithID(ctx, w.Tenant.String(), "", label, "passive")
	if err != nil {
		w.T.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		w.T.Fatal(err)
	}
	if err := w.Keys.CreateArchiveKey(ctx, w.Tenant, device, 1, pub); err != nil {
		w.T.Fatal(err)
	}
	if err := w.Keys.PutGrant(ctx, store.Grant{TenantID: w.Tenant, DeviceID: device, UserID: w.Owner, Epoch: 1, SealedDSK: []byte("grant")}, &w.Owner); err != nil {
		w.T.Fatal(err)
	}
	if err := w.Users.SetDevicePermission(ctx, w.Tenant, w.Owner, store.DevicePermission{DeviceID: device, UserID: w.Owner, Read: true, Send: true, Manage: true}); err != nil {
		w.T.Fatal(err)
	}
	return device
}

// Perm is one permission of a token on a number: kc.CanRead, kc.CanSend or
// kc.CanManage.
type Perm struct {
	Device uuid.UUID
	Perm   string
}

// Read, Send and Manage are a perm on device.
func Read(device uuid.UUID) Perm   { return Perm{device, kc.CanRead} }
func Send(device uuid.UUID) Perm   { return Perm{device, kc.CanSend} }
func Manage(device uuid.UUID) Perm { return Perm{device, kc.CanManage} }

// Token is a live token: its id, its text, and its record's latest
// version.
type Token struct {
	ID       uuid.UUID
	Text     string
	Selector string
	Hash     string
	Key      *kc.ReadingKey
	Version  int64
	Perms    []Perm
}

// Token mints a token with perms, given by the owner, and makes it live:
// its record committed and judged, and a grant sealed to its identity at
// epoch 1 of every number it reads.
func (w *World) Token(perms ...Perm) *Token {
	w.T.Helper()
	text, selector, hash := Mint()
	return w.TokenWith(text, selector, hash, perms...)
}

// TokenWith is Token with the text, selector and hash given (the kit's
// vectors name theirs).
func (w *World) TokenWith(text, selector, hash string, perms ...Perm) *Token {
	w.T.Helper()
	tok := &Token{ID: uuid.New(), Text: text, Selector: selector, Hash: hash, Key: readingKey(w.T), Perms: perms}
	w.Commit(tok)
	if _, err := w.Tokens.JudgeTokenGrants(context.Background(), time.Now()); err != nil {
		w.T.Fatal(err)
	}
	for _, p := range perms {
		if p.Perm == kc.CanRead {
			w.Seal(tok, p.Device, 1)
		}
	}
	return tok
}

// Record is tok's record at its version, with its perms, created by the
// owner a day ago and expiring in 30 days; each opt changes it.
func (w *World) Record(tok *Token, opts ...func(*kc.TokenRecord)) kc.TokenRecord {
	created := time.Now().UTC().Truncate(time.Second).Add(-24 * time.Hour)
	if tok.Version == 0 {
		tok.Version = 1
	}
	r := kc.TokenRecord{V: kc.TokenRecordV, Type: kc.TokenRecordType, App: store.TokenApp, Generation: w.Gen.String(), ID: tok.ID.String(),
		Version: tok.Version, Selector: tok.Selector, Hash: tok.Hash, WorkspaceID: w.Tenant.String(), Name: "Nightly",
		CreatedBy: w.OwnerSub.String(), CreatedAt: kc.T(created), ExpiresAt: kc.T(created.Add(30 * 24 * time.Hour)),
		Items: []kc.TokenItem{}, ReadingKey: tok.Key}
	byDevice := map[uuid.UUID]int{}
	for _, p := range tok.Perms {
		i, ok := byDevice[p.Device]
		if !ok {
			i = len(r.Items)
			byDevice[p.Device] = i
			r.Items = append(r.Items, kc.TokenItem{ID: p.Device.String(), Kind: kc.ItemNumber})
		}
		r.Items[i].Perms = append(r.Items[i].Perms, kc.TokenPerm{Perm: p.Perm, GrantedBy: w.OwnerSub.String(), GrantedAt: kc.T(created)})
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

// Commit commits tok's record at its version, changed by opts, as one page
// of the token feed with more false.
func (w *World) Commit(tok *Token, opts ...func(*kc.TokenRecord)) {
	w.T.Helper()
	w.Page(w.Record(tok, opts...))
}

// Page commits records as one page of the token feed, from the stored
// cursor, with more false and published_through now.
func (w *World) Page(records ...kc.TokenRecord) {
	w.T.Helper()
	ctx := context.Background()
	var after int64
	if err := w.Pool.QueryRow(ctx, `SELECT feed_cursor FROM contract_token_state`).Scan(&after); err != nil {
		w.T.Fatal(err)
	}
	now := time.Now()
	feed := kc.TokenFeed{Generation: w.Gen.String(), GenerationConfirmed: true, PublishedThrough: kc.T(now), Items: []kc.TokenFeedItem{}}
	w.seq = max(w.seq, after)
	for _, r := range records {
		w.seq++
		raw, err := marshal(r)
		if err != nil {
			w.T.Fatal(err)
		}
		feed.Items = append(feed.Items, kc.TokenFeedItem{Seq: w.seq, Token: raw})
	}
	feed.Head, feed.NextAfter = w.seq, w.seq
	res, err := w.Tokens.CommitTokenPage(ctx, store.TokenPage{After: after, SeenGeneration: w.Gen, Feed: feed, Now: now})
	if err != nil {
		w.T.Fatalf("the token page: %v", err)
	}
	if !res.Committed {
		w.T.Fatal("the token page was not committed")
	}
}

// Seal is a grant of device at epoch to tok's identity, sealed by the
// owner, its signed GET fresh.
func (w *World) Seal(tok *Token, device uuid.UUID, epoch uint16) {
	w.T.Helper()
	if err := w.TrySeal(tok, device, epoch); err != nil {
		w.T.Fatalf("the token grant: %v", err)
	}
}

// TrySeal is Seal, returning its error.
func (w *World) TrySeal(tok *Token, device uuid.UUID, epoch uint16) error {
	w.T.Helper()
	now := time.Now()
	w.Scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE contract_tokens SET fetched_at = $2 WHERE id = $1`, tok.ID, now.Add(-time.Second))
		return err
	})
	return w.Tokens.PutTokenGrant(context.Background(), store.TokenGrant{Workspace: w.Tenant, Token: tok.ID, Device: device, Epoch: epoch,
		SealedDSK: []byte("sealed to the token"), Sealer: w.Owner, Now: now})
}

// Narrow commits tok's record again at the next version with perms, which
// drops every perm it held and does not list again.
func (w *World) Narrow(tok *Token, perms ...Perm) {
	w.T.Helper()
	tok.Version++
	tok.Perms = perms
	w.Commit(tok)
	if _, err := w.Tokens.JudgeTokenGrants(context.Background(), time.Now()); err != nil {
		w.T.Fatal(err)
	}
}

// Revoke commits tok's record again, revoked.
func (w *World) Revoke(tok *Token) {
	w.T.Helper()
	tok.Version++
	tok.Perms = nil
	at := kc.T(time.Now().Add(-time.Second))
	reason := "revoked"
	w.Commit(tok, func(r *kc.TokenRecord) { r.RevokedAt, r.RevokedReason = &at, &reason })
}

// Rotate gives device a new archive key at epoch, which leaves every token
// that reads it with no grant at the current epoch; the owner gets one.
func (w *World) Rotate(device uuid.UUID, epoch uint16) {
	w.T.Helper()
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		w.T.Fatal(err)
	}
	ctx := context.Background()
	if err := w.Keys.CreateArchiveKey(ctx, w.Tenant, device, epoch, pub); err != nil {
		w.T.Fatal(err)
	}
	// The owner reads the new epoch, so it can seal it to a token again.
	if err := w.Keys.PutGrant(ctx, store.Grant{TenantID: w.Tenant, DeviceID: device, UserID: w.Owner, Epoch: epoch, SealedDSK: []byte("grant")}, &w.Owner); err != nil {
		w.T.Fatal(err)
	}
}

// Switches sets the workspace's own text and attachments switches for
// tokens and MCP: nil is the operator's default.
func (w *World) Switches(text, media *bool) {
	w.T.Helper()
	w.Exec(`UPDATE tenants SET mcp_text = $2, mcp_media = $3 WHERE id = $1`, w.Tenant, text, media)
}

// Stale sets the token feed's published_through at, so send and manage
// see a stale feed once it is over an hour old.
func (w *World) Stale(at time.Time) {
	w.T.Helper()
	w.Exec(`UPDATE contract_token_state SET published_through = $1`, at)
}

// Auth is tok's TokenAuth now, from ForAuth.
func (w *World) Auth(tok *Token) store.TokenAuth {
	w.T.Helper()
	auth, fail, err := w.Tokens.ForAuth(context.Background(), tok.Text, time.Now())
	if err != nil {
		w.T.Fatalf("the token does not authenticate (%+v): %v", fail, err)
	}
	return auth
}

// Refusals are tok's counted refusals, as "device/perm=code:count", with
// "-" for a null device or perm.
func (w *World) Refusals(tok *Token) map[string]int64 {
	w.T.Helper()
	rows, err := w.Pool.Query(context.Background(), `SELECT coalesce(device_id::text, '-') || '/' || coalesce(perm, '-') || '=' || code, count
		FROM contract_token_refusals WHERE token_id = $1`, tok.ID)
	if err != nil {
		w.T.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			w.T.Fatal(err)
		}
		out[k] = n
	}
	if err := rows.Err(); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		w.T.Fatal(err)
	}
	return out
}

func marshal(r kc.TokenRecord) (json.RawMessage, error) { return json.Marshal(r) }

// readingKey is a fresh X25519 reading key with its fingerprint.
func readingKey(t testing.TB) *kc.ReadingKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	fp, err := kc.ReadingKeyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	return &kc.ReadingKey{Suite: kc.ReadingKeySuite, Key: key, Fingerprint: fp, RegisteredAt: kc.T(time.Now().Add(-time.Hour))}
}
