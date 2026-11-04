package store_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// tokenWorld is a workspace of the contract's current generation with an
// owner linked to the platform (a sub with an account document) and numbers
// that hold archive keys, for the token part's tests. Its clock is Wappie's:
// the store's token writes take it, never the database's.
type tokenWorld struct {
	t        *testing.T
	pool     *pgxpool.Pool
	backends *pgtest.Backends
	tokens   *store.Tokens
	contract *store.Contract
	users    *store.Users
	keys     *store.Keys
	devices  *store.Devices
	tenant   uuid.UUID
	gen      uuid.UUID
	owner    uuid.UUID
	ownerSub uuid.UUID
	now      time.Time
	seq      int64
	logs     *bytes.Buffer
}

func newTokenWorld(t *testing.T) *tokenWorld { return newTokenWorldIn(t, uuid.Nil, uuid.Nil) }

// newTokenWorldIn is newTokenWorld with the workspace's id and the owner's
// sub given (the kit's vectors name theirs).
func newTokenWorldIn(t *testing.T, tenant, ownerSub uuid.UUID) *tokenWorld {
	t.Helper()
	backends := &pgtest.Backends{}
	pool := pgtest.FreshWith(t, migrate.Run, backends.Configure)
	if tenant == uuid.Nil {
		tenant = uuid.New()
	}
	if ownerSub == uuid.Nil {
		ownerSub = uuid.New()
	}
	w := &tokenWorld{t: t, pool: pool, backends: backends, tokens: store.NewTokens(pool), contract: store.NewContract(pool),
		users: store.NewUsers(pool), keys: store.NewKeys(pool), devices: store.NewDevices(pool),
		tenant: tenant, gen: uuid.New(), ownerSub: ownerSub, now: time.Now().UTC().Truncate(time.Second), logs: &bytes.Buffer{}}
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'team')`, tenant)
	w.owner = w.linked("owner", "owner", ownerSub, true)
	w.exec(`UPDATE contract_state SET generation = $1, generation_confirmed = true`, w.gen)
	return w
}

func (w *tokenWorld) ctx() context.Context {
	return obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(w.logs, nil)))
}

func (w *tokenWorld) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.pool.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

// scoped runs fn in the workspace, deleted numbers visible.
func (w *tokenWorld) scoped(fn func(pgx.Tx) error) {
	w.t.Helper()
	inTenantTx(context.Background(), w.t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(context.Background(), tx, func() error { return fn(tx) })
	})
}

func (w *tokenWorld) count(query string, args ...any) int {
	w.t.Helper()
	var n int
	w.scoped(func(tx pgx.Tx) error { return tx.QueryRow(context.Background(), query, args...).Scan(&n) })
	return n
}

// linked is a person of the workspace with role, linked to the platform as
// sub, with an account document stored when doc.
func (w *tokenWorld) linked(name, role string, sub uuid.UUID, doc bool) uuid.UUID {
	w.t.Helper()
	ctx := context.Background()
	u, err := w.users.Create(ctx, store.NewUser{TenantID: w.tenant, Email: name + "-" + uuid.NewString()[:8] + "@acme.test",
		Role: role, AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		w.t.Fatal(err)
	}
	w.exec(`INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'new')`, sub, u.ID, name+"@acme.test")
	if doc {
		// Its document names the workspace, so the belt holds.
		w.exec(`INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active',
			jsonb_build_object('v', 1, 'workspaces', jsonb_build_array(jsonb_build_object('id', $3::text, 'kind', 'team',
				'role', $4::text, 'status', 'open', 'wversion', 1))))`, sub, w.gen, w.tenant, role)
	}
	return u.ID
}

// number is a number of the workspace with an archive key at epoch 1, read
// by the owner, with id given or the database's.
func (w *tokenWorld) number(id uuid.UUID) uuid.UUID {
	w.t.Helper()
	ctx := context.Background()
	var given string
	if id != uuid.Nil {
		given = id.String()
	}
	dev, err := w.devices.CreateWithID(ctx, w.tenant.String(), given, "Vendas", "passive")
	if err != nil {
		w.t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, device, 1, pub); err != nil {
		w.t.Fatal(err)
	}
	w.reads(w.owner, device)
	return device
}

// reads gives user the number's grant at epoch 1 and Read.
func (w *tokenWorld) reads(user, device uuid.UUID) {
	w.t.Helper()
	ctx := context.Background()
	if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: user, Epoch: 1, SealedDSK: []byte("grant")}, &w.owner); err != nil {
		w.t.Fatal(err)
	}
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: user, Read: true}); err != nil {
		w.t.Fatal(err)
	}
}

// readingKey is a fresh X25519 reading key with its fingerprint.
func readingKey(t *testing.T) *kc.ReadingKey {
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

// selectorOf and hashOf are a test token's selector and hash, from its id.
func selectorOf(id uuid.UUID) string { return strings.ReplaceAll(id.String(), "-", "")[16:] }

func tokenHashOf(id uuid.UUID) string {
	sum := sha256.Sum256(id[:])
	return hex.EncodeToString(sum[:])
}

// record is a good record of token id at version, created by the owner a
// day ago, expiring in 30 days, with no items; each opt changes it.
func (w *tokenWorld) record(id uuid.UUID, version int64, opts ...func(*kc.TokenRecord)) kc.TokenRecord {
	created := w.now.Add(-24 * time.Hour)
	r := kc.TokenRecord{V: kc.TokenRecordV, Type: kc.TokenRecordType, App: "wappie", Generation: w.gen.String(), ID: id.String(),
		Version: version, Selector: selectorOf(id), Hash: tokenHashOf(id), WorkspaceID: w.tenant.String(), Name: "Nightly",
		CreatedBy: w.ownerSub.String(), CreatedAt: kc.T(created), ExpiresAt: kc.T(created.Add(30 * 24 * time.Hour)),
		Items: []kc.TokenItem{}}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

// grants lists perms on device, given by by at at.
func grants(device uuid.UUID, by uuid.UUID, at time.Time, perms ...string) func(*kc.TokenRecord) {
	return func(r *kc.TokenRecord) {
		item := kc.TokenItem{ID: device.String(), Kind: kc.ItemNumber}
		for _, p := range perms {
			item.Perms = append(item.Perms, kc.TokenPerm{Perm: p, GrantedBy: by.String(), GrantedAt: kc.T(at)})
		}
		r.Items = append(r.Items, item)
	}
}

func revokedBy(reason string, at time.Time) func(*kc.TokenRecord) {
	return func(r *kc.TokenRecord) {
		t := kc.T(at)
		r.RevokedAt, r.RevokedReason, r.Items = &t, &reason, []kc.TokenItem{}
	}
}

// raw is a record's JSON, or the text given.
func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	switch r := v.(type) {
	case json.RawMessage:
		return r
	case []byte:
		return r
	case string:
		return json.RawMessage(r)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// page commits records (TokenRecord or raw JSON) as one page from the
// stored cursor, with more as given, and fails the test on an error.
func (w *tokenWorld) page(more bool, records ...any) store.TokenPageResult {
	w.t.Helper()
	res, err := w.tryPage(more, records...)
	if err != nil {
		w.t.Fatalf("the page: %v\n%s", err, w.logs.String())
	}
	if !res.Committed {
		w.t.Fatal("the page was not committed")
	}
	return res
}

func (w *tokenWorld) tryPage(more bool, records ...any) (store.TokenPageResult, error) {
	w.t.Helper()
	var after int64
	if err := w.pool.QueryRow(context.Background(), `SELECT feed_cursor FROM contract_token_state`).Scan(&after); err != nil {
		w.t.Fatal(err)
	}
	feed := kc.TokenFeed{Generation: w.gen.String(), GenerationConfirmed: true, PublishedThrough: kc.T(w.now), Items: []kc.TokenFeedItem{}, More: more}
	for _, r := range records {
		w.seq++
		feed.Items = append(feed.Items, kc.TokenFeedItem{Seq: w.seq, Token: raw(w.t, r)})
	}
	feed.Head, feed.NextAfter = max(w.seq, after), max(w.seq, after)
	return w.tokens.CommitTokenPage(w.ctx(), store.TokenPage{After: after, SeenGeneration: w.gen, Feed: feed, Now: w.now})
}

// storedToken is what a test reads of a contract_tokens row.
type storedToken struct {
	Exists        bool
	Revoked       bool
	Reason        *string
	Expires       string
	Version       *int64
	AccessVersion int64
	Unlisted      bool
	KeyChanged    bool
	Name          string
	Forgotten     bool
}

func (w *tokenWorld) token(id uuid.UUID) storedToken {
	w.t.Helper()
	var s storedToken
	w.scoped(func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), `SELECT revoked_at IS NOT NULL, revoked_reason, expires_at::text, version, access_version,
			unlisted_at IS NOT NULL, key_changed_at IS NOT NULL, name, forgotten_at IS NOT NULL FROM contract_tokens WHERE id = $1`, id).
			Scan(&s.Revoked, &s.Reason, &s.Expires, &s.Version, &s.AccessVersion, &s.Unlisted, &s.KeyChanged, &s.Name, &s.Forgotten)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		s.Exists = err == nil
		return err
	})
	return s
}

// perms are a token's perm rows, as "device/perm=state[:code]".
func (w *tokenWorld) perms(id uuid.UUID) map[string]string {
	w.t.Helper()
	out := map[string]string{}
	w.scoped(func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT device_id, perm, state, coalesce(code, '') FROM contract_token_perms WHERE token_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var device uuid.UUID
			var perm, state, code string
			if err := rows.Scan(&device, &perm, &state, &code); err != nil {
				return err
			}
			if code != "" {
				state += ":" + code
			}
			out[device.String()+"/"+perm] = state
		}
		return rows.Err()
	})
	return out
}

// sticky is a token's sticky row: whether it exists, is revoked, how it
// ended.
func (w *tokenWorld) sticky(id uuid.UUID) (exists, revoked bool, ended string) {
	w.t.Helper()
	err := w.pool.QueryRow(context.Background(), `SELECT revoked_at IS NOT NULL, coalesce(ended, '') FROM contract_token_sticky WHERE token_id = $1`, id).
		Scan(&revoked, &ended)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, ""
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return true, revoked, ended
}

// refused are the queued refusals of token, as "item/perm=code@version".
func (w *tokenWorld) refused(id uuid.UUID) []string {
	w.t.Helper()
	rows, err := w.pool.Query(context.Background(), `SELECT item || '/' || perm || '=' || code || '@' || version FROM contract_token_refusals_out
		WHERE token_id = $1 ORDER BY 1`, id)
	if err != nil {
		w.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

func (w *tokenWorld) cursor() int64 {
	w.t.Helper()
	var c int64
	if err := w.pool.QueryRow(context.Background(), `SELECT feed_cursor FROM contract_token_state`).Scan(&c); err != nil {
		w.t.Fatal(err)
	}
	return c
}

func (w *tokenWorld) judge() store.TokenJudgeResult {
	w.t.Helper()
	res, err := w.tokens.JudgeTokenGrants(w.ctx(), w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

// A good record applies; a lower or equal version later changes nothing,
// and a higher one applies; a reset forgets the version, so the new
// generation's first record applies whatever its number.
func TestTokenRecordsOnlyRise(t *testing.T) {
	w := newTokenWorld(t)
	id, device := uuid.New(), w.number(uuid.Nil)
	w.page(false, w.record(id, 2, grants(device, w.ownerSub, w.now, kc.CanRead)))
	if s := w.token(id); !s.Exists || *s.Version != 2 || s.Name != "Nightly" {
		t.Fatalf("after v2: %+v", s)
	}
	w.page(false, w.record(id, 1, func(r *kc.TokenRecord) { r.Name = "Older" }), w.record(id, 2, func(r *kc.TokenRecord) { r.Name = "Same" }))
	if s := w.token(id); *s.Version != 2 || s.Name != "Nightly" || len(w.perms(id)) != 1 {
		t.Fatalf("an older and the same version changed the token: %+v %v", s, w.perms(id))
	}
	w.page(false, w.record(id, 3, func(r *kc.TokenRecord) { r.Name = "Newer" }, grants(device, w.ownerSub, w.now, kc.CanRead)))
	if s := w.token(id); *s.Version != 3 || s.Name != "Newer" {
		t.Fatalf("after v3: %+v", s)
	}
	// One generation resets both feeds: the token keeps its row, forgets
	// its version, and the new generation's v1 applies.
	next := uuid.New()
	if ok, err := w.contract.RestartFromTokens(w.ctx(), w.gen, &next, true); err != nil || !ok {
		t.Fatalf("the reset: %v %v", ok, err)
	}
	w.gen = next
	if s := w.token(id); !s.Exists || s.Version != nil {
		t.Fatalf("after the reset: %+v", s)
	}
	w.page(false, w.record(id, 1, func(r *kc.TokenRecord) { r.Name = "Restored" }, grants(device, w.ownerSub, w.now, kc.CanRead)))
	if s := w.token(id); *s.Version != 1 || s.Name != "Restored" {
		t.Fatalf("the new generation's v1: %+v", s)
	}
}

// TestAPoisonRecordNeverStallsRevocations is the plan's 10.2 (H1): whatever
// lies between two revocations on a page, both revocations apply in the
// page's one commit and the cursor moves past all three. Each poison is
// either skipped, applied for its narrowings only, or, when even that
// fails, stops its own token (apply_failed) and nothing else.
func TestAPoisonRecordNeverStallsRevocations(t *testing.T) {
	type poison struct {
		name string
		// setup runs before the page; it returns the poison record.
		setup func(w *tokenWorld) any
		// check runs after it.
		check func(t *testing.T, w *tokenWorld, res store.TokenPageResult)
	}
	held := func(w *tokenWorld, opts ...func(*kc.TokenRecord)) uuid.UUID {
		id := uuid.New()
		w.page(false, w.record(id, 1, opts...))
		return id
	}
	var poisonID, poisonDevice uuid.UUID
	for _, c := range []poison{
		{"an unknown workspace", func(w *tokenWorld) any {
			poisonID = uuid.New()
			return w.record(poisonID, 1, func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() })
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if w.token(poisonID).Exists || res.Skipped != 1 {
				t.Fatalf("a record of an unknown workspace: %+v %+v", w.token(poisonID), res)
			}
		}},
		{"an unknown workspace's revocation", func(w *tokenWorld) any {
			poisonID = uuid.New()
			return w.record(poisonID, 1, func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }, revokedBy(kc.RevokedInConsole, w.now))
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if exists, revoked, _ := w.sticky(poisonID); !exists || !revoked || w.token(poisonID).Exists {
				t.Fatal("an unknown workspace's revocation did not stick")
			}
		}},
		{"a non-UUID item, an unknown one and a purged one", func(w *tokenWorld) any {
			poisonID = uuid.New()
			purged := w.number(uuid.Nil)
			w.scoped(func(tx pgx.Tx) error {
				_, err := tx.Exec(context.Background(), `DELETE FROM device_key_grants WHERE device_id = $1`, purged)
				if err == nil {
					_, err = tx.Exec(context.Background(), `DELETE FROM devices WHERE id = $1`, purged)
				}
				return err
			})
			return w.record(poisonID, 1, func(r *kc.TokenRecord) {
				r.Items = append(r.Items,
					kc.TokenItem{ID: "not-a-uuid", Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanRead, GrantedBy: w.ownerSub.String(), GrantedAt: kc.T(w.now)}}},
					kc.TokenItem{ID: uuid.NewString(), Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanSend, GrantedBy: w.ownerSub.String(), GrantedAt: kc.T(w.now)}}},
					kc.TokenItem{ID: purged.String(), Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanManage, GrantedBy: w.ownerSub.String(), GrantedAt: kc.T(w.now)}}})
			})
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if s := w.token(poisonID); !s.Exists || len(w.perms(poisonID)) != 0 {
				t.Fatalf("items that are no live number: %+v %v", s, w.perms(poisonID))
			}
			if n := w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1 AND cause = 'item_unknown'`, poisonID); n != 3 {
				t.Fatalf("%d item_unknown instances, want 3", n)
			}
			if got := w.refused(poisonID); len(got) != 3 || !strings.Contains(strings.Join(got, " "), "not-a-uuid/read=item_unknown@1") {
				t.Fatalf("the refusals: %v", got)
			}
		}},
		{"a changed selector", func(w *tokenWorld) any {
			poisonID = held(w)
			return w.record(poisonID, 2, func(r *kc.TokenRecord) { r.Selector = "aaaaaaaaaaaaaaaa"; r.Name = "Changed" })
		}, nil},
		{"a changed hash", func(w *tokenWorld) any {
			poisonID = held(w)
			return w.record(poisonID, 2, func(r *kc.TokenRecord) { r.Hash = strings.Repeat("0", 64); r.Name = "Changed" })
		}, nil},
		{"a changed workspace", func(w *tokenWorld) any {
			poisonID = held(w)
			other := uuid.New()
			w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'other')`, other)
			return w.record(poisonID, 2, func(r *kc.TokenRecord) { r.WorkspaceID = other.String(); r.Name = "Changed" })
		}, nil},
		{"a changed creator", func(w *tokenWorld) any {
			poisonID = held(w)
			return w.record(poisonID, 2, func(r *kc.TokenRecord) { r.CreatedBy = uuid.NewString(); r.Name = "Changed" })
		}, nil},
		{"a changed creation time", func(w *tokenWorld) any {
			poisonID = held(w)
			return w.record(poisonID, 2, func(r *kc.TokenRecord) { r.CreatedAt = kc.T(r.CreatedAt.Add(time.Second)); r.Name = "Changed" })
		}, nil},
		{"a selector taken by another id", func(w *tokenWorld) any {
			first := held(w)
			poisonID = uuid.New()
			return w.record(poisonID, 1, func(r *kc.TokenRecord) { r.Selector = selectorOf(first) })
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if w.token(poisonID).Exists {
				t.Fatal("a record whose selector another token holds made a row")
			}
		}},
		{"zero expires_at and revoked_at", func(w *tokenWorld) any {
			poisonID = held(w)
			r := w.record(poisonID, 2)
			b := raw(t, r)
			b = bytes.Replace(b, []byte(`"expires_at":"`+r.ExpiresAt.UTC().Format(time.RFC3339Nano)+`"`), []byte(`"expires_at":7`), 1)
			b = bytes.Replace(b, []byte(`"revoked_at":null,"revoked_reason":null`), []byte(`"revoked_at":0,"revoked_reason":"revoked"`), 1)
			return b
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if s := w.token(poisonID); !s.Revoked || s.Expires != "-infinity" {
				t.Fatalf("zero times: %+v", s)
			}
			// A zero revoked_at beside a revocation is Wappie's clock.
			var at time.Time
			w.scoped(func(tx pgx.Tx) error {
				return tx.QueryRow(context.Background(), `SELECT revoked_at FROM contract_tokens WHERE id = $1`, poisonID).Scan(&at)
			})
			if !at.Equal(w.now) {
				t.Fatalf("a zero revoked_at stored as %v, want Wappie's clock %v", at, w.now)
			}
		}},
		{"a widening that fails, applied for its narrowings", func(w *tokenWorld) any {
			// The database refuses this token's new perms, never its
			// drops: the record fails whole, then applies narrowed.
			device := w.number(uuid.Nil)
			poisonID = held(w, grants(device, w.ownerSub, w.now, kc.CanRead))
			w.exec(`CREATE FUNCTION no_widening() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
				IF NEW.token_id = '` + poisonID.String() + `' THEN RAISE EXCEPTION 'no widening'; END IF; RETURN NEW; END $$`)
			w.exec(`CREATE TRIGGER no_widening BEFORE INSERT ON contract_token_perms FOR EACH ROW EXECUTE FUNCTION no_widening()`)
			poisonDevice = device
			return w.record(poisonID, 2, grants(device, w.ownerSub, w.now, kc.CanSend), func(r *kc.TokenRecord) { r.Name = "Widened" })
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if res.Bad != 1 || res.Failed != 0 {
				t.Fatalf("the result: %+v", res)
			}
			if n := w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1`, selectorOf(poisonID)); n != 0 {
				t.Fatal("a record applied narrowed stopped its token")
			}
			if s, p := w.token(poisonID), w.perms(poisonID); s.Name != "Nightly" || *s.Version != 1 || len(p) != 0 {
				t.Fatalf("narrowed: %+v %v (its Read dropped, nothing else)", s, p)
			}
			if got := w.refused(poisonID); len(got) != 1 || got[0] != poisonDevice.String()+"/send=invalid_record@2" {
				t.Fatalf("its new grant's refusal: %v", got)
			}
			if !strings.Contains(w.logs.String(), "applied for its narrowings only") {
				t.Fatalf("no WARN of the narrowed apply:\n%s", w.logs.String())
			}
		}},
		{"a failure that reaches the apply_failed stop", func(w *tokenWorld) any {
			poisonID = held(w)
			w.exec(`CREATE FUNCTION boom() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
				IF NEW.id = '` + poisonID.String() + `' THEN RAISE EXCEPTION 'boom'; END IF; RETURN NEW; END $$`)
			w.exec(`CREATE TRIGGER boom BEFORE UPDATE ON contract_tokens FOR EACH ROW EXECUTE FUNCTION boom()`)
			return w.record(poisonID, 2, func(r *kc.TokenRecord) { r.Name = "Boom" })
		}, func(t *testing.T, w *tokenWorld, res store.TokenPageResult) {
			if res.Failed != 1 {
				t.Fatalf("%+v", res)
			}
			if n := w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1 AND cause = 'apply_failed' AND lifted_at IS NULL`,
				selectorOf(poisonID)); n != 1 {
				t.Fatal("no apply_failed stop")
			}
			if !strings.Contains(w.logs.String(), store.TokenErrorApplyFailed) {
				t.Fatalf("no ERROR of its class:\n%s", w.logs.String())
			}
			w.exec(`DROP TRIGGER boom ON contract_tokens`)
			// A later version that applies cleanly lifts it.
			w.page(false, w.record(poisonID, 3))
			if n := w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1 AND lifted_at IS NULL`, selectorOf(poisonID)); n != 0 {
				t.Fatal("a clean version left the apply_failed stop")
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newTokenWorld(t)
			a, b := uuid.New(), uuid.New()
			w.page(false, w.record(a, 1), w.record(b, 1))
			poisonRec := c.setup(w)
			before := w.cursor()
			res := w.page(false, w.record(a, 2, revokedBy(kc.RevokedInConsole, w.now)), poisonRec, w.record(b, 2, revokedBy(kc.RevokedOperator, w.now)))
			for _, id := range []uuid.UUID{a, b} {
				if s := w.token(id); !s.Revoked {
					t.Fatalf("revocation %s did not apply: %+v\n%s", id, s, w.logs.String())
				}
				if exists, revoked, ended := w.sticky(id); !exists || !revoked || ended != "revoked" {
					t.Fatalf("revocation %s is not sticky", id)
				}
			}
			if w.cursor() != before+3 {
				t.Fatalf("the cursor: %d, want %d", w.cursor(), before+3)
			}
			if c.check != nil {
				c.check(t, w, res)
			} else if s := w.token(poisonID); s.Name != "Nightly" || *s.Version != 1 {
				// A record that differs in an immutable member is bad: its
				// immutable members are never written, nor anything it widens.
				t.Fatalf("a bad record was applied: %+v", s)
			}
		})
	}
}

// TestZeroTimesNarrow: a zero expires_at is kept as -infinity through every
// later LEAST, and a bad record's sticky until is never past Wappie's clock
// + 365 days, whatever it says (TestANeverHeldRevocationSticksToItsCreation).
func TestZeroTimesNarrow(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	w.page(false, w.record(id, 1))
	r := w.record(id, 2)
	b := bytes.Replace(raw(t, r), []byte(`"expires_at":"`+r.ExpiresAt.UTC().Format(time.RFC3339Nano)+`"`), []byte(`"expires_at":null`), 1)
	w.page(false, b)
	if s := w.token(id); s.Expires != "-infinity" {
		t.Fatalf("a zero expires_at: %+v (%s)\n%s", s, b, w.logs.String())
	}
	w.page(false, w.record(id, 3, func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(w.now.Add(300 * 24 * time.Hour)) }))
	if s := w.token(id); s.Expires != "-infinity" {
		t.Fatalf("a later expiry raised -infinity: %+v", s)
	}

	// A bad record of a token Wappie does not hold, that revokes and says it
	// expires far ahead: created a day ago, its sticky row lasts to that +
	// 365 days, never longer; created 400 days ago, its records have left
	// the feed, and nothing is kept.
	recent, old := uuid.New(), uuid.New()
	farAhead := func(created time.Time) func(*kc.TokenRecord) {
		return func(r *kc.TokenRecord) {
			r.CreatedAt = kc.T(created)
			r.ExpiresAt = kc.T(w.now.Add(400 * 24 * time.Hour)) // over 365 days: Validate refuses it
		}
	}
	w.page(false, w.record(recent, 1, revokedBy(kc.RevokedInConsole, w.now), farAhead(w.now.Add(-24*time.Hour))),
		w.record(old, 1, revokedBy(kc.RevokedInConsole, w.now), farAhead(w.now.Add(-400*24*time.Hour))))
	var until time.Time
	if err := w.pool.QueryRow(context.Background(), `SELECT until FROM contract_token_sticky WHERE token_id = $1`, recent).Scan(&until); err != nil {
		t.Fatal(err)
	}
	if want := w.now.Add(-24 * time.Hour).Add(365 * 24 * time.Hour); !until.Equal(want) {
		t.Fatalf("a bad record's sticky until %v, want its created_at + 365 days %v", until, want)
	}
	if exists, _, _ := w.sticky(old); exists {
		t.Fatal("a bad record created 400 days ago left a sticky row")
	}
}

// TestABadRecordOfAnUnknownTokenMakesNoLiveRow: neither its selector nor a
// row, nor a perm; only its revocation, when it has one, and its grants'
// refusals. A revocation kept so, in the sticky set alone (of a bad record,
// or of a workspace Wappie did not hold), is never revived: a good record
// of the token that lists it unrevoked, as after a platform restore, makes
// no row either, and the reset's pass reports it held revoked (M8).
func TestABadRecordOfAnUnknownTokenMakesNoLiveRow(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	id := uuid.New()
	bad := w.record(id, 1, grants(device, w.ownerSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.Name = "bad@name" })
	res := w.page(false, bad)
	if w.token(id).Exists || res.Bad != 1 {
		t.Fatalf("a bad record made a row: %+v", res)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_selectors WHERE token_id = $1`, id); n != 0 {
		t.Fatal("a bad record took a selector")
	}
	if got := w.refused(id); len(got) != 1 || got[0] != device.String()+"/read=invalid_record@1" {
		t.Fatalf("its grant's refusal: %v", got)
	}
	// Its good version later is a token as any other.
	w.page(false, w.record(id, 2, grants(device, w.ownerSub, w.now, kc.CanRead)))
	if s := w.token(id); !s.Exists || w.perms(id)[device.String()+"/read"] != "pending" {
		t.Fatalf("the good version: %+v %v", s, w.perms(id))
	}

	// A bad record that revokes, and a revocation of a workspace Wappie
	// does not hold yet.
	revoked, orphan, elsewhere := uuid.New(), uuid.New(), uuid.New()
	w.page(false, w.record(revoked, 1, revokedBy(kc.RevokedInConsole, w.now), func(r *kc.TokenRecord) { r.Name = "bad@name" }),
		w.record(orphan, 1, revokedBy(kc.RevokedInConsole, w.now), func(r *kc.TokenRecord) { r.WorkspaceID = elsewhere.String() }))
	for _, gone := range []uuid.UUID{revoked, orphan} {
		if exists, rev, _ := w.sticky(gone); !exists || !rev || w.token(gone).Exists {
			t.Fatalf("%s: the revocation is not in the sticky set alone", gone)
		}
	}
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'elsewhere')`, elsewhere)
	// A platform restore: the new generation lists both, unrevoked.
	w.reset()
	res = w.page(false, w.record(revoked, 1, grants(device, w.ownerSub, w.now, kc.CanRead)),
		w.record(orphan, 1, func(r *kc.TokenRecord) { r.WorkspaceID = elsewhere.String() }))
	if res.Bad != 2 {
		t.Fatalf("the restored records: %+v", res)
	}
	held := w.held()
	for _, gone := range []uuid.UUID{revoked, orphan} {
		if w.token(gone).Exists {
			t.Fatalf("%s: a sticky revocation was revived as a row", gone)
		}
		if n := w.count(`SELECT count(*) FROM contract_token_selectors WHERE token_id = $1`, gone); n != 0 {
			t.Fatalf("%s: a sticky revocation took a selector", gone)
		}
		if h, ok := held[gone]; !ok || !h.Revoked {
			t.Fatalf("%s: not held revoked in the pass: %+v", gone, held)
		}
	}
	if len(w.perms(revoked)) != 0 {
		t.Fatalf("the restored record's grant: %v", w.perms(revoked))
	}
}

// TestANarrowingBumpsAccessVersionOnce (the plan's 3.3): every narrowing of
// a token, a perm dropped included, which no column of its row shows,
// raises its access_version by exactly one, so REST's finish refuses a
// request it began before; what widens nothing, and an older or the same
// version, leave it.
func TestANarrowingBumpsAccessVersionOnce(t *testing.T) {
	w := newTokenWorld(t)
	id, device := uuid.New(), w.number(uuid.Nil)
	w.page(false, w.record(id, 1, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanSend)))
	version := func() int64 { return w.token(id).AccessVersion }
	v := version()
	w.page(false, w.record(id, 2, func(r *kc.TokenRecord) { r.Name = "Renamed" }, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanSend, kc.CanManage)))
	if version() != v {
		t.Fatalf("a rename and a new grant bumped access_version: %d, want %d", version(), v)
	}
	// A good record drops send.
	w.page(false, w.record(id, 3, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanManage)))
	if version() != v+1 {
		t.Fatalf("a perm dropped: access_version %d, want %d", version(), v+1)
	}
	// An older and the same version.
	w.page(false, w.record(id, 2, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanSend, kc.CanManage)),
		w.record(id, 3, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanManage)))
	if version() != v+1 {
		t.Fatalf("an older and the same version: access_version %d, want %d", version(), v+1)
	}
	// A bad record drops manage: its narrowing only, its version not kept.
	w.page(false, w.record(id, 4, grants(device, w.ownerSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.Name = "bad@name" }))
	if s := w.token(id); s.AccessVersion != v+2 || *s.Version != 3 || w.perms(id)[device.String()+"/manage"] != "" {
		t.Fatalf("a bad record's drop: %+v %v, want access_version %d", s, w.perms(id), v+2)
	}
	// A drop and an earlier expiry in one record: one narrowing.
	w.page(false, w.record(id, 5, func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(r.ExpiresAt.Add(-time.Hour)) }))
	if s := w.token(id); s.AccessVersion != v+3 || len(w.perms(id)) != 0 {
		t.Fatalf("a drop and an earlier expiry: %+v %v, want access_version %d", s, w.perms(id), v+3)
	}
}

// TestAStalePageCommitsNothing (the plan's 4.2): the commit compares and
// sets the cursor and the generation the follower asked from, so a page of
// a leader that lost its place writes nothing; a page whose generation is
// not the follower's is a reset.
func TestAStalePageCommitsNothing(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	w.page(false, w.record(id, 1))
	w.page(false, w.record(id, 2, func(r *kc.TokenRecord) { r.Name = "Second" }))
	cursor := w.cursor()
	feed := func(gen uuid.UUID) kc.TokenFeed {
		rec := w.record(id, 3, revokedBy(kc.RevokedInConsole, w.now), func(r *kc.TokenRecord) { r.Generation = gen.String() })
		return kc.TokenFeed{Generation: gen.String(), GenerationConfirmed: true, PublishedThrough: kc.T(w.now), More: false,
			Head: cursor + 1, NextAfter: cursor + 1, Items: []kc.TokenFeedItem{{Seq: cursor + 1, Token: raw(t, rec)}}}
	}
	unchanged := func(what string) {
		t.Helper()
		if s := w.token(id); w.cursor() != cursor || s.Revoked || *s.Version != 2 || len(w.refused(id)) != 0 {
			t.Fatalf("%s wrote: cursor %d (want %d), %+v", what, w.cursor(), cursor, s)
		}
		if exists, _, _ := w.sticky(id); exists {
			t.Fatalf("%s wrote the sticky set", what)
		}
	}
	res, err := w.tokens.CommitTokenPage(w.ctx(), store.TokenPage{After: cursor - 1, SeenGeneration: w.gen, Feed: feed(w.gen), Now: w.now})
	if err != nil || res.Committed {
		t.Fatalf("a page from an older cursor: %+v %v", res, err)
	}
	unchanged("a page from an older cursor")
	other := uuid.New()
	res, err = w.tokens.CommitTokenPage(w.ctx(), store.TokenPage{After: cursor, SeenGeneration: other, Feed: feed(other), Now: w.now})
	if err != nil || res.Committed {
		t.Fatalf("a page of a generation Wappie no longer holds: %+v %v", res, err)
	}
	unchanged("a page of a generation Wappie no longer holds")
	if _, err := w.tokens.CommitTokenPage(w.ctx(), store.TokenPage{After: cursor, SeenGeneration: w.gen, Feed: feed(other), Now: w.now}); !errors.Is(err, store.ErrPageGeneration) {
		t.Fatalf("a page of another generation than the follower's: %v", err)
	}
	unchanged("a page of another generation than the follower's")
	if res := w.page(false, w.record(id, 3, revokedBy(kc.RevokedInConsole, w.now))); !res.Committed || !w.token(id).Revoked {
		t.Fatal("the page from the stored cursor did not commit")
	}
}

// TestAPublishedThroughAheadIsNotTrusted: a page with more false vouches for
// its published_through only when it is at most ContractClockSkew past
// Wappie's clock; one further ahead commits all the same, keeps the last
// trusted value, and logs one ERROR.
func TestAPublishedThroughAheadIsNotTrusted(t *testing.T) {
	w := newTokenWorld(t)
	w.page(false)
	stored := func() time.Time {
		t.Helper()
		var at time.Time
		if err := w.pool.QueryRow(context.Background(), `SELECT published_through FROM contract_token_state`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if !stored().Equal(w.now) {
		t.Fatalf("published_through %v, want %v", stored(), w.now)
	}
	commit := func(through time.Time) store.TokenPageResult {
		t.Helper()
		c := w.cursor()
		res, err := w.tokens.CommitTokenPage(w.ctx(), store.TokenPage{After: c, SeenGeneration: w.gen, Now: w.now,
			Feed: kc.TokenFeed{Generation: w.gen.String(), GenerationConfirmed: true, PublishedThrough: kc.T(through), Head: c, NextAfter: c,
				Items: []kc.TokenFeedItem{}}})
		if err != nil || !res.Committed {
			t.Fatalf("the page: %+v %v", res, err)
		}
		return res
	}
	if res := commit(w.now.Add(store.ContractClockSkew + time.Minute)); !res.Ahead || res.Vouched {
		t.Fatalf("a published_through 6 minutes ahead: %+v", res)
	}
	if !stored().Equal(w.now) {
		t.Fatalf("an untrusted published_through was stored: %v", stored())
	}
	if !strings.Contains(w.logs.String(), "level=ERROR") || !strings.Contains(w.logs.String(), "ahead of the clock") {
		t.Fatalf("no ERROR:\n%s", w.logs.String())
	}
	if res := commit(w.now.Add(4 * time.Minute)); res.Ahead || !res.Vouched || !stored().Equal(w.now.Add(4*time.Minute)) {
		t.Fatalf("a published_through 4 minutes ahead: %+v, stored %v", res, stored())
	}
}

// TestAStoppedTokenStaysListedInAPass: a record of a reset's pass that
// Wappie cannot apply even narrowed stops its token (apply_failed), but the
// platform listed it, so the pass never unlists it, which is terminal: the
// stop lifts when a later version applies.
func TestAStoppedTokenStaysListedInAPass(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	id := uuid.New()
	w.page(false, w.record(id, 1, grants(device, w.ownerSub, w.now, kc.CanRead)))
	if got := w.judge(); got.Applied != 1 {
		t.Fatalf("the judge: %+v", got)
	}
	w.reset()
	// The database refuses to drop this token's perms: the pass's record,
	// which drops its Read, fails whole and narrowed.
	w.exec(`CREATE FUNCTION no_drop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF OLD.token_id = '` + id.String() + `' THEN RAISE EXCEPTION 'no drop'; END IF; RETURN OLD; END $$`)
	w.exec(`CREATE TRIGGER no_drop BEFORE DELETE ON contract_token_perms FOR EACH ROW EXECUTE FUNCTION no_drop()`)
	if res := w.page(false, w.record(id, 1)); res.Failed != 1 {
		t.Fatalf("the pass's record: %+v\n%s", res, w.logs.String())
	}
	if n := w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1 AND cause = 'apply_failed' AND lifted_at IS NULL`, selectorOf(id)); n != 1 {
		t.Fatal("no apply_failed stop")
	}
	w.exec(`UPDATE contract_state SET round_generation = $1`, w.gen)
	if res := w.page(false); !res.PassReady {
		t.Fatal("the pass is not ready")
	}
	res, err := w.tokens.FinishTokenPass(w.ctx(), w.gen, w.now)
	if err != nil || !res.Done || len(res.Unlisted) != 0 {
		t.Fatalf("the pass: %+v %v", res, err)
	}
	if s := w.token(id); s.Unlisted {
		t.Fatal("the pass unlisted a token it listed, for a fault of Wappie's own")
	}
	if exists, _, _ := w.sticky(id); exists {
		t.Fatal("the stopped token is in the sticky set")
	}
}
