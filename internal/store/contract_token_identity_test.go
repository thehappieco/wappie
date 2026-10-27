package store_test

import (
	"context"
	"encoding/base64"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// tokensOn turns tokens on and caught up, with the contract at observe, as
// token auth and the grant write need.
func (w *tokenWorld) tokensOn() {
	w.t.Helper()
	w.exec(`UPDATE contract_state SET mode = 'observe', events_from = coalesce(events_from, clock_timestamp())`)
	w.exec(`UPDATE contract_token_state SET mode = 'on', caught_up_at = clock_timestamp()`)
}

// readingToken is a token of the owner's, with key pinned and the given
// perms on device, given by the owner and judged.
func (w *tokenWorld) readingToken(device uuid.UUID, key *kc.ReadingKey, perms ...string) uuid.UUID {
	w.t.Helper()
	if len(perms) == 0 {
		perms = []string{kc.CanRead}
	}
	id := uuid.New()
	w.page(false, w.record(id, 1, grants(device, w.ownerSub, w.now, perms...), func(r *kc.TokenRecord) { r.ReadingKey = key }))
	w.judge()
	return id
}

// identityOf is a token's identity and whether it was dropped.
func (w *tokenWorld) identityOf(token uuid.UUID) (identity *uuid.UUID, dropped bool) {
	w.t.Helper()
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT identity_user_id, identity_dropped_at IS NOT NULL FROM contract_tokens WHERE id = $1`, token).
			Scan(&identity, &dropped)
	})
	return identity, dropped
}

// fetched stamps a token's signed GET at at, as ApplyTokenRecord does.
func (w *tokenWorld) fetched(token uuid.UUID, at time.Time) {
	w.t.Helper()
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE contract_tokens SET fetched_at = $2 WHERE id = $1`, token, at)
		return err
	})
}

// seal is a token grant of device at epoch by sealer, its GET fresh.
func (w *tokenWorld) seal(token, device, sealer uuid.UUID, epoch uint16) error {
	w.t.Helper()
	w.fetched(token, w.now.Add(-5*time.Second))
	return w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: token, Device: device, Epoch: epoch,
		SealedDSK: []byte("sealed to the token"), Sealer: sealer, Now: w.now})
}

func (w *tokenWorld) grantsOf(user uuid.UUID) int {
	w.t.Helper()
	return w.count(`SELECT count(*) FROM device_key_grants WHERE user_id = $1`, user)
}

// TestATokenIdentityIsNeverAMember (the plan's 10.4): a live token's
// identity, made at pin time with the pinned key, has no membership and no
// personal workspace, is in no listing, and refuses every act on members
// and grants.
func TestATokenIdentityIsNeverAMember(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	key := readingKey(t)
	token := w.readingToken(device, key)
	identity, dropped := w.identityOf(token)
	if identity == nil || dropped {
		t.Fatal("a live token with a pinned key has no identity")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(key.Key)
	var email string
	var pub []byte
	var service, flagged bool
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT email, public_key, role = 'service', token_identity FROM users WHERE id = $1`, *identity).
			Scan(&email, &pub, &service, &flagged)
	})
	if email != "t-"+token.String()+"@token.invalid" || string(pub) != string(raw) || !service || !flagged {
		t.Fatalf("the identity: %s %x service %v flagged %v", email, pub, service, flagged)
	}
	if n := w.count(`SELECT count(*) FROM workspace_memberships WHERE user_id = $1`, *identity); n != 0 {
		t.Fatalf("%d memberships", n)
	}
	if n := w.count(`SELECT count(*) FROM tenants WHERE personal_owner_id = $1`, *identity); n != 0 {
		t.Fatal("a personal workspace")
	}
	list, err := w.users.List(ctx, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range list {
		if u.ID == *identity {
			t.Fatal("Users.List lists the identity")
		}
	}
	if _, err := w.users.Get(ctx, w.tenant, *identity); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Users.Get: %v", err)
	}
	members, err := w.users.Members(ctx, w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.ID == *identity {
			t.Fatal("Members lists the identity")
		}
	}
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"grant.add": w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: *identity, Epoch: 1, SealedDSK: []byte("g")}, &w.owner),
		"a permission": w.users.SetDevicePermission(ctx, w.tenant, w.owner,
			store.DevicePermission{DeviceID: device, UserID: *identity, Read: true}),
		"a member's update":  w.users.UpdateMember(ctx, w.tenant, w.owner, *identity, "admin", "active"),
		"a member's removal": w.users.RemoveMember(ctx, w.tenant, w.owner, *identity),
		"grant.revoke":       w.keys.RevokeGrant(ctx, w.tenant, device, *identity),
	} {
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s on a token identity: %v", name, err)
		}
	}
	if w.grantsOf(*identity) != 1 {
		t.Fatal("a refused revoke took the token's grant")
	}
}

// TestAGrantToATokenIdentityAddsNoPermissionRow and
// TestDeviceReadersListsTokensApart: the grant brings no permission row (a
// token's Read is its record's), the readers never list it, and
// device.readers' tokens do.
func TestAGrantToATokenIdentityAddsNoPermissionRow(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	identity, _ := w.identityOf(token)
	if n := w.count(`SELECT count(*) FROM device_permissions WHERE user_id = $1`, *identity); n != 0 {
		t.Fatalf("%d permission rows for the identity", n)
	}
	readers, err := w.keys.Readers(ctx, w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range readers {
		if r.UserID == *identity {
			t.Fatal("the readers list the token")
		}
	}
	held, err := w.keys.TokenReaders(ctx, w.tenant, device)
	if err != nil || len(held) != 1 || held[0].ID != token || held[0].Name != "Nightly" || held[0].Epoch != 1 || held[0].GrantedBy == "" {
		t.Fatalf("the token readers: %+v %v", held, err)
	}
}

// TestATokenIdentityIsADecoyAtSignIn: its address answers the challenge as
// an unknown one does, and no password or recovery proof opens it.
func TestATokenIdentityIsADecoyAtSignIn(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	token := w.readingToken(w.number(uuid.Nil), readingKey(t))
	email := "t-" + token.String() + "@token.invalid"
	salt, params, err := w.users.Challenge(ctx, email)
	unknownSalt, unknownParams, err2 := w.users.Challenge(ctx, "t-"+uuid.NewString()+"@token.invalid")
	if err != nil || err2 != nil || len(salt) != 16 || params != unknownParams || len(unknownSalt) != 16 {
		t.Fatalf("the challenge: %x %+v %v, an unknown address's %+v %v", salt, params, err, unknownParams, err2)
	}
	if _, err := w.users.Authenticate(ctx, email, "anything"); !errors.Is(err, store.ErrBadCredentials) {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := w.users.OpenRecovery(ctx, email, "anything"); !errors.Is(err, store.ErrBadCredentials) {
		t.Fatalf("OpenRecovery: %v", err)
	}
}

// TestATokenNeverCountsAsABackup: with one human holder of a number's key
// and a token that reads it with a grant, removing or disabling the human is
// refused as the last reader; the snapshot protects the human and counts no
// other backup. And TestDroppingATokensGrantsNeverStrands: a token's Read
// dropped takes its grant in the same write, and strands nothing.
func TestATokenNeverCountsAsABackup(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	// The key moves to a member, the one human holder.
	memberSub := uuid.New()
	member := w.linked("member", "member", memberSub, true)
	w.reads(member, device)
	if err := w.keys.RevokeGrant(ctx, w.tenant, device, w.owner); err != nil {
		t.Fatal(err)
	}
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, member); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("removing the one human holder beside a token: %v", err)
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, member, "member", "disabled"); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("disabling the one human holder beside a token: %v", err)
	}
	snap, err := w.contract.Snapshot(ctx, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range snap.Items {
		if it.ID != device {
			continue
		}
		if len(it.Protected) != 1 || it.Protected[0] != memberSub || it.OtherBackups != 0 {
			t.Fatalf("the snapshot: protected %v, other backups %d", it.Protected, it.OtherBackups)
		}
	}

	// The token's Read dropped: its grant goes in that commit, and nothing
	// is stranded or noticed.
	identity, _ := w.identityOf(token)
	w.page(false, w.record(token, 2, grants(device, w.ownerSub, w.now, kc.CanSend)))
	if w.grantsOf(*identity) != 0 {
		t.Fatal("a dropped Read left the token's grant")
	}
	if n := w.count(`SELECT count(*) FROM item_events WHERE type = 'stranded'`); n != 0 {
		t.Fatalf("%d stranded rows", n)
	}
	if n := w.count(`SELECT count(*) FROM device_notices WHERE kind = 'number_stranded'`); n != 0 {
		t.Fatalf("%d stranded notices", n)
	}
}

// TestDroppingReadDeletesTheTokensGrantsInTheSameWrite: a Read dropped on
// one number takes the grant there and no other; a bad record's narrowing
// does the same; a revocation takes them all, with the identity.
func TestDroppingReadDeletesTheTokensGrantsInTheSameWrite(t *testing.T) {
	w := newTokenWorld(t)
	a, b, c := w.number(uuid.Nil), w.number(uuid.Nil), w.number(uuid.Nil)
	key := readingKey(t)
	id := uuid.New()
	all := func(version int64, devices ...uuid.UUID) kc.TokenRecord {
		var opts []func(*kc.TokenRecord)
		for _, d := range devices {
			opts = append(opts, grants(d, w.ownerSub, w.now, kc.CanRead))
		}
		return w.record(id, version, append(opts, func(r *kc.TokenRecord) { r.ReadingKey = key })...)
	}
	w.page(false, all(1, a, b, c))
	w.judge()
	w.tokensOn()
	for _, d := range []uuid.UUID{a, b, c} {
		if err := w.seal(id, d, w.owner, 1); err != nil {
			t.Fatal(err)
		}
	}
	identity, _ := w.identityOf(id)
	on := func(d uuid.UUID) int {
		return w.count(`SELECT count(*) FROM device_key_grants WHERE user_id = $1 AND device_id = $2`, *identity, d)
	}
	w.page(false, all(2, a, b))
	if on(c) != 0 || on(a) != 1 || on(b) != 1 {
		t.Fatalf("a dropped Read on c: %d %d %d", on(a), on(b), on(c))
	}
	bad := all(3, a)
	bad.Name = "bad@name"
	w.page(false, bad)
	if on(b) != 0 || on(a) != 1 {
		t.Fatalf("a bad record's narrowing: %d %d", on(a), on(b))
	}
	w.page(false, w.record(id, 4, revokedBy(kc.RevokedInConsole, w.now)))
	if w.grantsOf(*identity) != 0 || w.count(`SELECT count(*) FROM users WHERE id = $1`, *identity) != 0 {
		t.Fatal("a revocation left the identity or its grants")
	}
}

// TestTheFirstReadingKeyIsPinned and TestADifferentKeyIsReadingKeyChanged,
// with handcrafted records (contracttest never publishes one): the first
// key is pinned, and the identity's key is it; a record with another key is
// applied for its narrowings, its new Read refused as reading_key_changed,
// the grant already sealed kept, and every new seal refused.
func TestADifferentKeyIsReadingKeyChanged(t *testing.T) {
	w := newTokenWorld(t)
	a, b := w.number(uuid.Nil), w.number(uuid.Nil)
	first, second := readingKey(t), readingKey(t)
	id := uuid.New()
	w.page(false, w.record(id, 1, grants(a, w.ownerSub, w.now, kc.CanRead, kc.CanSend), func(r *kc.TokenRecord) { r.ReadingKey = first }))
	w.judge()
	w.tokensOn()
	if err := w.seal(id, a, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	var pinned string
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT fingerprint FROM contract_token_pins WHERE token_id = $1`, id).Scan(&pinned)
	})
	if pinned != first.Fingerprint {
		t.Fatalf("the pin: %s, want %s", pinned, first.Fingerprint)
	}
	// The second key: send dropped (a narrowing), a new Read on b.
	w.page(false, w.record(id, 2, grants(a, w.ownerSub, w.now, kc.CanRead), grants(b, w.ownerSub, w.now, kc.CanRead),
		func(r *kc.TokenRecord) { r.ReadingKey = second }))
	if s := w.token(id); !s.KeyChanged {
		t.Fatal("no key_changed_at")
	}
	if !strings.Contains(w.logs.String(), store.TokenErrorKeyChanged) {
		t.Fatalf("no ERROR of its class:\n%s", w.logs.String())
	}
	w.judge()
	perms := w.perms(id)
	if perms[a.String()+"/send"] != "" || perms[b.String()+"/read"] != "refused:reading_key_changed" || perms[a.String()+"/read"] != "applied" {
		t.Fatalf("the perms after another key: %v", perms)
	}
	identity, _ := w.identityOf(id)
	if w.grantsOf(*identity) != 1 {
		t.Fatal("the grant sealed to the pinned key went")
	}
	if err := w.seal(id, a, w.owner, 1); !errors.Is(err, store.ErrTokenKeyChanged) {
		t.Fatalf("a seal after the key changed: %v", err)
	}
}

// TestTheGrantGETChecksTheFingerprint: a by-id GET whose fingerprint is not
// its key's is never pinned, and refuses its new grants as
// reading_key_changed; the good one then pins.
func TestTheGrantGETChecksTheFingerprint(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	id := uuid.New()
	w.page(false, w.record(id, 1))
	key := readingKey(t)
	bad := *key
	bad.Fingerprint = strings.Repeat("0", 32)
	res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 2, grants(device, w.ownerSub, w.now, kc.CanRead),
		func(r *kc.TokenRecord) { r.ReadingKey = &bad }), w.now, w.now)
	if err != nil || !res.Bad {
		t.Fatalf("a mismatched fingerprint: %+v %v", res, err)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_pins WHERE token_id = $1`, id); n != 0 {
		t.Fatal("a mismatched fingerprint was pinned")
	}
	if got := w.refused(id); len(got) != 1 || got[0] != device.String()+"/read=reading_key_changed@2" {
		t.Fatalf("its refusal: %v", got)
	}
	if _, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 3, func(r *kc.TokenRecord) { r.ReadingKey = key }), w.now, w.now); err != nil {
		t.Fatal(err)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_pins WHERE token_id = $1 AND fingerprint = $2`, id, key.Fingerprint); n != 1 {
		t.Fatal("the good GET did not pin")
	}
}

// TestRevokingATokenDeletesItsIdentityAndKeepsThePin: a revocation of every
// reason, an unlisting and an expiry each delete the identity, its grants
// and login with it; the pin stays, and the identity is never made again.
func TestRevokingATokenDeletesItsIdentityAndKeepsThePin(t *testing.T) {
	for _, end := range []string{kc.RevokedInConsole, kc.RevokedAppRemoved, kc.RevokedAppHeld, "unlisted", "expired"} {
		t.Run(end, func(t *testing.T) {
			w := newTokenWorld(t)
			device := w.number(uuid.Nil)
			key := readingKey(t)
			id := w.readingToken(device, key)
			w.tokensOn()
			if err := w.seal(id, device, w.owner, 1); err != nil {
				t.Fatal(err)
			}
			identity, _ := w.identityOf(id)
			switch end {
			case "unlisted":
				w.reset()
				w.exec(`UPDATE contract_state SET round_generation = $1`, w.gen)
				w.page(false)
				if res, err := w.tokens.FinishTokenPass(w.ctx(), w.gen, w.now); err != nil || len(res.Unlisted) != 1 {
					t.Fatalf("the pass: %+v %v", res, err)
				}
			case "expired":
				if _, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(40*24*time.Hour)); err != nil {
					t.Fatal(err)
				}
			default:
				w.page(false, w.record(id, 2, revokedBy(end, w.now)))
			}
			got, dropped := w.identityOf(id)
			if got == nil || *got != *identity || !dropped {
				t.Fatalf("the identity after the end: %v dropped %v", got, dropped)
			}
			if n := w.count(`SELECT count(*) FROM users WHERE id = $1`, *identity); n != 0 {
				t.Fatal("the identity's row stayed")
			}
			if w.grantsOf(*identity) != 0 {
				t.Fatal("its grants stayed")
			}
			var login int
			if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM user_logins WHERE user_id = $1`, *identity).Scan(&login); err != nil || login != 0 {
				t.Fatalf("its login: %d %v", login, err)
			}
			if n := w.count(`SELECT count(*) FROM contract_token_pins WHERE token_id = $1`, id); n != 1 {
				t.Fatal("the pin went")
			}
			// A later record never makes it again.
			w.page(false, w.record(id, 9, grants(device, w.ownerSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = key }))
			if n := w.count(`SELECT count(*) FROM users WHERE token_identity`); n != 0 {
				t.Fatal("an identity was made again")
			}
		})
	}
}

// TestATokenGrantNeedsAFreshSignedGET, TestATokenGrantNeedsTheReadFlag and
// TestATokenGrantNeedsTheSealerToReadNow: the grant write's every refusal,
// in the plan's order, and the one it then writes.
func TestATokenGrantNeedsItsConditions(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	put := func(token, device, sealer uuid.UUID, epoch uint16) error {
		return w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: token, Device: device, Epoch: epoch,
			SealedDSK: []byte("s"), Sealer: sealer, Now: w.now})
	}
	w.fetched(token, w.now)
	if err := put(token, device, w.owner, 1); !errors.Is(err, store.ErrTokenNotLive) {
		t.Fatalf("tokens off: %v", err)
	}
	w.tokensOn()
	if err := put(uuid.New(), device, w.owner, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown token: %v", err)
	}
	// Another workspace's token answers as an unknown one.
	if err := w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: uuid.MustParse(newTenant(t, w.pool, "other")), Token: token,
		Device: device, Epoch: 1, SealedDSK: []byte("s"), Sealer: w.owner, Now: w.now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another workspace's token: %v", err)
	}
	// The signed GET: none recent, over a minute, then just now by
	// ApplyTokenRecord's stamp.
	w.fetched(token, w.now.Add(-61*time.Second))
	if err := put(token, device, w.owner, 1); !errors.Is(err, store.ErrTokenStale) {
		t.Fatalf("a GET 61 s old: %v", err)
	}
	if res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(token, 1, grants(device, w.ownerSub, w.now, kc.CanRead),
		func(r *kc.TokenRecord) { r.ReadingKey = readingKeyOf(t, w, token) }), w.now.Add(-2*time.Second), w.now); err != nil || !res.Stamped {
		t.Fatalf("the GET: %+v %v", res, err)
	}
	// The sealer: a member, then an admin who does not read it.
	member := w.linked("member", "member", uuid.New(), true)
	w.reads(member, device)
	if err := put(token, device, member, 1); !errors.Is(err, store.ErrSealerCannotRead) {
		t.Fatalf("a member's seal: %v", err)
	}
	admin := w.linked("admin", "admin", uuid.New(), true)
	if err := put(token, device, admin, 1); !errors.Is(err, store.ErrSealerCannotRead) {
		t.Fatalf("a seal by an admin who does not read: %v", err)
	}
	// The Read: none on another number, an old epoch after a rotation.
	other := w.number(uuid.Nil)
	if err := put(token, other, w.owner, 1); !errors.Is(err, store.ErrTokenNoRead) {
		t.Fatalf("a number the token does not read: %v", err)
	}
	if err := put(token, device, w.owner, 1); err != nil {
		t.Fatalf("the grant: %v", err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, device, 2, pub); err != nil {
		t.Fatal(err)
	}
	if err := put(token, device, w.owner, 1); !errors.Is(err, store.ErrTokenEpoch) {
		t.Fatalf("an old epoch: %v", err)
	}
	// TestKeyRotationLeavesTheTokenWaiting: its Read stands, with no grant
	// at the new epoch until someone seals again.
	got, err := w.tokens.TokenGrantContext(ctx, w.tenant, token, []uuid.UUID{device, other}, w.now)
	if err != nil || len(got.Numbers) != 2 || !got.Live {
		t.Fatalf("the grant context: %+v %v", got, err)
	}
	for _, n := range got.Numbers {
		switch n.Device {
		case device:
			if n.CurrentEpoch != 2 || n.Read != store.TokenReadApplied || n.Granted {
				t.Fatalf("after the rotation: %+v", n)
			}
		case other:
			if n.Read != store.TokenReadNone || n.Granted {
				t.Fatalf("the other number: %+v", n)
			}
		}
	}
	// Waiting and refused are no Read: a token given by someone whose
	// document Wappie does not hold, and by one who does not read.
	waitingSub, notReaderSub := uuid.New(), uuid.New()
	w.linked("waiting", "admin", waitingSub, false)
	w.linked("notreader", "admin", notReaderSub, true)
	waiting, refused := uuid.New(), uuid.New()
	key := readingKey(t)
	w.page(false, w.record(waiting, 1, grants(device, waitingSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = key }),
		w.record(refused, 1, grants(device, notReaderSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }))
	w.judge()
	for name, tok := range map[string]uuid.UUID{"waiting": waiting, "refused": refused} {
		w.fetched(tok, w.now)
		if err := put(tok, device, w.owner, 2); !errors.Is(err, store.ErrTokenNoRead) {
			t.Errorf("a %s Read: %v", name, err)
		}
	}
}

// readingKeyOf is the key pinned for token, as its record carries it.
func readingKeyOf(t *testing.T, w *tokenWorld, token uuid.UUID) *kc.ReadingKey {
	t.Helper()
	var key []byte
	var fp string
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT key, fingerprint FROM contract_token_pins WHERE token_id = $1`, token).Scan(&key, &fp)
	})
	return &kc.ReadingKey{Suite: kc.ReadingKeySuite, Key: base64.RawURLEncoding.EncodeToString(key), Fingerprint: fp, RegisteredAt: kc.T(w.now.Add(-time.Hour))}
}

// A Read drop racing a grant write waits on the grant's locks (the
// workspace's row, then the token's rows), then deletes the grant it wrote:
// no grant outlives the Read it was sealed under.
func TestATokenGrantRacingAReadDropIsDeleted(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	key := readingKey(t)
	token := w.readingToken(device, key)
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	identity, _ := w.identityOf(token)
	// The grant write's own locks and write, held open.
	holder, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck // committed below; a no-op then
	for _, q := range []string{
		`SELECT set_config('app.tenant_id', '` + w.tenant.String() + `', true)`,
		`SELECT id FROM tenants WHERE id = '` + w.tenant.String() + `' FOR UPDATE`,
		`SELECT 1 FROM contract_tokens WHERE id = '` + token.String() + `' FOR SHARE`,
		`SELECT 1 FROM contract_token_perms WHERE token_id = '` + token.String() + `' AND perm = 'read' FOR SHARE`,
		`UPDATE device_key_grants SET sealed_dsk = 'resealed' WHERE user_id = '` + identity.String() + `'`,
	} {
		if _, err := holder.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.tryPage(false, w.record(token, 2, grants(device, w.ownerSub, w.now, kc.CanSend), func(r *kc.TokenRecord) { r.ReadingKey = key }))
		done <- err
	}()
	untilTokenWaiters(t, w, 1)
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the Read drop: %v", err)
	}
	if w.grantsOf(*identity) != 0 {
		t.Fatal("the grant written beside the drop outlived it")
	}
	if strings.Contains(w.logs.String(), "deadlock") {
		t.Fatalf("a deadlock:\n%s", w.logs.String())
	}
}

// TestADeletedNumberLeavesEveryTokenWithItsGrants and
// TestMoveAndDeleteChecksCountATeamToken: the deletion's check lists the
// token; the deletion takes the number off it, its grants with it, every
// instance kept off (item_deleted); a recovery gives nothing back, and a
// late record listing the same grant is refused as no such item.
func TestADeletedNumberLeavesEveryTokenWithItsGrants(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	// Linked, so the deletion has a number to delete rather than a
	// registration to drop.
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511912345678@s.whatsapp.net', last_connected_at = now() WHERE id = $1`, device)
		return err
	})
	key := readingKey(t)
	token := w.readingToken(device, key, kc.CanRead, kc.CanSend)
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	identity, _ := w.identityOf(token)
	check, err := w.devices.DeleteCheck(ctx, w.tenant, w.owner, device)
	if err != nil || len(check.Tokens) != 1 || check.Tokens[0].ID != token || check.Tokens[0].Name != "Nightly" {
		t.Fatalf("the deletion's check: %+v %v", check.Tokens, err)
	}
	for _, s := range check.ServiceAccounts {
		if s.ID == *identity {
			t.Fatal("the check lists the token as a service account")
		}
	}
	if _, err := w.devices.Quarantine(ctx, w.tenant, w.owner, device, nil); err != nil {
		t.Fatal(err)
	}
	if len(w.perms(token)) != 0 || w.grantsOf(*identity) != 0 {
		t.Fatalf("after the deletion: %v, %d grants", w.perms(token), w.grantsOf(*identity))
	}
	if n := w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1 AND cause = 'item_deleted'`, token); n != 2 {
		t.Fatalf("%d instances kept off, want 2", n)
	}
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, device); err != nil {
		t.Fatal(err)
	}
	if len(w.perms(token)) != 0 || w.grantsOf(*identity) != 0 {
		t.Fatal("a recovery gave the token something back")
	}
	w.page(false, w.record(token, 2, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanSend), func(r *kc.TokenRecord) { r.ReadingKey = key }))
	if len(w.perms(token)) != 0 {
		t.Fatalf("a late record brought the grant back: %v", w.perms(token))
	}
	if got := strings.Join(w.refused(token), " "); !strings.Contains(got, device.String()+"/read=item_unknown@2") {
		t.Fatalf("the late record's refusals: %s", got)
	}
}

// TestAMovedOutNumberLeavesEveryToken and
// TestMoveAndDeleteChecksCountATeamToken: a token that holds the number
// refuses its move-out, listed as kind token, never service; one whose perms
// were all refused does not, and the move takes them off (item_moved).
func TestAMovedOutNumberLeavesEveryToken(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	identity, _ := w.identityOf(token)
	preview, err := w.devices.PreviewPersonalTransfer(ctx, w.tenant, w.owner, device)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range preview.Others {
		if o.Kind == "service" || (o.UserID != nil && *o.UserID == *identity) {
			t.Fatalf("the token listed as %+v", o)
		}
		if o.Kind == "token" && o.TokenID == token.String() && o.Name == "Nightly" && strings.Join(o.Why, ",") == "read,key" {
			found = true
		}
	}
	if preview.Eligible || !found {
		t.Fatalf("the preview: %+v", preview)
	}
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, device, personal); err == nil {
		t.Fatal("a token's number moved out")
	}
	// Revoked, the token holds nothing; another token's refused perm is
	// all that is left.
	w.page(false, w.record(token, 2, revokedBy(kc.RevokedInConsole, w.now)))
	stranger := uuid.New()
	w.page(false, w.record(stranger, 1, grants(device, uuid.New(), w.now, kc.CanSend)))
	w.judge()
	if got := w.perms(stranger)[device.String()+"/send"]; got != "refused:local_role" {
		t.Fatalf("the stranger's perm: %s", got)
	}
	if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, device, personal); err != nil {
		t.Fatalf("the move with only a refused perm left: %v", err)
	}
	if len(w.perms(stranger)) != 0 {
		t.Fatal("the refused perm stayed with a moved number")
	}
	// Kept off for good: refused already, so its instance keeps that cause.
	if n := w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1 AND item = $2`, stranger, device.String()); n != 1 {
		t.Fatalf("%d instances kept off", n)
	}
}

// TestEveryGrantCountJoinsAMembership is a static test over every query of
// the store that reads device_key_grants: each either joins
// workspace_memberships, so a token identity (which has none) is never a
// holder, a reader or a backup, or names one account (a parameter, a
// connection's service account, a token's identity). A new query that
// counts holders without either fails here. Writes are not counted.
func TestEveryGrantCountJoinsAMembership(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	one := regexp.MustCompile(`user_id\s*(=|<>)\s*(\$\d+|[a-z]+\.(identity_user_id|service_user_id))`)
	write := regexp.MustCompile(`(?is)^\s*(INSERT|DELETE|UPDATE)\b`)
	seen, files14 := 0, map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			q, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(q, "device_key_grants") || !strings.Contains(q, "SELECT") && !strings.Contains(q, "DELETE") {
				// A table's name alone, in a list of tables, is no query.
				return true
			}
			files14[path] = true
			if write.MatchString(q) && !strings.Contains(q, "SELECT") {
				return true
			}
			seen++
			if !strings.Contains(q, "workspace_memberships") && !one.MatchString(q) {
				t.Errorf("%s: a query reads device_key_grants with no membership and no one account:\n%s", path, q)
			}
			return true
		})
	}
	if seen < 20 || len(files14) < 14 {
		t.Fatalf("the scan found %d queries in %d files: not the store's", seen, len(files14))
	}
}
