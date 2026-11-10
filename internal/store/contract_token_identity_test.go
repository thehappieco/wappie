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

// TestAGiversLostReadLeavesTheToken (DS47, the platform's 0061): a
// platform token is its own holder kind. Its giver's Read and every flag
// taken on Wappie's screen end the giver's own connections, and the grant
// the giver sealed to the token stays, its Read applied, its identity
// live. The judge decided that Read once.
func TestAGiversLostReadLeavesTheToken(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	// Another reader, so the owner's Read may go.
	w.reads(w.linked("member", "member", uuid.New(), true), device)
	if _, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: w.owner}); err != nil {
		t.Fatal(err)
	}
	if n := w.count(`SELECT count(*) FROM device_key_grants WHERE user_id = $1 AND device_id = $2`, w.owner, device); n != 0 {
		t.Fatalf("the giver kept %d grants", n)
	}
	identity, dropped := w.identityOf(token)
	if identity == nil || dropped || w.grantsOf(*identity) != 1 {
		t.Fatal("the giver's lost Read took the token's identity or grant")
	}
	if n := w.count(`SELECT count(*) FROM contract_token_perms WHERE token_id = $1 AND perm = 'read' AND state = 'applied'`, token); n != 1 {
		t.Fatalf("the token's Read: %d applied", n)
	}
}

// TestAReadGivenAgainTakesItsGrants (design 3.5, the plan's 5.2): a record
// whose Read on a number is another grant instance than the one Wappie holds
// (the feed carries only a token's latest version, so a Read ungranted and
// given again between two reads of it arrives so) drops the stored Read with
// its grants in that write, whatever the judge then says of the new one,
// which opens the number only with a fresh seal. A reset over the new,
// pending one then leaves the token nothing on the number, so it moves.
func TestAReadGivenAgainTakesItsGrants(t *testing.T) {
	for _, then := range []string{"applied", "refused", "reset"} {
		t.Run(then, func(t *testing.T) {
			w := newTokenWorld(t)
			ctx := context.Background()
			device := w.number(uuid.Nil)
			key := readingKey(t)
			id, first := uuid.New(), w.now.Add(-time.Hour)
			w.page(false, w.record(id, 1, grants(device, w.ownerSub, first, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = key }))
			w.judge()
			w.tokensOn()
			if err := w.seal(id, device, w.owner, 1); err != nil {
				t.Fatal(err)
			}
			identity, _ := w.identityOf(id)
			giver := w.ownerSub
			if then == "refused" {
				// No one Wappie knows: local_role.
				giver = uuid.New()
			}
			w.page(false, w.record(id, 2, grants(device, giver, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = key }))
			if n := w.grantsOf(*identity); n != 0 {
				t.Fatalf("the Read given again kept %d grants", n)
			}
			if n := w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1 AND perm = 'read' AND cause = 'dropped' AND granted_at = $2`,
				id, first); n != 1 {
				t.Fatalf("%d removed rows for the old instance", n)
			}
			if then == "reset" {
				w.reset()
				if p, n := w.perms(id), w.grantsOf(*identity); len(p) != 0 || n != 0 {
					t.Fatalf("after the reset: %v, %d grants", p, n)
				}
				preview, err := w.devices.PreviewPersonalTransfer(ctx, w.tenant, w.owner, device)
				if err != nil {
					t.Fatal(err)
				}
				for _, o := range preview.Others {
					if o.Kind == "token" {
						t.Fatalf("the token still holds the number: %+v", o)
					}
				}
				return
			}
			w.judge()
			want := "applied"
			if then == "refused" {
				want = "refused:local_role"
			}
			if got := w.perms(id)[device.String()+"/read"]; got != want {
				t.Fatalf("the new instance: %s, want %s", got, want)
			}
			got, err := w.tokens.TokenGrantContext(ctx, w.tenant, id, []uuid.UUID{device}, w.now)
			if err != nil || len(got.Numbers) != 1 || got.Numbers[0].Granted || got.Numbers[0].Read != then {
				t.Fatalf("the grant context: %+v %v", got, err)
			}
			if held, err := w.keys.TokenReaders(ctx, w.tenant, device); err != nil || len(held) != 0 {
				t.Fatalf("the token readers: %+v %v", held, err)
			}
			err = w.seal(id, device, w.owner, 1)
			switch {
			case then == "applied" && err != nil:
				t.Fatalf("a fresh seal under the new instance: %v", err)
			case then == "applied" && w.grantsOf(*identity) != 1:
				t.Fatal("the fresh seal wrote no grant")
			case then == "refused" && !errors.Is(err, store.ErrTokenNoRead):
				t.Fatalf("a seal under a refused instance: %v", err)
			}
		})
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

// TestATokenGrantNeedsALiveToken: every way tokenLiveSQL says a token is
// not live refuses the grant write as ErrTokenNotLive, and the grant
// context says so, each undone before the next; and the grant write's last
// refusals: no signed GET ever stamped, and a number no longer live whose
// perm stands.
func TestATokenGrantNeedsALiveToken(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	put := func() error {
		w.fetched(token, w.now)
		return w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: token, Device: device, Epoch: 1,
			SealedDSK: []byte("s"), Sealer: w.owner, Now: w.now})
	}
	if err := put(); err != nil {
		t.Fatalf("the live token's grant: %v", err)
	}
	selector := selectorOf(token)
	var doc string
	if err := w.pool.QueryRow(ctx, `SELECT doc::text FROM contract_accounts WHERE sub = $1`, w.ownerSub).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, set, undo string }{
		{"an operator's stop",
			`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ('` + selector + `', 'operator', 'root')`,
			`UPDATE contract_token_stops SET lifted_at = clock_timestamp() WHERE selector = '` + selector + `' AND cause = 'operator'`},
		{"an apply_failed stop",
			`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ('` + selector + `', 'apply_failed', 'wappie')`,
			`UPDATE contract_token_stops SET lifted_at = clock_timestamp() WHERE selector = '` + selector + `' AND cause = 'apply_failed'`},
		{"the creator's document without the workspace",
			`UPDATE contract_accounts SET doc = jsonb_set(doc, '{workspaces}', '[]') WHERE sub = '` + w.ownerSub.String() + `'`,
			`UPDATE contract_accounts SET doc = '` + doc + `'::jsonb WHERE sub = '` + w.ownerSub.String() + `'`},
		{"the contract off",
			`UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`,
			`UPDATE contract_state SET mode = 'observe', events_paused_at = NULL`},
		{"tokens not caught up",
			`UPDATE contract_token_state SET caught_up_at = NULL`,
			`UPDATE contract_token_state SET caught_up_at = clock_timestamp()`},
		{"the workspace suspended",
			`UPDATE tenants SET status = 'suspended' WHERE id = '` + w.tenant.String() + `'`,
			`UPDATE tenants SET status = 'active' WHERE id = '` + w.tenant.String() + `'`},
		// Last: a sticky row stays to its until.
		{"a sticky revocation",
			`INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until)
				VALUES ('` + token.String() + `', clock_timestamp(), 'revoked', clock_timestamp() + interval '1 day')`,
			""},
	} {
		w.exec(c.set)
		if err := put(); !errors.Is(err, store.ErrTokenNotLive) {
			t.Errorf("%s: %v", c.name, err)
		}
		got, err := w.tokens.TokenGrantContext(ctx, w.tenant, token, []uuid.UUID{device}, w.now)
		if err != nil || got.Live {
			t.Errorf("%s: the grant context %+v %v", c.name, got, err)
		}
		if c.undo == "" {
			continue
		}
		w.exec(c.undo)
		if err := put(); err != nil {
			t.Fatalf("%s undone: %v", c.name, err)
		}
	}

	// A fresh token, never fetched by a signed GET: stale.
	other := w.readingToken(device, readingKey(t))
	if err := w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: other, Device: device, Epoch: 1,
		SealedDSK: []byte("s"), Sealer: w.owner, Now: w.now}); !errors.Is(err, store.ErrTokenStale) {
		t.Fatalf("no signed GET: %v", err)
	}
	// A number that is no longer live while its perm stands (no deletion
	// leaves one: this one is marked deleted by hand).
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET paused = true, deleted_at = now(), purge_after = now() + interval '30 days' WHERE id = $1`, device)
		return err
	})
	w.fetched(other, w.now)
	if err := w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: other, Device: device, Epoch: 1,
		SealedDSK: []byte("s"), Sealer: w.owner, Now: w.now}); !errors.Is(err, store.ErrNumberGone) {
		t.Fatalf("a number no longer live: %v", err)
	}
}

// TestTheTokenGrantContext: what the grant page draws from, from the pin
// and the identity's row, never from the record; a Read pending or waiting
// is waiting, a refused one refused; a deleted number is left out; and a
// token of another workspace, or one with no identity, is not found.
func TestTheTokenGrantContext(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device, gone := w.number(uuid.Nil), w.number(uuid.Nil)
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511912345678@s.whatsapp.net', last_connected_at = now() WHERE id = $1`, gone)
		return err
	})
	key := readingKey(t)
	token := w.readingToken(device, key)
	identity, _ := w.identityOf(token)
	w.fetched(token, w.now.Add(-7*time.Second))
	raw, _ := base64.RawURLEncoding.DecodeString(key.Key)
	got, err := w.tokens.TokenGrantContext(ctx, w.tenant, token, []uuid.UUID{device, gone, uuid.New()}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	var pub []byte
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT public_key FROM users WHERE id = $1`, *identity).Scan(&pub)
	})
	if got.ID != token || got.Name != "Nightly" || string(got.Key) != string(raw) || string(pub) != string(raw) ||
		got.Fingerprint != key.Fingerprint || got.Identity != *identity || got.KeyChanged || got.Live ||
		got.FetchedAt == nil || !got.FetchedAt.Equal(w.now.Add(-7*time.Second)) {
		t.Fatalf("the context: %+v", got)
	}
	// An unknown number is left out; both live ones are there.
	if len(got.Numbers) != 2 {
		t.Fatalf("the numbers: %+v", got.Numbers)
	}
	if _, err := w.devices.Quarantine(ctx, w.tenant, w.owner, gone, nil); err != nil {
		t.Fatal(err)
	}
	got, err = w.tokens.TokenGrantContext(ctx, w.tenant, token, []uuid.UUID{device, gone}, w.now)
	if err != nil || len(got.Numbers) != 1 || got.Numbers[0].Device != device || got.Numbers[0].Read != store.TokenReadApplied ||
		got.Numbers[0].CurrentEpoch != 1 || got.Numbers[0].Granted {
		t.Fatalf("beside a deleted number: %+v %v", got.Numbers, err)
	}
	var archive uuid.UUID
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT archive_tenant_id FROM devices WHERE id = $1`, device).Scan(&archive)
	})
	if got.Numbers[0].ArchiveTenantID != archive {
		t.Fatalf("the archive namespace: %s, want %s", got.Numbers[0].ArchiveTenantID, archive)
	}

	// Pending (not yet judged), waiting and refused Reads.
	waitingSub := uuid.New()
	w.linked("waiting", "admin", waitingSub, false)
	pending, waiting, refused := uuid.New(), uuid.New(), uuid.New()
	w.page(false,
		w.record(pending, 1, grants(device, w.ownerSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }),
		w.record(waiting, 1, grants(device, waitingSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }),
		w.record(refused, 1, grants(device, uuid.New(), w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }))
	read := func(token uuid.UUID) string {
		t.Helper()
		got, err := w.tokens.TokenGrantContext(ctx, w.tenant, token, []uuid.UUID{device}, w.now)
		if err != nil || len(got.Numbers) != 1 {
			t.Fatalf("the context of %s: %+v %v", token, got, err)
		}
		return got.Numbers[0].Read
	}
	if r := read(pending); r != store.TokenReadWaiting {
		t.Fatalf("a pending Read: %s", r)
	}
	w.judge()
	if r := read(waiting); r != store.TokenReadWaiting {
		t.Fatalf("a waiting Read: %s", r)
	}
	if r := read(refused); r != store.TokenReadRefused {
		t.Fatalf("a refused Read: %s", r)
	}

	// Not found: another workspace's token, and one with no identity.
	if _, err := w.tokens.TokenGrantContext(ctx, uuid.MustParse(newTenant(t, w.pool, "other")), token, []uuid.UUID{device}, w.now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another workspace's token: %v", err)
	}
	keyless := uuid.New()
	w.page(false, w.record(keyless, 1, grants(device, w.ownerSub, w.now, kc.CanRead)))
	if _, err := w.tokens.TokenGrantContext(ctx, w.tenant, keyless, []uuid.UUID{device}, w.now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a token with no identity: %v", err)
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

// TestATokenGrantRacingAReadDropIsDeleted (the plan's 5.3 step 1, 10.4):
// the real grant write and a page that drops the token's Read, queued on
// the workspace's row behind a holder, both ways round. The grant first: it
// writes its grant, and the drop's commit then deletes it. The drop first:
// the grant write reads the Read only under the workspace's lock, finds it
// gone, and writes nothing. Either way no grant outlives the Read.
func TestATokenGrantRacingAReadDropIsDeleted(t *testing.T) {
	for _, grantFirst := range []bool{true, false} {
		name := "the drop first"
		if grantFirst {
			name = "the grant first"
		}
		t.Run(name, func(t *testing.T) {
			w := newTokenWorld(t)
			ctx := context.Background()
			device := w.number(uuid.Nil)
			key := readingKey(t)
			token := w.readingToken(device, key)
			w.tokensOn()
			identity, _ := w.identityOf(token)
			w.fetched(token, w.now)
			holder, err := w.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(ctx) //nolint:errcheck // rolled back below; a no-op then
			if _, err := holder.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
				t.Fatal(err)
			}
			granted, dropped := make(chan error, 1), make(chan error, 1)
			grant := func() {
				granted <- w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: token, Device: device, Epoch: 1,
					SealedDSK: []byte("sealed to the token"), Sealer: w.owner, Now: w.now})
			}
			drop := func() {
				_, err := w.tryPage(false, w.record(token, 2, grants(device, w.ownerSub, w.now, kc.CanSend), func(r *kc.TokenRecord) { r.ReadingKey = key }))
				dropped <- err
			}
			// Each waits on the workspace's row in the order started.
			first, second := drop, grant
			if grantFirst {
				first, second = grant, drop
			}
			go first()
			untilTokenWaiters(t, w, 1)
			go second()
			untilTokenWaiters(t, w, 2)
			if err := holder.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-dropped; err != nil {
				t.Fatalf("the Read drop: %v", err)
			}
			err = <-granted
			switch {
			case grantFirst && err != nil:
				t.Fatalf("the grant before the drop: %v", err)
			case !grantFirst && !errors.Is(err, store.ErrTokenNoRead):
				t.Fatalf("the grant after the drop: %v", err)
			}
			if n := w.grantsOf(*identity); n != 0 {
				t.Fatalf("%d grants outlived the Read", n)
			}
			if p := w.perms(token); p[device.String()+"/read"] != "" {
				t.Fatalf("the Read stayed: %v", p)
			}
			if strings.Contains(w.logs.String(), "deadlock") {
				t.Fatalf("a deadlock:\n%s", w.logs.String())
			}
		})
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

// TestAMoveOutKeepsTheTokensOffAsMoved (the plan's 5.6): a token whose
// perm is pending or waiting holds the number (fail closed) and refuses
// its move-out, as one with an applied perm does; a grant at an old epoch
// that is not retired counts as old_key; and a perm that reaches the move
// with nothing kept of it yet (an applied Read of a token past its expiry,
// which the janitor has not swept) is taken off as item_moved, while a
// refused one keeps its refusal; a late record of the same grant is
// refused as no such item.
func TestAMoveOutKeepsTheTokensOffAsMoved(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), true); err != nil {
		t.Fatal(err)
	}
	holds := func(token uuid.UUID) string {
		t.Helper()
		preview, err := w.devices.PreviewPersonalTransfer(ctx, w.tenant, w.owner, device)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range preview.Others {
			if o.Kind == "token" && o.TokenID == token.String() {
				if preview.Eligible {
					t.Fatalf("eligible beside a token that holds the number: %+v", preview)
				}
				return strings.Join(o.Why, ",")
			}
		}
		return ""
	}
	waitingSub := uuid.New()
	w.linked("waiting", "admin", waitingSub, false)
	for _, c := range []struct {
		name  string
		by    uuid.UUID
		judge bool
	}{{"pending", w.ownerSub, false}, {"waiting", waitingSub, true}} {
		id := uuid.New()
		w.page(false, w.record(id, 1, grants(device, c.by, w.now, kc.CanSend)))
		if c.judge {
			w.judge()
		}
		if got := w.perms(id)[device.String()+"/send"]; got != c.name {
			t.Fatalf("the %s perm: %s", c.name, got)
		}
		if why := holds(id); why != "send" {
			t.Fatalf("a %s perm: held as %q", c.name, why)
		}
		var denied *store.TransferDenied
		if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, device, personal); !errors.As(err, &denied) {
			t.Fatalf("a move beside a %s perm: %v", c.name, err)
		}
		w.page(false, w.record(id, 2, revokedBy(kc.RevokedInConsole, w.now)))
	}

	// Past its expiry by Wappie's clock, unswept: it holds nothing, and its
	// applied Read reaches the move with nothing kept of it.
	expired, at := uuid.New(), w.now.Add(-2*time.Hour)
	w.page(false, w.record(expired, 1, grants(device, w.ownerSub, at, kc.CanRead),
		func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(w.now.Add(-time.Minute)) }))
	w.judge()
	if got := w.perms(expired)[device.String()+"/read"]; got != "applied" {
		t.Fatalf("the expired token's Read: %s", got)
	}
	stranger, strangerAt := uuid.New(), w.now.Add(-time.Hour)
	w.page(false, w.record(stranger, 1, grants(device, uuid.New(), strangerAt, kc.CanSend)))
	w.judge()
	if why := holds(expired) + holds(stranger); why != "" {
		t.Fatalf("an ended token or a refused perm holds the number: %q", why)
	}
	if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, device, personal); err != nil {
		t.Fatalf("the move: %v", err)
	}
	cause := func(token uuid.UUID, at time.Time) string {
		t.Helper()
		var c string
		w.scoped(func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT coalesce(string_agg(cause, ','), '') FROM contract_token_removed WHERE token_id = $1 AND item = $2 AND granted_at = $3`,
				token, device.String(), at).Scan(&c)
		})
		return c
	}
	if got := cause(expired, at); got != "item_moved" {
		t.Fatalf("the expired token's Read kept off as %q", got)
	}
	if got := cause(stranger, strangerAt); got != "refused" {
		t.Fatalf("the refused perm kept off as %q", got)
	}
	if len(w.perms(expired)) != 0 || len(w.perms(stranger)) != 0 {
		t.Fatal("a perm stayed with the moved number")
	}
	w.page(false, w.record(stranger, 2, grants(device, uuid.New(), strangerAt, kc.CanSend)))
	if got := strings.Join(w.refused(stranger), " "); !strings.Contains(got, device.String()+"/send=item_unknown@2") {
		t.Fatalf("a late record of the moved number: %s", got)
	}
}

// TestAnOldEpochsTokenGrantHoldsTheNumber: after a rotation, a token's
// grant at the old epoch, not retired, is old_key; once the epoch is
// retired it is not.
func TestAnOldEpochsTokenGrantHoldsTheNumber(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	if err := w.seal(token, device, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	why := func() string {
		t.Helper()
		preview, err := w.devices.PreviewPersonalTransfer(ctx, w.tenant, w.owner, device)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range preview.Others {
			if o.Kind == "token" && o.TokenID == token.String() {
				return strings.Join(o.Why, ",")
			}
		}
		return ""
	}
	if got := why(); got != "read,key" {
		t.Fatalf("at its epoch: %q", got)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, device, 2, pub); err != nil {
		t.Fatal(err)
	}
	// The mover holds every epoch's key, or the preview stops before the
	// others.
	if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: w.owner, Epoch: 2, SealedDSK: []byte("grant")}, &w.owner); err != nil {
		t.Fatal(err)
	}
	if got := why(); got != "read,old_key" {
		t.Fatalf("after a rotation: %q", got)
	}
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_archive_keys SET retired_at = now() WHERE device_id = $1 AND epoch = 1`, device)
		return err
	})
	if got := why(); got != "read" {
		t.Fatalf("its epoch retired: %q", got)
	}
}

// TestEveryGrantCountJoinsAMembership is a static test over every query of
// the store that reads device_key_grants: each grant it reads is either
// bound to a membership (its user_id equals that of an inner-joined
// workspace_memberships row, or of a users row joined to one), so a token
// identity (which has none) is never a holder, a reader or a backup, or
// names one account by equality (a parameter, a connection's service
// account, a token's identity). Everyone but one (<>) is no account, and a
// LEFT JOIN, or a membership bound to another row, is no membership. A new
// query that counts holders without either fails here; the few that read
// every account's grants are named below, each with what keeps identities
// out of it. Writes are not counted.
func TestEveryGrantCountJoinsAMembership(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	grantAlias := regexp.MustCompile(`(?i)\bdevice_key_grants\b(?:\s+(?:AS\s+)?([a-z_]+))?`)
	members := regexp.MustCompile(`(?i)\b(LEFT\s+JOIN|RIGHT\s+JOIN|FULL\s+JOIN|JOIN|FROM)\s+workspace_memberships\s+([a-z_]+)`)
	usersOn := regexp.MustCompile(`(?i)\bJOIN\s+users\s+([a-z_]+)\s+ON\s+(?:([a-z_]+)\.id\s*=\s*([a-z_]+)\.user_id|([a-z_]+)\.user_id\s*=\s*([a-z_]+)\.id)`)
	write := regexp.MustCompile(`(?is)^\s*(INSERT|DELETE|UPDATE)\b`)
	keywords := map[string]bool{"where": true, "join": true, "on": true, "left": true, "inner": true, "using": true, "group": true, "order": true}
	// The queries that read every account's grants on purpose, and what
	// keeps a token identity out of each.
	exempt := []struct {
		name, file, marks, keeps string
	}{
		// 0040's rule counts every account with rows, its membership
		// disabled or gone (fail closed); its callers leave identities out.
		{"accessRowsQuery", "transfer_access.go", "WITH held AS", ""},
		// Its rows are platform identities' (an inner JOIN on
		// platform_identities), which a token identity never has.
		{"the snapshot's holders", "contract_snapshot.go", "WITH holders AS", `JOIN platform_identities pi ON pi.user_id = x.user_id`},
		// It bumps memberships' access_version: a row a token identity
		// never has.
		{"a deletion's access bump", "device_deletion.go", "UPDATE workspace_memberships SET access_version", "UPDATE workspace_memberships"},
	}
	// One account: the grant's user_id = a parameter or an account column,
	// written grant side first (an anti-join's "c.service_user_id =
	// g.user_id" names no account).
	oneAccount := func(q, ref string) bool {
		return regexp.MustCompile(`(?i)(^|[^a-z_.])` + ref + `\s*=\s*(\$\d+|[a-z_]+\.(identity_user_id|service_user_id))\b`).MatchString(q)
	}
	bound := func(q, ref string, aliases map[string]bool) bool {
		for _, m := range regexp.MustCompile(`(?i)(?:(?:^|[^a-z_.])`+ref+`\s*=\s*([a-z_]+)\.(?:user_id|id)\b|\b([a-z_]+)\.(?:user_id|id)\s*=\s*`+ref+`\b)`).FindAllStringSubmatch(q, -1) {
			if aliases[m[1]] || aliases[m[2]] {
				return true
			}
		}
		return false
	}
	seen, files14, used := 0, map[string]bool{}, map[string]bool{}
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
			for _, e := range exempt {
				if path == e.file && strings.Contains(q, e.marks) {
					used[e.name] = true
					if !strings.Contains(q, e.keeps) {
						t.Errorf("%s: %s no longer has %q, which keeps token identities out of it:\n%s", path, e.name, e.keeps, q)
					}
					return true
				}
			}
			aliases := map[string]bool{}
			for _, m := range members.FindAllStringSubmatch(q, -1) {
				if verb := strings.ToUpper(m[1]); verb == "JOIN" || verb == "FROM" {
					aliases[strings.ToLower(m[2])] = true
				}
			}
			for _, m := range usersOn.FindAllStringSubmatch(q, -1) {
				if (m[2] == m[1] && aliases[m[3]]) || (m[4] == m[1] && aliases[m[5]]) || (m[5] == m[1] && aliases[m[4]]) {
					aliases[m[1]] = true
				}
			}
			for _, g := range grantAlias.FindAllStringSubmatch(q, -1) {
				ref := `user_id`
				if a := strings.ToLower(g[1]); a != "" && !keywords[a] {
					ref = regexp.QuoteMeta(a) + `\.user_id`
				}
				if !oneAccount(q, ref) && !bound(q, ref, aliases) {
					t.Errorf("%s: a query reads device_key_grants bound to no membership and no one account:\n%s", path, q)
					return true
				}
			}
			return true
		})
	}
	if seen < 20 || len(files14) < 14 {
		t.Fatalf("the scan found %d queries in %d files: not the store's", seen, len(files14))
	}
	for _, e := range exempt {
		if !used[e.name] {
			t.Errorf("%s (%s) is gone: take it off the exemptions", e.name, e.file)
		}
	}

	// accessRowsQuery's callers: each keeps token identities out, by
	// token_identity or by naming a connection's service account.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "transfer_access.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	callers := 0
	ast.Inspect(f, func(n ast.Node) bool {
		b, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		var parts []string
		var uses bool
		var flatten func(e ast.Expr)
		flatten = func(e ast.Expr) {
			switch x := e.(type) {
			case *ast.BinaryExpr:
				flatten(x.X)
				flatten(x.Y)
			case *ast.BasicLit:
				if s, err := strconv.Unquote(x.Value); err == nil {
					parts = append(parts, s)
				}
			case *ast.Ident:
				uses = uses || x.Name == "accessRowsQuery"
			}
		}
		flatten(b)
		if !uses {
			return false
		}
		callers++
		q := strings.Join(parts, " ")
		if !strings.Contains(q, "NOT u.token_identity") && !strings.Contains(q, "a.user_id = c.service_user_id") {
			t.Errorf("transfer_access.go:%d: a query over accessRowsQuery lets token identities through:\n%s", fset.Position(b.Pos()).Line, q)
		}
		return false
	})
	if callers < 2 {
		t.Fatalf("%d queries over accessRowsQuery: the scan no longer finds its callers", callers)
	}
}
