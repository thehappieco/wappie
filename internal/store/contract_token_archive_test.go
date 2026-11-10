package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// A token grant names the archive key it was sealed for (the platform's
// answer of 2026-11-10, W46 7929b4a): after reset-archive -keep-devices and
// device-key, the number's new key takes epoch 1 again, so a grant sealed to
// the old key at epoch 1 is refused, and one sealed to the new key is
// written. The grant page's context names the key the number has now.

// rekey gives device a new archive key at epoch 1, after an archive reset
// that kept the numbers, as device-key does, sealed to the owner.
func (w *tokenWorld) rekey(device uuid.UUID) {
	w.t.Helper()
	ctx := context.Background()
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, device, 1, pub); err != nil {
		w.t.Fatal(err)
	}
	if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: w.owner, Epoch: 1, SealedDSK: []byte("grant")}, &w.owner); err != nil {
		w.t.Fatal(err)
	}
}

// TestATokenGrantNamesItsArchiveKey: through an archive reset that keeps
// the number and a new key at epoch 1, a grant sealed for the old key is
// refused, as is one with no fingerprint; one sealed for the new key is
// written; and the context names each key in its turn.
func TestATokenGrantNamesItsArchiveKey(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	identity, _ := w.identityOf(token)
	old := w.archiveKey(device, 1)
	numberOf := func() store.TokenGrantNumber {
		t.Helper()
		got, err := w.tokens.TokenGrantContext(ctx, w.tenant, token, []uuid.UUID{device}, w.now)
		if err != nil || len(got.Numbers) != 1 {
			t.Fatalf("the context: %+v %v", got, err)
		}
		return got.Numbers[0]
	}
	if n := numberOf(); n.CurrentEpoch != 1 || n.ArchiveKeyFingerprint != old || !store.ValidArchiveKeyFingerprint(old) {
		t.Fatalf("before the reset: %+v, want epoch 1 and %s", n, old)
	}
	put := func(epoch uint16, fp string) error {
		w.fetched(token, w.now)
		return w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: token, Device: device, Epoch: epoch,
			ArchiveKeyFingerprint: fp, SealedDSK: []byte("sealed to the token"), Sealer: w.owner, Now: w.now})
	}
	if err := put(1, old); err != nil {
		t.Fatalf("the grant before the reset: %v", err)
	}

	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	if w.grantsOf(*identity) != 0 {
		t.Fatal("the reset left the token's grant")
	}
	// No key yet: nothing to grant.
	if n := numberOf(); n.CurrentEpoch != 0 || n.ArchiveKeyFingerprint != "" || n.Read != store.TokenReadApplied {
		t.Fatalf("between the reset and the new key: %+v", n)
	}
	// Both errors, as DS49's check answers grant.add's no key.
	if err := put(0, old); !errors.Is(err, store.ErrNoArchiveKey) || !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("a grant with no key: %v", err)
	}

	w.rekey(device)
	fresh := w.archiveKey(device, 1)
	if fresh == old {
		t.Fatal("the new key has the old key's fingerprint")
	}
	if n := numberOf(); n.CurrentEpoch != 1 || n.ArchiveKeyFingerprint != fresh || n.Granted {
		t.Fatalf("after the new key: %+v, want epoch 1 and %s", n, fresh)
	}
	for name, fp := range map[string]string{"the old key's": old, "none": "", "not a fingerprint": "zz"} {
		if err := put(1, fp); !errors.Is(err, store.ErrArchiveKeyChanged) {
			t.Errorf("a grant for %s: %v", name, err)
		}
	}
	if w.grantsOf(*identity) != 0 {
		t.Fatal("a grant sealed for the old key was written")
	}
	if err := put(1, fresh); err != nil {
		t.Fatalf("the grant for the new key: %v", err)
	}
	if w.grantsOf(*identity) != 1 || !numberOf().Granted {
		t.Fatal("the grant for the new key was not written")
	}
}

// TestATokenGrantMeetsAResetUnderTheWorkspacesRow: the grant write compares
// the fingerprint under the workspace's row, in its own transaction, so a
// reset and a new key that commit while it waits for that row are what it
// compares with. A grant sealed for the old key then writes nothing.
func TestATokenGrantMeetsAResetUnderTheWorkspacesRow(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device := w.number(uuid.Nil)
	token := w.readingToken(device, readingKey(t))
	w.tokensOn()
	identity, _ := w.identityOf(token)
	old := w.archiveKey(device, 1)
	w.fetched(token, w.now)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	holder, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck // committed below; a no-op then
	if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	granted := make(chan error, 1)
	go func() {
		granted <- w.tokens.PutTokenGrant(w.ctx(), store.TokenGrant{Workspace: w.tenant, Token: token, Device: device, Epoch: 1,
			ArchiveKeyFingerprint: old, SealedDSK: []byte("sealed to the token"), Sealer: w.owner, Now: w.now})
	}()
	untilTokenWaiters(t, w, 1)
	// The reset and device-key, as one writer: every grant and key of the
	// number go, and a new key takes epoch 1, sealed to the owner.
	for _, step := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM device_key_grants WHERE device_id = $1`, []any{device}},
		{`DELETE FROM device_archive_keys WHERE device_id = $1`, []any{device}},
		{`INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key) VALUES ($1, $2, 1, $3)`, []any{w.tenant, device, pub.Bytes()}},
		{`INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by) VALUES ($1, $2, $3, 1, 'grant', $3)`,
			[]any{w.tenant, device, w.owner}},
	} {
		if _, err := holder.Exec(ctx, step.sql, step.args...); err != nil {
			t.Fatalf("%s: %v", step.sql, err)
		}
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-granted; !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("the grant that waited: %v", err)
	}
	if n := w.grantsOf(*identity); n != 0 {
		t.Fatalf("%d grants sealed for the old key", n)
	}
	var fp string
	w.scoped(func(tx pgx.Tx) error {
		var key []byte
		err := tx.QueryRow(ctx, `SELECT public_key FROM device_archive_keys WHERE device_id = $1 AND epoch = 1`, device).Scan(&key)
		fp = store.ArchiveKeyFingerprint(key)
		return err
	})
	if fp == old {
		t.Fatal("the key was not replaced")
	}
}

// TestTheArchiveKeyFingerprint: the SHA-256 of the key's bytes, in
// lowercase hex, and the shape the socket checks.
func TestTheArchiveKeyFingerprint(t *testing.T) {
	// SHA-256 of 32 zero bytes.
	const zero = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
	if got := store.ArchiveKeyFingerprint(make([]byte, 32)); got != zero {
		t.Fatalf("the fingerprint of 32 zero bytes: %s", got)
	}
	if !store.ValidArchiveKeyFingerprint(zero) {
		t.Fatal("a fingerprint is not valid")
	}
	for _, bad := range []string{"", zero[:63], zero + "0", "66687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925", "g" + zero[1:]} {
		if store.ValidArchiveKeyFingerprint(bad) {
			t.Errorf("%q is valid", bad)
		}
	}
}
