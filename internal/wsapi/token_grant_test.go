package wsapi_test

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
	"whatserver2/internal/wsapi"
)

// The grant page's frames (step 7's plan, 5.4 and 10.4): token.grant_context,
// token.waiting and token.grant, an owner's or admin's; grants.list for a
// token; and a grant that names the archive key it was sealed for.

// tokenRecords is the contract's client for the grant frames: each GET
// applies the token's record as the platform holds it now, stamped with
// the time it was asked, unless failing.
type tokenRecords struct {
	w       *tokentest.World
	mu      sync.Mutex
	tokens  map[uuid.UUID]*tokentest.Token
	calls   atomic.Int64
	failing atomic.Bool
}

func (r *tokenRecords) FetchToken(ctx context.Context, _, token uuid.UUID) error {
	r.calls.Add(1)
	if r.failing.Load() {
		return errors.New("the platform did not answer")
	}
	r.mu.Lock()
	tok := r.tokens[token]
	r.mu.Unlock()
	if tok == nil {
		return errors.New("not found")
	}
	_, err := r.w.Tokens.ApplyTokenRecord(ctx, r.w.Record(tok), time.Now(), time.Now())
	return err
}

func (r *tokenRecords) add(toks ...*tokentest.Token) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, tok := range toks {
		r.tokens[tok.ID] = tok
	}
}

// grantSocket is a token socket server whose grant frames ask records.
func grantSocket(t *testing.T) (*tokenSocket, *tokenRecords) {
	t.Helper()
	records := &tokenRecords{tokens: map[uuid.UUID]*tokentest.Token{}}
	ts := newTokenSocket(t, func(c *wsapi.Config) { c.TokenRecords = records })
	records.w = ts.w
	return ts, records
}

// person opens a socket for user of the world's workspace, signed in now.
func (ts *tokenSocket) person(t *testing.T, user uuid.UUID) (*websocket.Conn, store.Session) {
	t.Helper()
	u, err := ts.w.Users.Get(context.Background(), ts.w.Tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	text, session, err := ts.w.Users.StartSession(context.Background(), u, "test")
	if err != nil {
		t.Fatal(err)
	}
	conn, f := ts.hello(t, wsapi.Hello{Session: text})
	if f.Type != wsapi.TypeWelcome {
		t.Fatalf("the person's hello: %s %s", f.Type, f.Payload)
	}
	return conn, session
}

// fetched sets tok's last signed GET at.
func fetched(w *tokentest.World, tok *tokentest.Token, at time.Time) {
	w.T.Helper()
	w.ExecIn(`UPDATE contract_tokens SET fetched_at = $2 WHERE id = $1`, tok.ID, at)
}

func waitingOf(t *testing.T, f wsapi.Frame) []string {
	t.Helper()
	if f.Type != wsapi.TypeTokenWaitingList {
		t.Fatalf("token.waiting: %s %s", f.Type, f.Payload)
	}
	out := []string{}
	for _, w := range payload[wsapi.TokenWaitingList](t, f).Tokens {
		out = append(out, w.DeviceID+"/"+w.TokenID)
	}
	slices.Sort(out)
	return out
}

// TestTheGrantPagesFrames: token.waiting lists the tokens whose Read waits
// for a number's key; token.grant_context draws the page from the pin, the
// identity and each number's epoch and archive key, asking the platform
// first when the last signed GET is over a minute old; token.grant writes
// the grant and answers the readers, the token apart, and the token then
// reads the number and waits no more. Only an owner or admin uses them.
// A grant.revoke of the token's identity is not_found.
func TestTheGrantPagesFrames(t *testing.T) {
	ts, records := grantSocket(t)
	w := ts.w
	a, b, unread := w.Number("Vendas"), w.Number("Suporte"), w.Number("Outro")
	tok := w.TokenUnsealed(tokentest.Read(a), tokentest.Read(b), tokentest.Send(b))
	records.add(tok)
	// Opened once the numbers are made: a new number's permission changes
	// the owner's access, which closes their socket.
	owner, _ := ts.person(t, w.Owner)

	want := []string{a.String() + "/" + tok.ID.String(), b.String() + "/" + tok.ID.String()}
	slices.Sort(want)
	if got := waitingOf(t, on(t, owner, wsapi.TypeTokenWaiting, nil)); !slices.Equal(got, want) {
		t.Fatalf("every number: %v, want %v", got, want)
	}
	if got := waitingOf(t, on(t, owner, wsapi.TypeTokenWaiting, wsapi.TokenWaitingRequest{DeviceIDs: []string{a.String()}})); !slices.Equal(got, []string{a.String() + "/" + tok.ID.String()}) {
		t.Fatalf("a: %v", got)
	}

	// The context: never fetched by a signed GET, so the platform is
	// asked first.
	ask := func(devices ...uuid.UUID) wsapi.TokenGrantContext {
		t.Helper()
		ids := []string{}
		for _, d := range devices {
			ids = append(ids, d.String())
		}
		f := on(t, owner, wsapi.TypeTokenGrantContext, wsapi.TokenGrantContextRequest{TokenID: tok.ID.String(), DeviceIDs: ids})
		if f.Type != wsapi.TypeTokenGrantContextResult {
			t.Fatalf("token.grant_context: %s %s", f.Type, f.Payload)
		}
		return payload[wsapi.TokenGrantContext](t, f)
	}
	got := ask(a, b, uuid.New())
	identity, err := w.Tokens.Identity(context.Background(), store.TokenAuth{ID: tok.ID, Tenant: w.Tenant})
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenID != tok.ID.String() || got.Name != "Nightly" || got.ReadingKey != tok.Key.Key || got.ReadingKeyFingerprint != tok.Key.Fingerprint ||
		got.IdentityID != identity.String() || !got.Live || got.KeyChanged || !got.Fresh || len(got.Numbers) != 2 || records.calls.Load() != 1 {
		t.Fatalf("the context: %+v after %d GETs", got, records.calls.Load())
	}
	if _, err := base64.RawURLEncoding.DecodeString(got.ReadingKey); err != nil {
		t.Fatalf("the reading key's text: %v", err)
	}
	for _, n := range got.Numbers {
		d := uuid.MustParse(n.DeviceID)
		if n.Epoch != 1 || n.ArchiveKeyFingerprint != w.ArchiveKey(d, 1) || n.Read != store.TokenReadApplied || n.Granted || n.ArchiveTenantID == "" {
			t.Fatalf("a number: %+v", n)
		}
	}
	// Fresh now: the platform is not asked again.
	if again := ask(a); !again.Fresh || records.calls.Load() != 1 {
		t.Fatalf("a fresh context asked the platform: %+v, %d GETs", again, records.calls.Load())
	}
	// Over a minute old and the platform down: what Wappie holds, not fresh.
	fetched(w, tok, time.Now().Add(-61*time.Second))
	records.failing.Store(true)
	if down := ask(a); down.Fresh || !down.Live || records.calls.Load() != 2 {
		t.Fatalf("with the platform down: %+v, %d GETs", down, records.calls.Load())
	}

	grant := func(conn *websocket.Conn, device uuid.UUID, epoch int, fp string) wsapi.Frame {
		t.Helper()
		return on(t, conn, wsapi.TypeTokenGrant, wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: device.String(), Epoch: epoch,
			ArchiveKeyFingerprint: fp, SealedDSK: []byte("sealed to the token")})
	}
	// Still down: the grant cannot be confirmed.
	wantError(t, grant(owner, a, 1, w.ArchiveKey(a, 1)), wsapi.ErrCodeTokenUnconfirmed)
	if records.calls.Load() != 3 {
		t.Fatalf("%d GETs", records.calls.Load())
	}
	// The platform answers: the grant asks it once and is written.
	records.failing.Store(false)
	f := grant(owner, a, 1, w.ArchiveKey(a, 1))
	if f.Type != wsapi.TypeReaders || records.calls.Load() != 4 {
		t.Fatalf("the grant: %s %s, %d GETs", f.Type, f.Payload, records.calls.Load())
	}
	readers := payload[wsapi.Readers](t, f)
	if readers.DeviceID != a.String() || len(readers.Tokens) != 1 || readers.Tokens[0].ID != tok.ID.String() || readers.Tokens[0].Epoch != 1 {
		t.Fatalf("the readers: %+v", readers)
	}
	for _, r := range readers.Readers {
		if r.UserID == identity.String() {
			t.Fatal("the token's identity is listed as a reader")
		}
	}
	if got := waitingOf(t, on(t, owner, wsapi.TypeTokenWaiting, nil)); !slices.Equal(got, []string{b.String() + "/" + tok.ID.String()}) {
		t.Fatalf("after the grant: %v", got)
	}
	if n := ask(a).Numbers[0]; !n.Granted {
		t.Fatalf("the context after the grant: %+v", n)
	}
	conn := ts.open(t, tok)
	if f := on(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: a.String()}); f.Type != wsapi.TypeChats {
		t.Fatalf("the token's read after its grant: %s %s", f.Type, f.Payload)
	}
	// grant.revoke never takes a token's grant: its identity is no person
	// (DS48 stops before it), and the token still reads.
	wantError(t, on(t, owner, wsapi.TypeGrantRevoke, wsapi.GrantRevoke{DeviceID: a.String(), UserID: identity.String()}), wsapi.ErrCodeNotFound)
	if f := on(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: a.String()}); f.Type != wsapi.TypeChats {
		t.Fatalf("the token's read after a refused grant.revoke: %s %s", f.Type, f.Payload)
	}

	// The refusals.
	for name, c := range map[string]struct {
		req  wsapi.TokenGrantRequest
		code string
	}{
		"a prefix":         {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String()[:8], Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(b, 1), SealedDSK: []byte("s")}, wsapi.ErrCodeBadRequest},
		"no fingerprint":   {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String(), Epoch: 1, SealedDSK: []byte("s")}, wsapi.ErrCodeBadRequest},
		"epoch 0":          {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String(), ArchiveKeyFingerprint: w.ArchiveKey(b, 1), SealedDSK: []byte("s")}, wsapi.ErrCodeBadRequest},
		"no sealed key":    {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(b, 1)}, wsapi.ErrCodeBadRequest},
		"an unknown token": {wsapi.TokenGrantRequest{TokenID: uuid.NewString(), DeviceID: b.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(b, 1), SealedDSK: []byte("s")}, wsapi.ErrCodeNotFound},
		"another key":      {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(a, 1), SealedDSK: []byte("s")}, wsapi.ErrCodeConflict},
		"another epoch":    {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String(), Epoch: 2, ArchiveKeyFingerprint: w.ArchiveKey(b, 1), SealedDSK: []byte("s")}, wsapi.ErrCodeConflict},
		"a number unread":  {wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: unread.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(a, 1), SealedDSK: []byte("s")}, wsapi.ErrCodeTokenNoRead},
	} {
		t.Logf("%s", name)
		wantError(t, on(t, owner, wsapi.TypeTokenGrant, c.req), c.code)
	}
	// A member: none of the three.
	member, _ := ts.person(t, w.Linked("member", "member", uuid.New()))
	for kind, p := range map[string]any{
		wsapi.TypeTokenWaiting:      nil,
		wsapi.TypeTokenGrantContext: wsapi.TokenGrantContextRequest{TokenID: tok.ID.String()},
		wsapi.TypeTokenGrant:        wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: b.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(b, 1), SealedDSK: []byte("s")},
	} {
		wantError(t, on(t, member, kind, p), wsapi.ErrCodeNotAuthorized)
	}
	// Nor a token, on its own socket.
	for _, kind := range []string{wsapi.TypeTokenWaiting, wsapi.TypeTokenGrantContext, wsapi.TypeTokenGrant} {
		refusedWith(t, kind, on(t, conn, kind, nil), tokenFrameRefused)
	}
}

// TestATokenGrantNeedsAStepUpAndAReader: a grant waits for the person's
// fresh step-up, as grant.add does, and only an owner or admin who reads
// the number now seals it.
func TestATokenGrantNeedsAStepUpAndAReader(t *testing.T) {
	ts, records := grantSocket(t)
	w := ts.w
	a := w.Number("Vendas")
	tok := w.TokenUnsealed(tokentest.Read(a))
	records.add(tok)
	owner, session := ts.person(t, w.Owner)
	req := wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: a.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(a, 1),
		SealedDSK: []byte("sealed")}
	w.Exec(`UPDATE sessions SET authenticated_at = now() - interval '11 minutes' WHERE id = $1`, session.ID)
	wantError(t, on(t, owner, wsapi.TypeTokenGrant, req), wsapi.ErrCodeStepUpRequired)
	if err := w.Users.MarkStepUp(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	admin, _ := ts.person(t, w.Linked("admin", "admin", uuid.New()))
	wantError(t, on(t, admin, wsapi.TypeTokenGrant, req), wsapi.ErrCodeNotAuthorized)
	if f := on(t, owner, wsapi.TypeTokenGrant, req); f.Type != wsapi.TypeReaders {
		t.Fatalf("the owner's grant: %s %s", f.Type, f.Payload)
	}
}

// TestAResetNumbersOldKeyGetsNoGrantOnTheSocket (the platform's answer of
// 2026-11-10, W46 7929b4a): after reset-archive -keep-devices and a new key
// at epoch 1, a grant sealed for the old key is refused conflict, as
// grant.add answers it (DS49), and the token's reads stay no_grant; the
// grant for the new key lets it read again.
func TestAResetNumbersOldKeyGetsNoGrantOnTheSocket(t *testing.T) {
	ts, records := grantSocket(t)
	w := ts.w
	a := w.Number("Vendas")
	tok := w.Token(tokentest.Read(a))
	records.add(tok)
	old := w.ArchiveKey(a, 1)
	conn := ts.open(t, tok)
	if f := on(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: a.String()}); f.Type != wsapi.TypeChats {
		t.Fatalf("before the reset: %s %s", f.Type, f.Payload)
	}
	w.ResetArchive()
	w.Rotate(a, 1)
	owner, _ := ts.person(t, w.Owner)
	grant := func(fp string) wsapi.Frame {
		return on(t, owner, wsapi.TypeTokenGrant, wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: a.String(), Epoch: 1,
			ArchiveKeyFingerprint: fp, SealedDSK: []byte("sealed to the token")})
	}
	wantError(t, grant(old), wsapi.ErrCodeConflict)
	refusedWith(t, "a read with the old key's grant refused", on(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: a.String()}), tokenNumberRefused)
	if err := ts.checker.Use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Refusals(tok); len(got) != 1 || got[a.String()+"/read=no_grant"] != 1 {
		t.Fatalf("the refusals: %v", got)
	}
	if f := grant(w.ArchiveKey(a, 1)); f.Type != wsapi.TypeReaders {
		t.Fatalf("the grant for the new key: %s %s", f.Type, f.Payload)
	}
	if f := on(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: a.String()}); f.Type != wsapi.TypeChats {
		t.Fatalf("after the new key's grant: %s %s", f.Type, f.Payload)
	}
}

// TestGrantsListForAToken (the plan's 5.4): a token's grants.list is its
// identity's grants at each number's current epoch, on the numbers it
// reads now, with user_id its identity; a number it reads no more, or
// whose key rotated, is left out; a token with no reading key holds none.
func TestGrantsListForAToken(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(a), tokentest.Read(b))
	identity, err := w.Tokens.Identity(context.Background(), store.TokenAuth{ID: tok.ID, Tenant: w.Tenant})
	if err != nil {
		t.Fatal(err)
	}
	conn := ts.open(t, tok)
	list := func() wsapi.Grants {
		t.Helper()
		f := on(t, conn, wsapi.TypeGrantsList, nil)
		if f.Type != wsapi.TypeGrants {
			t.Fatalf("grants.list: %s %s", f.Type, f.Payload)
		}
		return payload[wsapi.Grants](t, f)
	}
	got := list()
	if got.UserID != identity.String() || len(got.Grants) != 2 {
		t.Fatalf("the grants: %+v", got)
	}
	for _, g := range got.Grants {
		if g.Epoch != 1 || string(g.SealedDSK) != "sealed to the token" || g.ArchiveTenantID == "" || g.Label == "" {
			t.Fatalf("a grant: %+v", g)
		}
	}
	// A rotation of b: its grant at the old epoch is not listed.
	w.Rotate(b, 2)
	if got := list(); len(got.Grants) != 1 || got.Grants[0].DeviceID != a.String() {
		t.Fatalf("after b's rotation: %+v", got)
	}
	// A reply read under a, built just before the text switch goes off,
	// which bumps no version: the writer answers the refusal in its place.
	ts.mu.Lock()
	ts.onReply = func() {
		off := false
		w.Switches(&off, nil)
	}
	ts.mu.Unlock()
	refusedWith(t, "a token's grants built just before text went off", on(t, conn, wsapi.TypeGrantsList, nil), tokenNumberRefused)
	w.Switches(nil, nil)
	// Text off: it reads nothing, and lists nothing.
	off := false
	w.Switches(&off, nil)
	if got := list(); len(got.Grants) != 0 || got.UserID != identity.String() {
		t.Fatalf("with text off: %+v", got)
	}
	w.Switches(nil, nil)
	// A token with Read and no reading key yet has no identity, and holds
	// none.
	text, selector, hash := tokentest.Mint()
	keyless := &tokentest.Token{ID: uuid.New(), Text: text, Selector: selector, Hash: hash, Perms: []tokentest.Perm{tokentest.Read(a)}}
	w.Commit(keyless)
	if got := payload[wsapi.Grants](t, on(t, ts.open(t, keyless), wsapi.TypeGrantsList, nil)); got.UserID != "" || len(got.Grants) != 0 {
		t.Fatalf("a token with no reading key: %+v", got)
	}
}

// TestAnotherWorkspacesTokenIsUnknownOnTheSocket (the plan's 10.2): the
// grant frames answer a token of another workspace exactly as an unknown
// one, and token.waiting lists none of it.
func TestAnotherWorkspacesTokenIsUnknownOnTheSocket(t *testing.T) {
	ts, _ := grantSocket(t)
	w := ts.w
	a := w.Number("Vendas")
	other := uuid.New()
	w.Exec(`INSERT INTO tenants (id, name) VALUES ($1, 'other')`, other)
	// A token of the other workspace, with a reading key, so it has an
	// identity there.
	text, selector, hash := tokentest.Mint()
	theirs := &tokentest.Token{ID: uuid.New(), Text: text, Selector: selector, Hash: hash, Key: tokentest.ReadingKey(t)}
	w.Commit(theirs, func(r *kc.TokenRecord) {
		r.WorkspaceID = other.String()
		r.Items = []kc.TokenItem{{ID: a.String(), Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanRead, GrantedBy: w.OwnerSub.String(), GrantedAt: kc.T(time.Now())}}}}
	})
	var made bool
	if err := pg.InTenantTx(context.Background(), w.Pool, other.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT identity_user_id IS NOT NULL FROM contract_tokens WHERE id = $1`, theirs.ID).Scan(&made)
	}); err != nil || !made {
		t.Fatalf("the other workspace's token has no identity there: %v", err)
	}
	owner, _ := ts.person(t, w.Owner)
	answer := func(token uuid.UUID) (wsapi.Error, wsapi.Error) {
		t.Helper()
		context := wantError(t, on(t, owner, wsapi.TypeTokenGrantContext, wsapi.TokenGrantContextRequest{TokenID: token.String(),
			DeviceIDs: []string{a.String()}}), wsapi.ErrCodeNotFound)
		grant := wantError(t, on(t, owner, wsapi.TypeTokenGrant, wsapi.TokenGrantRequest{TokenID: token.String(), DeviceID: a.String(), Epoch: 1,
			ArchiveKeyFingerprint: w.ArchiveKey(a, 1), SealedDSK: []byte("s")}), wsapi.ErrCodeNotFound)
		return context, grant
	}
	c1, g1 := answer(uuid.New())
	c2, g2 := answer(theirs.ID)
	if c1.Message != c2.Message || g1.Message != g2.Message {
		t.Fatalf("another workspace's token answers apart: %+v %+v, unknown %+v %+v", c2, g2, c1, g1)
	}
	if got := waitingOf(t, on(t, owner, wsapi.TypeTokenWaiting, nil)); len(got) != 0 {
		t.Fatalf("token.waiting lists another workspace's token: %v", got)
	}
}

// TestATokenGrantAppliesANarrowingGETFirst (the plan's 10.4): a grant
// whose token's last signed GET is over a minute old asks the platform
// first, and a record that dropped the token's Read on the number, which
// the feed has not brought yet, is applied before the grant, which is then
// refused.
func TestATokenGrantAppliesANarrowingGETFirst(t *testing.T) {
	ts, records := grantSocket(t)
	w := ts.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	tok := w.TokenUnsealed(tokentest.Read(a), tokentest.Read(b))
	records.add(tok)
	owner, _ := ts.person(t, w.Owner)
	fetched(w, tok, time.Now().Add(-61*time.Second))
	// The platform's record now: b's Read dropped.
	tok.Version++
	tok.Perms = []tokentest.Perm{tokentest.Read(a)}
	grant := func(device uuid.UUID) wsapi.Frame {
		return on(t, owner, wsapi.TypeTokenGrant, wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: device.String(), Epoch: 1,
			ArchiveKeyFingerprint: w.ArchiveKey(device, 1), SealedDSK: []byte("sealed to the token")})
	}
	wantError(t, grant(b), wsapi.ErrCodeTokenNoRead)
	if records.calls.Load() != 1 {
		t.Fatalf("%d GETs", records.calls.Load())
	}
	// The GET was fresh: a's grant asks nothing more.
	if f := grant(a); f.Type != wsapi.TypeReaders || records.calls.Load() != 1 {
		t.Fatalf("a's grant: %s %s, %d GETs", f.Type, f.Payload, records.calls.Load())
	}
}

// slowWidening is a freshness hook whose RequireWidening takes delay first,
// as a membership GET may (up to its bound).
type slowWidening struct {
	*freshRecorder
	delay time.Duration
}

func (f *slowWidening) RequireWidening(ctx context.Context, act string, tenant uuid.UUID, parties ...membership.Party) (membership.Verdict, error) {
	time.Sleep(f.delay)
	return f.freshRecorder.RequireWidening(ctx, act, tenant, parties...)
}

// TestATokenGrantChecksTheActorsFreshness (the plan's 5.4): token.grant
// asks the freshness hook to widen for the person, IfStale, outside any
// transaction, as grant.add does; a refusal is memberships_unconfirmed and
// writes nothing. The token's record must be under a minute old when the
// grant is written, not only when it was asked: a record 59 s old whose
// freshness check takes 2 s is asked of the platform again first.
func TestATokenGrantChecksTheActorsFreshness(t *testing.T) {
	hook := &slowWidening{freshRecorder: &freshRecorder{}}
	records := &tokenRecords{tokens: map[uuid.UUID]*tokentest.Token{}}
	ts := newTokenSocket(t, func(c *wsapi.Config) {
		c.TokenRecords = records
		c.Membership = hook
	})
	records.w = ts.w
	hook.pool = ts.pool
	w := ts.w
	a := w.Number("Vendas")
	tok := w.TokenUnsealed(tokentest.Read(a))
	records.add(tok)
	owner, _ := ts.person(t, w.Owner)
	req := wsapi.TokenGrantRequest{TokenID: tok.ID.String(), DeviceID: a.String(), Epoch: 1, ArchiveKeyFingerprint: w.ArchiveKey(a, 1),
		SealedDSK: []byte("sealed to the token")}
	actor := membership.Party{User: w.Owner, How: membership.IfStale}

	hook.set(membership.ErrMembershipsUnconfirmed, nil)
	n := hook.count()
	wantError(t, on(t, owner, wsapi.TypeTokenGrant, req), wsapi.ErrCodeMembershipsUnconfirmed)
	hook.one(t, n, "widening", wsapi.TypeTokenGrant, actor)
	if got := waitingOf(t, on(t, owner, wsapi.TypeTokenWaiting, nil)); len(got) != 1 || records.calls.Load() != 0 {
		t.Fatalf("a refused freshness wrote the grant or asked the platform: %v, %d GETs", got, records.calls.Load())
	}

	hook.set(nil, nil)
	hook.delay = 2 * time.Second
	fetched(w, tok, time.Now().Add(-59*time.Second))
	n = hook.count()
	if f := on(t, owner, wsapi.TypeTokenGrant, req); f.Type != wsapi.TypeReaders {
		t.Fatalf("the grant: %s %s", f.Type, f.Payload)
	}
	hook.one(t, n, "widening", wsapi.TypeTokenGrant, actor)
	if records.calls.Load() != 1 {
		t.Fatalf("a record 61 s old at the write was not asked again: %d GETs", records.calls.Load())
	}
}

// TestATokenGrantsRefusalsOnTheSocket: a revoked token is token_not_live;
// one whose record brought another reading key is reading_key_changed; a
// live token with no reading key yet is not_found, word for word as an
// unknown token, as its context answers.
func TestATokenGrantsRefusalsOnTheSocket(t *testing.T) {
	ts, records := grantSocket(t)
	w := ts.w
	a := w.Number("Vendas")
	revoked, swapped := w.TokenUnsealed(tokentest.Read(a)), w.TokenUnsealed(tokentest.Read(a))
	text, selector, hash := tokentest.Mint()
	keyless := &tokentest.Token{ID: uuid.New(), Text: text, Selector: selector, Hash: hash, Perms: []tokentest.Perm{tokentest.Read(a)}}
	w.Commit(keyless)
	records.add(revoked, swapped, keyless)
	w.Revoke(revoked)
	swapped.Version++
	swapped.Key = tokentest.ReadingKey(t)
	w.Commit(swapped)
	owner, _ := ts.person(t, w.Owner)
	grant := func(token uuid.UUID) wsapi.Frame {
		t.Helper()
		return on(t, owner, wsapi.TypeTokenGrant, wsapi.TokenGrantRequest{TokenID: token.String(), DeviceID: a.String(), Epoch: 1,
			ArchiveKeyFingerprint: w.ArchiveKey(a, 1), SealedDSK: []byte("sealed to the token")})
	}
	wantError(t, grant(revoked.ID), wsapi.ErrCodeTokenNotLive)
	wantError(t, grant(swapped.ID), wsapi.ErrCodeReadingKeyChanged)
	unknown := wantError(t, grant(uuid.New()), wsapi.ErrCodeNotFound)
	if none := wantError(t, grant(keyless.ID), wsapi.ErrCodeNotFound); none.Message != unknown.Message {
		t.Fatalf("a token with no reading key: %+v, an unknown one: %+v", none, unknown)
	}
	if c := wantError(t, on(t, owner, wsapi.TypeTokenGrantContext, wsapi.TokenGrantContextRequest{TokenID: keyless.ID.String(),
		DeviceIDs: []string{a.String()}}), wsapi.ErrCodeNotFound); c.Message != unknown.Message {
		t.Fatalf("the context of a token with no reading key: %+v", c)
	}
	if records.calls.Load() != 0 {
		t.Fatalf("a refusal before the minute's check asked the platform: %d GETs", records.calls.Load())
	}
}
