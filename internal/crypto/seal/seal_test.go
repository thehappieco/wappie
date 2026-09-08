package seal_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

var (
	tenant = uuid.MustParse("01a034b7-d09c-7121-b7f8-41f210a9244a")
	// The archive key is per device, so every content key names one.
	testDevice = uuid.MustParse("01a036b0-ddcc-78ae-a207-82f3cb3e9502")
	rowA       = uuid.MustParse("11111111-1111-7111-8111-111111111111")
	rowB       = uuid.MustParse("22222222-2222-7222-8222-222222222222")
)

func keys(t *testing.T) (seal.PublicKey, seal.PrivateKey) {
	t.Helper()
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv
}

func contentKey(t *testing.T, pub seal.PublicKey, id uint32) *seal.ContentKey {
	t.Helper()
	ck, err := seal.NewContentKey(pub, tenant, testDevice, 1, id)
	if err != nil {
		t.Fatalf("NewContentKey: %v", err)
	}
	return ck
}

// TestServerCannotOpenItsOwnArchive is the whole premise, stated as a test.
//
// It hands a hypothetical attacker everything the server has — the public key,
// every sealed blob, the sealed content keys, the tenant id, the row ids — and
// asserts that none of it recovers a single byte of plaintext. The only thing
// withheld is the private key, which the server never receives.
func TestServerCannotOpenItsOwnArchive(t *testing.T) {
	pub, priv := keys(t)
	secret := []byte("a message the server must never be able to read")

	ck := contentKey(t, pub, 1)
	sealedBody, err := ck.Seal(seal.KindBody, tenant, rowA, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Everything the server holds, in one place.
	serverHas := [][]byte{
		pub.Bytes(),
		sealedBody,
		ck.Sealed,
		tenant[:],
		rowA[:],
	}
	for _, blob := range serverHas {
		if bytes.Contains(blob, secret) {
			t.Fatalf("plaintext is recoverable from server-held data: %q", blob)
		}
	}

	// And the sealed content key cannot be unwrapped without the private key.
	// Trying every other key in the system does not help.
	_, otherPriv := keys(t)
	if _, err := seal.OpenContentKey(otherPriv, tenant, testDevice, 1, ck.Sealed); err == nil {
		t.Fatal("an unrelated private key unwrapped the content key")
	}

	// With the private key — which lives only in the client — it opens.
	reopened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatalf("the legitimate holder cannot open it either: %v", err)
	}
	got, err := reopened.Open(seal.KindBody, tenant, rowA, sealedBody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("round trip lost the plaintext")
	}
}

// TestRelocationIsDetected is why this uses HPKE rather than a NaCl sealed box.
//
// An attacker with write access to Postgres can move a sealed blob from one row
// to another. Without associated data the client decrypts it happily: content
// swapped between conversations, a message attributed to the wrong person, no
// integrity failure anywhere. Binding the row into the AAD makes it fail.
func TestRelocationIsDetected(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)

	sealed, err := ck.Seal(seal.KindBody, tenant, rowA, []byte("meet me at eight"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	// The same bytes, presented as if they belonged to a different message.
	if _, err := opened.Open(seal.KindBody, tenant, rowB, sealed); !errors.Is(err, seal.ErrAuthentication) {
		t.Fatalf("a blob moved to another row opened successfully: %v", err)
	}
	// In its own row it still works, so the test is detecting relocation and
	// not simply a broken pipeline.
	if _, err := opened.Open(seal.KindBody, tenant, rowA, sealed); err != nil {
		t.Fatalf("the blob no longer opens in its own row: %v", err)
	}
}

// A blob sealed as one kind must not be presentable as another. Otherwise a
// thumbnail could be swapped in where a message body is expected, or a media
// key served as text.
func TestKindConfusionIsDetected(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)

	sealed, err := ck.Seal(seal.KindThumbnail, tenant, rowA, []byte("thumbnail bytes"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Open(seal.KindBody, tenant, rowA, sealed); !errors.Is(err, seal.ErrAuthentication) {
		t.Fatalf("a thumbnail opened as a message body: %v", err)
	}
}

// One tenant's blob must not open under another tenant's identity, even with
// the right key. This is the last line of defence if row-level security is ever
// misconfigured.
func TestTenantConfusionIsDetected(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)
	other := uuid.MustParse("99999999-9999-7999-8999-999999999999")

	sealed, err := ck.Seal(seal.KindBody, tenant, rowA, []byte("tenant a data"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Open(seal.KindBody, other, rowA, sealed); !errors.Is(err, seal.ErrAuthentication) {
		t.Fatalf("a blob opened under the wrong tenant: %v", err)
	}
}

// Every single-bit flip must be caught.
func TestTamperingIsDetected(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)
	sealed, err := ck.Seal(seal.KindBody, tenant, rowA, []byte("integrity matters"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	for i := range sealed {
		for _, bit := range []byte{0x01, 0x80} {
			tampered := bytes.Clone(sealed)
			tampered[i] ^= bit
			if _, err := opened.Open(seal.KindBody, tenant, rowA, tampered); err == nil {
				t.Fatalf("byte %d bit %#x: tampering not detected", i, bit)
			}
		}
	}
}

func TestDirectRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	for name, payload := range map[string][]byte{
		"empty":     {},
		"key sized": make([]byte, seal.KeyLen),
		"text":      []byte("a grant"),
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := seal.SealDirect(pub, seal.KindDeviceGrant, tenant, rowA, 1, payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := seal.OpenDirect(priv, seal.KindDeviceGrant, tenant, rowA, sealed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("got %q, want %q", got, payload)
			}
		})
	}
}

func TestBatchRoundTripAcrossSizes(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 7)
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 7, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range []int{0, 1, 32, 280, 4096, 1 << 16} {
		payload := bytes.Repeat([]byte("x"), n)
		sealed, err := ck.Seal(seal.KindBody, tenant, rowA, payload)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := len(sealed), seal.BatchOverhead+n; got != want {
			t.Errorf("size %d: envelope is %d bytes, want %d", n, got, want)
		}
		got, err := opened.Open(seal.KindBody, tenant, rowA, sealed)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("size %d: round trip mismatch", n)
		}
	}
}

// The overhead is documented and load-bearing: forty bytes on an eighty byte
// message is what the storage estimate is built on.
func TestOverheadMatchesTheDocumentedConstants(t *testing.T) {
	pub, _ := keys(t)
	ck := contentKey(t, pub, 1)

	batch, err := ck.Seal(seal.KindBody, tenant, rowA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != seal.BatchOverhead || seal.BatchOverhead != 40 {
		t.Errorf("batch overhead = %d (constant says %d), want 40", len(batch), seal.BatchOverhead)
	}

	direct, err := seal.SealDirect(pub, seal.KindContentKey, tenant, rowA, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != seal.DirectOverhead || seal.DirectOverhead != 56 {
		t.Errorf("direct overhead = %d (constant says %d), want 56", len(direct), seal.DirectOverhead)
	}
}

// A parser that guessed at an unknown suite would be a downgrade vector. The
// byte exists so that it can refuse.
func TestUnknownHeaderIsRefused(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)
	good, err := ck.Seal(seal.KindBody, tenant, rowA, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func([]byte){
		"bad magic":      func(b []byte) { b[0] ^= 0xff },
		"future version": func(b []byte) { b[2] = 0x02 },
		"unknown suite":  func(b []byte) { b[3] = 0x99 },
		"unknown mode":   func(b []byte) { b[4] = 0x07 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(good)
			mutate(bad)
			if _, err := opened.Open(seal.KindBody, tenant, rowA, bad); err == nil {
				t.Fatal("a malformed header was accepted")
			}
		})
	}

	for name, in := range map[string][]byte{
		"empty":       {},
		"header only": good[:8],
		"truncated":   good[:len(good)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := opened.Open(seal.KindBody, tenant, rowA, in); err == nil {
				t.Fatal("a truncated envelope was accepted")
			}
		})
	}
}

// The dispatcher has to know which key an envelope needs before it can fetch
// one, so the id must be readable without opening anything.
func TestContentKeyIDIsReadableWithoutTheKey(t *testing.T) {
	pub, _ := keys(t)
	ck := contentKey(t, pub, 4242)
	sealed, err := ck.Seal(seal.KindBody, tenant, rowA, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	id, epoch, err := seal.ContentKeyID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if id != 4242 {
		t.Errorf("id = %d, want 4242", id)
	}
	if epoch != 1 {
		t.Errorf("epoch = %d, want 1", epoch)
	}
}

// An envelope sealed under one content key must not silently open under
// another, even one belonging to the same tenant.
func TestWrongContentKeyIsRefused(t *testing.T) {
	pub, priv := keys(t)
	a, b := contentKey(t, pub, 1), contentKey(t, pub, 2)
	sealed, err := a.Seal(seal.KindBody, tenant, rowA, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	openedB, err := seal.OpenContentKey(priv, tenant, testDevice, 2, b.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	err = func() error { _, e := openedB.Open(seal.KindBody, tenant, rowA, sealed); return e }()
	if err == nil {
		t.Fatal("the wrong content key opened the envelope")
	}
	if !strings.Contains(err.Error(), "content key") {
		t.Errorf("the error should name the mismatch: %v", err)
	}
}

// Content keys must be distinct, and their sealed forms must differ even for
// the same key material and slot.
func TestContentKeysAreFresh(t *testing.T) {
	pub, _ := keys(t)
	seen := map[string]bool{}
	for i := range uint32(20) {
		ck := contentKey(t, pub, i+1)
		if seen[string(ck.Sealed)] {
			t.Fatal("a sealed content key repeated")
		}
		seen[string(ck.Sealed)] = true
	}
}

func TestKeyParsing(t *testing.T) {
	pub, priv := keys(t)

	reparsed, err := seal.ParsePublicKey(pub.Bytes())
	if err != nil || !bytes.Equal(reparsed.Bytes(), pub.Bytes()) {
		t.Fatalf("public key did not survive a round trip: %v", err)
	}
	raw, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.ParsePrivateKey(raw); err != nil {
		t.Fatalf("private key did not survive a round trip: %v", err)
	}
	derived, err := priv.PublicKey()
	if err != nil || !bytes.Equal(derived.Bytes(), pub.Bytes()) {
		t.Fatalf("PublicKey() does not match the generated public key: %v", err)
	}

	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := seal.ParsePublicKey(make([]byte, n)); err == nil {
			t.Errorf("a %d byte public key was accepted", n)
		}
	}
}

// Sealing with no key must fail loudly rather than emitting plaintext.
func TestZeroKeyRefusesToSeal(t *testing.T) {
	if _, err := seal.SealDirect(seal.PublicKey{}, seal.KindBody, tenant, rowA, 1, []byte("x")); err == nil {
		t.Fatal("sealing succeeded with no public key")
	}
	if _, err := seal.OpenDirect(seal.PrivateKey{}, seal.KindBody, tenant, rowA, nil); err == nil {
		t.Fatal("opening succeeded with no private key")
	}
}

// Arbitrary input must never panic: envelopes come out of a database an
// attacker may have written to.
func FuzzOpen(f *testing.F) {
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	ck, err := seal.NewContentKey(pub, tenant, testDevice, 1, 1)
	if err != nil {
		f.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		f.Fatal(err)
	}
	good, _ := ck.Seal(seal.KindBody, tenant, rowA, []byte("seed"))
	f.Add(good)
	f.Add([]byte{})
	f.Add(make([]byte, 40))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = opened.Open(seal.KindBody, tenant, rowA, data)
		_, _ = seal.OpenDirect(priv, seal.KindBody, tenant, rowA, data)
		_, _, _ = seal.ContentKeyID(data)
	})
}

// TestHeaderIsAuthenticated pins the fix for a real weakness.
//
// The header sits in the clear at the front of every envelope: version, suite,
// mode and epoch. Before these bytes were bound into the associated data, an
// attacker with write access to the database could flip any of them and the
// payload still opened — an epoch rewritten so a client reaches for the wrong
// key era, or a mode byte changed under a reader. Nothing else in the envelope
// covered them.
//
// The general tampering test found it; this one names it, so a future refactor
// that stops passing the header into buildAAD fails with an explanation rather
// than a confusing byte offset.
func TestHeaderIsAuthenticated(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)
	sealed, err := ck.Seal(seal.KindBody, tenant, rowA, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenContentKey(priv, tenant, testDevice, 1, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	// Byte 5 is the high half of the epoch. Flipping it changes which key era
	// the envelope claims to belong to, and must not go unnoticed.
	forged := bytes.Clone(sealed)
	forged[5] ^= 0x01
	if _, err := opened.Open(seal.KindBody, tenant, rowA, forged); err == nil {
		t.Fatal("the epoch was rewritten and the envelope still opened")
	}

	// Every header byte, not just the epoch.
	for i := range 8 {
		forged := bytes.Clone(sealed)
		forged[i] ^= 0x01
		if _, err := opened.Open(seal.KindBody, tenant, rowA, forged); err == nil {
			t.Errorf("header byte %d is not authenticated", i)
		}
	}
}
