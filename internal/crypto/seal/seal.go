package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// KeyLen is the size of an X25519 key and of a content key.
const KeyLen = 32

// suite returns the frozen cipher suite. Its components are fixed in code
// rather than configured, so there is nothing to misconfigure and nothing to
// negotiate down.
func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// PublicKey is a tenant's archive public key.
type PublicKey struct {
	raw []byte
	pk  hpke.PublicKey
}

// ParsePublicKey deserialises a 32-byte X25519 public key.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != KeyLen {
		return PublicKey{}, fmt.Errorf("seal: public key must be %d bytes, got %d", KeyLen, len(b))
	}
	kem, _, _ := suite()
	pk, err := kem.NewPublicKey(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("seal: invalid public key: %w", err)
	}
	return PublicKey{raw: append([]byte(nil), b...), pk: pk}, nil
}

// Bytes returns the serialised key.
func (p PublicKey) Bytes() []byte { return append([]byte(nil), p.raw...) }

// Valid reports whether the key was parsed.
func (p PublicKey) Valid() bool { return p.pk != nil }

// PrivateKey is a tenant's archive private key.
//
// It exists in this package so that tests, the CLI and the eventual client
// tooling can open what the server sealed. The server itself never constructs
// one: nothing in the ingest path can, because nothing gives it the bytes.
type PrivateKey struct {
	sk hpke.PrivateKey
}

// GenerateKeyPair creates a tenant archive keypair.
//
// In production this runs in the founder's browser and only the public half is
// ever transmitted. The server-side implementation exists for tests and for
// tooling that runs on an operator's own machine.
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	kem, _, _ := suite()
	sk, err := kem.GenerateKey()
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("seal: generate key: %w", err)
	}
	pub, err := ParsePublicKey(sk.PublicKey().Bytes())
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return pub, PrivateKey{sk: sk}, nil
}

// ParsePrivateKey deserialises a private key.
func ParsePrivateKey(b []byte) (PrivateKey, error) {
	if len(b) != KeyLen {
		return PrivateKey{}, fmt.Errorf("seal: private key must be %d bytes, got %d", KeyLen, len(b))
	}
	kem, _, _ := suite()
	sk, err := kem.NewPrivateKey(b)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("seal: invalid private key: %w", err)
	}
	return PrivateKey{sk: sk}, nil
}

// Bytes serialises the private key.
func (p PrivateKey) Bytes() ([]byte, error) {
	if p.sk == nil {
		return nil, errors.New("seal: no private key")
	}
	return p.sk.Bytes()
}

// PublicKey returns the matching public key.
func (p PrivateKey) PublicKey() (PublicKey, error) {
	if p.sk == nil {
		return PublicKey{}, errors.New("seal: no private key")
	}
	return ParsePublicKey(p.sk.PublicKey().Bytes())
}

// Valid reports whether the key was parsed.
func (p PrivateKey) Valid() bool { return p.sk != nil }

// ---------------------------------------------------------------------------
// Direct mode: sealed straight to the tenant key.
// ---------------------------------------------------------------------------

// SealDirect seals a small, low-volume payload to the tenant public key.
//
// Used for content keys and key grants. Never for message content: one
// asymmetric operation per message is what makes a phone take half a minute to
// open a conversation.
func SealDirect(pub PublicKey, kind Kind, tenant, row uuid.UUID, epoch uint16, plaintext []byte) ([]byte, error) {
	if !pub.Valid() {
		return nil, errors.New("seal: no public key")
	}
	_, kdf, aead := suite()
	hdr := header{Version: Version, Suite: SuiteV1, Mode: ModeDirect, Epoch: epoch}.encode()

	enc, sender, err := hpke.NewSender(pub.pk, kdf, aead, infoFor(kind, tenant, epoch))
	if err != nil {
		return nil, fmt.Errorf("seal: hpke sender: %w", err)
	}
	ct, err := sender.Seal(buildAAD(kind, tenant, row, hdr), plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal: hpke seal: %w", err)
	}

	out := make([]byte, 0, headerLen+len(enc)+len(ct))
	out = append(out, hdr...)
	out = append(out, enc...)
	return append(out, ct...), nil
}

// OpenDirect reverses SealDirect. Client side only.
func OpenDirect(priv PrivateKey, kind Kind, tenant, row uuid.UUID, envelope []byte) ([]byte, error) {
	if !priv.Valid() {
		return nil, errors.New("seal: no private key")
	}
	h, err := parseHeader(envelope)
	if err != nil {
		return nil, err
	}
	if h.Mode != ModeDirect {
		return nil, fmt.Errorf("%w: expected direct, got %#x", ErrMode, h.Mode)
	}
	if len(envelope) < headerLen+encLen+tagLen {
		return nil, ErrShort
	}

	enc := envelope[headerLen : headerLen+encLen]
	ct := envelope[headerLen+encLen:]

	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(enc, priv.sk, kdf, aead, infoFor(kind, tenant, h.Epoch))
	if err != nil {
		return nil, fmt.Errorf("seal: hpke recipient: %w", err)
	}
	pt, err := recipient.Open(buildAAD(kind, tenant, row, envelope[:headerLen]), ct)
	if err != nil {
		// Deliberately opaque. Distinguishing "wrong key" from "tampered" from
		// "wrong row" would hand an attacker with database write access an
		// oracle for probing the binding.
		return nil, ErrAuthentication
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// Batch mode: sealed under a content key.
// ---------------------------------------------------------------------------

// ContentKey is a symmetric key covering a batch of sealed values.
type ContentKey struct {
	// ID is a per-tenant counter, carried in the envelope so a reader knows
	// which key to unwrap. Scoped per tenant so it does not leak system-wide
	// volume to clients.
	ID    uint32
	Epoch uint16

	key []byte // 32 bytes, AES-256-GCM

	// Sealed is the key itself sealed to the tenant public key. This is what
	// is stored; the raw key never touches disk.
	Sealed []byte
}

// NewContentKey generates a content key and seals it to one device's archive key.
//
// Per device rather than per tenant. With one key for a whole tenant, "this
// operator may read that WhatsApp account and not this one" is a rule the
// server enforces — and the premise here is that server-enforced rules do not
// survive a compromised server. Sealing to the device makes the separation
// arithmetic: a reader holding one device's key cannot open another's.
func NewContentKey(pub PublicKey, tenant, device uuid.UUID, epoch uint16, id uint32) (*ContentKey, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("seal: entropy: %w", err)
	}
	// The row identity is derived from the device and the id, so a key sealed
	// for one slot cannot be presented as another — or as another device's.
	sealed, err := SealDirect(pub, KindContentKey, tenant, ContentKeyRow(tenant, device, id), epoch, key)
	if err != nil {
		return nil, err
	}
	return &ContentKey{ID: id, Epoch: epoch, key: key, Sealed: sealed}, nil
}

// OpenContentKey unwraps a stored content key. Client side only.
func OpenContentKey(priv PrivateKey, tenant, device uuid.UUID, id uint32, sealed []byte) (*ContentKey, error) {
	h, err := parseHeader(sealed)
	if err != nil {
		return nil, err
	}
	key, err := OpenDirect(priv, KindContentKey, tenant, ContentKeyRow(tenant, device, id), sealed)
	if err != nil {
		return nil, err
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("seal: content key is %d bytes, want %d", len(key), KeyLen)
	}
	return &ContentKey{ID: id, Epoch: h.Epoch, key: key, Sealed: sealed}, nil
}

// ContentKeyRow derives the stable uuid a content key binds to.
//
// Exported because the browser has to compute the same value to open one, and
// reimplementing a derivation from prose is how two sides quietly disagree.
func ContentKeyRow(tenant, device uuid.UUID, id uint32) uuid.UUID {
	name := make([]byte, 0, 16+4)
	name = append(name, device[:]...)
	name = binary.BigEndian.AppendUint32(name, id)
	return uuid.NewSHA1(tenant, name)
}

// GrantRow derives the uuid a key grant binds to.
//
// A grant is one device's private archive key sealed to one person's public
// key. Binding it to (device, user, epoch) is what stops a grant issued for one
// device being presented as the grant for another.
func GrantRow(tenant, device, user uuid.UUID, epoch uint16) uuid.UUID {
	name := make([]byte, 0, 16+16+2)
	name = append(name, device[:]...)
	name = append(name, user[:]...)
	name = binary.BigEndian.AppendUint16(name, epoch)
	return uuid.NewSHA1(tenant, name)
}

// Seal encrypts a value under this content key.
func (c *ContentKey) Seal(kind Kind, tenant, row uuid.UUID, plaintext []byte) ([]byte, error) {
	gcm, err := c.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: entropy: %w", err)
	}

	hdr := header{Version: Version, Suite: SuiteV1, Mode: ModeBatch, Epoch: c.Epoch}.encode()

	out := make([]byte, 0, BatchOverhead+len(plaintext))
	out = append(out, hdr...)
	out = binary.BigEndian.AppendUint32(out, c.ID)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, buildAAD(kind, tenant, row, hdr)), nil
}

// Open decrypts a value sealed under this content key. Client side only.
func (c *ContentKey) Open(kind Kind, tenant, row uuid.UUID, envelope []byte) ([]byte, error) {
	h, err := parseHeader(envelope)
	if err != nil {
		return nil, err
	}
	if h.Mode != ModeBatch {
		return nil, fmt.Errorf("%w: expected batch, got %#x", ErrMode, h.Mode)
	}
	if len(envelope) < BatchOverhead {
		return nil, ErrShort
	}
	if id := binary.BigEndian.Uint32(envelope[headerLen : headerLen+4]); id != c.ID {
		return nil, fmt.Errorf("seal: envelope needs content key %d, have %d", id, c.ID)
	}

	gcm, err := c.gcm()
	if err != nil {
		return nil, err
	}
	nonce := envelope[headerLen+4 : headerLen+4+nonceLen]
	ct := envelope[headerLen+4+nonceLen:]
	pt, err := gcm.Open(nil, nonce, ct, buildAAD(kind, tenant, row, envelope[:headerLen]))
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

func (c *ContentKey) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("seal: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: gcm: %w", err)
	}
	return gcm, nil
}

// ContentKeyID reads which content key an envelope needs, without opening it.
// The dispatcher uses this to fetch the right key.
func ContentKeyID(envelope []byte) (id uint32, epoch uint16, err error) {
	h, err := parseHeader(envelope)
	if err != nil {
		return 0, 0, err
	}
	if h.Mode != ModeBatch {
		return 0, h.Epoch, fmt.Errorf("%w: not a batch envelope", ErrMode)
	}
	if len(envelope) < headerLen+4 {
		return 0, 0, ErrShort
	}
	return binary.BigEndian.Uint32(envelope[headerLen : headerLen+4]), h.Epoch, nil
}
