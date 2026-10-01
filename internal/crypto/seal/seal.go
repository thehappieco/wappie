package seal

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/thehappieco/kit/hpke"
	kit "github.com/thehappieco/kit/seal"
)

// KeyLen is the size of an X25519 key and of a content key.
const KeyLen = kit.KeyLen

// PublicKey is a tenant's archive public key.
type PublicKey = hpke.PublicKey

// PrivateKey is a tenant's archive private key.
//
// It exists in this package so that tests, the CLI and the eventual client
// tooling can open what the server sealed. The server itself never constructs
// one: nothing in the ingest path can, because nothing gives it the bytes.
type PrivateKey = hpke.PrivateKey

// ParsePublicKey deserialises a 32-byte X25519 public key. The length is
// checked here so that pairing keeps answering a wrong one in these words.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != KeyLen {
		return PublicKey{}, fmt.Errorf("seal: public key must be %d bytes, got %d", KeyLen, len(b))
	}
	return hpke.ParsePublicKey(b)
}

// GenerateKeyPair creates a tenant archive keypair.
//
// In production this runs in the founder's browser and only the public half is
// ever transmitted. The server-side implementation exists for tests and for
// tooling that runs on an operator's own machine.
func GenerateKeyPair() (PublicKey, PrivateKey, error) { return hpke.GenerateKeyPair() }

// ParsePrivateKey deserialises a private key.
func ParsePrivateKey(b []byte) (PrivateKey, error) {
	if len(b) != KeyLen {
		return PrivateKey{}, fmt.Errorf("seal: private key must be %d bytes, got %d", KeyLen, len(b))
	}
	return hpke.ParsePrivateKey(b)
}

// ---------------------------------------------------------------------------
// Direct mode: sealed straight to the tenant key.
// ---------------------------------------------------------------------------

// SealDirect seals a small, low-volume payload to the tenant public key.
//
// Used for content keys and key grants. Never for message content: one
// asymmetric operation per message is what makes a phone take half a minute to
// open a conversation.
func SealDirect(pub PublicKey, kind Kind, tenant, row uuid.UUID, epoch uint16, plaintext []byte) ([]byte, error) {
	return kit.SealDirect(pub, kind, tenant, row, epoch, plaintext)
}

// OpenDirect reverses SealDirect. Client side only.
func OpenDirect(priv PrivateKey, kind Kind, tenant, row uuid.UUID, envelope []byte) ([]byte, error) {
	return kit.OpenDirect(priv, kind, tenant, row, envelope)
}

// ---------------------------------------------------------------------------
// Batch mode: sealed under a content key.
// ---------------------------------------------------------------------------

// ContentKey is a symmetric key covering a batch of sealed values. Its ID is
// a per-device counter, carried in the envelope so a reader knows which key
// to unwrap; Sealed is the key sealed to the device's archive key, which is
// what is stored, while the raw key never touches disk.
type ContentKey = kit.ContentKey[Kind]

// NewContentKey generates a content key and seals it to one device's archive key.
//
// Per device rather than per tenant. With one key for a whole tenant, "this
// operator may read that WhatsApp account and not this one" is a rule the
// server enforces — and the premise here is that server-enforced rules do not
// survive a compromised server. Sealing to the device makes the separation
// arithmetic: a reader holding one device's key cannot open another's.
func NewContentKey(pub PublicKey, tenant, device uuid.UUID, epoch uint16, id uint32) (*ContentKey, error) {
	return kit.NewContentKey[Kind](pub, tenant, device, epoch, id)
}

// OpenContentKey unwraps a stored content key. Client side only.
func OpenContentKey(priv PrivateKey, tenant, device uuid.UUID, id uint32, sealed []byte) (*ContentKey, error) {
	return kit.OpenContentKey[Kind](priv, tenant, device, id, sealed)
}

// ContentKeyID reads which content key an envelope needs, without opening it.
// The dispatcher uses this to fetch the right key.
func ContentKeyID(envelope []byte) (id uint32, epoch uint16, err error) {
	return kit.ContentKeyID[Kind](envelope)
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

// ContentKeyRow derives the stable uuid a content key binds to.
//
// Exported because the browser has to compute the same value to open one, and
// reimplementing a derivation from prose is how two sides quietly disagree.
func ContentKeyRow(tenant, device uuid.UUID, id uint32) uuid.UUID {
	return kit.ContentKeyRow(tenant, device, id)
}

// GrantRow derives the uuid a key grant binds to.
//
// A grant is one device's private archive key sealed to one person's public
// key. Binding it to (device, user, epoch) is what stops a grant issued for one
// device being presented as the grant for another.
func GrantRow(tenant, device, user uuid.UUID, epoch uint16) uuid.UUID {
	return kit.GrantRow(tenant, device, user, epoch)
}

// DraftRow derives the uuid an assistant's draft binds to
// (docs/mcp-enclave.md §17.6): the number, the connection, the draft, the
// message it replies to (sixteen zero bytes for none) and the chat.
//
// Every routing field is in it because the ledger row that carries the
// envelope is this server's: rebuilt with another chat, another reply target
// or another connection, the row opens nothing, so a draft the person was
// shown for one recipient can never be delivered to another. The browser and
// the attested reader compute the same value (packages/client draftRow).
func DraftRow(tenant, device, connection, draft uuid.UUID, reply *uuid.UUID, chatKey string) uuid.UUID {
	replyTo := make([]byte, 16)
	if reply != nil {
		replyTo = reply[:]
	}
	return kit.Row(tenant, device[:], connection[:], draft[:], replyTo, []byte(chatKey))
}
