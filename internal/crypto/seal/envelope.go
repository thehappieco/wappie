// Package seal implements the sealed archive.
//
// The server holds only a public key. It can seal content on the way in and is
// structurally unable to open it again: the private half is generated in the
// founder's browser and never transmitted. This is not access control that
// could be misconfigured, it is an absence of the key.
//
// # Why HPKE rather than a NaCl sealed box
//
// HPKE accepts additional authenticated data; crypto_box_seal does not. Without
// AAD, an attacker with write access to Postgres can move a sealed blob from
// one row to another and the client decrypts it happily — content swapped
// between conversations, messages attributed to the wrong person, with no
// integrity failure anywhere. Binding the AAD to the tenant, the field and the
// row makes any such relocation fail authentication. For a design whose whole
// premise is not trusting the server, that is not optional.
//
// HPKE also has an upgrade path: Go's standard library already ships
// MLKEM768X25519, so a post-quantum hybrid becomes a new suite byte rather than
// a new format.
//
// # Why content keys are shared across a batch
//
// Sealing each message directly with HPKE means one X25519 operation per
// message when opening. Measured on a mid-range Android that is twelve to
// thirty seconds to open a ten-thousand message history — long enough that the
// product is unusable, and it recurs on every new device. A symmetric content
// key sealed once and covering a batch turns that into roughly ten asymmetric
// operations. The batching is a requirement, not a tuning knob.
//
// The cost, stated plainly: the content key lives in the server's memory for
// the life of the batch. Under the threat model this design actually claims —
// stolen disk, leaked backup, database dump — that costs nothing, because a
// server executing attacker code already sees plaintext in flight.
package seal

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Wire format constants.
const (
	// magic identifies an envelope. Two bytes, so a truncated or foreign blob
	// is rejected before any crypto runs.
	magic0 = 0x57 // 'W'
	magic1 = 0x53 // 'S'

	// Version covers the layout. A parser that does not recognise it fails
	// rather than guessing.
	Version = 0x01

	// SuiteV1 is HPKE base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
	// and AES-256-GCM. Frozen: nothing is negotiated at runtime, so there is
	// no downgrade to negotiate.
	//
	// SuiteV2 is reserved for the ML-KEM768 + X25519 hybrid.
	SuiteV1 = 0x01

	headerLen = 8

	// ModeDirect seals straight to the tenant public key. Used for low-volume
	// payloads: content keys themselves, and key grants.
	ModeDirect = 0x01
	// ModeBatch seals under a content key. Used for everything high-volume.
	ModeBatch = 0x02

	// encLen is the size of an X25519 encapsulated key.
	encLen = 32
	// nonceLen is the AES-GCM nonce.
	nonceLen = 12
	// tagLen is the AES-GCM authentication tag.
	tagLen = 16

	// BatchOverhead and DirectOverhead are the fixed cost per sealed value.
	BatchOverhead  = headerLen + 4 + nonceLen + tagLen // 40 bytes
	DirectOverhead = headerLen + encLen + tagLen       // 56 bytes
)

// Kind identifies what a sealed value is.
//
// It is bound into the AAD, so a blob sealed as one kind cannot be presented as
// another: a thumbnail cannot be swapped in where a message body is expected.
type Kind byte

const (
	KindBody        Kind = 0x01 // message text or caption
	KindRawProto    Kind = 0x02 // the original protobuf
	KindMediaKey    Kind = 0x03 // the 32 bytes that make a stored blob readable
	KindThumbnail   Kind = 0x04
	KindContactName Kind = 0x05
	KindContentKey  Kind = 0x06 // a content key sealed to a device archive key
	// KindDeviceGrant is a device's private archive key sealed to one user's
	// public key. It is what lets somebody read an archive by logging in
	// rather than by keeping a 32-byte secret in a text file.
	KindDeviceGrant Kind = 0x07
	KindUserWrap    Kind = 0x08 // a user private key wrapped under a password key

	// KindPayload is the structured content of a message — a location, a
	// poll, contact cards, an event, a link preview, the mention list — as
	// JSON. One value rather than a column per type; see domain.Payload.
	KindPayload Kind = 0x09

	// Contact names. Three kinds rather than one because they are three
	// different claims — what someone calls themselves, what this account
	// saved them as, and what WhatsApp verified about a business — and a
	// reader that could not tell them apart would have to guess which it was
	// showing.
	KindPushName     Kind = 0x0A
	KindFullName     Kind = 0x0B
	KindBusinessName Kind = 0x0C

	// KindAvatar is a profile picture. Sealed here rather than stored as
	// received: WhatsApp serves these over plain HTTP without encryption,
	// unlike message media.
	KindAvatar Kind = 0x0D
)

// String renders a kind for error messages.
func (k Kind) String() string {
	switch k {
	case KindBody:
		return "body"
	case KindRawProto:
		return "raw_proto"
	case KindMediaKey:
		return "media_key"
	case KindThumbnail:
		return "thumbnail"
	case KindContactName:
		return "contact_name"
	case KindContentKey:
		return "content_key"
	case KindDeviceGrant:
		return "device_grant"
	case KindUserWrap:
		return "user_wrap"
	case KindPayload:
		return "payload"
	case KindPushName:
		return "push_name"
	case KindFullName:
		return "full_name"
	case KindBusinessName:
		return "business_name"
	case KindAvatar:
		return "avatar"
	default:
		return fmt.Sprintf("kind(%#x)", byte(k))
	}
}

var (
	ErrShort          = errors.New("seal: envelope too short")
	ErrMagic          = errors.New("seal: not an envelope")
	ErrVersion        = errors.New("seal: unsupported envelope version")
	ErrSuite          = errors.New("seal: unsupported cipher suite")
	ErrMode           = errors.New("seal: unknown envelope mode")
	ErrAuthentication = errors.New("seal: authentication failed")
)

// header is the fixed prefix every envelope carries.
type header struct {
	Version byte
	Suite   byte
	Mode    byte
	Epoch   uint16
}

func (h header) encode() []byte {
	b := make([]byte, headerLen)
	b[0], b[1] = magic0, magic1
	b[2] = h.Version
	b[3] = h.Suite
	b[4] = h.Mode
	binary.BigEndian.PutUint16(b[5:7], h.Epoch)
	b[7] = 0 // reserved
	return b
}

// parseHeader validates the prefix.
//
// The suite is checked before any key material is touched. A parser that
// guessed at an unknown suite would be a downgrade vector; failing is the whole
// point of putting the byte there.
func parseHeader(b []byte) (header, error) {
	if len(b) < headerLen {
		return header{}, ErrShort
	}
	if b[0] != magic0 || b[1] != magic1 {
		return header{}, ErrMagic
	}
	h := header{Version: b[2], Suite: b[3], Mode: b[4], Epoch: binary.BigEndian.Uint16(b[5:7])}
	if h.Version != Version {
		return header{}, fmt.Errorf("%w: %#x", ErrVersion, h.Version)
	}
	if h.Suite != SuiteV1 {
		return header{}, fmt.Errorf("%w: %#x", ErrSuite, h.Suite)
	}
	if h.Mode != ModeDirect && h.Mode != ModeBatch {
		return header{}, fmt.Errorf("%w: %#x", ErrMode, h.Mode)
	}
	return h, nil
}

// aadLen is the fixed size of the associated data.
const aadLen = 4 + 1 + 16 + 16 + headerLen

// buildAAD binds a sealed value to where it lives and to its own header.
//
// The row and tenant are what make relocation detectable: moving a blob to
// another row changes the identifiers, the AAD no longer matches, and the open
// fails. They are never transmitted, only reconstructed from the columns beside
// the blob.
//
// The header is included because otherwise it is unauthenticated. Version,
// suite, mode and epoch all sit in the clear at the front of the envelope, and
// without covering them an attacker with write access can flip any of those
// bits and the payload still opens — a mode byte changed under a reader, or an
// epoch rewritten so a client reaches for the wrong key era. A test that flips
// every bit in a sealed envelope is what surfaced this.
func buildAAD(kind Kind, tenant, row uuid.UUID, hdr []byte) []byte {
	aad := make([]byte, 0, aadLen)
	aad = append(aad, 'w', 's', 'v', '1')
	aad = append(aad, byte(kind))
	aad = append(aad, tenant[:]...)
	aad = append(aad, row[:]...)
	return append(aad, hdr...)
}

// infoFor is the HPKE info string, giving each use of the tenant key its own
// domain. A content key sealed for one epoch cannot be replayed as a grant.
func infoFor(kind Kind, tenant uuid.UUID, epoch uint16) []byte {
	return fmt.Appendf(nil, "wsv1/%s/%s/%d", kind, tenant, epoch)
}
