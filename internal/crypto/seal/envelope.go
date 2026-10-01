// Package seal implements the sealed archive.
//
// The server holds only a public key. It can seal content on the way in and is
// structurally unable to open it again: the private half is generated in the
// founder's browser and never transmitted. This is not access control that
// could be misconfigured, it is an absence of the key.
//
// The format lives in the shared kit, github.com/thehappieco/kit/seal, which
// started as this package. Two parts of it are a product's own and come from
// Wappie's profile (github.com/thehappieco/kit/profiles/wappie): the magic
// "WS" with the label "wsv1" that prefixes the AAD and the HPKE info, and the
// names of the kinds below, which go into a direct envelope's info. They are
// frozen; everything already sealed opens only with exactly these. This
// package keeps the names the rest of the server uses, what each kind means,
// and the draft rows of the MCP ledger.
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
	"github.com/thehappieco/kit/profiles/wappie"
	kit "github.com/thehappieco/kit/seal"
)

// Wire format constants.
const (
	// Version covers the layout. A parser that does not recognise it fails
	// rather than guessing.
	Version = kit.Version

	// SuiteV1 is HPKE base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
	// and AES-256-GCM. Frozen: nothing is negotiated at runtime, so there is
	// no downgrade to negotiate.
	SuiteV1 = kit.SuiteV1

	// ModeDirect seals straight to the tenant public key. Used for low-volume
	// payloads: content keys themselves, and key grants.
	ModeDirect = kit.ModeDirect
	// ModeBatch seals under a content key. Used for everything high-volume.
	ModeBatch = kit.ModeBatch

	// BatchOverhead and DirectOverhead are the fixed cost per sealed value.
	BatchOverhead  = kit.BatchOverhead  // 40 bytes
	DirectOverhead = kit.DirectOverhead // 56 bytes
)

// Kind identifies what a sealed value is.
//
// It is bound into the AAD, so a blob sealed as one kind cannot be presented as
// another: a thumbnail cannot be swapped in where a message body is expected.
// Its String is the wire name a direct envelope's HPKE info carries, and a
// metric label here.
type Kind = wappie.Kind

const (
	KindBody        = wappie.KindBody     // message text or caption
	KindRawProto    = wappie.KindRawProto // the original protobuf
	KindMediaKey    = wappie.KindMediaKey // the 32 bytes that make a stored blob readable
	KindThumbnail   = wappie.KindThumbnail
	KindContactName = wappie.KindContactName
	KindContentKey  = wappie.KindContentKey // a content key sealed to a device archive key
	// KindDeviceGrant is a device's private archive key sealed to one user's
	// public key. It is what lets somebody read an archive by logging in
	// rather than by keeping a 32-byte secret in a text file.
	KindDeviceGrant = wappie.KindDeviceGrant
	KindUserWrap    = wappie.KindUserWrap // a user private key wrapped under a password key

	// KindPayload is the structured content of a message — a location, a
	// poll, contact cards, an event, a link preview, the mention list — as
	// JSON. One value rather than a column per type; see domain.Payload.
	KindPayload = wappie.KindPayload

	// Contact names. Three kinds rather than one because they are three
	// different claims — what someone calls themselves, what this account
	// saved them as, and what WhatsApp verified about a business — and a
	// reader that could not tell them apart would have to guess which it was
	// showing.
	KindPushName     = wappie.KindPushName
	KindFullName     = wappie.KindFullName
	KindBusinessName = wappie.KindBusinessName

	// KindAvatar is a profile picture. Sealed here rather than stored as
	// received: WhatsApp serves these over plain HTTP without encryption,
	// unlike message media.
	KindAvatar = wappie.KindAvatar

	// KindMcpDraft is a message an assistant drafted through an MCP
	// connection, sealed inside the attested reader to the number's archive
	// key (docs/mcp-enclave.md §17.6). This server stores it and cannot open
	// it; the person reads it in the console before anything is sent. 0x0F
	// stays reserved.
	KindMcpDraft = wappie.KindMcpDraft
)

// The ways an envelope fails before or at opening. OpenDirect and a content
// key's Open report every failure past the header as ErrAuthentication:
// distinguishing "wrong key" from "tampered" from "wrong row" would hand an
// attacker with database write access an oracle for probing the binding.
var (
	ErrShort          = kit.ErrShort
	ErrMagic          = kit.ErrMagic
	ErrVersion        = kit.ErrVersion
	ErrSuite          = kit.ErrSuite
	ErrMode           = kit.ErrMode
	ErrAuthentication = kit.ErrAuthentication
)
