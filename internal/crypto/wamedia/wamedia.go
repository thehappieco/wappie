// Package wamedia implements WhatsApp's media encryption scheme.
//
// This is the format the Meta CDN serves and expects: AES-256-CBC with an
// Encrypt-then-MAC HMAC-SHA256 truncated to 10 bytes, all keyed by HKDF-SHA256
// expansion of a 32-byte mediaKey.
//
// Why it matters here: the ciphertext we download is already strongly encrypted
// under a key WhatsApp handed us. So the archive stores the blob verbatim and
// seals only the 32-byte mediaKey (see internal/crypto/seal). An attacker who
// steals the bucket gets nothing. The v1 server got this half right — it stored
// the .enc blob but then wrote media_key in the clear in the column beside it,
// which defeats the whole point.
//
// Ported from whatserver/internal/waapp/crypto.go with four corrections:
// mediaKey length is now validated, the type is a real type instead of a bare
// map key, HKDF comes from the standard library, and large media can stream
// instead of being held in RAM twice.
package wamedia

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// KeyLen is the size of a WhatsApp mediaKey.
const KeyLen = 32

// MACLen is the number of HMAC bytes appended to the ciphertext.
const MACLen = 10

// Type identifies a media kind. It selects the HKDF info string, so using the
// wrong one yields keys that fail the MAC check rather than silently producing
// garbage plaintext.
type Type string

const (
	Image    Type = "image"
	Sticker  Type = "sticker"
	Video    Type = "video"
	PTV      Type = "ptv" // round video note
	Audio    Type = "audio"
	PTT      Type = "ptt" // push-to-talk voice note
	Document Type = "document"
)

// infoString maps a media type to its HKDF info label. Several types
// deliberately share a label: that is WhatsApp's scheme, not a mistake.
// Stickers use the image keys and PTV/PTT ride on video/audio respectively.
var infoString = map[Type]string{
	Image:    "WhatsApp Image Keys",
	Sticker:  "WhatsApp Image Keys",
	Video:    "WhatsApp Video Keys",
	PTV:      "WhatsApp Video Keys",
	Audio:    "WhatsApp Audio Keys",
	PTT:      "WhatsApp Audio Keys",
	Document: "WhatsApp Document Keys",
}

var (
	ErrUnknownType  = errors.New("wamedia: unknown media type")
	ErrKeyLen       = errors.New("wamedia: mediaKey must be 32 bytes")
	ErrShort        = errors.New("wamedia: ciphertext too short")
	ErrNotBlock     = errors.New("wamedia: ciphertext is not a multiple of the block size")
	ErrMAC          = errors.New("wamedia: MAC mismatch")
	ErrPadding      = errors.New("wamedia: invalid padding")
	ErrTypeMismatch = errors.New("wamedia: type has no info string")
)

// Keys are the three values HKDF expands the mediaKey into.
type Keys struct {
	IV     []byte // 16 bytes
	Cipher []byte // 32 bytes, AES-256
	MAC    []byte // 32 bytes, HMAC-SHA256
}

// DeriveKeys expands a mediaKey into the IV, cipher key and MAC key.
//
// WhatsApp expands to 112 bytes and uses the first 80; the trailing 32 are a
// "refKey" that this scheme never consumes. We expand the full 112 anyway
// because truncating the expansion would change the output of the first 80.
func DeriveKeys(mediaKey []byte, t Type) (Keys, error) {
	info, ok := infoString[t]
	if !ok {
		return Keys{}, fmt.Errorf("%w: %q", ErrUnknownType, t)
	}
	// The v1 server skipped this check, so a short or empty key derived
	// perfectly valid-looking keys and failed much later with a confusing
	// MAC error.
	if len(mediaKey) != KeyLen {
		return Keys{}, fmt.Errorf("%w: got %d", ErrKeyLen, len(mediaKey))
	}
	expanded, err := hkdf.Key(sha256.New, mediaKey, nil, info, 112)
	if err != nil {
		return Keys{}, fmt.Errorf("wamedia: hkdf: %w", err)
	}
	return Keys{
		IV:     expanded[0:16],
		Cipher: expanded[16:48],
		MAC:    expanded[48:80],
	}, nil
}

// Decrypt reverses the scheme. Input is ciphertext||mac10, exactly the bytes
// the CDN serves.
//
// The MAC is verified before any decryption happens, which is what makes the
// padding check below safe from acting as an oracle.
func Decrypt(enc, mediaKey []byte, t Type) ([]byte, error) {
	k, err := DeriveKeys(mediaKey, t)
	if err != nil {
		return nil, err
	}
	if len(enc) < MACLen+aes.BlockSize {
		return nil, ErrShort
	}

	ct, mac := enc[:len(enc)-MACLen], enc[len(enc)-MACLen:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, ErrNotBlock
	}
	if !verifyMAC(k, ct, mac) {
		return nil, ErrMAC
	}

	block, err := aes.NewCipher(k.Cipher)
	if err != nil {
		return nil, fmt.Errorf("wamedia: aes: %w", err)
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, k.IV).CryptBlocks(pt, ct)

	return unpad(pt)
}

// Encrypt produces the exact bytes the CDN would return for this plaintext and
// mediaKey. It is deterministic: the IV comes from the HKDF expansion, not from
// a fresh random draw.
//
// That determinism is the point. On outbound media, whatsmeow's Upload returns
// the mediaKey it used; re-encrypting locally with the same key and comparing
// against the reported FileEncSHA256 proves the bytes we archive are
// byte-identical to what the recipient will later fetch. Content addressing
// then works across inbound and outbound alike.
func Encrypt(plaintext, mediaKey []byte, t Type) ([]byte, error) {
	k, err := DeriveKeys(mediaKey, t)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k.Cipher)
	if err != nil {
		return nil, fmt.Errorf("wamedia: aes: %w", err)
	}

	padded := pad(plaintext)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, k.IV).CryptBlocks(ct, padded)

	out := make([]byte, 0, len(ct)+MACLen)
	out = append(out, ct...)
	return append(out, computeMAC(k, ct)...), nil
}

// DecryptTo streams decryption into dst, for media too large to hold in memory
// twice. It returns the number of plaintext bytes written.
//
// IMPORTANT: the MAC covers the whole ciphertext, so it can only be checked
// after the last block has already been written to dst. On a non-nil error the
// caller MUST discard everything written — the bytes are unauthenticated.
// Write to a temporary file and rename only on success; never stream this
// straight to a client.
func DecryptTo(dst io.Writer, src io.Reader, size int64, mediaKey []byte, t Type) (int64, error) {
	k, err := DeriveKeys(mediaKey, t)
	if err != nil {
		return 0, err
	}
	if size < MACLen+aes.BlockSize {
		return 0, ErrShort
	}
	ctLen := size - MACLen
	if ctLen%aes.BlockSize != 0 {
		return 0, ErrNotBlock
	}

	block, err := aes.NewCipher(k.Cipher)
	if err != nil {
		return 0, fmt.Errorf("wamedia: aes: %w", err)
	}
	dec := cipher.NewCBCDecrypter(block, k.IV)
	mac := hmac.New(sha256.New, k.MAC)
	mac.Write(k.IV)

	// One block is always held back: the final block carries the padding and
	// must not reach dst until it has been trimmed.
	var (
		buf     = make([]byte, 64*1024)
		held    = make([]byte, 0, aes.BlockSize)
		written int64
		read    int64
	)
	for read < ctLen {
		n := int64(len(buf))
		if rem := ctLen - read; rem < n {
			n = rem
		}
		chunk := buf[:n]
		if _, err := io.ReadFull(src, chunk); err != nil {
			return written, fmt.Errorf("wamedia: read ciphertext: %w", err)
		}
		read += n
		mac.Write(chunk)
		dec.CryptBlocks(chunk, chunk)

		// Emit the previously held block now that we know it is not the last.
		if len(held) > 0 {
			w, err := dst.Write(held)
			written += int64(w)
			if err != nil {
				return written, fmt.Errorf("wamedia: write plaintext: %w", err)
			}
			held = held[:0]
		}
		held = append(held, chunk[len(chunk)-aes.BlockSize:]...)
		if body := chunk[:len(chunk)-aes.BlockSize]; len(body) > 0 {
			w, err := dst.Write(body)
			written += int64(w)
			if err != nil {
				return written, fmt.Errorf("wamedia: write plaintext: %w", err)
			}
		}
	}

	gotMAC := make([]byte, MACLen)
	if _, err := io.ReadFull(src, gotMAC); err != nil {
		return written, fmt.Errorf("wamedia: read mac: %w", err)
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil)[:MACLen], gotMAC) != 1 {
		return written, ErrMAC
	}

	final, err := unpad(held)
	if err != nil {
		return written, err
	}
	w, err := dst.Write(final)
	written += int64(w)
	if err != nil {
		return written, fmt.Errorf("wamedia: write plaintext: %w", err)
	}
	return written, nil
}

// NewKey returns a fresh 32-byte mediaKey.
func NewKey() []byte {
	k := make([]byte, KeyLen)
	// crypto/rand.Read never returns an error in Go 1.24+; it panics on a
	// failing entropy source, which is the correct outcome here anyway.
	if _, err := rand.Read(k); err != nil {
		panic("wamedia: entropy source failed: " + err.Error())
	}
	return k
}

func computeMAC(k Keys, ct []byte) []byte {
	h := hmac.New(sha256.New, k.MAC)
	h.Write(k.IV)
	h.Write(ct)
	return h.Sum(nil)[:MACLen]
}

func verifyMAC(k Keys, ct, want []byte) bool {
	return subtle.ConstantTimeCompare(computeMAC(k, ct), want) == 1
}

func pad(b []byte) []byte {
	n := aes.BlockSize - (len(b) % aes.BlockSize) // always 1..16, never 0
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// unpad strips PKCS#7 padding, rejecting anything malformed.
//
// This runs only after the MAC has been verified, so it cannot be used as a
// padding oracle: an attacker cannot produce a ciphertext that reaches here.
func unpad(pt []byte) ([]byte, error) {
	if len(pt) == 0 || len(pt)%aes.BlockSize != 0 {
		return nil, ErrPadding
	}
	n := int(pt[len(pt)-1])
	if n == 0 || n > aes.BlockSize || n > len(pt) {
		return nil, ErrPadding
	}
	for _, b := range pt[len(pt)-n:] {
		if int(b) != n {
			return nil, ErrPadding
		}
	}
	return pt[:len(pt)-n], nil
}
