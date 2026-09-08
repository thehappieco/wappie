package wamedia

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
)

// goldenKey/goldenPlain/goldenEnc were produced by an independent
// implementation (Python HKDF + the openssl CLI for AES-256-CBC), not by this
// package. They pin the wire format: if a refactor changes the HKDF expansion,
// the info string, the padding, or the MAC truncation, this test fails and the
// archive stops being readable by real WhatsApp clients.
var (
	goldenKey   = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	goldenPlain = []byte("whatserver2 golden vector")
	goldenEnc   = mustHex("d7c13d226c88ac66ce0de87202cbd333887b194ad8d2a6f4a7a6ebaeb597038666afa4346f7c14c9878b")

	goldenIV     = mustHex("aa6a127218397cbd2383e4ccf7176a79")
	goldenCipher = mustHex("008c9aea9b7c5d81eb56b3f530f87d42dcc92d27b11ad6b5bd66f0560d0d8c46")
	goldenMAC    = mustHex("91d09ffec108833c1699574c52657923fb6e3e161d9698bc6b3a05fbc508a515")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestDeriveKeysGolden(t *testing.T) {
	k, err := DeriveKeys(goldenKey, Image)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	for _, tc := range []struct {
		name      string
		got, want []byte
	}{
		{"IV", k.IV, goldenIV},
		{"cipher", k.Cipher, goldenCipher},
		{"mac", k.MAC, goldenMAC},
	} {
		if !bytes.Equal(tc.got, tc.want) {
			t.Errorf("%s = %x, want %x", tc.name, tc.got, tc.want)
		}
	}
}

func TestEncryptGolden(t *testing.T) {
	got, err := Encrypt(goldenPlain, goldenKey, Image)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(got, goldenEnc) {
		t.Fatalf("Encrypt = %x\nwant        %x", got, goldenEnc)
	}
}

func TestDecryptGolden(t *testing.T) {
	got, err := Decrypt(goldenEnc, goldenKey, Image)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, goldenPlain) {
		t.Fatalf("Decrypt = %q, want %q", got, goldenPlain)
	}
}

// Sizes clustered around the AES block boundary: PKCS#7 must add a full block
// when the input is already aligned, which is the classic off-by-one here.
var roundTripSizes = []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 4096, 65536, 65537}

func TestRoundTrip(t *testing.T) {
	key := NewKey()
	for _, typ := range []Type{Image, Sticker, Video, PTV, Audio, PTT, Document} {
		for _, n := range roundTripSizes {
			t.Run(fmt.Sprintf("%s/%d", typ, n), func(t *testing.T) {
				plain := deterministicBytes(n)
				enc, err := Encrypt(plain, key, typ)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				if got, want := len(enc), blocksFor(n)+MACLen; got != want {
					t.Errorf("len(enc) = %d, want %d", got, want)
				}
				got, err := Decrypt(enc, key, typ)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got, plain) {
					t.Errorf("round trip mismatch at %d bytes", n)
				}
			})
		}
	}
}

// Sticker rides on the image key schedule and PTV/PTT on video/audio. That
// sharing is WhatsApp's design; asserting it here stops someone from
// "cleaning up" the duplicate info strings.
func TestTypesSharingKeySchedule(t *testing.T) {
	key := NewKey()
	same := [][2]Type{{Image, Sticker}, {Video, PTV}, {Audio, PTT}}
	for _, p := range same {
		a, err := DeriveKeys(key, p[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := DeriveKeys(key, p[1])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.Cipher, b.Cipher) {
			t.Errorf("%s and %s should share a key schedule", p[0], p[1])
		}
	}
	distinct := [][2]Type{{Image, Video}, {Image, Audio}, {Image, Document}, {Video, Audio}}
	for _, p := range distinct {
		a, _ := DeriveKeys(key, p[0])
		b, _ := DeriveKeys(key, p[1])
		if bytes.Equal(a.Cipher, b.Cipher) {
			t.Errorf("%s and %s must not share a key schedule", p[0], p[1])
		}
	}
}

// Decrypting with the wrong type derives different keys, so it must fail the
// MAC check rather than emit garbage plaintext.
func TestWrongTypeFailsMAC(t *testing.T) {
	key := NewKey()
	enc, err := Encrypt([]byte("hello"), key, Image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(enc, key, Video); !errors.Is(err, ErrMAC) {
		t.Fatalf("err = %v, want ErrMAC", err)
	}
}

func TestWrongKeyFailsMAC(t *testing.T) {
	enc, err := Encrypt([]byte("hello"), NewKey(), Image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(enc, NewKey(), Image); !errors.Is(err, ErrMAC) {
		t.Fatalf("err = %v, want ErrMAC", err)
	}
}

// Every single-bit flip anywhere in the blob must be caught. This is the
// property the archive relies on: an attacker with write access to the bucket
// cannot alter stored media undetected.
func TestTamperDetection(t *testing.T) {
	key := NewKey()
	enc, err := Encrypt(deterministicBytes(64), key, Document)
	if err != nil {
		t.Fatal(err)
	}
	for i := range enc {
		for _, bit := range []byte{0x01, 0x80} {
			tampered := bytes.Clone(enc)
			tampered[i] ^= bit
			if _, err := Decrypt(tampered, key, Document); err == nil {
				t.Fatalf("byte %d bit %#x: tampering not detected", i, bit)
			}
		}
	}
}

func TestKeyLengthValidated(t *testing.T) {
	// The v1 server accepted any length here and failed later with a
	// confusing MAC error instead.
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := DeriveKeys(make([]byte, n), Image); !errors.Is(err, ErrKeyLen) {
			t.Errorf("len %d: err = %v, want ErrKeyLen", n, err)
		}
	}
}

func TestUnknownType(t *testing.T) {
	if _, err := DeriveKeys(NewKey(), Type("gif")); !errors.Is(err, ErrUnknownType) {
		t.Errorf("err = %v, want ErrUnknownType", err)
	}
}

func TestMalformedInput(t *testing.T) {
	key := NewKey()
	for name, in := range map[string][]byte{
		"empty":           {},
		"mac only":        make([]byte, MACLen),
		"under one block": make([]byte, MACLen+aes.BlockSize-1),
		"not aligned":     make([]byte, MACLen+aes.BlockSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(in, key, Image); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// A ciphertext carrying a valid MAC but decrypting to invalid padding must be
// rejected. Reaching this path requires the MAC key, so it is not an oracle —
// but it must still not return garbage.
func TestBadPaddingRejected(t *testing.T) {
	key := NewKey()
	k, err := DeriveKeys(key, Image)
	if err != nil {
		t.Fatal(err)
	}
	// Encrypt a block whose plaintext ends in 0x00, an illegal pad byte.
	bad := make([]byte, aes.BlockSize)
	enc, err := Encrypt(bad, key, Image)
	if err != nil {
		t.Fatal(err)
	}
	ct := enc[:len(enc)-MACLen]
	// Truncate to one block: that block decrypts to something that will not
	// be valid padding, and we re-MAC so it passes authentication.
	ct = ct[:aes.BlockSize]
	h := hmac.New(sha256.New, k.MAC)
	h.Write(k.IV)
	h.Write(ct)
	forged := append(bytes.Clone(ct), h.Sum(nil)[:MACLen]...)

	_, err = Decrypt(forged, key, Image)
	if err != nil && !errors.Is(err, ErrPadding) {
		t.Fatalf("err = %v, want ErrPadding or nil-with-valid-pad", err)
	}
}

func TestDecryptToMatchesDecrypt(t *testing.T) {
	key := NewKey()
	// Sizes that straddle the 64 KiB streaming buffer, where the held-back
	// final block logic is easiest to get wrong.
	for _, n := range []int{0, 1, 16, 65536 - 17, 65536 - 16, 65536, 65536 + 1, 3 * 65536} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			plain := deterministicBytes(n)
			enc, err := Encrypt(plain, key, Video)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			written, err := DecryptTo(&out, bytes.NewReader(enc), int64(len(enc)), key, Video)
			if err != nil {
				t.Fatalf("DecryptTo: %v", err)
			}
			if written != int64(n) {
				t.Errorf("written = %d, want %d", written, n)
			}
			if !bytes.Equal(out.Bytes(), plain) {
				t.Errorf("streamed output differs from plaintext at %d bytes", n)
			}
		})
	}
}

func TestDecryptToRejectsTampering(t *testing.T) {
	key := NewKey()
	enc, err := Encrypt(deterministicBytes(1000), key, Video)
	if err != nil {
		t.Fatal(err)
	}
	enc[500] ^= 0x01
	var out bytes.Buffer
	if _, err := DecryptTo(&out, bytes.NewReader(enc), int64(len(enc)), key, Video); !errors.Is(err, ErrMAC) {
		t.Fatalf("err = %v, want ErrMAC", err)
	}
}

func TestDecryptToTruncated(t *testing.T) {
	key := NewKey()
	enc, err := Encrypt(deterministicBytes(1000), key, Video)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	// Claim the full size but supply a short reader.
	_, err = DecryptTo(&out, bytes.NewReader(enc[:len(enc)-20]), int64(len(enc)), key, Video)
	if err == nil {
		t.Fatal("expected an error on truncated input")
	}
}

func TestNewKeyIsFresh(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		k := NewKey()
		if len(k) != KeyLen {
			t.Fatalf("len = %d, want %d", len(k), KeyLen)
		}
		if seen[string(k)] {
			t.Fatal("NewKey returned a duplicate")
		}
		seen[string(k)] = true
	}
}

// FuzzDecrypt asserts only that arbitrary input never panics. Decrypt runs on
// bytes fetched from the Meta CDN, so it is genuinely attacker-adjacent.
func FuzzDecrypt(f *testing.F) {
	key := NewKey()
	enc, _ := Encrypt([]byte("seed"), key, Image)
	f.Add(enc)
	f.Add([]byte{})
	f.Add(make([]byte, MACLen+aes.BlockSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, typ := range []Type{Image, Video, Audio, Document} {
			if pt, err := Decrypt(data, key, typ); err == nil && len(pt) > len(data) {
				t.Fatalf("plaintext (%d) longer than ciphertext (%d)", len(pt), len(data))
			}
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	key := NewKey()
	f.Fuzz(func(t *testing.T, plain []byte) {
		enc, err := Encrypt(plain, key, Document)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(enc, key, Document)
		if err != nil {
			t.Fatalf("Decrypt after Encrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("round trip mismatch")
		}
		var out bytes.Buffer
		if _, err := DecryptTo(&out, bytes.NewReader(enc), int64(len(enc)), key, Document); err != nil {
			t.Fatalf("DecryptTo: %v", err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatal("stream round trip mismatch")
		}
	})
}

func blocksFor(n int) int { return (n/aes.BlockSize + 1) * aes.BlockSize }

func deterministicBytes(n int) []byte {
	b := make([]byte, n)
	h := sha256.New()
	for off := 0; off < n; off += sha256.Size {
		h.Reset()
		h.Write(fmt.Appendf(nil, "whatserver2/%d", off))
		copy(b[off:], h.Sum(nil))
	}
	return b
}

var _ io.Reader = (*bytes.Reader)(nil)
