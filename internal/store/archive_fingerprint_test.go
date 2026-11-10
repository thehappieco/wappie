package store_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"whatserver2/internal/store"
)

// fingerprintVectors is testdata/archive-key-fingerprints.json. The
// clients that compute a fingerprint themselves read the same file:
// packages/cli's tests, and wappie-cloud's web tests from the core
// checkout its CI pins. So a change of the format fails here and there.
type fingerprintVectors struct {
	Vectors []struct {
		Name        string `json:"name"`
		PrivateKey  string `json:"private_key"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	} `json:"vectors"`
	Invalid []string `json:"invalid"`
}

// TestArchiveKeyFingerprint pins the fingerprint's format (DS49): the
// lowercase hex SHA-256 of the stored public key bytes, 64 characters, no
// prefix. Clients compute it from the key they open, and step 7's
// token.grant uses the same helper, so a change here is a change of the
// wire. Where a vector gives the private key, its X25519 public half is
// the vector's public key, as a client derives it.
func TestArchiveKeyFingerprint(t *testing.T) {
	raw, err := os.ReadFile("testdata/archive-key-fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	var file fingerprintVectors
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 4 || len(file.Invalid) == 0 {
		t.Fatalf("%d vectors and %d invalid forms: the file lost some", len(file.Vectors), len(file.Invalid))
	}
	var derived int
	for _, v := range file.Vectors {
		public, err := hex.DecodeString(v.PublicKey)
		if err != nil || len(public) != 32 {
			t.Fatalf("%s: public key %q is not 32 hex bytes", v.Name, v.PublicKey)
		}
		if v.PrivateKey != "" {
			private, err := hex.DecodeString(v.PrivateKey)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			key, err := ecdh.X25519().NewPrivateKey(private)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if got := key.PublicKey().Bytes(); !bytes.Equal(got, public) {
				t.Fatalf("%s: the private key's public half is %x, the file says %x", v.Name, got, public)
			}
			derived++
		}
		got := store.ArchiveKeyFingerprint(public)
		if got != v.Fingerprint {
			t.Fatalf("%s: fingerprint %s, want %s", v.Name, got, v.Fingerprint)
		}
		if !store.ValidArchiveKeyFingerprint(got) {
			t.Fatalf("%s: %s is not valid", v.Name, got)
		}
	}
	if derived == 0 {
		t.Fatal("no vector gives a private key: a client's derivation goes untested")
	}
	for _, bad := range file.Invalid {
		if store.ValidArchiveKeyFingerprint(bad) {
			t.Fatalf("%q is valid", bad)
		}
	}
}
