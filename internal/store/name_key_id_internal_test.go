package store

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"testing"

	"whatserver2/internal/crypto/seal"
)

// TestContactNameKeyIDVectors reads which content key each sealed name
// needs from testdata/contact-name-key-ids.json, as nameKeyID does for
// the per-name ids the server sends (DS50). The readers that open names
// with their own code read the same file: wappie-cloud's web tests from
// the core checkout its CI pins, and packages/client's at reader 0.6.1.
// So the server's ids and every reader's cannot drift.
func TestContactNameKeyIDVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/contact-name-key-ids.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name   string  `json:"name"`
			Sealed string  `json:"sealed"`
			KeyID  *uint32 `json:"key_id"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var named, unnamed int
	const row = 42
	for _, v := range file.Vectors {
		sealed, err := base64.StdEncoding.DecodeString(v.Sealed)
		if err != nil || len(sealed) == 0 {
			t.Fatalf("%s: sealed is not base64: %v", v.Name, err)
		}
		id, _, err := seal.ContentKeyID(sealed)
		if v.KeyID == nil {
			unnamed++
			if err == nil && id != 0 && id <= math.MaxInt32 {
				t.Errorf("%s: the envelope names content key %d, the file says none", v.Name, id)
			}
			if got := nameKeyID(sealed, row); got != row {
				t.Errorf("%s: nameKeyID = %d, want the row's %d", v.Name, got, row)
			}
			continue
		}
		named++
		if err != nil || id != *v.KeyID {
			t.Errorf("%s: the envelope names content key %d (%v), the file says %d", v.Name, id, err, *v.KeyID)
		}
		if got := nameKeyID(sealed, row); got != *v.KeyID {
			t.Errorf("%s: nameKeyID = %d, want %d", v.Name, got, *v.KeyID)
		}
	}
	if named < 3 || unnamed < 5 {
		t.Fatalf("%d named and %d unnamed vectors: the file lost some", named, unnamed)
	}
	if got := nameKeyID(nil, row); got != 0 {
		t.Errorf("no name: nameKeyID = %d, want 0", got)
	}
}
