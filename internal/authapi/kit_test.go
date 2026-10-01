package authapi_test

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/thehappieco/kit/vectors"

	"whatserver2/internal/authapi"
	"whatserver2/internal/config"
)

// The public PRF salt is computed once per RP by the server and stored beside
// every passkey wrap: a different one evaluates a different PRF, and every
// existing passkey stops unlocking. The kit captured it from this package
// before the derivation moved; the provider must still hand out exactly that.
func TestPasskeySaltIsTheKitVector(t *testing.T) {
	raw, err := fs.ReadFile(vectors.FS, "wappie/golden/passkey-salt-go.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			ID string `json:"id"`
			In struct {
				RPID string `json:"rp_id"`
			} `json:"in"`
			Out struct {
				Salt string `json:"salt_b64"`
			} `json:"out"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Cases) == 0 {
		t.Fatalf("passkey-salt-go.json: %v", err)
	}
	for _, c := range f.Cases {
		provider, err := authapi.NewPasskeyProvider(config.Passkeys{RPID: c.In.RPID, Origins: []string{"https://" + c.In.RPID}})
		if err != nil || provider == nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		if got := base64.StdEncoding.EncodeToString(authapi.PasskeySalt(provider)); got != c.Out.Salt {
			t.Errorf("%s: salt %s, want %s", c.ID, got, c.Out.Salt)
		}
	}
}
