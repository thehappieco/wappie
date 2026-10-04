package mcpauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/thehappieco/kit/reqhmac"
	"github.com/thehappieco/kit/vectors"
)

// TestKitSignatureVectors runs the shared kit's request-HMAC vectors, which
// it captured from this file before the scheme moved, through the names this
// package still calls: Signature, sign, readSignedHeaders, signedBy and the
// replay cache. The kit proves its scheme; this proves the wrappers bind
// wappie-mcp-hmac/v1, its headers, its skew and its replay lifetime.
func TestKitSignatureVectors(t *testing.T) {
	raw, err := fs.ReadFile(vectors.FS, "wappie/golden/reqhmac-go.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Format      string `json:"format"`
		GeneratedBy struct {
			Toolchain string `json:"toolchain"`
		} `json:"generated_by"`
		Cases []struct {
			ID    string          `json:"id"`
			Op    string          `json:"op"`
			Langs []string        `json:"langs"`
			In    json.RawMessage `json:"in"`
			Out   json.RawMessage `json:"out"`
			Error string          `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Format != "thehappieco-kit-vectors/1" || len(f.Cases) == 0 {
		t.Fatalf("reqhmac-go.json: %v", err)
	}
	type in struct {
		Secret    string              `json:"secret"`
		Secrets   []string            `json:"secrets"`
		Direction string              `json:"direction"`
		Sender    string              `json:"sender"`
		Method    string              `json:"method"`
		Target    string              `json:"target"`
		Timestamp string              `json:"timestamp"`
		Nonce     string              `json:"nonce"`
		Signature string              `json:"signature"`
		Body      string              `json:"body_b64"`
		Headers   map[string][]string `json:"headers"`
		Now       int64               `json:"now"`
		Seed      uint64              `json:"seed"`
		Capacity  int                 `json:"capacity"`
		Lifetime  int64               `json:"lifetime_seconds"`
		Steps     []struct {
			Direction string `json:"direction"`
			Sender    string `json:"sender"`
			Nonce     string `json:"nonce"`
			Timestamp int64  `json:"timestamp"`
			Now       int64  `json:"now"`
		} `json:"steps"`
	}
	type out struct {
		Signature string            `json:"signature"`
		Timestamp string            `json:"timestamp"`
		Unix      int64             `json:"unix"`
		Nonce     string            `json:"nonce"`
		OK        bool              `json:"ok"`
		Len       int               `json:"len"`
		Results   []*string         `json:"results"`
		Headers   map[string]string `json:"headers"`
	}
	// The routes and tests set the headers by these names; the scheme reads
	// them by the profile's.
	if mcpHMAC.Headers != (reqhmac.Headers{Sender: HeaderReader, Timestamp: HeaderTimestamp, Nonce: HeaderNonce, Signature: HeaderSignature}) {
		t.Fatalf("the header constants are not the scheme's: %+v", mcpHMAC.Headers)
	}
	replays := runtime.Version() == f.GeneratedBy.Toolchain
	for _, c := range f.Cases {
		if len(c.Langs) > 0 && !slices.Contains(c.Langs, "go") {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var i in
			var o out
			if err := json.Unmarshal(c.In, &i); err != nil {
				t.Fatal(err)
			}
			if c.Error == "" {
				if err := json.Unmarshal(c.Out, &o); err != nil {
					t.Fatal(err)
				}
			}
			body, err := base64.StdEncoding.DecodeString(i.Body)
			if err != nil {
				t.Fatal(err)
			}
			switch c.Op {
			case "reqhmac.signature":
				if got := Signature(i.Secret, i.Direction, i.Sender, i.Method, i.Target, i.Timestamp, i.Nonce, body); got != o.Signature {
					t.Errorf("signature %s, want %s", got, o.Signature)
				}
			case "reqhmac.read":
				got, err := readSignedHeaders(http.Header(i.Headers), time.Unix(i.Now, 0))
				if c.Error != "" {
					if err == nil || err.Error() != c.Error {
						t.Errorf("error %v, want %s", err, c.Error)
					}
					return
				}
				if err != nil || got != (signedHeaders{timestamp: o.Timestamp, unix: o.Unix, nonce: o.Nonce, signature: o.Signature}) {
					t.Errorf("read %+v, %v", got, err)
				}
			case "reqhmac.signed_by":
				got := signedHeaders{timestamp: i.Timestamp, nonce: i.Nonce, signature: i.Signature}
				if ok := signedBy(i.Secrets, got, i.Direction, i.Sender, i.Method, i.Target, body); ok != o.OK {
					t.Errorf("signed by: %v, want %v", ok, o.OK)
				}
			case "reqhmac.replay":
				if time.Duration(i.Lifetime)*time.Second != 61*time.Second {
					t.Fatalf("the vector's lifetime is %ds; this server's cache keeps nonces 61s", i.Lifetime)
				}
				cache := newReplayCache(i.Capacity)
				for n, s := range i.Steps {
					err := cache.admit(s.Direction, s.Sender, s.Nonce, s.Timestamp, time.Unix(s.Now, 0))
					want := ""
					if o.Results[n] != nil {
						want = *o.Results[n]
					}
					if got := errorText(err); got != want {
						t.Errorf("step %d: %q, want %q", n, got, want)
					}
				}
				if cache.Len() != o.Len {
					t.Errorf("cache holds %d, want %d", cache.Len(), o.Len)
				}
			case "reqhmac.sign":
				if !replays {
					t.Skip("the nonce replays only on the toolchain that recorded it")
				}
				if i.Direction != DirectionToReader {
					t.Fatalf("sign signs %s only", DirectionToReader)
				}
				cryptotest.SetGlobalRandom(t, i.Seed)
				req := httptest.NewRequest(i.Method, i.Target, bytes.NewReader(body))
				if err := sign(req, i.Secret, i.Sender, body, time.Unix(i.Now, 0)); err != nil {
					t.Fatal(err)
				}
				for name, value := range o.Headers {
					if got := req.Header.Values(name); len(got) != 1 || got[0] != value {
						t.Errorf("%s: %q, want %q", name, got, value)
					}
				}
			default:
				t.Errorf("op %q is not handled", c.Op)
			}
		})
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
