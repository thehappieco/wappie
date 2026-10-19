package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"
	kitvectors "github.com/thehappieco/kit/vectors"

	"whatserver2/internal/config"
	"whatserver2/internal/membership/membershiptest"
)

// The contract's vectors, as the kit go.mod requires embeds them
// (vectors.FS, platform/contract-v1/, byte for byte the platform's), run
// through Wappie's own client rather than the kit's API alone: the kit
// proves its scheme reproduces them; these prove Wappie's client signs
// with it, checks answers with the secrets its loader gave it, and decodes
// documents as the follower and the sign-in will.

func readVectors(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/"+name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type signedCase struct {
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	Direction string `json:"direction"`
	App       string `json:"app"`
	Method    string `json:"method"`
	Target    string `json:"target"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Body      string `json:"body"`
	Canonical string `json:"canonical"`
	Signature string `json:"signature"`
}

type signatureVectors struct {
	Format   string       `json:"format"`
	Kind     string       `json:"kind"`
	Label    string       `json:"label"`
	Requests []signedCase `json:"requests"`
	Answers  []signedCase `json:"answers"`
	Checks   []struct {
		Name      string            `json:"name"`
		Headers   map[string]string `json:"headers"`
		Secrets   []string          `json:"secrets"`
		App       string            `json:"app"`
		Method    string            `json:"method"`
		Target    string            `json:"target"`
		SentNonce string            `json:"sent_nonce"`
		Body      string            `json:"body"`
		Now       int64             `json:"now"`
		Result    string            `json:"result"`
	} `json:"answer_checks"`
	Secrets []struct {
		Name    string `json:"name"`
		Current string `json:"current"`
		Next    string `json:"next"`
		Valid   bool   `json:"valid"`
	} `json:"secrets"`
}

// roundTrip is an http.RoundTripper in a function.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// signedAnswer is what the platform sends for r: body, signed with secret
// over r's own method, target and nonce (contract.SignAnswer).
func signedAnswer(r *http.Request, secret string, status int, body []byte, now time.Time) *http.Response {
	h := http.Header{}
	kc.SignAnswer(h, secret, r.Header.Get(kc.HeaderApp), r.Method, r.URL.RequestURI(), r.Header.Get(kc.HeaderNonce), body, now)
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), Request: r}
}

func clientOn(rt roundTrip, now func() time.Time) *Client {
	return NewClient(&http.Client{Transport: rt}, Base, now)
}

func vectorErrorCode(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, kc.ErrAnswerNonce):
		return "answer_nonce"
	case errors.Is(err, kc.ErrStale):
		return "hmac_stale"
	case errors.Is(err, kc.ErrMissing):
		return "hmac_missing"
	case errors.Is(err, kc.ErrBad):
		return "hmac_bad"
	}
	return err.Error()
}

// TestContractSignatureVectors is TB1: every request and answer of
// signatures.json, its ten answer checks (the must-fail ones included)
// and its secret pairs, through Wappie's client and loader.
func TestContractSignatureVectors(t *testing.T) {
	var v signatureVectors
	readVectors(t, "signatures.json", &v)
	if v.Kind != "signatures" || v.Label != kc.Label || len(v.Requests) < 4 || len(v.Answers) < 3 || len(v.Checks) < 10 || len(v.Secrets) < 7 {
		t.Fatalf("not the signature vectors: %q %q, %d/%d/%d/%d", v.Kind, v.Label, len(v.Requests), len(v.Answers), len(v.Checks), len(v.Secrets))
	}
	scheme := kc.Scheme()
	for _, c := range append(append([]signedCase{}, v.Requests...), v.Answers...) {
		if got := scheme.Canonical(c.Direction, c.App, c.Method, c.Target, c.Timestamp, c.Nonce, []byte(c.Body)); got != c.Canonical {
			t.Errorf("%s: canonical %q", c.Name, got)
		}
		if got := scheme.Signature(c.Secret, c.Direction, c.App, c.Method, c.Target, c.Timestamp, c.Nonce, []byte(c.Body)); got != c.Signature {
			t.Errorf("%s: signature %s", c.Name, got)
		}
	}

	t.Run("requests, as Wappie's client sends them", func(t *testing.T) {
		for _, c := range v.Requests {
			if c.App != App {
				continue // another app's request: its scheme is checked above
			}
			unix, err := strconv.ParseInt(c.Timestamp, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Unix(unix, 0)
			var seen bool
			client := clientOn(func(r *http.Request) (*http.Response, error) {
				seen = true
				body, _ := io.ReadAll(r.Body)
				nonce := r.Header.Get(kc.HeaderNonce)
				switch {
				case r.URL.RequestURI() != c.Target || !bytes.Equal(body, []byte(c.Body)):
					t.Errorf("%s: sent %s %s", c.Name, r.Method, r.URL.RequestURI())
				case r.Header.Get(kc.HeaderApp) != c.App || r.Header.Get(kc.HeaderTimestamp) != c.Timestamp || len(nonce) != 22:
					t.Errorf("%s: headers %v", c.Name, r.Header)
				case r.Header.Get(kc.HeaderSignature) != scheme.Signature(c.Secret, kc.ToPlatform, c.App, c.Method, c.Target, c.Timestamp, nonce, body):
					t.Errorf("%s: the signature is not the scheme's", c.Name)
				}
				return signedAnswer(r, c.Secret, http.StatusOK, []byte(`{}`), at), nil
			}, func() time.Time { return at })
			if err := client.Use(c.Secret, ""); err != nil {
				t.Fatal(err)
			}
			err = client.call(func(k *kc.Client) error {
				_, _, err := k.Do(context.Background(), c.Method, c.Target, []byte(c.Body))
				return err
			})
			if err != nil || !seen {
				t.Errorf("%s: %v", c.Name, err)
			}
		}
	})

	t.Run("answers, as Wappie's client takes them", func(t *testing.T) {
		for _, c := range v.Answers {
			if c.App != App {
				continue
			}
			unix, _ := strconv.ParseInt(c.Timestamp, 10, 64)
			at := time.Unix(unix, 0)
			client := clientOn(func(r *http.Request) (*http.Response, error) {
				return signedAnswer(r, c.Secret, http.StatusOK, []byte(c.Body), at), nil
			}, func() time.Time { return at })
			if err := client.Use(c.Secret, ""); err != nil {
				t.Fatal(err)
			}
			err := client.call(func(k *kc.Client) error {
				_, got, err := k.Do(context.Background(), c.Method, c.Target, nil)
				if err == nil && string(got) != c.Body {
					t.Errorf("%s: body %q", c.Name, got)
				}
				return err
			})
			if err != nil {
				t.Errorf("%s: %v", c.Name, err)
			}
		}
	})

	t.Run("answer checks, with the secrets Wappie's client accepts", func(t *testing.T) {
		results := map[string]bool{}
		for _, c := range v.Checks {
			client := clientOn(nil, nil)
			current, other := c.Secrets[0], ""
			if len(c.Secrets) > 1 {
				other = c.Secrets[1]
			}
			h := http.Header{}
			for k, val := range c.Headers {
				h.Set(k, val)
			}
			accept := c.Secrets
			if err := client.Use(current, other); err != nil {
				// A key that is not a secret (the 32 bytes decoded) never
				// reaches the client: the loader refuses it, and under it no
				// answer verifies (the kit's VerifyAnswer says hmac_bad).
				if !errors.Is(err, kc.ErrSecret) || c.Result != "hmac_bad" {
					t.Errorf("%s: the client refused the secrets (%v), the vector says %s", c.Name, err, c.Result)
				}
			} else {
				accept = client.kit.Load().Accept
			}
			got := vectorErrorCode(kc.VerifyAnswer(h, accept, c.App, c.Method, c.Target, c.SentNonce, []byte(c.Body), time.Unix(c.Now, 0)))
			if got != c.Result {
				t.Errorf("%s: %s, want %s", c.Name, got, c.Result)
			}
			results[got] = true
		}
		for _, want := range []string{"ok", "answer_nonce", "hmac_bad", "hmac_stale", "hmac_missing"} {
			if !results[want] {
				t.Errorf("no answer check ends in %s", want)
			}
		}
	})

	t.Run("must-fail answers to a real request are ignored", func(t *testing.T) {
		secret, another := membershiptest.Secret(t), membershiptest.Secret(t)
		body := []byte(`{"subscribed":false}`)
		for name, spoil := range map[string]func(r *http.Request, now time.Time) *http.Response{
			"unsigned": func(r *http.Request, _ time.Time) *http.Response {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}
			},
			"a swapped nonce": func(r *http.Request, now time.Time) *http.Response {
				r.Header.Set(kc.HeaderNonce, "AAECAwQFBgcICQoLDA0ODw")
				return signedAnswer(r, secret, 200, body, now)
			},
			"the request's direction": func(r *http.Request, now time.Time) *http.Response {
				res := signedAnswer(r, secret, 200, body, now)
				res.Header.Set(kc.HeaderSignature, kc.Scheme().Signature(secret, kc.ToPlatform, App, r.Method, r.URL.RequestURI(),
					res.Header.Get(kc.HeaderTimestamp), r.Header.Get(kc.HeaderNonce), body))
				return res
			},
			"another app": func(r *http.Request, now time.Time) *http.Response {
				r.Header.Set(kc.HeaderApp, "mailie")
				return signedAnswer(r, secret, 200, body, now)
			},
			"another body": func(r *http.Request, now time.Time) *http.Response {
				res := signedAnswer(r, secret, 200, body, now)
				res.Body = io.NopCloser(strings.NewReader(`{"subscribed":true}`))
				return res
			},
			"the key decoded": func(r *http.Request, now time.Time) *http.Response {
				res := signedAnswer(r, secret, 200, body, now)
				raw, _ := decodeSecret(secret)
				res.Header.Set(kc.HeaderSignature, kc.Scheme().Signature(string(raw), kc.ToApp, App, r.Method, r.URL.RequestURI(),
					res.Header.Get(kc.HeaderTimestamp), r.Header.Get(kc.HeaderNonce), body))
				return res
			},
			"another secret": func(r *http.Request, now time.Time) *http.Response {
				return signedAnswer(r, another, 200, body, now)
			},
			"stale": func(r *http.Request, now time.Time) *http.Response {
				return signedAnswer(r, secret, 200, body, now.Add(-61*time.Second))
			},
			// Signed, but not README 6.1's answer to a DELETE: the sweep
			// would remove its row while the platform still follows the sub.
			"a signed subscribed true": func(r *http.Request, now time.Time) *http.Response {
				return signedAnswer(r, secret, 200, []byte(`{"subscribed":true}`), now)
			},
			"a signed empty object": func(r *http.Request, now time.Time) *http.Response {
				return signedAnswer(r, secret, 200, []byte(`{}`), now)
			},
			"a signed null": func(r *http.Request, now time.Time) *http.Response {
				return signedAnswer(r, secret, 200, []byte(`{"subscribed":null}`), now)
			},
			"a signed body that is not JSON": func(r *http.Request, now time.Time) *http.Response {
				return signedAnswer(r, secret, 200, []byte(`subscribed: false`), now)
			},
		} {
			now := time.Now()
			client := clientOn(func(r *http.Request) (*http.Response, error) { return spoil(r, now), nil }, func() time.Time { return now })
			if err := client.Use(secret, ""); err != nil {
				t.Fatal(err)
			}
			if err := client.Unsubscribe(context.Background(), "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"); Classify(err) != Unverified {
				t.Errorf("%s: %v (%s)", name, err, Classify(err))
			}
		}
		// The two answers a DELETE may have: README 6.1's, and a refusal.
		for _, tc := range []struct {
			body string
			want Outcome
		}{{`{"subscribed":false}`, Answered}, {`{"code":"unavailable","message":"no"}`, Refused}} {
			now := time.Now()
			client := clientOn(func(r *http.Request) (*http.Response, error) {
				return signedAnswer(r, secret, 200, []byte(tc.body), now), nil
			}, func() time.Time { return now })
			if err := client.Use(secret, ""); err != nil {
				t.Fatal(err)
			}
			if err := client.Unsubscribe(context.Background(), "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"); Classify(err) != tc.want {
				t.Errorf("%s: %v (%s)", tc.body, err, Classify(err))
			}
		}
	})

	t.Run("secret pairs, through the loader", func(t *testing.T) {
		ctx := context.Background()
		key := membershiptest.NewKMS(t)
		for _, c := range v.Secrets {
			for _, sealed := range []bool{true, false} {
				dir := t.TempDir()
				cfg := config.Contract{
					Socket:     "/run/platform/contract.sock",
					SecretFile: filepath.Join(dir, SecretFileName), SecretOtherFile: filepath.Join(dir, SecretOtherFileName),
				}
				if sealed {
					cfg.KMSKeyARN, cfg.KMSRegion = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", "eu-west-1"
				}
				writeSecret(ctx, t, key, sealed, cfg.SecretFile, c.Current)
				if c.Next != "" {
					writeSecret(ctx, t, key, sealed, cfg.SecretOtherFile, c.Next)
				}
				client := clientOn(nil, nil)
				s := &Secrets{Config: cfg, Client: client, OpenWrapper: key.Open}
				err := s.Load(ctx)
				if (err == nil) != c.Valid || client.Loaded() != c.Valid {
					t.Errorf("%s (sealed %v): loaded %v, err %v", c.Name, sealed, client.Loaded(), err)
				}
				if !c.Valid && s.Last().Error != "check" {
					t.Errorf("%s (sealed %v): step %s", c.Name, sealed, s.Last().Error)
				}
				if err != nil && (c.Current != "" && strings.Contains(err.Error(), c.Current) || c.Next != "" && strings.Contains(err.Error(), c.Next)) {
					t.Errorf("%s: the error echoes a secret", c.Name)
				}
			}
		}
	})
}

// writeSecret writes a secret's file: an envelope under key, or, for
// development, the text and a newline.
func writeSecret(ctx context.Context, t *testing.T, key *membershiptest.KMS, sealed bool, path, secret string) []byte {
	t.Helper()
	data := []byte(secret + "\n")
	if sealed {
		data = seal(ctx, t, key, secret)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	return data
}

type wireVectors struct {
	Format    string    `json:"format"`
	Kind      string    `json:"kind"`
	Documents []wireRow `json:"documents"`
	Snapshots []wireRow `json:"snapshots"`
	Events    []wireRow `json:"events"`
}

type wireRow struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
	Valid bool            `json:"valid"`
}

// TestContractWireVectors is TB2's documents part: every document of
// wire.json and wire-item-ids.json, signed as the platform signs it, on a
// feed page (the follower's decode and validation) and as a PUT's answer
// (the sign-in's): a valid one is an answer, any other one is ignored. The
// snapshots' and events' round trips land with Wappie's own encoders.
func TestContractWireVectors(t *testing.T) {
	secret := membershiptest.Secret(t)
	for _, file := range []string{"wire.json", "wire-item-ids.json"} {
		var w wireVectors
		readVectors(t, file, &w)
		if w.Format != "thehappie-contract/vectors" || w.Kind != "wire" {
			t.Fatalf("%s: %q %q", file, w.Format, w.Kind)
		}
		if file == "wire.json" && len(w.Documents) < 13 {
			t.Fatalf("wire.json: %d documents", len(w.Documents))
		}
		for _, c := range w.Documents {
			var head struct {
				Generation any `json:"generation"`
				Sub        any `json:"sub"`
			}
			if err := json.Unmarshal(c.Value, &head); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			generation, _ := head.Generation.(string)
			if !kc.ValidUUID(generation) {
				generation = "0199b1e0-0000-7000-8000-0000000000ff"
			}
			sub, _ := head.Sub.(string)
			if sub == "" {
				sub = "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
			}
			page := []byte(`{"generation":"` + generation + `","generation_confirmed":true,"head":1,` +
				`"published_through":"2026-10-14T12:00:00Z","items":[{"seq":1,"doc":` + string(c.Value) + `}],"next_after":1,"more":false}`)
			client := clientOn(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodPut {
					return signedAnswer(r, secret, http.StatusOK, c.Value, time.Now()), nil
				}
				return signedAnswer(r, secret, http.StatusOK, page, time.Now()), nil
			}, nil)
			if err := client.Use(secret, ""); err != nil {
				t.Fatal(err)
			}
			f, err := client.Feed(context.Background(), 0, 0)
			if (Classify(err) == Answered) != c.Valid || (err != nil && Classify(err) != Unverified) {
				t.Errorf("%s: %s: through the feed %v, valid should be %v", file, c.Name, err, c.Valid)
			}
			if err == nil && (len(f.Items) != 1 || f.Items[0].Doc.Sub != sub) {
				t.Errorf("%s: %s: the page's document %+v", file, c.Name, f.Items)
			}
			d, err := client.Subscribe(context.Background(), sub)
			if (Classify(err) == Answered) != c.Valid || (err != nil && Classify(err) != Unverified) {
				t.Errorf("%s: %s: as a PUT's answer %v, valid should be %v", file, c.Name, err, c.Valid)
			}
			if err == nil && (d.Sub != sub || d.App != App) {
				t.Errorf("%s: %s: the document %+v", file, c.Name, d)
			}
		}
		if file == "wire-item-ids.json" && (len(w.Documents) != 0 || len(w.Snapshots) == 0) {
			t.Errorf("%s: %d documents, %d snapshots: it holds snapshots only", file, len(w.Documents), len(w.Snapshots))
		}
	}
}

// TestClientRetriesOnceWithAFreshNonce: a signed replay or unavailable is
// asked again, once, signed afresh; any other refusal is not.
func TestClientRetriesOnceWithAFreshNonce(t *testing.T) {
	secret := membershiptest.Secret(t)
	for _, tc := range []struct {
		code  string
		calls int
	}{{kc.CodeReplay, 2}, {kc.CodeUnavailable, 2}, {kc.CodeNotFound, 1}, {kc.CodeRateLimited, 1}} {
		var nonces []string
		client := clientOn(func(r *http.Request) (*http.Response, error) {
			nonces = append(nonces, r.Header.Get(kc.HeaderNonce))
			body, _ := json.Marshal(kc.Error{Code: tc.code, Message: "no"})
			return signedAnswer(r, secret, http.StatusServiceUnavailable, body, time.Now()), nil
		}, nil)
		if err := client.Use(secret, ""); err != nil {
			t.Fatal(err)
		}
		_, err := client.Account(context.Background(), "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20")
		if Classify(err) != Refused || RefusalCode(err) != tc.code || len(nonces) != tc.calls {
			t.Errorf("%s: %v, %d calls", tc.code, err, len(nonces))
		}
		if len(nonces) == 2 && nonces[0] == nonces[1] {
			t.Errorf("%s: the retry reused the nonce", tc.code)
		}
	}
	// No secret, no call.
	client := clientOn(func(*http.Request) (*http.Response, error) {
		t.Fatal("a call without a secret")
		return nil, nil
	}, nil)
	if _, err := client.Feed(context.Background(), 0, 0); !errors.Is(err, ErrNoSecret) || Classify(err) != Unavailable {
		t.Fatalf("%v", err)
	}
	if client.Loaded() || client.Rotating() {
		t.Fatal("loaded without a secret")
	}
	if err := client.Use(secret, secret); !errors.Is(err, kc.ErrSecret) || client.Loaded() {
		t.Fatalf("an equal pair: %v", err)
	}
	for _, o := range []Outcome{Answered, Refused, Unverified, Unavailable, 0} {
		if o.String() == "" {
			t.Errorf("%d has no name", o)
		}
	}
}
