package membership

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/membership/membershiptest"
)

// The token part's vectors (kit v0.9.0, vectors.FS's platform/contract-v1/
// tokens.json, reading-keys.json and wire-tokens.json), run against the kit's
// functions as Wappie takes them, and through Wappie's own client where one
// of them is an answer it receives or a body it sends. What the store and
// the auth paths make of them is their own tests'.

type tokenVectors struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Tokens []struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		Selector  string `json:"selector"`
		SecretHex string `json:"secret_hex"`
		Hash      string `json:"hash"`
	} `json:"tokens"`
	Refused []struct {
		Name  string `json:"name"`
		Token string `json:"token"`
		Step  int    `json:"step"`
	} `json:"refused"`
	Authorization []struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
		Valid  bool     `json:"valid"`
	} `json:"authorization"`
}

// TestTokenVectors: every token of tokens.json parses to its selector and
// hash, verifies against a record of both and against nothing else, and
// prints as its selector alone; every refused text is refused at its step,
// with no byte of it in the error, against a record or none; and the
// Authorization values give a token exactly where the vectors say.
func TestTokenVectors(t *testing.T) {
	var v tokenVectors
	readVectors(t, "tokens.json", &v)
	if v.Kind != "tokens" || v.Label != kc.TokenHashLabel || len(v.Tokens) < 5 || len(v.Refused) < 28 || len(v.Authorization) < 16 {
		t.Fatalf("not the token vectors: %q %q, %d/%d/%d", v.Kind, v.Label, len(v.Tokens), len(v.Refused), len(v.Authorization))
	}
	records := map[string]*kc.TokenRecord{}
	for _, c := range v.Tokens {
		records[c.Selector] = &kc.TokenRecord{Selector: c.Selector, Hash: c.Hash}
	}
	shared := 0
	for _, c := range v.Tokens {
		p, err := kc.ParseToken(c.Token)
		if err != nil || p.Selector != c.Selector || p.Hash() != c.Hash {
			t.Errorf("%s: %+v, %v", c.Name, p, err)
			continue
		}
		raw, err := hex.DecodeString(c.SecretHex)
		if err != nil || len(raw) != kc.TokenSecretBytes {
			t.Fatalf("%s: secret_hex %v", c.Name, err)
		}
		if got := kc.TokenHash([kc.TokenSecretBytes]byte(raw)); got != c.Hash {
			t.Errorf("%s: TokenHash %s", c.Name, got)
		}
		if err := kc.VerifyToken(records[c.Selector], c.Token); err != nil {
			t.Errorf("%s: against its own record: %v", c.Name, err)
		}
		if err := kc.VerifyToken(nil, c.Token); !errors.Is(err, kc.ErrToken) {
			t.Errorf("%s: against no record: %v", c.Name, err)
		}
		// Another token's record never takes it, the one of its secret
		// included: the selector is compared beside the hash.
		for sel, rec := range records {
			if sel == c.Selector {
				continue
			}
			if rec.Hash == c.Hash {
				shared++
			}
			if err := kc.VerifyToken(rec, c.Token); !errors.Is(err, kc.ErrToken) {
				t.Errorf("%s: against the record of %s: %v", c.Name, sel, err)
			}
		}
		// What a log line or an error may print of it is its selector:
		// never its secret, in any verb, field or handler.
		var logs bytes.Buffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("token", "token", p)
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("token", "token", p)
		printed := fmt.Sprintf("%v %+v %#v %s %q", p, p, p, p, p) +
			fmt.Sprintf("%v %+v", struct{ T kc.ParsedToken }{p}, struct{ t kc.ParsedToken }{p}) + logs.String()
		if strings.Contains(printed, c.Token[21:]) || strings.Contains(printed, c.Token) || !strings.Contains(logs.String(), "token="+c.Selector) {
			t.Errorf("%s: printed %q", c.Name, printed)
		}
	}
	if shared == 0 {
		t.Error("no two tokens share a secret, so no case shows the selector keeps them apart")
	}

	for _, c := range v.Refused {
		for name, check := range map[string]func() error{
			"ParseToken":                   func() error { _, err := kc.ParseToken(c.Token); return err },
			"VerifyToken with no record":   func() error { return kc.VerifyToken(nil, c.Token) },
			"VerifyToken against a record": func() error { return kc.VerifyToken(records[v.Tokens[0].Selector], c.Token) },
		} {
			err := check()
			var step *kc.TokenError
			if !errors.As(err, &step) || step.Step != c.Step || !errors.Is(err, kc.ErrToken) {
				t.Errorf("%s: %s: %v, want step %d", c.Name, name, err, c.Step)
				continue
			}
			if c.Token != "" && strings.Contains(err.Error(), c.Token) || len(c.Token) > 21 && strings.Contains(err.Error(), c.Token[21:]) {
				t.Errorf("%s: %s: the error echoes the text", c.Name, name)
			}
		}
	}

	valid := 0
	for _, c := range v.Authorization {
		got, err := kc.BearerToken(c.Values)
		if (err == nil) != c.Valid {
			t.Errorf("%s: %v, valid should be %v", c.Name, err, c.Valid)
			continue
		}
		if err != nil {
			if !errors.Is(err, kc.ErrToken) {
				t.Errorf("%s: %v is not ErrToken", c.Name, err)
			}
			continue
		}
		valid++
		if kc.VerifyToken(records[v.Tokens[0].Selector], got) != nil {
			t.Errorf("%s: the header gave another token", c.Name)
		}
	}
	if valid == 0 {
		t.Error("no Authorization value gives a token")
	}
}

type readingKeyVectors struct {
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	CheckLabel string `json:"check_label"`
	Keys       []struct {
		Name        string `json:"name"`
		Key         string `json:"key"`
		Fingerprint string `json:"fingerprint"`
		Result      string `json:"result"`
	} `json:"reading_keys"`
}

// readingKeyResult names what CheckReadingKey returned, as the vectors do.
func readingKeyResult(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, kc.ErrReadingKeyEncoding):
		return "encoding"
	case errors.Is(err, kc.ErrReadingKeyNotCanonical):
		return "not_canonical"
	case errors.Is(err, kc.ErrReadingKeyLowOrder):
		return "low_order"
	case errors.Is(err, kc.ErrReadingKeyFingerprint):
		return "fingerprint"
	}
	return err.Error()
}

// Made-up ids of the records the tests below answer with.
const (
	vecGeneration = "0199b1e0-0000-7000-8000-000000000001"
	vecToken      = "0199f2a1-0000-7000-8000-000000000011"
	vecTeam       = "01a034b7-d09c-7121-b7f8-41f210a9244a"
	vecSub        = "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
	vecNumber     = "0199e000-0000-7000-8000-000000000004"
	vecSelector   = "9f3c0a7be41d2c58"
)

// vecTokenRecord is a live record of Wappie's that validates, with no item
// and no reading key.
func vecTokenRecord() kc.TokenRecord {
	created := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	return kc.TokenRecord{
		V: kc.TokenRecordV, Type: kc.TokenRecordType, App: App, Generation: vecGeneration, ID: vecToken, Version: 1,
		Selector: vecSelector, Hash: strings.Repeat("ab", 32), WorkspaceID: vecTeam, Name: "Integration",
		CreatedBy: vecSub, CreatedAt: kc.T(created), ExpiresAt: kc.T(created.Add(24 * time.Hour)), Items: []kc.TokenItem{},
	}
}

// answering is a client whose every request is answered with body, signed
// with secret as the platform signs it; sent keeps each request's body.
func answering(t *testing.T, secret string, body []byte, sent *[][]byte) *Client {
	t.Helper()
	client := clientOn(func(r *http.Request) (*http.Response, error) {
		if sent != nil {
			b, _ := io.ReadAll(r.Body)
			*sent = append(*sent, b)
		}
		return signedAnswer(r, secret, http.StatusOK, body, time.Now()), nil
	}, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	return client
}

// TestReadingKeyVectors: every pair of reading-keys.json gets its result
// from CheckReadingKey, and every key that decodes its fingerprint. A
// record's reading key reaches Wappie through the signed GET whenever its
// shape holds, a fingerprint of another key's included: the kit's Token runs
// the record's Validate, never ReadingKey.Check, so the store checks the
// pair itself before it pins a key.
func TestReadingKeyVectors(t *testing.T) {
	var v readingKeyVectors
	readVectors(t, "reading-keys.json", &v)
	if v.Kind != "reading-keys" || v.Label != kc.ReadingKeyLabel || v.CheckLabel != "thehappie-token/v1/low-order-check" || len(v.Keys) < 27 {
		t.Fatalf("not the reading-key vectors: %q %q, %d", v.Kind, v.Label, len(v.Keys))
	}
	if err := vecTokenRecord().Validate(); err != nil {
		t.Fatalf("the base record: %v", err)
	}
	secret := membershiptest.Secret(t)
	results := map[string]int{}
	answeredUnchecked := 0
	for _, c := range v.Keys {
		err := kc.CheckReadingKey(c.Key, c.Fingerprint)
		if got := readingKeyResult(err); got != c.Result {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Result)
		}
		results[c.Result]++
		if err != nil && c.Key != "" && strings.Contains(err.Error(), c.Key) {
			t.Errorf("%s: the error echoes the key", c.Name)
		}
		keyOK := c.Result == "ok" || c.Result == "fingerprint"
		if err := kc.ValidReadingKey(c.Key); (err == nil) != keyOK {
			t.Errorf("%s: ValidReadingKey %v", c.Name, err)
		}
		fp, err := kc.ReadingKeyFingerprint(c.Key)
		switch {
		case c.Result == "encoding":
			if !errors.Is(err, kc.ErrReadingKeyEncoding) {
				t.Errorf("%s: a fingerprint of a key that does not decode: %q, %v", c.Name, fp, err)
			}
		case c.Result != "fingerprint" && (err != nil || fp != c.Fingerprint):
			t.Errorf("%s: fingerprint %q, %v", c.Name, fp, err)
		}

		rec := vecTokenRecord()
		rec.ReadingKey = &kc.ReadingKey{Suite: kc.ReadingKeySuite, Key: c.Key, Fingerprint: c.Fingerprint, RegisteredAt: rec.CreatedAt}
		body, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := answering(t, secret, body, nil).Token(context.Background(), vecToken)
		shape := rec.ReadingKey.Validate() == nil
		if (Classify(err) == Answered) != shape || (err != nil && Classify(err) != Unverified) {
			t.Errorf("%s: by the GET %v (%s), the shape holds: %v", c.Name, err, Classify(err), shape)
		}
		if err != nil {
			continue
		}
		if got.ReadingKey == nil || got.ReadingKey.Key != c.Key || readingKeyResult(got.ReadingKey.Check()) != c.Result {
			t.Errorf("%s: the GET's key %+v", c.Name, got.ReadingKey)
		}
		if c.Result != "ok" {
			answeredUnchecked++
		}
	}
	for _, r := range []string{"ok", "encoding", "not_canonical", "low_order", "fingerprint"} {
		if results[r] == 0 {
			t.Errorf("no reading key ends in %s", r)
		}
	}
	if answeredUnchecked == 0 {
		t.Error("no fingerprint of another key passes the GET: the store's own check would go untested")
	}
}

type tokenWireVectors struct {
	Format  string    `json:"format"`
	Kind    string    `json:"kind"`
	Records []wireRow `json:"records"`
	Feeds   []wireRow `json:"feeds"`
	Applied []wireRow `json:"applied"`
	Usage   []struct {
		Name  string `json:"name"`
		Body  string `json:"body"`
		Valid bool   `json:"valid"`
	} `json:"usage"`
	Actions []struct {
		Name       string          `json:"name"`
		App        string          `json:"app"`
		Generation string          `json:"generation"`
		Value      json.RawMessage `json:"value"`
		Action     string          `json:"action"`
		Code       *string         `json:"code"`
	} `json:"actions"`
}

// strictDecode decodes one object as the kit's vectors decode what an app
// sends: no member its type does not have. A member named in another case is
// the kit's types' own to refuse (WaitingPerms, Suspensions).
func strictDecode(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one value")
	}
	return nil
}

// tokenAction is what an app holding generation does with a record it
// received (wire-tokens.json's actions), from the kit's functions alone in
// the order TokenFeed.Validate gives: another app's record is refused; a
// record of another valid generation is a reset; one that does not decode
// or fails Validate, or whose fingerprint is not its key's, is narrowed;
// then its revocation; else it applies.
func tokenAction(app, generation string, it kc.TokenFeedItem) (string, string) {
	r, err := it.Record()
	switch {
	case kc.ValidApp(r.App) && r.App != app:
		return "refuse", ""
	case kc.ValidUUID(r.Generation) && r.Generation != generation:
		return "reset", ""
	case err != nil || r.Validate() != nil:
		return "narrow", kc.RefusedInvalidRecord
	case r.ReadingKey != nil && r.ReadingKey.Check() != nil:
		return "narrow", kc.RefusedReadingKeyChanged
	case r.RevokedReason != nil:
		return "revoke", *r.RevokedReason
	}
	return "apply", ""
}

// TestTokenWireVectors runs wire-tokens.json: every record on a feed page
// (decoded on its own) and as the signed GET's answer, every page through
// Wappie's client, every acknowledgement and usage body as the platform
// decodes it and as Wappie's client sends it, and every record of the
// actions on a page, where it never fails the page, then decided as the kit
// orders it.
func TestTokenWireVectors(t *testing.T) {
	var w tokenWireVectors
	readVectors(t, "wire-tokens.json", &w)
	if w.Format != "thehappie-contract/vectors" || w.Kind != "wire-tokens" ||
		len(w.Records) < 41 || len(w.Feeds) < 13 || len(w.Applied) < 50 || len(w.Usage) < 18 || len(w.Actions) < 17 {
		t.Fatalf("not the token wire vectors: %q %q, %d/%d/%d/%d/%d", w.Format, w.Kind,
			len(w.Records), len(w.Feeds), len(w.Applied), len(w.Usage), len(w.Actions))
	}
	secret := membershiptest.Secret(t)
	ctx := context.Background()

	t.Run("records, on a feed page and as the GET's answer", func(t *testing.T) {
		answered, anotherApp := 0, 0
		for _, c := range w.Records {
			r, err := kc.TokenFeedItem{Seq: 1, Token: c.Value}.Record()
			if (err == nil && r.Validate() == nil) != c.Valid {
				t.Errorf("%s: decoded on its own %v, %v; valid should be %v", c.Name, err, r.Validate(), c.Valid)
			}
			id, selector := r.ID, r.Selector
			if !kc.ValidUUID(id) {
				id = vecToken
			}
			if !kc.ValidSelector(selector) {
				selector = vecSelector
			}
			want := c.Valid && r.App == App
			if c.Valid && r.App != App {
				anotherApp++
			}
			for name, get := range map[string]func(*Client) (kc.TokenRecord, error){
				"by id":       func(cl *Client) (kc.TokenRecord, error) { return cl.Token(ctx, id) },
				"by selector": func(cl *Client) (kc.TokenRecord, error) { return cl.TokenBySelector(ctx, selector) },
			} {
				got, err := get(answering(t, secret, c.Value, nil))
				if (Classify(err) == Answered) != want || (err != nil && Classify(err) != Unverified) {
					t.Errorf("%s: %s: %v (%s); valid and Wappie's: %v", c.Name, name, err, Classify(err), want)
				}
				if err == nil && (got.ID != id || got.Selector != selector || got.App != App) {
					t.Errorf("%s: %s: the record %s %s %s", c.Name, name, got.ID, got.Selector, got.App)
				}
				if err == nil && name == "by id" {
					answered++
				}
			}
		}
		if answered == 0 || anotherApp == 0 {
			t.Errorf("%d records answered, %d of another app refused: the vectors hold both", answered, anotherApp)
		}
	})

	t.Run("feed pages, through the client", func(t *testing.T) {
		for _, c := range w.Feeds {
			f, err := answering(t, secret, c.Value, nil).Tokens(ctx, 0, 0)
			if (Classify(err) == Answered) != c.Valid || (err != nil && Classify(err) != Unverified) {
				t.Errorf("%s: %v (%s), valid should be %v", c.Name, err, Classify(err), c.Valid)
			}
			if err != nil {
				continue
			}
			var page struct {
				Items []struct {
					Token json.RawMessage `json:"token"`
				} `json:"items"`
			}
			if err := json.Unmarshal(c.Value, &page); err != nil || len(page.Items) != len(f.Items) {
				t.Fatalf("%s: %v, %d items for %d", c.Name, err, len(f.Items), len(page.Items))
			}
			// Each record comes as it was sent, for the store to decode.
			for i, it := range f.Items {
				if !bytes.Equal(it.Token, page.Items[i].Token) {
					t.Errorf("%s: item %d came as %s", c.Name, i, it.Token)
				}
			}
		}
	})

	t.Run("acknowledgements, as the platform decodes them and Wappie's client sends them", func(t *testing.T) {
		for _, c := range w.Applied {
			var a kc.TokenApplied
			valid := strictDecode(c.Value, &a) == nil && a.Validate() == nil
			if valid != c.Valid {
				t.Errorf("%s: valid %v, the vector says %v", c.Name, valid, c.Valid)
			}
			if !valid {
				continue
			}
			var sent [][]byte
			if err := answering(t, secret, []byte(`{"accepted":true}`), &sent).TokensApplied(ctx, a); err != nil || len(sent) != 1 {
				t.Errorf("%s: %v, %d requests", c.Name, err, len(sent))
				continue
			}
			var got kc.TokenApplied
			if err := strictDecode(sent[0], &got); err != nil || got.Validate() != nil || !reflect.DeepEqual(got, a) {
				t.Errorf("%s: sent %s (%v)", c.Name, sent[0], err)
			}
		}
		ack := kc.TokenApplied{Generation: vecGeneration, AppliedAt: kc.T(time.Now())}
		for body, want := range map[string]Outcome{
			`{"accepted":false}`: Unverified,
			`{}`:                 Unverified,
			`{"code":"gone","message":"another one"}`: Refused,
		} {
			if err := answering(t, secret, []byte(body), nil).TokensApplied(ctx, ack); Classify(err) != want {
				t.Errorf("%s: %v (%s)", body, err, Classify(err))
			}
		}
	})

	t.Run("usage bodies, as the platform decodes them and Wappie's client sends them", func(t *testing.T) {
		for _, c := range w.Usage {
			var u kc.TokenUsage
			decoded := strictDecode([]byte(c.Body), &u) == nil && u.Validate() == nil
			if valid := decoded && len(c.Body) <= kc.UsageBodyLimit; valid != c.Valid {
				t.Errorf("%s: valid %v, the vector says %v", c.Name, valid, c.Valid)
			}
			if !decoded {
				continue
			}
			var sent [][]byte
			if err := answering(t, secret, []byte(`{"accepted":true}`), &sent).TokenUsage(ctx, u); err != nil || len(sent) != 1 {
				t.Errorf("%s: %v, %d requests", c.Name, err, len(sent))
				continue
			}
			var got kc.TokenUsage
			if err := strictDecode(sent[0], &got); err != nil || got.Validate() != nil || !reflect.DeepEqual(got, u) ||
				(len(sent[0]) <= kc.UsageBodyLimit) != c.Valid {
				t.Errorf("%s: sent %d bytes (%v)", c.Name, len(sent[0]), err)
			}
		}
	})

	t.Run("actions, each record on a page that stands", func(t *testing.T) {
		seen := map[string]bool{}
		for _, c := range w.Actions {
			page := []byte(`{"generation":"` + c.Generation + `","generation_confirmed":true,"head":1,` +
				`"published_through":"2026-10-13T12:00:00Z","items":[{"seq":1,"token":` + string(c.Value) + `}],"next_after":1,"more":false}`)
			f, err := answering(t, secret, page, nil).Tokens(ctx, 0, 0)
			if err != nil || len(f.Items) != 1 {
				t.Errorf("%s: the page fell with its record: %v", c.Name, err)
				continue
			}
			want := ""
			if c.Code != nil {
				want = *c.Code
			}
			if action, code := tokenAction(c.App, c.Generation, f.Items[0]); action != c.Action || code != want {
				t.Errorf("%s: %s %q, want %s %q", c.Name, action, code, c.Action, want)
			}
			seen[c.Action] = true
			// A revocation sticks whatever the record's shape: revoked_at or
			// revoked_reason by its exact name, and not null.
			var members map[string]json.RawMessage
			if err := json.Unmarshal(c.Value, &members); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			revokes := false
			for _, name := range []string{"revoked_at", "revoked_reason"} {
				if v, ok := members[name]; ok && string(bytes.TrimSpace(v)) != "null" {
					revokes = true
				}
			}
			if r, _ := f.Items[0].Record(); (r.RevokedAt != nil) != revokes {
				t.Errorf("%s: revoked %v, the record says %v", c.Name, r.RevokedAt != nil, revokes)
			}
		}
		for _, a := range []string{"apply", "reset", "revoke", "narrow", "refuse"} {
			if !seen[a] {
				t.Errorf("no record ends in %s", a)
			}
		}
	})
}

// TestTokenCallsReachTheFake: the five token calls go through Wappie's
// client to the kit's fake platform and back, each named by membershiptest
// as contracttest names it, with its argument, so a test may count, hold,
// refuse or cut it; each is asked once more after a signed unavailable,
// never after any other refusal.
func TestTokenCallsReachTheFake(t *testing.T) {
	ctx := context.Background()
	secret := membershiptest.Secret(t)
	fake := membershiptest.StartFake(t, secret)
	client := NewClient(&http.Client{}, fake.URL, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.AddAccount(vecSub); err != nil {
		t.Fatal(err)
	}
	team, err := fake.AddTeam("Equipe", vecSub)
	if err != nil {
		t.Fatal(err)
	}
	// The team is named to Wappie in its owner's document.
	if _, err := client.Subscribe(ctx, vecSub); err != nil {
		t.Fatal(err)
	}
	id, text, err := fake.AddToken(team, vecSub, "Integration", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.GrantToken(id, App, vecNumber, kc.ItemNumber, kc.CanRead, vecSub); err != nil {
		t.Fatal(err)
	}

	page, err := client.Tokens(ctx, 0, 0)
	if err != nil || len(page.Items) != 1 || page.More {
		t.Fatalf("the token feed: %+v, %v", page, err)
	}
	rec, err := page.Items[0].Record()
	if err != nil || rec.Validate() != nil || rec.ID != id || kc.VerifyToken(&rec, text) != nil {
		t.Fatalf("the feed's record: %+v, %v", rec, err)
	}
	var args []string
	for _, call := range []string{contracttest.CallToken, contracttest.CallTokenBySelector} {
		fake.Before(call, func(arg string) { args = append(args, arg) })
	}
	byID, err := client.Token(ctx, id)
	if err != nil || byID.ID != id || byID.Version != rec.Version {
		t.Fatalf("by id: %+v, %v", byID, err)
	}
	bySelector, err := client.TokenBySelector(ctx, rec.Selector)
	if err != nil || bySelector.ID != id {
		t.Fatalf("by selector: %+v, %v", bySelector, err)
	}
	if !reflect.DeepEqual(args, []string{id, rec.Selector}) {
		t.Fatalf("the calls' arguments: %q", args)
	}
	ack := kc.TokenApplied{Generation: page.Generation, Through: page.Head, AppliedAt: kc.T(time.Now())}
	if err := client.TokensApplied(ctx, ack); err != nil {
		t.Fatal(err)
	}
	if acks := fake.TokensApplied(App); len(acks) != 1 || acks[0].Through != page.Head || acks[0].Refused == nil || acks[0].Held == nil {
		t.Fatalf("the fake took %+v", acks)
	}
	other := ack
	other.Generation = vecGeneration
	if err := client.TokensApplied(ctx, other); Classify(err) != Refused || RefusalCode(err) != kc.CodeGone {
		t.Fatalf("another generation's acknowledgement: %v", err)
	}
	usage := kc.TokenUsage{Used: []kc.TokenUsed{{Token: id, Day: time.Now().UTC().Format(time.DateOnly)}}}
	if err := client.TokenUsage(ctx, usage); err != nil {
		t.Fatal(err)
	}
	if got := fake.TokenUsage(App); len(got) != 1 || len(got[0].Used) != 1 || got[0].Refusals == nil {
		t.Fatalf("the fake took %+v", got)
	}

	calls := map[string]func() error{
		contracttest.CallTokens: func() error { _, err := client.Tokens(ctx, page.Head, 0); return err },
		contracttest.CallToken:  func() error { _, err := client.Token(ctx, id); return err },
		contracttest.CallTokenBySelector: func() error {
			_, err := client.TokenBySelector(ctx, rec.Selector)
			return err
		},
		contracttest.CallTokensApplied: func() error { return client.TokensApplied(ctx, ack) },
		contracttest.CallTokenUsage:    func() error { return client.TokenUsage(ctx, usage) },
	}
	want := map[string]int{
		contracttest.CallTokens: 1, contracttest.CallToken: 1, contracttest.CallTokenBySelector: 1,
		contracttest.CallTokensApplied: 2, contracttest.CallTokenUsage: 1,
	}
	for call, n := range want {
		if got := fake.Count(call); got != n {
			t.Errorf("%s: %d requests counted, want %d", call, got, n)
		}
	}
	for call, f := range calls {
		for _, tc := range []struct {
			code  string
			calls int
		}{{kc.CodeUnavailable, 2}, {kc.CodeReplay, 2}, {kc.CodeNotFound, 1}, {kc.CodeRateLimited, 1}} {
			before := fake.Count(call)
			fake.RefuseAlways(call, tc.code)
			err := f()
			fake.RefuseAlways(call, "")
			if Classify(err) != Refused || RefusalCode(err) != tc.code || fake.Count(call)-before != tc.calls {
				t.Errorf("%s refused %s: %v, %d requests", call, tc.code, err, fake.Count(call)-before)
			}
		}
		fake.SetDown(true)
		err := f()
		fake.SetDown(false)
		if Classify(err) != Unavailable {
			t.Errorf("%s with the platform down: %v (%s)", call, err, Classify(err))
		}
		if err := f(); err != nil {
			t.Errorf("%s once the platform is back: %v", call, err)
		}
	}

	// An id or a selector that is not one never leaves Wappie.
	before := fake.Count(contracttest.CallToken) + fake.Count(contracttest.CallTokenBySelector)
	if _, err := client.Token(ctx, "not-a-token-id"); !errors.Is(err, kc.ErrInvalid) || Classify(err) != Unavailable {
		t.Errorf("a bad id: %v", err)
	}
	if _, err := client.TokenBySelector(ctx, "9F3C0A7BE41D2C58"); !errors.Is(err, kc.ErrInvalid) {
		t.Errorf("a bad selector: %v", err)
	}
	if fake.Count(contracttest.CallToken)+fake.Count(contracttest.CallTokenBySelector) != before {
		t.Error("a bad id or selector reached the platform")
	}
}
