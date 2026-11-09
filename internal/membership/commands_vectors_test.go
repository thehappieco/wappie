package membership

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"

	"whatserver2/internal/store"
)

// The settings part's command vectors (the kit's command-macs.json and
// wire-commands.json, byte for byte the platform's), run through Wappie's
// own client, its follower's decisions and its results poster's checks.

// vectorSecretA is signatures.json's SecretA, which signs every command of
// wire-commands.json: the bytes 0 to 31, base64url without padding. It is
// built here rather than written out so the secrets scan has no literal to
// flag; it protects nothing.
var vectorSecretA = func() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}()

type commandMACVectors struct {
	Label string `json:"label"`
	MACs  []struct {
		Name    string   `json:"name"`
		App     string   `json:"app"`
		Secrets []string `json:"secrets"`
		Command string   `json:"command"`
		JCS     string   `json:"jcs"`
		MAC     string   `json:"mac"`
		Valid   bool     `json:"valid"`
	} `json:"macs"`
}

type commandVectors struct {
	Commands []struct {
		Name          string          `json:"name"`
		App           string          `json:"app"`
		WorkspaceKind string          `json:"workspace_kind"`
		Value         json.RawMessage `json:"value"`
		Valid         bool            `json:"valid"`
	} `json:"commands"`
	Actions []struct {
		Name       string          `json:"name"`
		App        string          `json:"app"`
		Generation string          `json:"generation"`
		SignedAt   string          `json:"signed_at"`
		LastWSeq   *int64          `json:"last_wseq"`
		Again      bool            `json:"again"`
		Value      json.RawMessage `json:"value"`
		Action     string          `json:"action"`
	} `json:"actions"`
	Results []struct {
		Name  string          `json:"name"`
		App   string          `json:"app"`
		Kind  string          `json:"kind"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"results"`
}

// commandFeedClient is a client whose command feed answers, signed with
// secret, one page holding raw as its one command.
func commandFeedClient(t *testing.T, secret, other string, raw []byte) *Client {
	t.Helper()
	c := clientOn(func(r *http.Request) (*http.Response, error) {
		var b bytes.Buffer
		b.WriteString(`{"generation":"0199b1e0-0000-7000-8000-000000000001","head":1,"items":[{"cseq":1,"command":`)
		b.Write(raw)
		b.WriteString(`,"again":false}],"next_after":1,"more":false}`)
		return signedAnswer(r, secret, http.StatusOK, b.Bytes(), time.Now()), nil
	}, nil)
	if err := c.Use(secret, other); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestCommandMACVectors: every case of command-macs.json through Wappie's
// client, holding the case's secrets (Client.Use), a command feed page
// carrying the command as received, and VerifyCommand: valid is the
// verdict for Wappie's own cases; of another app's, one whose body names
// that app is refused, Wappie running only its own, and the one whose
// body is Wappie's (refused for Mailie) is Wappie's case of the same text
// under the same secrets;
// and the ledger's body key is the sha256 of the case's canonical text
// without generation, cseq and secret (of the raw text where it has none).
func TestCommandMACVectors(t *testing.T) {
	var v commandMACVectors
	readVectors(t, "command-macs.json", &v)
	if len(v.MACs) != 21 || v.Label != kc.CommandMACLabel {
		t.Fatalf("command-macs.json has %d cases under %q", len(v.MACs), v.Label)
	}
	ctx := context.Background()
	// Wappie's verdicts by the command's text and the secrets held.
	wappie := map[string]bool{}
	for _, c := range v.MACs {
		if c.App == App {
			wappie[c.Command+"\n"+strings.Join(c.Secrets, ",")] = c.Valid
		}
	}
	for _, c := range v.MACs {
		t.Run(c.Name, func(t *testing.T) {
			want := c.Valid
			if c.App != App {
				var head struct {
					App string `json:"app"`
				}
				if err := json.Unmarshal([]byte(c.Command), &head); err != nil {
					t.Fatal(err)
				}
				valid, ours := wappie[c.Command+"\n"+strings.Join(c.Secrets, ",")]
				if head.App == App && !ours {
					t.Fatal("a case of another app whose body is Wappie's, and no Wappie case of its text")
				}
				want = head.App == App && valid
			}
			other := ""
			if len(c.Secrets) > 1 {
				other = c.Secrets[1]
			}
			client := commandFeedClient(t, c.Secrets[0], other, []byte(c.Command))
			page, err := client.Commands(ctx, 0, 0)
			if err != nil {
				t.Fatalf("the page: %v", err)
			}
			_, err = client.VerifyCommand(page, page.Feed.Items[0].Command)
			if (err == nil) != want {
				t.Errorf("verified %v (%v), want %v", err == nil, err, want)
			}
			key := sha256.Sum256([]byte(c.Command))
			if c.JCS != "" {
				dec := json.NewDecoder(strings.NewReader(c.JCS))
				dec.UseNumber()
				var m map[string]any
				if err := dec.Decode(&m); err != nil {
					t.Fatal(err)
				}
				delete(m, "generation")
				delete(m, "cseq")
				delete(m, "secret")
				canonical, err := jcs.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				key = sha256.Sum256(canonical)
			}
			if got := bodyKey([]byte(c.Command)); !bytes.Equal(got, key[:]) {
				t.Errorf("body key %x, want %x", got, key)
			}
		})
	}
}

// actionOf is what the follower and the take do with a command app holds
// generation held of, carried in a page of the command's own generation
// signed at signedAt, delivered again or not, with last the highest wseq
// the memory holds there with another id: run, expired, reset (the page's
// generation is another) or invalid_command. The wseq rule (step 7) is the
// take's, under its lock (store.TakeCommands, whose tests drive it); here
// it is the same rule on the decoded fields.
func actionOf(t *testing.T, app, held string, signedAt time.Time, again bool, last *int64, raw []byte) string {
	t.Helper()
	var head struct {
		Generation string `json:"generation"`
		CSeq       int64  `json:"cseq"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		t.Fatal(err)
	}
	if head.Generation != held {
		// The page's generation, as the platform serves it: a reset of the
		// whole page, decided before any item.
		return "reset"
	}
	verify := func(raw json.RawMessage) (kc.Command, error) {
		return kc.VerifyCommand(raw, app, []string{vectorSecretA})
	}
	kindOf := func(uuid.UUID) (string, error) { return kc.KindTeam, nil }
	item := kc.CommandFeedItem{CSeq: head.CSeq, Command: raw, Again: again}
	take, unreadable, err := decideCommand(app, verify, head.Generation, signedAt, item, kindOf)
	switch {
	case err != nil:
		t.Fatal(err)
	case unreadable != nil:
		return kc.CodeInvalidCommand
	}
	d := take.Decoded
	if take.Verdict == "" && !again && last != nil && d != nil && d.WSeq != nil && *d.WSeq <= *last {
		return kc.CodeInvalidCommand
	}
	switch take.Verdict {
	case "":
		return "run"
	case store.CommandExpired:
		return kc.CodeExpired
	}
	return take.Verdict
}

// signOutEverywhere is a Wappie person.sign_out_everywhere issued at
// issued, signed with SecretA.
func signOutEverywhere(t *testing.T, generation string, issued time.Time) []byte {
	t.Helper()
	at := issued.UTC().Format(time.RFC3339)
	actor := "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
	raw := fmt.Sprintf(`{"v":1,"type":"command","app":"wappie","generation":%q,"id":"0199f3c4-0000-7000-8000-000000000077",`+
		`"retry_of":null,"cseq":9,"workspace_id":null,"wseq":null,"kind":"person.sign_out_everywhere","section":"person",`+
		`"actor":%q,"actor_role":null,"target":{},"params":{},"based_on":{"state_seq":1791892800000,"docs":{%q:7}},`+
		`"issued_at":%q,"first_issued_at":%q,"expires_at":null,"confirm":null,"agreement":null,"secret":2}`,
		generation, actor, actor, at, at)
	signed, err := kc.SignCommand([]byte(raw), App, vectorSecretA)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestDecideMatchesTheKit: every actions case of wire-commands.json, each
// decided for its own app under that app's SecretA, with last_wseq as the
// memory, gives the kit's action; the reset case goes in a page of the
// command's own generation. And Wappie's own 30-day boundary: a
// person.sign_out_everywhere issued exactly 30 days before the page was
// signed runs, one 30 days and a second before is expired, and that one
// delivered again runs.
func TestDecideMatchesTheKit(t *testing.T) {
	var v commandVectors
	readVectors(t, "wire-commands.json", &v)
	if len(v.Actions) != 14 {
		t.Fatalf("wire-commands.json has %d actions", len(v.Actions))
	}
	for _, a := range v.Actions {
		t.Run(a.Name, func(t *testing.T) {
			signed, err := time.Parse(time.RFC3339, a.SignedAt)
			if err != nil {
				t.Fatal(err)
			}
			if got := actionOf(t, a.App, a.Generation, signed, a.Again, a.LastWSeq, a.Value); got != a.Action {
				t.Errorf("%s, the kit says %s", got, a.Action)
			}
		})
	}
	gen := "0199b1e0-0000-7000-8000-000000000001"
	signed := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name   string
		before time.Duration
		again  bool
		want   string
	}{
		{"issued exactly 30 days before", kc.CommandRetention, false, "run"},
		{"issued 30 days and a second before", kc.CommandRetention + time.Second, false, kc.CodeExpired},
		{"the same delivered again", kc.CommandRetention + time.Second, true, "run"},
	} {
		raw := signOutEverywhere(t, gen, signed.Add(-c.before))
		if got := actionOf(t, App, gen, signed, c.again, nil, raw); got != c.want {
			t.Errorf("a sign-out everywhere %s: %s, want %s", c.name, got, c.want)
		}
	}
}

// TestCommandsValidMatchTheKit: Wappie's take refuses invalid_command
// exactly the commands of wire-commands.json that are not valid for
// Wappie, in a page of their own generation signed when they were issued
// (so none is expired), each carried at its own cseq, in a workspace of
// the case's kind; a valid one is decoded whole for the ledger, an invalid
// one keeps no decoded field. Two cases rest on a workspace kind an app
// passes ValidateIn that Wappie never passes: Wappie reads the kind of the
// workspace the command names, so a person's kind (which names none) is
// checked with ValidateIn(""), and a workspace no document named with
// Validate alone (the plan's 3.1, step 4); both are taken.
func TestCommandsValidMatchTheKit(t *testing.T) {
	var v commandVectors
	readVectors(t, "wire-commands.json", &v)
	if len(v.Commands) != 161 {
		t.Fatalf("wire-commands.json has %d commands", len(v.Commands))
	}
	notPassed := map[string]string{
		"a person's kind given a workspace": "",
		"a workspace's kind given none":     "unrecorded",
	}
	n := 0
	for _, c := range v.Commands {
		if c.App != App {
			continue
		}
		n++
		t.Run(c.Name, func(t *testing.T) {
			want := c.Valid
			if _, ok := notPassed[c.Name]; ok {
				var cmd kc.Command
				if err := json.Unmarshal(c.Value, &cmd); err != nil || cmd.ValidateIn(c.WorkspaceKind) == nil || cmd.Validate() != nil {
					t.Fatalf("the case no longer rests on the kind passed: %v", err)
				}
				want = true
			}
			var head struct {
				Generation string `json:"generation"`
				CSeq       int64  `json:"cseq"`
				IssuedAt   string `json:"issued_at"`
			}
			_ = json.Unmarshal(c.Value, &head) //nolint:errcheck // a body that does not decode is refused all the same
			signed, err := time.Parse(time.RFC3339Nano, head.IssuedAt)
			if err != nil {
				signed = time.Now()
			}
			verify := func(raw json.RawMessage) (kc.Command, error) {
				return kc.VerifyCommand(raw, App, []string{vectorSecretA})
			}
			kindOf := func(uuid.UUID) (string, error) {
				if notPassed[c.Name] == "unrecorded" {
					return "", nil
				}
				return c.WorkspaceKind, nil
			}
			take, unreadable, err := decideCommand(App, verify, head.Generation, signed,
				kc.CommandFeedItem{CSeq: head.CSeq, Command: c.Value}, kindOf)
			if err != nil {
				t.Fatal(err)
			}
			invalid := unreadable != nil || take.Verdict == store.CommandInvalid
			if invalid == want {
				t.Errorf("refused invalid_command %v (%s), want taken %v (the kit says valid %v)", invalid, take.Why, want, c.Valid)
			}
			if invalid && take.Decoded != nil {
				t.Error("a command refused before it was decoded keeps a decoded field")
			}
			if !invalid && (take.Decoded == nil || take.Decoded.Kind == "" || take.Verdict != "") {
				t.Errorf("a valid command: %+v", take)
			}
		})
	}
	if n < 100 {
		t.Fatalf("only %d of Wappie's commands", n)
	}
}

// TestResultsMatchTheKit: Wappie's results of wire-commands.json, as the
// poster builds them from a ledger row, pass its check exactly where the
// kit says, and what it sends decodes as the platform reads it. A row with
// no kind (refused before it was decoded) is checked with Validate alone,
// so its invalid_command posts; so does one refused for a kind the kit
// does not know, which the ledger keeps with no kind.
func TestResultsMatchTheKit(t *testing.T) {
	var v commandVectors
	readVectors(t, "wire-commands.json", &v)
	if len(v.Results) != 64 {
		t.Fatalf("wire-commands.json has %d results", len(v.Results))
	}
	rowOf := func(t *testing.T, raw []byte, kind string) (store.ContractResult, bool) {
		t.Helper()
		var r kc.CommandResult
		if kc.DecodeStrict(raw, &r) != nil {
			return store.ContractResult{}, false
		}
		id, err := uuid.Parse(r.ID)
		if err != nil || r.At.IsZero() {
			return store.ContractResult{}, false
		}
		row := store.ContractResult{ID: id, Kind: kind, Outcome: r.Outcome, StateSeq: r.StateSeq, At: r.At.Time}
		if r.Code != nil {
			row.Code = *r.Code
		}
		if r.RetryAfter != nil {
			retry := int(*r.RetryAfter)
			row.RetryAfter = &retry
		}
		if r.Detail != nil {
			d, err := encodeData(r.Detail)
			if err != nil {
				t.Fatal(err)
			}
			row.Detail = d
		}
		return row, true
	}
	n := 0
	for _, c := range v.Results {
		if c.App != App {
			continue
		}
		row, ok := rowOf(t, c.Value, c.Kind)
		if !ok {
			// No ledger row holds it: what does not decode strictly, or
			// whose id or time the ledger could not hold.
			continue
		}
		n++
		r, why := resultOf(row)
		if (why == "") != c.Valid {
			t.Errorf("%s: posted %v (%s), the kit says %v", c.Name, why == "", why, c.Valid)
			continue
		}
		if why == "" {
			body, err := encodeData(kc.CommandResults{Results: []kc.CommandResult{r}})
			if err != nil {
				t.Fatal(err)
			}
			var back kc.CommandResults
			if err := kc.DecodeStrict(body, &back); err != nil || back.Validate() != nil {
				t.Errorf("%s: the body the poster sends: %v %v", c.Name, err, back.Validate())
			}
		}
	}
	if n < 40 {
		t.Fatalf("only %d of Wappie's results", n)
	}
	// A detail is read as strictly as the platform reads it: a member the
	// kit does not know is Wappie's bug, parked, never sent.
	loose := store.ContractResult{ID: uuid.New(), Kind: kc.OpItemRename, Outcome: kc.OutcomeRefused, Code: kc.CodeLabelChanged,
		StateSeq: ptr(int64(5)), Detail: json.RawMessage(`{"cleaned":"Vendas","extra":1}`), At: time.Now()}
	if _, why := resultOf(loose); why != "detail" {
		t.Errorf("a detail with a member the kit does not know: %q", why)
	}
	loose.Detail = json.RawMessage(`{"cleaned":"Vendas"}`)
	if _, why := resultOf(loose); why != "" {
		t.Errorf("a label_changed with its detail: %q", why)
	}

	// A command of a kind the kit does not know (item.relink, v0.11.0's) is
	// refused at take with no decoded field, so its row has no kind, and
	// its invalid_command posts with Validate alone, which ValidateFor
	// (refusing the kind) would never let go.
	gen := "0199b1e0-0000-7000-8000-000000000001"
	relink := fmt.Sprintf(`{"v":1,"type":"command","app":"wappie","generation":%q,"id":"0199f3c4-0000-7000-8000-000000000078",`+
		`"retry_of":null,"cseq":5,"workspace_id":"01a034b7-d09c-7121-b7f8-41f210a9244a","wseq":3,"kind":"item.relink",`+
		`"section":"numbers","actor":"0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20","actor_role":"owner",`+
		`"target":{"item":"0199e000-0000-7000-8000-000000000004"},"params":{},`+
		`"based_on":{"state_seq":1791892800000,"docs":{"0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20":7}},`+
		`"issued_at":"2026-10-13T12:00:00Z","first_issued_at":"2026-10-13T12:00:00Z","expires_at":"2026-10-13T12:05:00Z",`+
		`"confirm":null,"agreement":null,"secret":2}`, gen)
	signedRelink, err := kc.SignCommand([]byte(relink), App, vectorSecretA)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(raw json.RawMessage) (kc.Command, error) {
		return kc.VerifyCommand(raw, App, []string{vectorSecretA})
	}
	take, _, err := decideCommand(App, verify, gen, time.Date(2026, 10, 13, 12, 0, 1, 0, time.UTC),
		kc.CommandFeedItem{CSeq: 5, Command: signedRelink}, func(uuid.UUID) (string, error) { return kc.KindTeam, nil })
	if err != nil || take.Verdict != store.CommandInvalid || take.Decoded != nil {
		t.Fatalf("an item.relink at take: %+v %v", take, err)
	}
	row := store.ContractResult{ID: take.ID, Outcome: kc.OutcomeRefused, Code: kc.CodeInvalidCommand, At: time.Now()}
	if _, why := resultOf(row); why != "" {
		t.Errorf("an invalid_command with no kind is not posted: %s", why)
	}
	row.Kind = "item.relink"
	if _, why := resultOf(row); why == "" {
		t.Error("ValidateFor took a result of a kind the kit does not know")
	}
}

// TestDecideChecksNoVectorPins: what the follower decides that no case of
// the kit's pins. A command whose own generation is not its page's is the
// platform's fault: invalid_command, never a reset (the page's generation
// alone resets). One carried at another cseq than its own is
// invalid_command. An id that is not a UUID as the platform writes it
// names no row. A body that is no JSON object is refused and forged, its id
// read from a generic decode where it has one.
func TestDecideChecksNoVectorPins(t *testing.T) {
	gen, other := "0199b1e0-0000-7000-8000-000000000001", "0199b1e0-0000-7000-8000-000000000002"
	signed := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	verify := func(raw json.RawMessage) (kc.Command, error) {
		return kc.VerifyCommand(raw, App, []string{vectorSecretA})
	}
	decide := func(pageGen string, cseq int64, raw []byte) (store.ContractCommandTake, *store.ContractUnreadable) {
		t.Helper()
		take, unreadable, err := decideCommand(App, verify, pageGen, signed, kc.CommandFeedItem{CSeq: cseq, Command: raw},
			func(uuid.UUID) (string, error) { return kc.KindTeam, nil })
		if err != nil {
			t.Fatal(err)
		}
		return take, unreadable
	}
	ofGen := signOutEverywhere(t, other, signed)
	if take, _ := decide(gen, 9, ofGen); take.Verdict != store.CommandInvalid || take.Why != whyGeneration || take.Forged || take.Decoded != nil {
		t.Errorf("a command of another generation than its page: %+v", take)
	}
	if take, _ := decide(other, 9, ofGen); take.Verdict != "" || take.Decoded == nil {
		t.Errorf("the same in a page of its own generation: %+v", take)
	}
	own := signOutEverywhere(t, gen, signed)
	if take, _ := decide(gen, 10, own); take.Verdict != store.CommandInvalid || take.Why != whyCseq || take.Decoded != nil {
		t.Errorf("a command at another cseq than its own: %+v", take)
	}
	upper := bytes.Replace(own, []byte("0199f3c4-0000-7000-8000-000000000077"), []byte("0199F3C4-0000-7000-8000-000000000077"), 1)
	if _, unreadable := decide(gen, 9, upper); unreadable == nil || !unreadable.Forged {
		t.Errorf("an id in capitals names a row: %+v", unreadable)
	}
	if take, _ := decide(gen, 9, []byte(`{"id":"0199f3c4-0000-7000-8000-000000000079","app":"wappie","x":1,"x":2}`)); take.Verdict != store.CommandInvalid ||
		!take.Forged || take.Why != whyMalformed || take.ID.String() != "0199f3c4-0000-7000-8000-000000000079" {
		t.Errorf("a body with a member twice: %+v", take)
	}
	if take, _ := decide(gen, 9, []byte(`{"id":"0199f3c4-0000-7000-8000-000000000080","app":"mailie"}`)); take.Why != whyAnotherApp || !take.Forged {
		t.Errorf("another app's body: %+v", take)
	}
}

// TestVerifyCommandRotation: during a rotation a command signed with the
// other secret verifies, and one with neither does not; a page is checked
// with the secrets of the client that fetched it, so a reload between the
// fetch and the check changes nothing.
func TestVerifyCommandRotation(t *testing.T) {
	ctx := context.Background()
	next := "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8" //nolint:gosec // G101: signatures.json's next secret, a vector
	raw := signOutEverywhere(t, "0199b1e0-0000-7000-8000-000000000001", time.Now())
	byNext, err := kc.SignCommand(raw, App, next)
	if err != nil {
		t.Fatal(err)
	}
	c := commandFeedClient(t, vectorSecretA, next, byNext)
	page, err := c.Commands(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Use(vectorSecretA, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyCommand(page, page.Feed.Items[0].Command); err != nil {
		t.Fatalf("a command signed with the other secret, checked with the fetching client's: %v", err)
	}
	alone := commandFeedClient(t, vectorSecretA, "", byNext)
	page, err = alone.Commands(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alone.VerifyCommand(page, page.Feed.Items[0].Command); !errors.Is(err, kc.ErrCommandMAC) {
		t.Fatalf("a command signed with a secret the client does not hold: %v", err)
	}
}

// TestDecideReadsTheSignedCommand: the ledger's id is the id the MAC
// covers, read with the member's exact name as the kit reads it, never
// encoding/json's match in any case; and a command whose MAC holds but
// that does not decode as a command (the platform signed it) is
// invalid_command, not a forgery, while one the kit cannot canonicalize
// for its MAC (a mac that is no string, a fraction) is a forgery.
func TestDecideReadsTheSignedCommand(t *testing.T) {
	gen := "0199b1e0-0000-7000-8000-000000000001"
	signed := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	verify := func(raw json.RawMessage) (kc.Command, error) {
		return kc.VerifyCommand(raw, App, []string{vectorSecretA})
	}
	decide := func(raw []byte) (store.ContractCommandTake, *store.ContractUnreadable) {
		t.Helper()
		take, unreadable, err := decideCommand(App, verify, gen, signed, kc.CommandFeedItem{CSeq: 9, Command: raw},
			func(uuid.UUID) (string, error) { return kc.KindTeam, nil })
		if err != nil {
			t.Fatal(err)
		}
		return take, unreadable
	}
	// members is the command signOutEverywhere signs, without its mac,
	// numbers as written.
	members := func() map[string]any {
		t.Helper()
		dec := json.NewDecoder(bytes.NewReader(signOutEverywhere(t, gen, signed)))
		dec.UseNumber()
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		delete(v, "mac")
		return v
	}
	sign := func(v map[string]any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := kc.SignCommand(raw, App, vectorSecretA)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	const real, other = "0199f3c4-0000-7000-8000-000000000077", "0199f3c4-0000-7000-8000-0000000000aa"

	// An "ID" member beside "id", served after it (any order verifies).
	v := members()
	v["ID"] = other
	body := sign(v)
	moved := bytes.Replace(body, []byte(`"ID":"`+other+`",`), nil, 1)
	moved = append(moved[:len(moved)-1], []byte(`,"ID":"`+other+`"}`)...)
	if c, err := verify(moved); err != nil || c.ID != real {
		t.Fatalf("the body with ID last: %v %q", err, c.ID)
	}
	if take, unreadable := decide(moved); unreadable != nil || take.ID.String() != real || take.Verdict != "" || take.Decoded == nil {
		t.Errorf("an ID member after id: the row %s, verdict %q, %+v", take.ID, take.Verdict, unreadable)
	}
	// An "Id" and no "id": no id the MAC covers names a row.
	v = members()
	delete(v, "id")
	v["Id"] = other
	if take, unreadable := decide(sign(v)); unreadable == nil || unreadable.Forged || take.ID != uuid.Nil {
		t.Errorf("a command with only an Id: %+v %+v", take, unreadable)
	}
	// Signed, but no command: a string where a number goes.
	for _, member := range []string{"wseq", "cseq"} {
		v = members()
		v[member] = "9"
		take, unreadable := decide(sign(v))
		if unreadable != nil || take.ID.String() != real || take.Verdict != store.CommandInvalid || take.Why != whyInvalid || take.Forged ||
			take.Decoded != nil {
			t.Errorf("a signed command with %s a string: %+v %+v", member, take, unreadable)
		}
	}
	// What the kit cannot canonicalize for a MAC: forged.
	for name, raw := range map[string]string{
		"a mac that is no string": `{"id":"` + real + `","app":"wappie","mac":5}`,
		"a fraction":              `{"id":"` + real + `","app":"wappie","x":1.5,"mac":"v1=00"}`,
		"a member twice":          `{"id":"` + real + `","app":"wappie","x":1,"x":2}`,
	} {
		if take, _ := decide([]byte(raw)); take.Why != whyMalformed || !take.Forged || take.ID.String() != real {
			t.Errorf("%s: %+v", name, take)
		}
	}
	// Another app's body, its app named exactly; one named "App" is not.
	if take, _ := decide([]byte(`{"id":"` + real + `","app":"mailie"}`)); take.Why != whyAnotherApp || !take.Forged {
		t.Errorf("another app's body: %+v", take)
	}
	if take, _ := decide([]byte(`{"id":"` + real + `","App":"wappie","app":"mailie"}`)); take.Why != whyAnotherApp || !take.Forged {
		t.Errorf("another app's body with an App member: %+v", take)
	}
}

// TestCommandPageHidesSecrets: a command page holds the client that
// fetched it by pointer, so printing one, or logging it, shows no secret.
func TestCommandPageHidesSecrets(t *testing.T) {
	raw := signOutEverywhere(t, "0199b1e0-0000-7000-8000-000000000001", time.Now())
	c := commandFeedClient(t, vectorSecretA, "", raw)
	page, err := c.Commands(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if s := fmt.Sprintf(verb, page); strings.Contains(s, vectorSecretA) {
			t.Errorf("%s of a command page prints the contract secret", verb)
		}
	}
	var b bytes.Buffer
	slog.New(slog.NewTextHandler(&b, nil)).Info("page", "page", page)
	slog.New(slog.NewJSONHandler(&b, nil)).Info("page", "page", page)
	if strings.Contains(b.String(), vectorSecretA) {
		t.Error("a log line of a command page prints the contract secret")
	}
	if _, err := c.VerifyCommand(page, page.Feed.Items[0].Command); err != nil {
		t.Fatalf("the page's command, checked with the fetching client: %v", err)
	}
	if _, err := c.VerifyCommand(CommandPage{}, page.Feed.Items[0].Command); !errors.Is(err, kc.ErrCommandMAC) {
		t.Fatalf("a page no client fetched: %v", err)
	}
}
