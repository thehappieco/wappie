package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
)

// kit v0.11.0's wire, as Wappie reads and writes it: can_relink in the
// numbers section, item.relink's results, and the vectors of
// wire-pairing.json and wire-v011.json run through Wappie's own take,
// results poster and section renderer.

// relinkable is a live number its phone logged out that passes every
// check of the relink's table.
func relinkable() store.ContractNumber {
	return store.ContractNumber{ID: uuid.New(), Status: "logged_out", LogoutCause: "phone", Known: true, Epoch: 1, KeyHeld: true,
		PN: "155501099001:3@s.whatsapp.net", LID: "100000000099001:3@lid"}
}

type mapBook struct{ pn, lid types.JID }

func (b mapBook) PhoneFor(context.Context, types.JID) (types.JID, bool) { return b.pn, !b.pn.IsEmpty() }
func (b mapBook) LIDFor(context.Context, types.JID) (types.JID, bool)   { return b.lid, !b.lid.IsEmpty() }

// TestNumbersCanRelink: can_relink is the relink's own table over what
// the section read, with no side effect: true for a live number logged
// out by its phone, and for one logged out by its deletion and recovered
// since; false for a deleted number, one online or banned, half an
// identity (true once whatsmeow's map fills it), no epoch, nobody holding
// its key, its account live as another number, a pairing of it now, or a
// move's pause; and with no looks. A hold of the process reads as passing.
// Every row of a section carries it, true or false, never null.
func TestNumbersCanRelink(t *testing.T) {
	ls := looks{pairing: map[string]time.Time{}, held: map[string]bool{}}
	can := func(n store.ContractNumber, others ...store.ContractNumber) bool {
		t.Helper()
		row := numberRow(n, append([]store.ContractNumber{n}, others...), ls)
		if row.CanRelink == nil {
			t.Fatal("can_relink is not set")
		}
		return *row.CanRelink
	}
	base := relinkable()
	if !can(base) {
		t.Fatal("a number its phone logged out")
	}
	recovered := base
	recovered.ID, recovered.LogoutCause = uuid.New(), "deletion"
	if !can(recovered) || connectionOf(recovered) != "logged_out_deletion" {
		t.Fatal("a number logged out by its deletion, recovered since")
	}
	if row := numberRow(base, nil, nil); row.CanRelink == nil || *row.CanRelink {
		t.Fatal("no looks")
	}
	other := relinkable()
	other.PN, other.LID = "155501099001:7@s.whatsapp.net", ""
	for name, change := range map[string]func(n *store.ContractNumber){
		"deleted":            func(n *store.ContractNumber) { n.Deleted = true },
		"recovered, deleted": func(n *store.ContractNumber) { n.Deleted, n.LogoutCause = true, "deletion" },
		"online":             func(n *store.ContractNumber) { n.Status, n.LogoutCause = "online", "" },
		"banned":             func(n *store.ContractNumber) { n.Status, n.LogoutCause = "banned", "" },
		"no LID":             func(n *store.ContractNumber) { n.LID = "" },
		"no phone number":    func(n *store.ContractNumber) { n.PN = "" },
		"no epoch":           func(n *store.ContractNumber) { n.Epoch = 0 },
		"no key holder":      func(n *store.ContractNumber) { n.KeyHeld = false },
		"a move's pause":     func(n *store.ContractNumber) { n.Paused, n.PauseCause = true, store.PauseForMove },
	} {
		n := base
		change(&n)
		if can(n) {
			t.Errorf("%s: can_relink true", name)
		}
	}
	paused := base
	paused.Paused, paused.PauseCause = true, store.PauseByPerson
	if !can(paused) {
		t.Error("a person's pause: the relink resumes it")
	}
	other.Status = "online"
	if can(base, other) {
		t.Error("its account live as another number")
	}
	for name, change := range map[string]func(o *store.ContractNumber){
		"logged out":    func(o *store.ContractNumber) { o.Status = "logged_out" },
		"banned":        func(o *store.ContractNumber) { o.Status = "banned" },
		"deleted":       func(o *store.ContractNumber) { o.Deleted = true },
		"another phone": func(o *store.ContractNumber) { o.PN = "155501099002:7@s.whatsapp.net" },
	} {
		o := other
		change(&o)
		if !can(base, o) {
			t.Errorf("another number %s holds no account of it", name)
		}
	}
	ls.pairing[base.ID.String()] = time.Now()
	if can(base) {
		t.Error("a pairing of it now")
	}
	delete(ls.pairing, base.ID.String())
	ls.held[base.ID.String()] = true
	if !can(base) {
		t.Error("a hold of the process: read as passing, never released here")
	}

	// whatsmeow's map fills a missing half, as Check fills it.
	half := base
	half.LID = ""
	read := store.ContractNumbers{Items: []store.ContractNumber{half}}
	fillIdentities(context.Background(), &read, nil)
	if can(read.Items[0]) {
		t.Fatal("half an identity with no map")
	}
	fillIdentities(context.Background(), &read, mapBook{lid: types.NewJID("100000000099001", types.HiddenUserServer)})
	if !can(read.Items[0]) {
		t.Fatalf("half an identity filled from the map: %+v", read.Items[0])
	}
	online := base
	online.Status, online.LID = "online", ""
	read = store.ContractNumbers{Items: []store.ContractNumber{online}}
	fillIdentities(context.Background(), &read, mapBook{lid: types.NewJID("100000000099001", types.HiddenUserServer)})
	if read.Items[0].LID != "" {
		t.Fatal("a number not logged out filled from the map")
	}

	// The section: every row has it, true or false, and it validates.
	rows, _ := numbersRead(t)
	rows.Items = append(rows.Items, base, recovered)
	for _, l := range []NumberLooks{nil, ls} {
		doc, err := numbersDoc(rows, store.SettingsOn, l)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.Validate(); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(doc.Data, []byte(`"can_relink":null`)) ||
			bytes.Count(doc.Data, []byte(`"can_relink":`)) != len(rows.Items) {
			t.Fatalf("can_relink in %s", doc.Data)
		}
		if !slicesContains(doc.Accepts, kc.OpItemRelink) {
			t.Fatalf("accepts %v", doc.Accepts)
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestRelinkResultsValidate: every result an item.relink's act writes
// passes the kit's ValidateFor as the poster builds it: in_progress at a
// seq, ran at one, each of its own codes and every kind's it answers, and
// expired with no state_seq; item_busy's retry_after within 1 to 3600;
// no code the act writes maps to app_only.
func TestRelinkResultsValidate(t *testing.T) {
	seq := int64(1791892800123)
	row := func(outcome, code string, retry int, withSeq bool) store.ContractResult {
		r := store.ContractResult{ID: uuid.New(), Kind: kc.OpItemRelink, Outcome: outcome, Code: code, At: time.Now()}
		if withSeq {
			r.StateSeq = &seq
		}
		if retry > 0 {
			r.RetryAfter = &retry
		}
		return r
	}
	for _, r := range []store.ContractResult{
		row(store.CommandInProgress, "", 0, true),
		row(store.CommandRan, "", 0, true),
		row(store.CommandRefused, kc.CodeExpired, 0, false),
		row(store.CommandRefused, kc.CodeItemBusy, 1, true),
		row(store.CommandRefused, kc.CodeItemBusy, kc.MaxRetryAfter, true),
	} {
		if _, why := resultOf(r); why != "" {
			t.Errorf("%s %s: %s", r.Outcome, r.Code, why)
		}
	}
	for _, code := range []string{kc.CodeOtherAccount, kc.CodeLinkTimeout, kc.CodeConnectFailed, kc.CodeNumberHeld, kc.CodeReadOnly,
		kc.CodeNoReader, kc.CodeCapacityReached, kc.CodeStoragePaused, kc.CodeStateChanged, kc.CodeNotFound, kc.CodeNotAuthorized,
		kc.CodeMembershipsUnconfirmed, kc.CodeKindNotAccepted, kc.CodeTeamClosed, kc.CodeNotHeld, kc.CodeRateLimited,
		kc.CodeWorkspaceBusy} {
		retry := 0
		if kc.CommandRefusalClass(code, false) == kc.ClassRetry && code != kc.CodeTeamClosed && code != kc.CodeKindNotAccepted {
			retry = 5
		}
		if _, why := resultOf(row(store.CommandRefused, code, retry, true)); why != "" {
			t.Errorf("refused %s: %s", code, why)
		}
	}
	if _, why := resultOf(row(store.CommandRefused, kc.CodeAppOnly, 0, true)); why == "" {
		t.Error("app_only is posted for an item.relink")
	}
	if _, why := resultOf(row(store.CommandRefused, kc.CodeItemBusy, kc.MaxRetryAfter+1, true)); why == "" {
		t.Error("item_busy waiting over an hour is posted")
	}
	if _, why := resultOf(row(store.CommandRan, "", 0, false)); why == "" {
		t.Error("ran with no state_seq is posted")
	}
}

type pairingVectors struct {
	Pairings []struct {
		Name  string `json:"name"`
		Body  string `json:"body"`
		Now   int64  `json:"now"`
		Valid bool   `json:"valid"`
	} `json:"pairings"`
	Answers []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"answers"`
	Commands []struct {
		Name          string          `json:"name"`
		App           string          `json:"app"`
		WorkspaceKind string          `json:"workspace_kind"`
		Value         json.RawMessage `json:"value"`
		Valid         bool            `json:"valid"`
	} `json:"commands"`
	Results []struct {
		Name  string          `json:"name"`
		App   string          `json:"app"`
		Kind  string          `json:"kind"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"results"`
	Classes []struct {
		Code       string `json:"code"`
		Tightening bool   `json:"tightening"`
		Class      string `json:"class"`
	} `json:"classes"`
}

// TestPairingVectors: wire-pairing.json through what Wappie sends and
// reads. Each pairing body is valid exactly when it is within 4 KiB,
// decodes strictly as the kit's PairingQR and holds at the case's clock
// (what Wappie's client checks before it sends); a valid one is what
// Wappie's own encoding writes back. Each answer decodes as Wappie's
// client reads it. Each command is taken exactly when the kit says it is
// valid for Wappie (another app's never), and Wappie's results pass the
// poster's check exactly where the kit says. The three codes kit v0.11.0
// adds are final whether or not the kind tightens, so a tightening
// delivered again never waits on one (againRetry).
func TestPairingVectors(t *testing.T) {
	var v pairingVectors
	readVectors(t, "wire-pairing.json", &v)
	if len(v.Pairings) != 32 || len(v.Answers) != 7 || len(v.Commands) != 13 || len(v.Results) != 34 || len(v.Classes) != 6 {
		t.Fatalf("wire-pairing.json has %d pairings, %d answers, %d commands, %d results, %d classes",
			len(v.Pairings), len(v.Answers), len(v.Commands), len(v.Results), len(v.Classes))
	}
	valid := 0
	for _, c := range v.Pairings {
		var q kc.PairingQR
		err := kc.DecodeStrict([]byte(c.Body), &q)
		ok := len(c.Body) <= kc.PairingBodyLimit && err == nil && q.ValidateAt(time.Unix(c.Now, 0)) == nil
		if ok != c.Valid {
			t.Errorf("pairing %s: valid %v (%v), the kit says %v", c.Name, ok, err, c.Valid)
			continue
		}
		if ok {
			valid++
			// What Wappie's client writes of it reads back the same, and
			// holds at the same clock.
			back, err := encodeData(q)
			if err != nil {
				t.Fatal(err)
			}
			var again kc.PairingQR
			if err := kc.DecodeStrict(back, &again); err != nil || again.Seq != q.Seq || again.QR != q.QR ||
				!again.ExpiresAt.Equal(q.ExpiresAt) || again.ValidateAt(time.Unix(c.Now, 0)) != nil {
				t.Errorf("pairing %s: Wappie writes %s: %v", c.Name, back, err)
			}
			if len(q.QR) > 8 && (strings.Contains(fmt.Sprint(q), q.QR) || strings.Contains(fmt.Sprintf("%#v", q), q.QR)) {
				t.Errorf("pairing %s: the QR prints", c.Name)
			}
		}
	}
	if valid != 9 {
		t.Errorf("%d valid pairings", valid)
	}
	for _, c := range v.Answers {
		var a kc.PairingAnswer
		if ok := kc.DecodeStrict(c.Value, &a) == nil; ok != c.Valid {
			t.Errorf("answer %s: valid %v, the kit says %v", c.Name, ok, c.Valid)
		}
	}
	for _, c := range v.Commands {
		t.Run("command "+c.Name, func(t *testing.T) {
			if got := takeVerdict(t, c.WorkspaceKind, c.Value); got != (c.App == App && c.Valid) {
				t.Errorf("taken %v; app %s, the kit says valid %v", got, c.App, c.Valid)
			}
		})
	}
	n := 0
	for _, c := range v.Results {
		if c.App != App {
			continue
		}
		row, ok := resultRowOf(t, c.Value, c.Kind)
		if !ok {
			if c.Valid {
				t.Errorf("result %s: valid, and no ledger row holds it", c.Name)
			}
			continue
		}
		n++
		if _, why := resultOf(row); (why == "") != c.Valid {
			t.Errorf("result %s: posted %v (%s), the kit says %v", c.Name, why == "", why, c.Valid)
		}
	}
	if n == 0 {
		t.Fatal("no result of Wappie's in wire-pairing.json")
	}
	for _, c := range v.Classes {
		if got := kc.CommandRefusalClass(c.Code, c.Tightening); got != c.Class {
			t.Errorf("%s (tightening %v): %s, the kit says %s", c.Code, c.Tightening, got, c.Class)
		}
		kind := kc.OpItemRelink
		if c.Tightening {
			kind = kc.OpItemFlagsDrop
		}
		if againRetry(kind, c.Code) != (c.Class == kc.ClassRetry) {
			t.Errorf("%s on %s: againRetry %v, class %s", c.Code, kind, againRetry(kind, c.Code), c.Class)
		}
	}
}

type v011Vectors struct {
	Sections []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"sections"`
	Commands []struct {
		Name          string          `json:"name"`
		App           string          `json:"app"`
		WorkspaceKind string          `json:"workspace_kind"`
		Value         json.RawMessage `json:"value"`
		Valid         bool            `json:"valid"`
	} `json:"commands"`
	Results []struct {
		Name  string          `json:"name"`
		App   string          `json:"app"`
		Kind  string          `json:"kind"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"results"`
	Pages []json.RawMessage `json:"pages"`
}

// TestV011Vectors: wire-v011.json through Wappie's renderer, take and
// poster. Wappie's numbers sections pass sectionRule exactly where the kit
// says, and a valid one decodes strictly as the renderer's type and
// encodes back as it came (can_relink true, false or absent, never null);
// the commands (Mailie's renames) are another app's, never taken; Wappie's
// results pass the poster's check exactly where the kit says (a null
// cleaned on its item.rename only). The token feed pages are not run: core
// does not consume the token feed (Wappie's tokens are the enclave's).
func TestV011Vectors(t *testing.T) {
	var v v011Vectors
	readVectors(t, "wire-v011.json", &v)
	if len(v.Sections) != 20 || len(v.Commands) != 11 || len(v.Results) != 13 || len(v.Pages) != 6 {
		t.Fatalf("wire-v011.json has %d sections, %d commands, %d results, %d pages", len(v.Sections), len(v.Commands),
			len(v.Results), len(v.Pages))
	}
	n := 0
	for _, c := range v.Sections {
		var doc kc.SettingsDoc
		if err := kc.DecodeStrict(c.Value, &doc); err != nil {
			if c.Valid {
				t.Errorf("section %s: %v", c.Name, err)
			}
			continue
		}
		if doc.App != App || doc.Section != kc.SectionNumbers {
			continue
		}
		n++
		why, rule := sectionRule(doc)
		if (why == "") != c.Valid {
			t.Errorf("section %s: Wappie would send it %v (%s %v), the kit says %v", c.Name, why == "", why, rule, c.Valid)
			continue
		}
		if !c.Valid {
			continue
		}
		var data kc.NumbersSettings
		if err := kc.DecodeStrict(doc.Data, &data); err != nil {
			t.Errorf("section %s: %v", c.Name, err)
			continue
		}
		back, err := encodeData(data)
		if err != nil {
			t.Fatal(err)
		}
		if canonical(t, back) != canonical(t, doc.Data) {
			t.Errorf("section %s: the renderer's type does not keep it:\n%s\n%s", c.Name, back, doc.Data)
		}
	}
	if n == 0 {
		t.Fatal("no numbers section of Wappie's in wire-v011.json")
	}
	for _, c := range v.Commands {
		t.Run("command "+c.Name, func(t *testing.T) {
			if got := takeVerdict(t, c.WorkspaceKind, c.Value); got != (c.App == App && c.Valid) {
				t.Errorf("taken %v; app %s, the kit says valid %v", got, c.App, c.Valid)
			}
		})
	}
	m := 0
	for _, c := range v.Results {
		if c.App != App {
			continue
		}
		row, ok := resultRowOf(t, c.Value, c.Kind)
		if !ok {
			if c.Valid {
				t.Errorf("result %s: valid, and no ledger row holds it", c.Name)
			}
			continue
		}
		m++
		if _, why := resultOf(row); (why == "") != c.Valid {
			t.Errorf("result %s: posted %v (%s), the kit says %v", c.Name, why == "", why, c.Valid)
		}
	}
	if m == 0 {
		t.Fatal("no result of Wappie's in wire-v011.json")
	}
}

// takeVerdict is whether Wappie's take runs raw (a command as the feed
// carries it, signed with SecretA) in a workspace of kind, in a page of
// its own generation signed when it was issued, at its own cseq.
func takeVerdict(t *testing.T, kind string, raw json.RawMessage) bool {
	t.Helper()
	var head struct {
		Generation string `json:"generation"`
		CSeq       int64  `json:"cseq"`
		IssuedAt   string `json:"issued_at"`
	}
	_ = json.Unmarshal(raw, &head) //nolint:errcheck // a body that does not decode is refused all the same
	signed, err := time.Parse(time.RFC3339Nano, head.IssuedAt)
	if err != nil {
		signed = time.Now()
	}
	verify := func(raw json.RawMessage) (kc.Command, error) {
		return kc.VerifyCommand(raw, App, []string{vectorSecretA})
	}
	take, unreadable, err := decideCommand(App, verify, head.Generation, signed, kc.CommandFeedItem{CSeq: head.CSeq, Command: raw},
		func(uuid.UUID) (string, error) { return kind, nil })
	if err != nil {
		t.Fatal(err)
	}
	return unreadable == nil && take.Verdict == "" && take.Decoded != nil
}

// resultRowOf is raw, a result the kit decodes strictly, as the ledger
// would hold it for a command of kind; false for one no row could hold.
func resultRowOf(t *testing.T, raw []byte, kind string) (store.ContractResult, bool) {
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
