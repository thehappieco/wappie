package membership

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/store"
)

// Slice 19's link check (E0; spec 15.11 "While ... observe"; Q57): after a
// pairing, before a move, and a relink's look at new_links, each only
// logged, nothing held back.

// linkTimes are the link check's timings for the tests.
func linkTimes() LinkTimings {
	return LinkTimings{GetWait: 5 * time.Second, MoveBudget: 5 * time.Second, Poll: 20 * time.Millisecond,
		Retries: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}}
}

// linkVector is one of wire-entitlements.json's links.
type linkVector struct {
	Name    string `json:"name"`
	Release string `json:"release"`
	Held    *struct {
		Mode     string `json:"mode"`
		NewLinks string `json:"new_links"`
	} `json:"held"`
	FreshMinutes *int `json:"fresh_minutes"`
	Get          string
	GetDoc       *struct {
		Mode     string `json:"mode"`
		NewLinks string `json:"new_links"`
	} `json:"get_doc"`
	Asks   bool   `json:"asks"`
	Action string `json:"action"`
	Logged bool   `json:"logged"`
}

// vectorDoc is a document of mode with new_links.
func vectorDoc(mode, newLinks string) *kc.EntitlementsDoc {
	d := contracttest.DefaultEntitlementsDoc(App)
	d.Mode, d.Switches.NewLinks = mode, newLinks
	return &d
}

// judgeVector is AfterPairing's judge of c in E0: whether it asks the GET,
// the judge after it, and E0's own verdict: linked always, logged when an
// enforcing release would refuse, held at observe when the document then
// held says enforce.
func judgeVector(c linkVector) (asks bool, j linkJudge) {
	held := c.Held != nil
	asks = !held || (c.FreshMinutes != nil && time.Duration(*c.FreshMinutes)*time.Minute > linkFreshFor)
	if held {
		j.Doc = vectorDoc(c.Held.Mode, c.Held.NewLinks)
	}
	if !asks {
		return asks, j
	}
	switch c.Get {
	case "doc":
		j.Doc = vectorDoc(c.GetDoc.Mode, c.GetDoc.NewLinks)
	case "not_found":
		j.NotFound = true
	default:
		j.Stale, j.NoDocument = held, !held
	}
	return asks, j
}

// TestLinksVectorsObserve: every case of wire-entitlements.json's links
// taken in E0. A case whose workspace does not enforce is taken as
// recorded: linked, logged as recorded. A refuse_link case needs an
// enforcing release (E2's): E0 links it and logs it, held at observe where
// the document says enforce (its automatic brake), the GET answering
// enforce with new links off at release observe among them.
func TestLinksVectorsObserve(t *testing.T) {
	var v struct {
		Links []json.RawMessage `json:"links"`
	}
	readVectors(t, "wire-entitlements.json", &v)
	if len(v.Links) != 17 {
		t.Fatalf("%d links cases, the design counted 17", len(v.Links))
	}
	for _, raw := range v.Links {
		var c linkVector
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		asks, j := judgeVector(c)
		if asks != c.Asks {
			t.Errorf("%s: asks %v, want %v", c.Name, asks, c.Asks)
		}
		reason := j.wouldRefuse(actLink)
		switch c.Action {
		case "link":
			if logged := reason != ""; logged != c.Logged {
				t.Errorf("%s: logged %v (%q), want %v", c.Name, logged, reason, c.Logged)
			}
		case "refuse_link":
			if reason == "" {
				t.Errorf("%s: E0 links it and logs nothing", c.Name)
			}
			if c.Release == store.EntObserve && c.GetDoc != nil && c.GetDoc.Mode == kc.ModeEnforce && !j.enforcing() {
				t.Errorf("%s: not held at observe", c.Name)
			}
		default:
			t.Errorf("%s: action %q", c.Name, c.Action)
		}
	}
}

// TestLinkJudgeReasons: no place by Wappie's own count, a move past the
// allowance, and used_up in a workspace on trial, each in its order.
func TestLinkJudgeReasons(t *testing.T) {
	doc := vectorDoc(kc.ModeObserve, kc.SwitchOn)
	doc.Places.Total = 2
	one, two := int64(1), int64(2)
	if r := (linkJudge{Doc: doc, Others: &one}).wouldRefuse(actLink); r != "" {
		t.Fatalf("a place free: %q", r)
	}
	if r := (linkJudge{Doc: doc, Others: &two}).wouldRefuse(actLink); r != refuseNoPlace {
		t.Fatalf("no place: %q", r)
	}
	if r := (linkJudge{Doc: doc, Others: &one, OverAllowance: true}).wouldRefuse(actMove); r != refuseAllowance {
		t.Fatalf("past the allowance: %q", r)
	}
	if r := (linkJudge{Doc: doc, Others: &one, OverAllowance: true}).wouldRefuse(actLink); r != "" {
		t.Fatalf("the allowance on a link: %q", r)
	}
	usedUp := &kc.LinkCheckAnswer{Trial: kc.TrialUsedUp, Switches: kc.LinkCheckSwitches{NewLinks: kc.SwitchOn}}
	if r := (linkJudge{Doc: doc, Others: &one, Answer: usedUp}).wouldRefuse(actLink); r != "" {
		t.Fatalf("used_up off trial: %q", r)
	}
	ends := kc.T(time.Now().Add(time.Hour))
	doc.State.TrialEndsAt = &ends
	if r := (linkJudge{Doc: doc, Others: &one, Answer: usedUp}).wouldRefuse(actLink); r != refuseUsedUp {
		t.Fatalf("used_up on trial: %q", r)
	}
	off := &kc.LinkCheckAnswer{Trial: kc.TrialNotNeeded, Switches: kc.LinkCheckSwitches{NewLinks: kc.SwitchOff}}
	if r := (linkJudge{Doc: doc, Others: &one, Answer: off}).wouldRefuse(actLink); r != refuseNewLinksOff {
		t.Fatalf("the answer's new_links off: %q", r)
	}
}

// TestLinkCheckVectors: wire-link-check.json's requests, decoded strictly
// and validated for their app, and Wappie's own request of each valid
// Wappie case's codes the same body; its answers as an app reads them.
func TestLinkCheckVectors(t *testing.T) {
	var v struct {
		Requests []struct {
			Name  string          `json:"name"`
			App   string          `json:"app"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"requests"`
		Answers []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"answers"`
	}
	readVectors(t, "wire-link-check.json", &v)
	ours := 0
	for _, c := range v.Requests {
		var lc kc.LinkCheck
		valid := len(c.Value) <= kc.LinkCheckBodyLimit && kc.DecodeStrict(c.Value, &lc) == nil && lc.ValidateFor(c.App) == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
		}
		if !valid || c.App != App || lc.Connected {
			continue
		}
		mine := kc.LinkCheck{Kind: kc.ItemNumber, Codes: lc.Codes}
		b, err := json.Marshal(mine)
		if err != nil {
			t.Fatal(err)
		}
		if canonical(t, b) != canonical(t, c.Value) {
			t.Errorf("%s: Wappie's request %s", c.Name, b)
		}
		ours++
	}
	if ours == 0 {
		t.Fatal("no Wappie request")
	}
	for _, c := range v.Answers {
		var a kc.LinkCheckAnswer
		valid := json.Unmarshal(c.Value, &a) == nil && a.Validate() == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
		}
	}
}

// linkWorld is a snapshot world whose entitlements part observes, with a
// key installed and the link check's short timings.
func linkWorld(t *testing.T) *snapshotWorld {
	t.Helper()
	w := newSnapshotWorld(t)
	w.installKey(t, w.trialKMS(t))
	w.members.LinkTimings = linkTimes()
	l := w.entLeader(t, w.logs, entTimes())
	l.Trial = trialTimes()
	run(t, l)
	w.applied(t, w.team, 1)
	eventually(t, soon, "the key opened", func() bool { return len(w.logs.Lines("contract: trial key opened")) == 1 })
	return w
}

// TestLinkCheckAfterPairingLogsOnly: Linked returns at once whatever the
// check does; it records the link, sends the check with both codes before
// the GET it asks for an absent document completes, logs the answer with
// no code, and holds nothing back; a rate_limited answer is logged and
// not retried.
func TestLinkCheckAfterPairingLogsOnly(t *testing.T) {
	w := linkWorld(t)
	ctx := context.Background()
	d, err := store.NewDevices(w.pool).Create(ctx, w.team.String(), "Loja", "passive")
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	// No document held: the GET goes, and waits until the check came.
	if _, err := w.pool.Exec(ctx, `DELETE FROM contract_ent_docs WHERE workspace_id = $1`, w.team); err != nil {
		t.Fatal(err)
	}
	checkFirst := make(chan bool, 1)
	w.fake.Before(contracttest.CallEntitlementsDoc, func(string) {
		deadline := time.Now().Add(3 * time.Second)
		for w.fake.Count(contracttest.CallLinkCheck) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		select {
		case checkFirst <- w.fake.Count(contracttest.CallLinkCheck) > 0:
		default:
		}
	})
	w.fake.Before(contracttest.CallLinkCheck, func(string) { time.Sleep(300 * time.Millisecond) })
	start := time.Now()
	w.members.Linked(ctx, w.team, device, &w.owner, testIdentity(20))
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("Linked held the pairing %v", took)
	}
	eventually(t, soon, "the link check logged", func() bool {
		return len(w.logs.Lines("contract: link check", "workspace="+w.team.String(), "device="+device.String(), "trial=not_needed")) == 1
	})
	if first := <-checkFirst; !first {
		t.Fatal("the GET completed before the check was sent")
	}
	if r := w.rowsOf(t, w.team, device, "linked"); len(r) != 1 {
		t.Fatalf("item.linked: %v", r)
	}
	w.fake.Before(contracttest.CallEntitlementsDoc, nil)
	w.fake.Before(contracttest.CallLinkCheck, nil)

	// rate_limited: logged, not retried.
	w.fake.RefuseAlways(contracttest.CallLinkCheck, kc.CodeRateLimited)
	checks := w.fake.Count(contracttest.CallLinkCheck)
	other := w.linkNumber(t, w.team, &w.owner, 21)
	w.members.AfterPairing(ctx, w.team, other, testIdentity(21))
	if len(w.logs.Lines("contract: link check failed", "device="+other.String())) != 1 {
		t.Fatalf("the failure's line:\n%s", w.logs.String())
	}
	if n := w.fake.Count(contracttest.CallLinkCheck) - checks; n != 1 {
		t.Fatalf("%d checks for one link", n)
	}
	w.fake.RefuseAlways(contracttest.CallLinkCheck, "")
	n, err := w.contract.LinkChecks(ctx)
	if err != nil || n.Answered < 1 || n.Failed != 1 {
		t.Fatalf("the checks kept: %+v %v", n, err)
	}
	assertNoKeyMaterial(t, w.logs.String())
}

// TestLinkWouldBeRefusedLogged: a link into a workspace whose document
// has new_links off logs what an enforcing release would refuse; the link
// stays.
func TestLinkWouldBeRefusedLogged(t *testing.T) {
	w := linkWorld(t)
	ctx := context.Background()
	v, err := w.fake.SetEntitlements(App, w.team.String(), teamDoc(kc.ModeObserve, kc.SwitchNewLinks))
	if err != nil {
		t.Fatal(err)
	}
	w.applied(t, w.team, v)
	device := w.linkNumber(t, w.team, &w.owner, 22)
	w.members.AfterPairing(ctx, w.team, device, testIdentity(22))
	if lines := w.logs.Lines("contract: link would be refused (observe)", "device="+device.String(), "act=link",
		"reason=new_links_off"); len(lines) != 1 {
		t.Fatalf("the line:\n%s", w.logs.String())
	}
	if r := w.rowsOf(t, w.team, device, "linked"); len(r) != 1 {
		t.Fatalf("the link: %v", r)
	}
}

// TestRelinkWouldBeRefusedLogged: a relink follows the last applied
// document's new_links alone: off, it is logged, with no GET and no check.
func TestRelinkWouldBeRefusedLogged(t *testing.T) {
	w := linkWorld(t)
	ctx := context.Background()
	gets, checks := w.fake.Count(contracttest.CallEntitlementsDoc), w.fake.Count(contracttest.CallLinkCheck)
	w.members.Relinked(ctx, w.team, w.device)
	if len(w.logs.Lines("act=relink")) != 0 {
		t.Fatal("a relink with new_links on was logged")
	}
	v, err := w.fake.SetEntitlements(App, w.team.String(), teamDoc(kc.ModeObserve, kc.SwitchNewLinks))
	if err != nil {
		t.Fatal(err)
	}
	w.applied(t, w.team, v)
	gets = w.fake.Count(contracttest.CallEntitlementsDoc)
	w.members.Relinked(ctx, w.team, w.device)
	if lines := w.logs.Lines("contract: link would be refused (observe)", "act=relink", "reason=new_links_off"); len(lines) != 1 {
		t.Fatalf("the line:\n%s", w.logs.String())
	}
	if w.fake.Count(contracttest.CallEntitlementsDoc) != gets || w.fake.Count(contracttest.CallLinkCheck) != checks {
		t.Fatal("a relink asked the platform")
	}
}

// TestMoveWouldBeRefusedLogged: a move's check, before its transaction,
// logs new_links off, the moved bytes past the allowance and no place by
// Wappie's own count, each with no figure; it holds no workspace's row.
func TestMoveWouldBeRefusedLogged(t *testing.T) {
	w := linkWorld(t)
	ctx := context.Background()
	w.applied(t, w.home, 1)
	move := func(moved int64) string {
		t.Helper()
		before := len(w.logs.Lines("act=move"))
		// No workspace's row is held while it runs: another transaction
		// takes both at once.
		w.fake.Before(contracttest.CallLinkCheck, func(string) {
			tx, err := w.pool.Begin(ctx)
			if err != nil {
				return
			}
			defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // read only
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
				t.Error(err)
				return
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id IN ($1, $2) FOR UPDATE`, w.team, w.home); err != nil {
				t.Errorf("a workspace's row is held during the move's check: %v", err)
			}
		})
		w.members.BeforeMove(ctx, w.team, w.home, w.device, moved)
		w.fake.Before(contracttest.CallLinkCheck, nil)
		lines := w.logs.Lines("act=move")
		if len(lines) == before {
			return ""
		}
		return lines[len(lines)-1]
	}
	doc := contracttest.DefaultEntitlementsDoc(App)
	doc.State.Since = kc.T(time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond))
	doc.Plan = kc.EntitlementsPlan{Source: kc.SourcePlan, Numbers: 5, Mailboxes: 0, Packs: 1}
	doc.Places.Total = 5
	doc.Storage.QuotaBytes, doc.Storage.AllowanceBytes, doc.Storage.CapBytes = 1_000_000, 1_000_000, 1_050_000
	publish := func(d kc.EntitlementsDoc) {
		t.Helper()
		v, err := w.fake.SetEntitlements(App, w.home.String(), d)
		if err != nil {
			t.Fatal(err)
		}
		w.applied(t, w.home, v)
	}
	publish(doc)
	if line := move(10); strings.Contains(line, "would be refused") {
		t.Fatalf("a move that fits: %s", line)
	}
	if line := move(987_654_321); !strings.Contains(line, "reason=allowance") {
		t.Fatalf("past the allowance: %q\n%s", line, w.logs.String())
	}
	doc.Places.Total = 0
	doc.Plan = kc.EntitlementsPlan{Source: kc.SourceNone}
	publish(doc)
	if line := move(10); !strings.Contains(line, "reason=no_place") || !strings.Contains(line, "count=hosted_only") {
		t.Fatalf("no place: %q", line)
	}
	doc.Switches.NewLinks = kc.SwitchOff
	publish(doc)
	if line := move(10); !strings.Contains(line, "reason=new_links_off") {
		t.Fatalf("new_links off: %q", line)
	}
	for _, figure := range []string{"987654321", "1000000", "1050000"} {
		if strings.Contains(w.logs.String(), figure) {
			t.Fatalf("a figure is in the log: %s", figure)
		}
	}
}
