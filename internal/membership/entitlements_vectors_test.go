package membership

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"
	kitvectors "github.com/thehappieco/kit/vectors"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The contract's part-15 vectors (kit v0.12.0): pinned by sha256, so a kit
// bump that changes one is seen here first, and wire-entitlements.json
// taken through Wappie's own judging and its real store.

// part15Vectors are the nine files of part 15 and their sha256, as the E0
// build design pins them (its 2.5).
var part15Vectors = map[string]string{
	"wire-entitlements.json": "118708c7304e5ec0a29f63d49b020adf76ce7501438ca7d5033a21b86308a4e5",
	"wire-usage.json":        "bb8787b65f459ac59a4ea3e31aa898d37fd11fdd0799291398ffb85fa8ae5ba2",
	"usage-dates.json":       "d0645f87a0c44ee8c7425d47a6e3dd7d57b213ef9308d7ef60e758b0f7f89c47",
	"trial-codes.json":       "3f5096f537cd84b655dec106ec7cd601bbba80a770746be86a5332a612670bb4",
	"wire-link-check.json":   "6c8c6799bd15aa318ef404466299d20bef15132df2f87d146d6ef001e63b6655",
	"wire-events-codes.json": "2a5368ee2729ffdd6099ce86fc5f148358bff2a535c96925f1ec34dc5bbff9c8",
	"wire-v012.json":         "2c0be71eff8f1deef3ebe2bc7ab6c2fc9a15bdf066dcf53bdabf062d85787d60",
	"wire-trim.json":         "638b67f840fb2840dce2b5cc5c0ad23581998607029cc7fd7e9aeb5ceab3296b",
	"trim-macs.json":         "d9f7f4221cd06aa1dd7bb4e305201c9c62a0f6998adf0d2b841dd18ce2e776ab",
}

// TestPart15VectorsPinned: each of the nine files, read through the kit's
// embedded vectors, has the sha256 the design pinned.
func TestPart15VectorsPinned(t *testing.T) {
	for name, want := range part15Vectors {
		raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/"+name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: sha256 %s, pinned %s", name, got, want)
		}
	}
}

// entVectors is wire-entitlements.json, each section as Wappie takes it.
type entVectors struct {
	Documents []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"documents"`
	Feeds []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"feeds"`
	Applied []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
		Valid bool            `json:"valid"`
	} `json:"applied"`
	Actions []struct {
		Name       string            `json:"name"`
		Generation string            `json:"generation"`
		Known      []string          `json:"known"`
		Held       map[string]int64  `json:"held"`
		Value      json.RawMessage   `json:"value"`
		Action     string            `json:"action"`
		Refused    *entVectorRefused `json:"refused"`
		Through    *int64            `json:"through"`
	} `json:"actions"`
	Gets []struct {
		Name       string          `json:"name"`
		Generation string          `json:"generation"`
		Workspace  string          `json:"workspace"`
		Held       int64           `json:"held"`
		Status     string          `json:"status"`
		Value      json.RawMessage `json:"value"`
		Action     string          `json:"action"`
		Fresh      bool            `json:"fresh"`
	} `json:"gets"`
	Sequences []struct {
		Name       string           `json:"name"`
		Generation string           `json:"generation"`
		Known      []string         `json:"known"`
		Held       map[string]int64 `json:"held"`
		Steps      []struct {
			Source    string          `json:"source"`
			Workspace string          `json:"workspace"`
			Status    string          `json:"status"`
			Value     json.RawMessage `json:"value"`
			Action    string          `json:"action"`
			HeldBack  []string        `json:"held_back"`
		} `json:"steps"`
	} `json:"sequences"`
	Versions []struct {
		Name string          `json:"name"`
		Feed json.RawMessage `json:"feed"`
		Get  json.RawMessage `json:"get"`
		Same bool            `json:"same"`
	} `json:"versions"`
	Resets []struct {
		Name   string         `json:"name"`
		Before entVectorState `json:"before"`
		Gen    string         `json:"generation"`
		After  entVectorState `json:"after"`
	} `json:"resets"`
	Freeze []struct {
		Name       string   `json:"name"`
		App        string   `json:"app"`
		Cause      string   `json:"cause"`
		At         kc.Time  `json:"at"`
		Now        kc.Time  `json:"now"`
		FreshAt    kc.Time  `json:"fresh_at"`
		StopsAt    *kc.Time `json:"stops_at"`
		PlanSource string   `json:"plan_source"`
		InPlace    bool     `json:"in_place"`
		Action     string   `json:"action"`
	} `json:"freeze"`
	Caps []struct {
		Name     string `json:"name"`
		CapBytes int64  `json:"cap_bytes"`
	} `json:"caps"`
	CapStops []struct {
		Name       string `json:"name"`
		TotalBytes int64  `json:"total_bytes"`
		CapBytes   int64  `json:"cap_bytes"`
		Action     string `json:"action"`
	} `json:"cap_stops"`
	Links       []json.RawMessage `json:"links"`
	CodesAfter  []json.RawMessage `json:"codes_after"`
	Places      []json.RawMessage `json:"places"`
	TrialStops  []json.RawMessage `json:"trial_stops"`
	PlacedAt    []json.RawMessage `json:"placed_at"`
	LinkOutcome []json.RawMessage `json:"link_outcomes"`
}

type entVectorRefused struct {
	Seq         int64   `json:"seq"`
	WorkspaceID *string `json:"workspace_id"`
	Code        string  `json:"code"`
}

type entVectorState struct {
	Generation string                     `json:"generation"`
	Cursor     int64                      `json:"cursor"`
	Versions   map[string]int64           `json:"versions"`
	Applied    map[string]json.RawMessage `json:"applied"`
	CodesAfter map[string]string          `json:"codes_after"`
}

// entVectorStore is one database the actions, gets and sequences cases run
// on, emptied before each.
type entVectorStore struct {
	pool *pgxpool.Pool
	c    *store.Contract
}

func newEntVectorStore(t *testing.T) entVectorStore {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	if _, err := c.SetMode(context.Background(), store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	return entVectorStore{pool: pool, c: c}
}

// seed empties the part, records the workspaces known as named by an
// account document, and holds, for generation gen, a document of each
// workspace of held at its version, applied where it is named.
func (s entVectorStore) seed(t *testing.T, gen string, known []string, held map[string]int64) {
	t.Helper()
	ctx := context.Background()
	for _, sql := range []string{`DELETE FROM contract_ent_docs`, `DELETE FROM contract_ent_refusals`, `DELETE FROM contract_ent_brakes`,
		`DELETE FROM contract_workspaces`,
		`UPDATE contract_ent_state SET feed_cursor = 0, published_through = NULL, unreadable_get_next_at = NULL, ack_urgent = false`} {
		if _, err := s.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, gen); err != nil {
		t.Fatal(err)
	}
	for _, ws := range known {
		if _, err := s.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, ws); err != nil {
			t.Fatal(err)
		}
	}
	for ws, v := range held {
		if _, err := s.pool.Exec(ctx, `INSERT INTO contract_ent_docs (workspace_id, generation, version, doc, mode, received_at, applied_at)
			VALUES ($1, $2, $3, '{}', 'observe', clock_timestamp(), CASE WHEN $4 THEN clock_timestamp() END)`,
			ws, gen, v, slices.Contains(known, ws)); err != nil {
			t.Fatal(err)
		}
	}
}

// page takes a page as the follower does: validated, then each item judged
// alone; another generation is a reset. It returns the action of its one
// item (or invalid, reset) and the refusal.
func (s entVectorStore) page(t *testing.T, raw json.RawMessage) (string, *store.EntRefusal) {
	t.Helper()
	ctx := context.Background()
	var f kc.EntitlementsFeed
	if json.Unmarshal(raw, &f) != nil || f.Validate() != nil {
		return "invalid", nil
	}
	st, err := s.c.EntState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := uuid.Parse(f.Generation)
	if err != nil || gen != *st.Generation {
		return store.EntReset, nil
	}
	p := judgeEntPage(f, gen, st.FeedCursor)
	res, err := s.c.CommitEntPage(ctx, p)
	if err != nil || !res.Committed || len(res.Items) != 1 {
		t.Fatalf("the page: %+v %v", res, err)
	}
	return res.Items[0].Action, res.Items[0].Refused
}

// get takes a GET's answer as the kit's client and the gets loop do: a
// document that fails Validate, or names another app or workspace, is
// refused; a signed not_found freezes; another refusal changes nothing.
func (s entVectorStore) get(t *testing.T, ws, status string, raw json.RawMessage) string {
	t.Helper()
	ctx := context.Background()
	switch status {
	case "200":
	case kc.CodeNotFound:
		id := uuid.MustParse(ws)
		if _, err := s.c.EntNotFound(ctx, id, time.Second); err != nil {
			t.Fatal(err)
		}
		return "not_found"
	default:
		return "none"
	}
	var d kc.EntitlementsDoc
	if json.Unmarshal(raw, &d) != nil || d.Validate() != nil || d.App != App || d.WorkspaceID != ws {
		return EntRefuseGet
	}
	doc, ok := store.NewEntDoc(d, raw, true)
	if !ok {
		t.Fatalf("the document's ids: %v", d)
	}
	res, err := s.c.EntGotDoc(ctx, doc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return res.Action
}

// EntRefuseGet is a GET's answer the kit refuses (the vectors' refuse).
const EntRefuseGet = "refuse"

// heldBack are the workspaces whose feed freshness a bad document holds
// back, in order.
func (s entVectorStore) heldBack(t *testing.T) []string {
	t.Helper()
	_, rows, err := s.c.EntRows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, r := range rows {
		if r.FeedHeldBack {
			out = append(out, r.Workspace.String())
		}
	}
	slices.Sort(out)
	return out
}

func TestEntitlementsVectors(t *testing.T) {
	var v entVectors
	readVectors(t, "wire-entitlements.json", &v)
	for name, c := range map[string]struct{ got, want int }{
		"documents": {len(v.Documents), 162}, "feeds": {len(v.Feeds), 28}, "applied": {len(v.Applied), 21},
		"actions": {len(v.Actions), 18}, "gets": {len(v.Gets), 10}, "sequences": {len(v.Sequences), 6},
		"versions": {len(v.Versions), 4}, "links": {len(v.Links), 17}, "resets": {len(v.Resets), 2},
		"freeze": {len(v.Freeze), 17}, "caps": {len(v.Caps), 14}, "codes_after": {len(v.CodesAfter), 6},
		"places": {len(v.Places), 13}, "trial_stops": {len(v.TrialStops), 10}, "cap_stops": {len(v.CapStops), 6},
		"placed_at": {len(v.PlacedAt), 9}, "link_outcomes": {len(v.LinkOutcome), 13},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d cases, the design counted %d", name, c.got, c.want)
		}
	}

	t.Run("documents", func(t *testing.T) {
		for _, c := range v.Documents {
			var d kc.EntitlementsDoc
			valid := json.Unmarshal(c.Value, &d) == nil && d.Validate() == nil
			if valid != c.Valid {
				t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
			}
		}
	})
	t.Run("feeds", func(t *testing.T) {
		for _, c := range v.Feeds {
			var f kc.EntitlementsFeed
			valid := json.Unmarshal(c.Value, &f) == nil && f.Validate() == nil
			if valid != c.Valid {
				t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
			}
		}
	})
	t.Run("applied", func(t *testing.T) {
		for _, c := range v.Applied {
			var a kc.EntitlementsApplied
			valid := kc.DecodeStrict(c.Value, &a) == nil && a.Validate() == nil
			if valid != c.Valid {
				t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
			}
		}
	})

	s := newEntVectorStore(t)
	t.Run("actions", func(t *testing.T) {
		for _, c := range v.Actions {
			s.seed(t, c.Generation, c.Known, c.Held)
			action, ref := s.page(t, c.Value)
			if action != c.Action {
				t.Errorf("%s: %s, want %s", c.Name, action, c.Action)
				continue
			}
			if c.Refused != nil {
				got := entVectorRefused{Seq: ref.Seq, Code: ref.Code}
				if ref.Workspace != nil {
					ws := ref.Workspace.String()
					got.WorkspaceID = &ws
				}
				if got.Seq != c.Refused.Seq || got.Code != c.Refused.Code ||
					(got.WorkspaceID == nil) != (c.Refused.WorkspaceID == nil) ||
					(got.WorkspaceID != nil && *got.WorkspaceID != *c.Refused.WorkspaceID) {
					t.Errorf("%s: refused %+v, want %+v", c.Name, got, *c.Refused)
				}
			}
			if c.Through != nil {
				a, ok, err := s.c.EntAckDue(context.Background())
				if err != nil || !ok || a.Through != *c.Through {
					t.Errorf("%s: acknowledged through %d (%v %v), want %d", c.Name, a.Through, ok, err, *c.Through)
				}
				if c.Refused != nil && (len(a.Refused) != 1 || a.Refused[0].Seq != c.Refused.Seq) {
					t.Errorf("%s: the acknowledgement lists %+v", c.Name, a.Refused)
				}
			}
		}
	})
	t.Run("gets", func(t *testing.T) {
		for _, c := range v.Gets {
			s.seed(t, c.Generation, []string{c.Workspace}, map[string]int64{c.Workspace: c.Held})
			action := s.get(t, c.Workspace, c.Status, c.Value)
			if action != c.Action {
				t.Errorf("%s: %s, want %s", c.Name, action, c.Action)
				continue
			}
			r, _, err := s.c.EntRow(context.Background(), uuid.MustParse(c.Workspace))
			if err != nil {
				t.Fatal(err)
			}
			if fresh := r.GetFreshAt != nil; fresh != c.Fresh {
				t.Errorf("%s: fresh %v, want %v", c.Name, fresh, c.Fresh)
			}
			if c.Action == "not_found" && (r.NotFoundSince == nil || r.Version == nil || *r.Version != c.Held) {
				t.Errorf("%s: the last document does not hold, frozen: %+v", c.Name, r)
			}
		}
	})
	t.Run("sequences", func(t *testing.T) {
		for _, c := range v.Sequences {
			s.seed(t, c.Generation, c.Known, c.Held)
			for i, step := range c.Steps {
				var action string
				if step.Source == "page" {
					action, _ = s.page(t, step.Value)
				} else {
					action = s.get(t, step.Workspace, step.Status, step.Value)
				}
				want := append([]string{}, step.HeldBack...)
				slices.Sort(want)
				if got := s.heldBack(t); action != step.Action || !slices.Equal(got, want) {
					t.Errorf("%s, step %d: %s held back %v, want %s %v", c.Name, i+1, action, got, step.Action, want)
				}
			}
		}
	})
	t.Run("resets", func(t *testing.T) {
		ctx := context.Background()
		for _, c := range v.Resets {
			s.seed(t, c.Before.Generation, nil, c.Before.Versions)
			for ws, raw := range c.Before.Applied {
				if _, err := s.pool.Exec(ctx, `UPDATE contract_ent_docs SET doc = $2, mode = 'enforce' WHERE workspace_id = $1`, ws, []byte(raw)); err != nil {
					t.Fatal(err)
				}
			}
			for ws, at := range c.Before.CodesAfter {
				if _, err := s.pool.Exec(ctx, `UPDATE contract_ent_docs SET codes_after_answered = $2 WHERE workspace_id = $1`, ws, at); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.pool.Exec(ctx, `UPDATE contract_ent_state SET feed_cursor = $1`, c.Before.Cursor); err != nil {
				t.Fatal(err)
			}
			gen := uuid.MustParse(c.Gen)
			if done, err := s.c.RestartFromEntitlements(ctx, uuid.MustParse(c.Before.Generation), &gen); err != nil || !done {
				t.Fatalf("%s: the reset: %v %v", c.Name, done, err)
			}
			st, rows, err := s.c.EntRows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if st.Generation == nil || st.Generation.String() != c.After.Generation || st.FeedCursor != c.After.Cursor {
				t.Errorf("%s: the state after: %+v", c.Name, st)
			}
			for _, r := range rows {
				if r.Version != nil {
					t.Errorf("%s: %s keeps its version", c.Name, r.Workspace)
				}
				if raw, ok := c.After.Applied[r.Workspace.String()]; ok && !bytes.Equal(r.Doc, raw) {
					t.Errorf("%s: %s lost its applied document", c.Name, r.Workspace)
				}
			}
			var answered int
			if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM contract_ent_docs WHERE codes_after_answered IS NOT NULL`).Scan(&answered); err != nil ||
				answered != len(c.After.CodesAfter) {
				t.Errorf("%s: %d codes_after kept, want %d (%v)", c.Name, answered, len(c.After.CodesAfter), err)
			}
		}
	})

	t.Run("versions", func(t *testing.T) {
		// Wappie keeps a feed document's bytes when a GET answers its
		// version (EntGotDoc's fresh): right only when the two are the same
		// document but a trim's secret and mac, which the vectors pin.
		same := func(a, b json.RawMessage) bool {
			canon := func(raw json.RawMessage) []byte {
				var m map[string]any
				dec := json.NewDecoder(bytes.NewReader(raw))
				dec.UseNumber()
				if dec.Decode(&m) != nil {
					return nil
				}
				if trim, ok := m["trim"].(map[string]any); ok {
					delete(trim, "secret")
					delete(trim, "mac")
				}
				out, err := jcs.Marshal(m)
				if err != nil {
					return nil
				}
				return out
			}
			return bytes.Equal(canon(a), canon(b))
		}
		for _, c := range v.Versions {
			if got := same(c.Feed, c.Get); got != c.Same {
				t.Errorf("%s: same %v, want %v", c.Name, got, c.Same)
			}
		}
	})
	t.Run("freeze", func(t *testing.T) {
		for _, c := range v.Freeze {
			fresh := c.FreshAt.Time
			stops, action := entStepAction(c.App, c.Cause, c.At.Time, c.Now.Time, &fresh, c.PlanSource, c.InPlace)
			if action != c.Action {
				t.Errorf("%s: %s, want %s", c.Name, action, c.Action)
			}
			if (stops == nil) != (c.StopsAt == nil) || (stops != nil && !stops.Equal(c.StopsAt.Time)) {
				t.Errorf("%s: stops at %v, want %v", c.Name, stops, c.StopsAt)
			}
		}
	})
	t.Run("caps and cap_stops, as would stop and would lift", func(t *testing.T) {
		for _, c := range v.Caps {
			if capSide(c.CapBytes, c.CapBytes) != capWithin || capSide(c.CapBytes+1, c.CapBytes) != capOver {
				t.Errorf("%s: the cap's sides", c.Name)
			}
		}
		for _, c := range v.CapStops {
			want := map[string]string{"stop": capOver, "lift": capWithin}[c.Action]
			if got := capSide(c.TotalBytes, c.CapBytes); got != want {
				t.Errorf("%s: %s, want %s", c.Name, got, c.Action)
			}
		}
	})
	t.Run("links", func(t *testing.T) {
		// Every case, in E0 (slice 19): TestLinksVectorsObserve runs the
		// same judge on each, its action and logged flag.
		for _, raw := range v.Links {
			var c linkVector
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			asks, j := judgeVector(c)
			reason := j.wouldRefuse(actLink)
			if asks != c.Asks || (c.Action == "link" && (reason != "") != c.Logged) || (c.Action == "refuse_link" && reason == "") {
				t.Errorf("%s: asks %v, would refuse %q", c.Name, asks, reason)
			}
		}
	})
	t.Run("codes_after", func(t *testing.T) {
		for _, raw := range v.CodesAfter {
			var c struct {
				Name         string   `json:"name"`
				LastAnswered *kc.Time `json:"last_answered"`
				CodesAfter   *kc.Time `json:"codes_after"`
				Action       string   `json:"action"`
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			var last, after *time.Time
			if c.LastAnswered != nil {
				last = &c.LastAnswered.Time
			}
			if c.CodesAfter != nil {
				after = &c.CodesAfter.Time
			}
			got := "none"
			if store.CodesAfterDue(last, after) {
				got = "send"
			}
			if got != c.Action {
				t.Errorf("%s: %s, want %s", c.Name, got, c.Action)
			}
		}
	})
	t.Run("placed_at", func(t *testing.T) {
		// Wappie's writers of placed_at (slice 19): a link, a recovery and
		// a move in set it, a relink keeps it; internal/store's
		// TestPlacedAtVectors runs each through its real path. Wappie has
		// no import (the E0 design's section 0).
		writers := map[string]string{"link": "set", "recovery": "set", "move_in": "set", "relink": "keep"}
		for _, raw := range v.PlacedAt {
			var c struct{ Name, App, Event, Action string }
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			want, ours := writers[c.Event]
			if c.App != App || !ours {
				continue
			}
			if want != c.Action {
				t.Errorf("%s: Wappie's writer would %s, want %s", c.Name, want, c.Action)
			}
		}
	})
	t.Run("E2", func(t *testing.T) {
		// Decoded above and counted; what they assert is not E0's: places
		// stops and lifts items by placed_at, trial_stops and link_outcomes
		// need the undo of a link, an enforcing release or an import. E0
		// logs a link's or a move's no_place by its own count
		// (TestLinkJudgeReasons, TestMoveWouldBeRefusedLogged).
		t.Skip("places, trial_stops, link_outcomes: E2")
	})
}

// TestWireV012Vectors: wire-v012.json's snapshots through the kit's strict
// decoding and Validate, and Wappie's own snapshot with neither server nor
// pending; its results through ValidateFor, with Wappie's own
// capacity_reached on item.sync_resume, which E0 never produces; its
// sections, Mailie's, decoded only.
func TestWireV012Vectors(t *testing.T) {
	var v struct {
		Snapshots []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"snapshots"`
		Results []struct {
			Name  string          `json:"name"`
			App   string          `json:"app"`
			Kind  string          `json:"kind"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"results"`
		Sections []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"sections"`
	}
	readVectors(t, "wire-v012.json", &v)
	if len(v.Snapshots) != 15 || len(v.Results) != 8 || len(v.Sections) != 15 {
		t.Fatalf("%d snapshots, %d results, %d sections", len(v.Snapshots), len(v.Results), len(v.Sections))
	}
	for _, c := range v.Snapshots {
		var s kc.Snapshot
		valid := kc.DecodeStrict(c.Value, &s) == nil && s.Validate() == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
		}
	}
	sawWappie := false
	for _, c := range v.Results {
		var r kc.CommandResult
		valid := kc.DecodeStrict(c.Value, &r) == nil && r.ValidateFor(c.App, c.Kind) == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v", c.Name, valid, c.Valid)
		}
		sawWappie = sawWappie || (c.App == App && c.Kind == kc.OpItemSyncResume && r.Code != nil && *r.Code == kc.CodeCapacityReached && c.Valid)
	}
	if !sawWappie {
		t.Error("no Wappie item.sync_resume capacity_reached result in the vectors")
	}
	for _, c := range v.Sections {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(c.Value, &m); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}

	// Wappie's own snapshot of seeded hosted numbers: neither member.
	ws := newSnapshotWorld(t)
	snap, ok, err := ws.contract.SnapshotNumbered(context.Background(), ws.team)
	if err != nil || !ok || len(snap.Items) == 0 {
		t.Fatalf("the snapshot: %v %v %d", ok, err, len(snap.Items))
	}
	wire := SnapshotOf(snap, snap.Seq)
	if err := wire.Validate(); err != nil {
		t.Fatalf("Wappie's snapshot: %v", err)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"server"`)) || bytes.Contains(raw, []byte(`"pending"`)) {
		t.Fatalf("Wappie's snapshot carries server or pending: %s", raw)
	}

	// E0 never answers capacity_reached: no source that answers a command
	// names the code.
	for _, dir := range []string{".", "../numberacts", "../store"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f) //nolint:gosec // G304: the packages' own sources
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(src, []byte("CodeCapacityReached")) || bytes.Contains(src, []byte(`"capacity_reached"`)) {
				t.Errorf("%s names capacity_reached: E0 never answers it", f)
			}
		}
	}
}

// TestEntitlementsTrimInObserveRefused: the vectors' observe document that
// carries a trim order is a bad document, refused invalid_document with
// its workspace; nothing of it is kept, so nothing of it can run.
func TestEntitlementsTrimInObserveRefused(t *testing.T) {
	var v entVectors
	readVectors(t, "wire-entitlements.json", &v)
	for _, c := range v.Actions {
		if !strings.HasPrefix(c.Name, "a trim order in an observe document") {
			continue
		}
		var f kc.EntitlementsFeed
		if err := json.Unmarshal(c.Value, &f); err != nil || f.Validate() != nil {
			t.Fatalf("the page: %v", err)
		}
		p := judgeEntPage(f, uuid.MustParse(c.Generation), 0)
		if len(p.Items) != 1 || p.Items[0].Doc != nil || p.Items[0].Refused == nil ||
			p.Items[0].Refused.Code != kc.RefusedInvalidDocument || p.Items[0].Refused.Workspace == nil {
			t.Fatalf("the trim in an observe document: %+v", p.Items)
		}
		return
	}
	t.Fatal("no such vector")
}
