package store_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	kitvectors "github.com/thehappieco/kit/vectors"

	"whatserver2/internal/store"
)

// actionCase is one of wire-tokens.json's actions: a record as an app
// holding generation receives it, and what the app does with it.
type actionCase struct {
	Name       string          `json:"name"`
	App        string          `json:"app"`
	Generation string          `json:"generation"`
	Value      json.RawMessage `json:"value"`
	Action     string          `json:"action"`
	Code       *string         `json:"code"`
}

// TestTokenActionVectors replays the kit's 17 action cases (kit v0.9.0,
// vectors.FS's platform/contract-v1/wire-tokens.json) through
// CommitTokenPage, the case's action and code the oracle, never one derived
// from the kit's functions: each case is replayed on a workspace that holds
// no token, and on one that holds the token at a lower version with the
// grants of the case's first record, to show what it narrows.
//   - refuse: nothing stored, nothing refused, the cursor advances, logged;
//   - reset: ErrPageGeneration, nothing stored, the cursor where it was;
//   - narrow: no live row; each grant it lists refused with the code; its
//     revocation sticks; on the held token, nothing widens;
//   - revoke: the token revoked with the code as its reason, sticky, and no
//     grant left;
//   - apply: the token at the record's version with its grants pending, and
//     its reading key pinned.
func TestTokenActionVectors(t *testing.T) {
	data, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/wire-tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Kind    string       `json:"kind"`
		Actions []actionCase `json:"actions"`
	}
	if err := json.Unmarshal(data, &v); err != nil || v.Kind != "wire-tokens" || len(v.Actions) != 17 {
		t.Fatalf("not the token wire vectors: %q, %d actions, %v", v.Kind, len(v.Actions), err)
	}
	// The case every other is replayed against: the token, held.
	base := v.Actions[0]
	if base.Action != "apply" {
		t.Fatalf("the first case is %q, not a record to apply", base.Action)
	}
	var baseRec struct {
		ID          string `json:"id"`
		WorkspaceID string `json:"workspace_id"`
		CreatedBy   string `json:"created_by"`
		Selector    string `json:"selector"`
		Items       []struct {
			ID    string `json:"id"`
			Perms []struct {
				Perm      string `json:"perm"`
				GrantedBy string `json:"granted_by"`
			} `json:"perms"`
		} `json:"items"`
	}
	if err := json.Unmarshal(base.Value, &baseRec); err != nil {
		t.Fatal(err)
	}
	token, number := uuid.MustParse(baseRec.ID), uuid.MustParse(baseRec.Items[0].ID)
	// The world the vectors name: their workspace, its owner (the
	// creator), the number, and the other giver, linked.
	world := func(t *testing.T, app string) *tokenWorld {
		w := newTokenWorldIn(t, uuid.MustParse(baseRec.WorkspaceID), uuid.MustParse(baseRec.CreatedBy))
		w.exec(`UPDATE contract_state SET generation = $1`, base.Generation)
		w.gen = uuid.MustParse(base.Generation)
		w.exec(`UPDATE contract_accounts SET generation = $1`, w.gen)
		w.number(number)
		for _, p := range baseRec.Items[0].Perms {
			if p.GrantedBy != baseRec.CreatedBy {
				w.linked("giver", "admin", uuid.MustParse(p.GrantedBy), true)
			}
		}
		if app != "wappie" {
			w.tokens.SetAppForTest(app)
		}
		return w
	}
	// hold commits the first case's record at version 3.
	hold := func(t *testing.T, w *tokenWorld) {
		var m map[string]any
		if err := json.Unmarshal(base.Value, &m); err != nil {
			t.Fatal(err)
		}
		m["version"] = 3
		w.page(false, raw(t, m))
		if s := w.token(token); !s.Exists || *s.Version != 3 || len(w.perms(token)) != 2 {
			t.Fatalf("the held token: %+v %v", s, w.perms(token))
		}
	}
	// What the case's record lists and revokes, from its JSON as written.
	type listed struct {
		version int64
		revokes bool
		grants  []string
		key     bool
	}
	read := func(c actionCase) listed {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(c.Value, &m); err != nil {
			t.Fatal(err)
		}
		var l listed
		_ = json.Unmarshal(m["version"], &l.version)
		l.revokes = len(m["revoked_reason"]) > 0 && string(m["revoked_reason"]) != "null"
		l.key = len(m["reading_key"]) > 0 && string(m["reading_key"]) != "null"
		var items []struct {
			ID    string `json:"id"`
			Perms []struct {
				Perm string `json:"perm"`
			} `json:"perms"`
		}
		_ = json.Unmarshal(m["items"], &items)
		for _, it := range items {
			for _, p := range it.Perms {
				l.grants = append(l.grants, it.ID+"/"+p.Perm)
			}
		}
		slices.Sort(l.grants)
		return l
	}
	seen := map[string]int{}
	for _, c := range v.Actions {
		seen[c.Action]++
		l := read(c)
		for _, held := range []bool{false, true} {
			if held && c.App != base.App {
				// A record as another app receives it: the held token is
				// Wappie's.
				continue
			}
			name := c.Name
			if held {
				name += ", over the token held"
			}
			t.Run(name, func(t *testing.T) {
				w := world(t, c.App)
				if held {
					hold(t, w)
				}
				before, perms := w.cursor(), w.perms(token)
				res, err := w.tryPage(false, c.Value)
				if c.Action == "reset" {
					if !errors.Is(err, store.ErrPageGeneration) || w.cursor() != before {
						t.Fatalf("a reset: %v, the cursor %d (was %d)", err, w.cursor(), before)
					}
					if held && len(w.perms(token)) != 2 || !held && w.token(token).Exists {
						t.Fatal("a reset's record was stored")
					}
					return
				}
				if err != nil || !res.Committed || w.cursor() != before+1 {
					t.Fatalf("the page: %+v %v, the cursor %d (was %d)\n%s", res, err, w.cursor(), before, w.logs.String())
				}
				s := w.token(token)
				exists, revoked, _ := w.sticky(token)
				refused := w.refused(token)
				switch c.Action {
				case "refuse":
					if s.Exists != held || exists || len(refused) != 0 || !strings.Contains(w.logs.String(), "another app") {
						t.Fatalf("a refused record left something: %+v sticky %v refused %v\n%s", s, exists, refused, w.logs.String())
					}
					if held && (s.Revoked || len(w.perms(token)) != 2) {
						t.Fatalf("another app's revocation reached the token: %+v", s)
					}
				case "narrow":
					if c.Code == nil {
						t.Fatal("a narrow case with no code")
					}
					if !held && s.Exists {
						t.Fatalf("a bad record made a live row: %+v", s)
					}
					if held && (*s.Version != 3 || len(w.perms(token)) > len(perms)) {
						t.Fatalf("a bad record widened: %+v %v", s, w.perms(token))
					}
					if exists != l.revokes || (held && s.Revoked != l.revokes) {
						t.Fatalf("its revocation (%v): sticky %v %v, token %+v", l.revokes, exists, revoked, s)
					}
					var want []string
					if !held {
						for _, g := range l.grants {
							want = append(want, g+"="+*c.Code+"@4")
						}
					}
					if !slices.Equal(refused, want) {
						t.Fatalf("its refusals: %v, want %v", refused, want)
					}
				case "revoke":
					if c.Code == nil || !s.Exists || !s.Revoked || s.Reason == nil || *s.Reason != *c.Code || !exists || !revoked ||
						len(w.perms(token)) != 0 || len(refused) != 0 {
						t.Fatalf("a revocation: %+v (want %v) sticky %v %v perms %v refused %v", s, c.Code, exists, revoked, w.perms(token), refused)
					}
				case "apply":
					if !s.Exists || s.Revoked || *s.Version != l.version || len(refused) != 0 {
						t.Fatalf("an applied record: %+v refused %v", s, refused)
					}
					var got []string
					for k, state := range w.perms(token) {
						if state != "pending" {
							t.Errorf("%s: %s", k, state)
						}
						got = append(got, k)
					}
					slices.Sort(got)
					if !slices.Equal(got, l.grants) {
						t.Fatalf("its grants: %v, want %v", got, l.grants)
					}
					// The held token's first record pinned a key, and a null
					// key leaves a pin.
					if pinned := w.count(`SELECT count(*) FROM contract_token_pins WHERE token_id = $1`, token) == 1; pinned != (l.key || held) {
						t.Fatalf("its pin: %v, want %v", pinned, l.key || held)
					}
				default:
					t.Fatalf("an action Wappie does not know: %q", c.Action)
				}
			})
		}
	}
	for _, a := range []string{"refuse", "reset", "narrow", "revoke", "apply"} {
		if seen[a] == 0 {
			t.Errorf("no case shows %s", a)
		}
	}
}
