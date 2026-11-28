package datacheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
)

// The declared expectations of plan 2.5 that Compare knows. Anything else a
// change declares is named with Expectations.Allow.
const (
	// ExpectEqual: every field equal (a restore drill, a class a change).
	ExpectEqual = "equal"
	// ExpectMigration: an additive migration or backfill. New schema
	// versions, and the columns the schema before lacked (digests' absent
	// lists shrink, their own digests and NULL counts appear); every row
	// digest and every other field equal unless allowed. Both manifests
	// come from one binary.
	ExpectMigration = "migration"
	// ExpectSeqOffset: an export round trip, a move or an import. Every
	// renumbered number's max seq (messages, receipts, events) is exactly
	// Offset higher, each workspace's last_seq at least its numbers'
	// highest, and everything else equal: the seq digests and the per-chat
	// order digests are offset-free. The renumbered numbers are Devices,
	// or every number when it names none.
	ExpectSeqOffset = "seq-offset"
	// ExpectKeyChange: a new epoch or new grants only. New archive keys and
	// grants, retired_at set on old keys, current_epoch raised, updated_at;
	// every holder of a number's old current epoch holds the new one, at
	// the new key's fingerprint; nothing removed.
	ExpectKeyChange = "key-change"
	// ExpectLIDBackfill: the first boot's LID backfill (plan 2.3 step 12).
	// Only previously NULL messages.sender_pn, chats.chat_pn and
	// contacts.contact_lid (and chats.uid, the chat uid backfill) became
	// non-NULL: their NULL counts fall, each one's own digest changes only
	// where its NULL count fell, and the storage they account changes. The
	// row digests, which cover every other column, stay equal.
	ExpectLIDBackfill = "lid-backfill"
)

// Expects lists the expectations, for usage text.
var Expects = []string{ExpectEqual, ExpectMigration, ExpectSeqOffset, ExpectKeyChange, ExpectLIDBackfill}

// Expectations are what a change declares.
type Expectations struct {
	Kind string
	// Offset is ExpectSeqOffset's offset.
	Offset int64
	// Allow are path patterns that may differ: segments split by "/", "*"
	// within one segment as path.Match has it, "**" for any number of
	// segments.
	Allow []string
	// WorkspaceMap renames a workspace of the first manifest to its id in
	// the second, for a round trip into another workspace.
	WorkspaceMap map[string]string
	// Devices are the numbers (devices.id) the change moves or renumbers.
	// Each is compared under its id in whichever workspace the second
	// manifest holds it, and with ExpectSeqOffset only they are
	// renumbered: every other number's max seq must stay equal.
	Devices []string
}

// Difference is one field that differs, or one rule a change broke.
type Difference struct {
	Path   string
	Before *string
	After  *string
	// Declared is true when the change's expectations account for it.
	Declared bool
	// Why names the rule that declares it, or what is wrong.
	Why string
}

// ErrNotManifest is input that is not a data check manifest.
var ErrNotManifest = errors.New("datacheck: not a data check manifest")

// Compare compares two manifests, as written by whatserverd datacheck, under
// exp. It returns every difference, declared or not, sorted by path, and
// every broken rule of exp; Unexpected counts those that are not declared.
func Compare(before, after []byte, exp Expectations) ([]Difference, error) {
	if exp.Kind == "" {
		exp.Kind = ExpectEqual
	}
	if !slices.Contains(Expects, exp.Kind) {
		return nil, fmt.Errorf("datacheck: unknown expectation %q (want one of %s)", exp.Kind, strings.Join(Expects, ", "))
	}
	for _, p := range exp.Allow {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("datacheck: allow %q: %w", p, err)
		}
	}
	b, err := Flatten(before)
	if err != nil {
		return nil, err
	}
	a, err := Flatten(after)
	if err != nil {
		return nil, err
	}
	b = remap(b, exp.WorkspaceMap)
	c := &comparer{a: a, exp: exp, devices: map[string]bool{}}
	for _, d := range exp.Devices {
		c.devices[d] = true
	}
	b = relocate(b, a, c.devices)
	c.b = b
	var diffs []Difference
	// The object check on one side only is one difference, not thousands.
	if hasPrefix(b, "objects/") != hasPrefix(a, "objects/") {
		diffs = append(diffs, Difference{Path: "objects", Why: "the object check ran on one side only"})
		drop(b, "objects/")
		drop(a, "objects/")
	}
	keys := map[string]bool{}
	for k := range b {
		keys[k] = true
	}
	for k := range a {
		keys[k] = true
	}
	for k := range keys {
		bv, inB := b[k]
		av, inA := a[k]
		if inB && inA && bv == av || k == "taken_at" {
			continue
		}
		d := Difference{Path: k}
		if inB {
			d.Before = &bv
		}
		if inA {
			d.After = &av
		}
		d.Declared, d.Why = c.declared(d)
		diffs = append(diffs, d)
	}
	diffs = append(diffs, c.rules()...)
	slices.SortFunc(diffs, func(x, y Difference) int { return strings.Compare(x.Path, y.Path) })
	return diffs, nil
}

// Unexpected counts the differences a change did not declare.
func Unexpected(diffs []Difference) int {
	n := 0
	for _, d := range diffs {
		if !d.Declared {
			n++
		}
	}
	return n
}

// WriteReport writes diffs, one line each, then a total line.
func WriteReport(w io.Writer, diffs []Difference) error {
	show := func(v *string) string {
		if v == nil {
			return "(absent)"
		}
		return *v
	}
	var buf bytes.Buffer
	for _, d := range diffs {
		tag := "unexpected"
		if d.Declared {
			tag = "declared  "
		}
		fmt.Fprintf(&buf, "%s %s: %s -> %s", tag, d.Path, show(d.Before), show(d.After))
		if d.Why != "" {
			fmt.Fprintf(&buf, " (%s)", d.Why)
		}
		buf.WriteByte('\n')
	}
	n := Unexpected(diffs)
	fmt.Fprintf(&buf, "datacheck compare: %d unexpected, %d declared\n", n, len(diffs)-n)
	_, err := w.Write(buf.Bytes())
	return err
}

// Flatten turns a manifest into path -> value: objects by key, joined with
// "/"; a list is one value, its JSON text.
func Flatten(data []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotManifest, err)
	}
	if f, ok := root["format"].(string); !ok || !strings.HasPrefix(f, "wappie-datacheck/") {
		return nil, ErrNotManifest
	}
	out := map[string]string{}
	var walk func(prefix string, v any) error
	walk = func(prefix string, v any) error {
		switch t := v.(type) {
		case map[string]any:
			for k, c := range t {
				if strings.Contains(k, "/") {
					return fmt.Errorf("%w: a key holds a slash at %s", ErrNotManifest, prefix)
				}
				p := k
				if prefix != "" {
					p = prefix + "/" + k
				}
				if err := walk(p, c); err != nil {
					return err
				}
			}
			if len(t) == 0 {
				out[prefix] = "{}"
			}
		case []any:
			j, err := json.Marshal(t)
			if err != nil {
				return err
			}
			out[prefix] = string(j)
		case nil:
			out[prefix] = "null"
		case string:
			out[prefix] = t
		case json.Number:
			out[prefix] = t.String()
		case bool:
			out[prefix] = strconv.FormatBool(t)
		default:
			return fmt.Errorf("%w: %T at %s", ErrNotManifest, v, prefix)
		}
		return nil
	}
	if err := walk("", root); err != nil {
		return nil, err
	}
	return out, nil
}

func remap(m map[string]string, ws map[string]string) map[string]string {
	if len(ws) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		seg := strings.Split(k, "/")
		for i := 0; i+1 < len(seg); i++ {
			if seg[i] == "workspaces" {
				if to, ok := ws[seg[i+1]]; ok {
					seg[i+1] = to
				}
			}
		}
		if k == "scope" {
			if to, ok := ws[v]; ok {
				v = to
			}
		}
		out[strings.Join(seg, "/")] = v
	}
	return out
}

func hasPrefix(m map[string]string, p string) bool {
	for k := range m {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

func drop(m map[string]string, p string) {
	for k := range m {
		if strings.HasPrefix(k, p) {
			delete(m, k)
		}
	}
}

// Match reports whether p matches the "/"-separated path k: "**" is any
// number of segments, any other segment is a path.Match pattern.
func Match(p, k string) bool {
	return matchSeg(strings.Split(p, "/"), strings.Split(k, "/"))
}

func matchSeg(p, k []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			for i := 0; i <= len(k); i++ {
				if matchSeg(p[1:], k[i:]) {
					return true
				}
			}
			return false
		}
		if len(k) == 0 {
			return false
		}
		// Compare checked every pattern's syntax first.
		if ok, err := path.Match(p[0], k[0]); err != nil || !ok {
			return false
		}
		p, k = p[1:], k[1:]
	}
	return len(k) == 0
}

// comparer holds both flattened manifests and what the change declares.
type comparer struct {
	b, a map[string]string
	exp  Expectations
	// devices are Expectations.Devices as a set.
	devices map[string]bool
}

// allowed says whether an -allow pattern matches p.
func (c *comparer) allowed(p string) (bool, string) {
	for _, pat := range c.exp.Allow {
		if Match(pat, p) {
			return true, "allowed: " + pat
		}
	}
	return false, ""
}

// renumbered says whether seq-offset renumbers the number dev: every
// number when the change names none, else only those it names.
func (c *comparer) renumbered(dev string) bool {
	return len(c.devices) == 0 || c.devices[dev]
}

// seqWorkspace says whether the workspace ws (as AFTER names it) holds a
// renumbered number, so its last_seq may change.
func (c *comparer) seqWorkspace(ws string) bool {
	if len(c.devices) == 0 {
		return true
	}
	for k := range c.a {
		seg := strings.Split(k, "/")
		if len(seg) > 3 && seg[0] == "workspaces" && seg[1] == ws && seg[2] == "devices" && c.devices[seg[3]] {
			return true
		}
	}
	return false
}

// absentBefore are the split columns of table t that BEFORE's schema lacked.
func (c *comparer) absentBefore(t string) []string {
	return jsonList(c.b["digests/"+t+"/absent"])
}

func jsonList(v string) []string {
	var out []string
	if v == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil
	}
	return out
}

// backfilled are the columns the start's backfills fill (plan 2.3 step
// 12): the LID backfill's three and the chat uid backfill's.
var backfilled = []struct{ table, column string }{
	{"messages", "sender_pn"}, {"chats", "chat_pn"}, {"chats", "uid"}, {"contacts", "contact_lid"},
}

// declared says whether the change accounts for one differing field, and why.
func (c *comparer) declared(d Difference) (bool, string) {
	if ok, why := c.allowed(d.Path); ok {
		return true, why
	}
	num := func(v *string) (int64, bool) {
		if v == nil {
			return 0, false
		}
		n, err := strconv.ParseInt(*v, 10, 64)
		return n, err == nil
	}
	seg := strings.Split(d.Path, "/")
	added := d.Before == nil && d.After != nil
	switch c.exp.Kind {
	case ExpectMigration:
		if added && Match("schema/**", d.Path) {
			return true, "a new migration"
		}
		// A column a migration added: the schema before lacked it, so it
		// was absent; now it has its own digest (and NULL count).
		if Match("digests/*/absent", d.Path) {
			after := []string{}
			if d.After != nil {
				after = jsonList(*d.After)
			}
			before := c.absentBefore(seg[1])
			for _, col := range after {
				if !slices.Contains(before, col) {
					return false, "a column the schema had is gone"
				}
			}
			return true, "a new column"
		}
		if added && (Match("workspaces/*/devices/*/tables/*/columns/*", d.Path) || Match("workspaces/*/devices/*/tables/*/nulls/*", d.Path) ||
			Match("workspaces/*/unowned/*/columns/*", d.Path) || Match("workspaces/*/unowned/*/nulls/*", d.Path)) {
			t, col := seg[len(seg)-3], seg[len(seg)-1]
			if slices.Contains(c.absentBefore(t), col) {
				return true, "a new column"
			}
		}
	case ExpectSeqOffset:
		// Checked by rules, which see the equal ones too.
		if Match("workspaces/*/devices/*/tables/*/max_seq", d.Path) && c.renumbered(seg[3]) {
			return true, "seq"
		}
		if Match("workspaces/*/fields/last_seq", d.Path) && c.seqWorkspace(seg[1]) {
			return true, "seq"
		}
	case ExpectKeyChange:
		switch {
		case added && (Match("workspaces/*/devices/*/archive_keys/**", d.Path) || Match("workspaces/*/devices/*/grants/**", d.Path)):
			return true, "a new key or grant"
		case Match("workspaces/*/devices/*/archive_keys/*/retired_at", d.Path) && d.Before != nil && *d.Before == "null" && d.After != nil:
			return true, "an old key retired"
		case Match("workspaces/*/devices/*/fields/current_epoch", d.Path):
			b, okB := num(d.Before)
			a, okA := num(d.After)
			if okB && okA && a > b {
				return true, "a new epoch"
			}
		case Match("workspaces/*/devices/*/fields/updated_at", d.Path):
			return true, "devices_touch"
		}
	case ExpectLIDBackfill:
		for _, t := range []string{"messages", "chats", "contacts"} {
			if Match("workspaces/*/inventory/"+t+"/bytes", d.Path) {
				return true, "backfilled columns' storage"
			}
		}
		if Match("workspaces/*/fields/storage_archive_bytes", d.Path) {
			return true, "backfilled columns' storage"
		}
		for _, f := range backfilled {
			// Only the column's own digest may change, and only where its
			// NULL count fell: the row digest, which covers every other
			// column, must stay equal.
			if Match("workspaces/*/devices/*/tables/"+f.table+"/columns/"+f.column, d.Path) {
				nulls := strings.TrimSuffix(d.Path, "columns/"+f.column) + "nulls/" + f.column
				bv, okB := c.b[nulls]
				av, okA := c.a[nulls]
				nb, errB := strconv.ParseInt(bv, 10, 64)
				na, errA := strconv.ParseInt(av, 10, 64)
				if okB && okA && errB == nil && errA == nil && na < nb {
					return true, "NULLs filled"
				}
				return false, "a backfill changes a column only by filling its NULLs"
			}
			if Match("workspaces/*/devices/*/tables/"+f.table+"/nulls/"+f.column, d.Path) {
				b, okB := num(d.Before)
				a, okA := num(d.After)
				if okB && okA && a < b {
					return true, "NULLs filled"
				}
				return false, "a backfill only fills NULLs"
			}
		}
	}
	return false, ""
}

// rules checks what an expectation demands of fields that may be equal.
// An -allow pattern declares a broken rule too, as it does a difference.
func (c *comparer) rules() []Difference {
	out := c.brokenRules()
	for i := range out {
		out[i].Declared, out[i].Why = func(d Difference) (bool, string) {
			if ok, why := c.allowed(d.Path); ok {
				return true, d.Why + "; " + why
			}
			return false, d.Why
		}(out[i])
	}
	return out
}

func (c *comparer) brokenRules() []Difference {
	b, a, exp := c.b, c.a, c.exp
	var out []Difference
	str := func(s string) *string { return &s }
	switch exp.Kind {
	case ExpectSeqOffset:
		highest := map[string]int64{}
		for k, v := range b {
			if !Match("workspaces/*/devices/*/tables/*/max_seq", k) || !c.renumbered(strings.Split(k, "/")[3]) {
				continue
			}
			before, errB := strconv.ParseInt(v, 10, 64)
			av, ok := a[k]
			after, errA := strconv.ParseInt(av, 10, 64)
			if !ok || errB != nil || errA != nil || after != before+exp.Offset {
				d := Difference{Path: k, Before: str(v), Why: fmt.Sprintf("want exactly %+d", exp.Offset)}
				if ok {
					d.After = str(av)
				}
				out = append(out, d)
			}
		}
		for k, v := range a {
			if !Match("workspaces/*/devices/*/tables/*/max_seq", k) {
				continue
			}
			seg := strings.Split(k, "/")
			if _, ok := b[k]; !ok && c.renumbered(seg[3]) {
				out = append(out, Difference{Path: k, After: str(v), Why: "a max seq the first manifest lacks"})
			}
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > highest[seg[1]] {
				highest[seg[1]] = n
			}
		}
		for k, v := range a {
			if !Match("workspaces/*/fields/last_seq", k) {
				continue
			}
			ws := strings.Split(k, "/")[1]
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < highest[ws] {
				out = append(out, Difference{Path: k, After: str(v),
					Why: fmt.Sprintf("last_seq must be raised past the highest seq, %d", highest[ws])})
			}
		}
	case ExpectKeyChange:
		for k, v := range a {
			if !Match("workspaces/*/devices/*/fields/current_epoch", k) {
				continue
			}
			bv, ok := b[k]
			if !ok || bv == v {
				continue
			}
			dev := strings.TrimSuffix(k, "/fields/current_epoch")
			fp, hasKey := a[dev+"/archive_keys/"+v+"/fingerprint"]
			if !hasKey {
				out = append(out, Difference{Path: dev + "/archive_keys/" + v, Why: "the new epoch has no archive key"})
				continue
			}
			prefix := dev + "/grants/"
			for gk := range b {
				user, epoch, found := strings.Cut(strings.TrimPrefix(gk, prefix), ":")
				if !strings.HasPrefix(gk, prefix) || !found || !strings.HasSuffix(epoch, "/sealed_dsk_sha256") ||
					strings.TrimSuffix(epoch, "/sealed_dsk_sha256") != bv {
					continue
				}
				nk := prefix + user + ":" + v + "/fingerprint"
				if got, ok := a[nk]; !ok || got != fp {
					d := Difference{Path: prefix + user + ":" + v, Why: "a holder of epoch " + bv + " holds no grant at epoch " + v + " for the new key"}
					if ok {
						d.After = str(got)
					}
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// relocate moves each named number's paths in b to the workspace that a
// holds it in, so a number a change moved between workspaces compares
// with itself.
func relocate(b, a map[string]string, devices map[string]bool) map[string]string {
	if len(devices) == 0 {
		return b
	}
	where := map[string]string{}
	for k := range a {
		seg := strings.SplitN(k, "/", 5)
		if len(seg) > 3 && seg[0] == "workspaces" && seg[2] == "devices" && devices[seg[3]] {
			where[seg[3]] = seg[1]
		}
	}
	out := make(map[string]string, len(b))
	left := map[string]bool{}
	for k, v := range b {
		seg := strings.Split(k, "/")
		if len(seg) > 3 && seg[0] == "workspaces" && seg[2] == "devices" {
			if ws, ok := where[seg[3]]; ok && ws != seg[1] {
				left[seg[1]] = true
				seg[1] = ws
			}
		}
		out[strings.Join(seg, "/")] = v
	}
	// A workspace the move left without numbers shows as Flatten shows an
	// empty one.
	for ws := range left {
		if !hasPrefix(out, "workspaces/"+ws+"/devices/") {
			out["workspaces/"+ws+"/devices"] = "{}"
		}
	}
	return out
}
