package datacheck

import (
	"errors"
	"strings"
	"testing"
)

const baseManifest = `{"format":"wappie-datacheck/1","taken_at":"T1","scope":"all",
 "schema":{"1":{"name":"foundation","checksum":"c1"}},
 "workspaces":{"w1":{"fields":{"last_seq":"10","storage_archive_bytes":"100"},
  "inventory":{"messages":{"count":2,"bytes":50}},
  "devices":{"d1":{"present":true,"fields":{"current_epoch":"1","updated_at":"U1"},
   "tables":{"messages":{"count":2,"rows":"r1","columns":{"sender_pn":"sp1"},"ciphertext":"c1","seq":"s1","max_seq":10,"nulls":{"sender_pn":2}},
             "chats":{"count":1,"rows":"cr1","columns":{"chat_pn":"cp1","uid":"cu1"},"nulls":{"chat_pn":1,"uid":1}}}}}}}}`

func edit(s string, pairs ...string) []byte {
	return []byte(strings.NewReplacer(pairs...).Replace(s))
}

func mustCompare(t *testing.T, before, after []byte, exp Expectations) []Difference {
	t.Helper()
	diffs, err := Compare(before, after, exp)
	if err != nil {
		t.Fatal(err)
	}
	return diffs
}

func TestCompareExpectations(t *testing.T) {
	base := []byte(baseManifest)
	if d := mustCompare(t, base, edit(baseManifest, `"T1"`, `"T2"`), Expectations{}); len(d) != 0 {
		t.Fatalf("taken_at is not compared: %v", d)
	}

	// A new migration is declared by migration and by nothing else; a
	// changed checksum never is.
	added := edit(baseManifest, `"schema":{`, `"schema":{"2":{"name":"more","checksum":"c2"},`)
	if n := Unexpected(mustCompare(t, base, added, Expectations{Kind: ExpectMigration})); n != 0 {
		t.Fatalf("a new migration: %d unexpected", n)
	}
	if n := Unexpected(mustCompare(t, base, added, Expectations{})); n == 0 {
		t.Fatal("a new migration passed as equal")
	}
	if n := Unexpected(mustCompare(t, base, edit(baseManifest, `"checksum":"c1"`, `"checksum":"cX"`), Expectations{Kind: ExpectMigration})); n == 0 {
		t.Fatal("a changed migration passed")
	}

	// The LID backfill: NULLs fall, the filled columns' own digests and
	// the accounted bytes change.
	filled := edit(baseManifest, `"sender_pn":2`, `"sender_pn":0`, `"sp1"`, `"sp2"`, `"chat_pn":1`, `"chat_pn":0`,
		`"cp1"`, `"cp2"`, `"uid":1`, `"uid":0`, `"cu1"`, `"cu2"`, `"bytes":50`, `"bytes":70`,
		`"storage_archive_bytes":"100"`, `"storage_archive_bytes":"120"`)
	if n := Unexpected(mustCompare(t, base, filled, Expectations{Kind: ExpectLIDBackfill})); n != 0 {
		t.Fatalf("a backfill: %d unexpected", n)
	}
	// Any other column of those rows (the row digest) is not the backfill.
	if n := Unexpected(mustCompare(t, base, edit(string(filled), `"rows":"r1"`, `"rows":"r2"`), Expectations{Kind: ExpectLIDBackfill})); n != 1 {
		t.Fatalf("a backfill that changed the row digest: %d unexpected", n)
	}
	// A filled column's digest that moved where no NULL was filled was
	// overwritten, not filled.
	if n := Unexpected(mustCompare(t, base, edit(baseManifest, `"sp1"`, `"sp2"`), Expectations{Kind: ExpectLIDBackfill})); n != 1 {
		t.Fatalf("an overwritten sender_pn: %d unexpected", n)
	}
	emptied := edit(baseManifest, `"sender_pn":2`, `"sender_pn":3`)
	if n := Unexpected(mustCompare(t, base, emptied, Expectations{Kind: ExpectLIDBackfill})); n != 1 {
		t.Fatalf("a NULL that grew: %d unexpected", n)
	}
	if n := Unexpected(mustCompare(t, base, edit(baseManifest, `"ciphertext":"c1"`, `"ciphertext":"c2"`), Expectations{Kind: ExpectLIDBackfill})); n != 1 {
		t.Fatal("a backfill may not change ciphertext")
	}

	// -allow declares by pattern.
	if n := Unexpected(mustCompare(t, base, edit(baseManifest, `"updated_at":"U1"`, `"updated_at":"U2"`),
		Expectations{Allow: []string{"workspaces/*/devices/*/fields/updated_at"}})); n != 0 {
		t.Fatal("an allowed field")
	}

	// A workspace renamed by the map compares as itself.
	moved := edit(baseManifest, `"w1"`, `"w9"`)
	if n := Unexpected(mustCompare(t, base, moved, Expectations{WorkspaceMap: map[string]string{"w1": "w9"}})); n != 0 {
		t.Fatalf("a mapped workspace: %d unexpected", n)
	}

	// The object check on one side only is one difference.
	withObjects := edit(baseManifest, `"taken_at":"T1",`, `"taken_at":"T1","objects":{"prefix":"","total":{"count":1,"bytes":1}},`)
	d := mustCompare(t, base, withObjects, Expectations{})
	if len(d) != 1 || d[0].Path != "objects" || d[0].Declared {
		t.Fatalf("objects on one side: %v", d)
	}

	if _, err := Compare([]byte(`{"format":"other"}`), base, Expectations{}); !errors.Is(err, ErrNotManifest) {
		t.Fatalf("not a manifest: %v", err)
	}
	if _, err := Compare(base, base, Expectations{Kind: "trim"}); err == nil {
		t.Fatal("an unknown expectation")
	}
}

// TestCompareNewColumn: a column the schema before lacked (absent) that the
// schema after has shows as its own digest and NULL count, which migration
// declares; a column that disappears is never declared.
func TestCompareNewColumn(t *testing.T) {
	const m = `{"format":"wappie-datacheck/1","taken_at":"T","scope":"all",
 "digests":{"contacts":{"key":["contact_key"],"rows":["contact_pn"],"columns":["contact_lid"]ABSENT}},
 "workspaces":{"w1":{"devices":{"d1":{"present":true,"tables":{"contacts":{"count":1,"rows":"r1"COLUMNS}}}}}}}`
	before := edit(m, "ABSENT", `,"absent":["contact_lid"]`, "COLUMNS", "")
	after := edit(m, "ABSENT", "", "COLUMNS", `,"columns":{"contact_lid":"cl1"},"nulls":{"contact_lid":1}`)
	if n := Unexpected(mustCompare(t, before, after, Expectations{Kind: ExpectMigration})); n != 0 {
		t.Fatalf("a new column: %d unexpected", n)
	}
	if n := Unexpected(mustCompare(t, before, after, Expectations{})); n == 0 {
		t.Fatal("a new column passed as equal")
	}
	if n := Unexpected(mustCompare(t, after, before, Expectations{Kind: ExpectMigration})); n == 0 {
		t.Fatal("a column that went passed as a migration")
	}
	// The row digest still has to be equal.
	if n := Unexpected(mustCompare(t, before, edit(string(after), `"rows":"r1"`, `"rows":"r2"`), Expectations{Kind: ExpectMigration})); n != 1 {
		t.Fatalf("a changed row digest under a migration: %d unexpected", n)
	}
}

// TestCompareSeqOffsetOfSomeNumbers: with numbers named, only they are
// renumbered, wherever the second manifest holds them; every other
// number's max seq must stay equal; -allow declares a broken rule too.
func TestCompareSeqOffsetOfSomeNumbers(t *testing.T) {
	const m = `{"format":"wappie-datacheck/1","taken_at":"T","scope":"all","workspaces":{
 "src":{"fields":{"last_seq":"@SRC@"},"devices":{@MOV@}},
 "dst":{"fields":{"last_seq":"@DST@"},"devices":{"d2":{"present":true,"tables":{"messages":{"count":1,"rows":"r2","seq":"s2","max_seq":@D2@}}}@DM@}}}}`
	moved := `"d1":{"present":true,"tables":{"messages":{"count":1,"rows":"r1","seq":"s1","max_seq":M1}}}`
	before := edit(m, "@SRC@", "10", "@DST@", "50", "@MOV@", strings.Replace(moved, "M1", "10", 1), "@D2@", "50", "@DM@", "")
	after := edit(m, "@SRC@", "10", "@DST@", "1010", "@MOV@", "", "@D2@", "50", "@DM@", ","+strings.Replace(moved, "M1", "1010", 1))
	exp := Expectations{Kind: ExpectSeqOffset, Offset: 1000, Devices: []string{"d1"}}
	if d := mustCompare(t, before, after, exp); Unexpected(d) != 0 {
		t.Fatalf("a move of d1 into a workspace with d2: %v", d)
	}
	// Without naming the number, d2 would have to move too.
	if d := mustCompare(t, before, after, Expectations{Kind: ExpectSeqOffset, Offset: 1000}); Unexpected(d) == 0 {
		t.Fatal("d2 left as it was passed as renumbered")
	}
	// d2 renumbered as well is not declared.
	if d := mustCompare(t, before, edit(string(after), `"max_seq":50`, `"max_seq":1050`, `"1010"`, `"1050"`), exp); Unexpected(d) != 1 {
		t.Fatalf("an untouched number renumbered: %v", d)
	}
	// A wrong offset breaks the rule; -allow can declare it.
	wrong := edit(string(after), `"max_seq":1010`, `"max_seq":1011`, `"1010"`, `"1011"`)
	if d := mustCompare(t, before, wrong, exp); Unexpected(d) != 1 {
		t.Fatalf("a wrong offset: %v", d)
	}
	exp.Allow = []string{"workspaces/dst/devices/d1/tables/messages/max_seq"}
	if d := mustCompare(t, before, wrong, exp); Unexpected(d) != 0 {
		t.Fatalf("an allowed rule: %v", d)
	}
}
