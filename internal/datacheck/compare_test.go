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
   "tables":{"messages":{"count":2,"rows":"r1","ciphertext":"c1","seq":"s1","max_seq":10,"nulls":{"sender_pn":2}},
             "chats":{"count":1,"rows":"cr1","nulls":{"chat_pn":1}}}}}}}}`

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

	// The LID backfill: NULLs fall, row digests and accounted bytes change.
	filled := edit(baseManifest, `"sender_pn":2`, `"sender_pn":0`, `"rows":"r1"`, `"rows":"r2"`, `"chat_pn":1`, `"chat_pn":0`,
		`"rows":"cr1"`, `"rows":"cr2"`, `"bytes":50`, `"bytes":70`, `"storage_archive_bytes":"100"`, `"storage_archive_bytes":"120"`)
	if n := Unexpected(mustCompare(t, base, filled, Expectations{Kind: ExpectLIDBackfill})); n != 0 {
		t.Fatalf("a backfill: %d unexpected", n)
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
