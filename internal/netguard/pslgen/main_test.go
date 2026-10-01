package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The committed snapshot is what this generator writes for its own rules,
// byte for byte: a refresh from the List is the same command.
func TestTheSnapshotIsThisGeneratorsOutput(t *testing.T) {
	committed, err := os.ReadFile("../psl/psl-2026-02-06.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(committed, &s); err != nil {
		t.Fatal(err)
	}
	var list strings.Builder
	list.WriteString("// ===BEGIN ICANN DOMAINS===\n")
	for _, rule := range s.ICANN {
		list.WriteString(rule + "\n")
	}
	list.WriteString("// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n")
	for _, rule := range s.Private {
		list.WriteString(rule + "\n")
	}
	list.WriteString("// ===END PRIVATE DOMAINS===\n")
	again, err := Parse(strings.NewReader(list.String()))
	if err != nil {
		t.Fatal(err)
	}
	again.ListDate, again.ListRevision = s.ListDate, s.ListRevision
	if !bytes.Equal(Encode(again), committed) {
		t.Fatal("the committed snapshot is not what pslgen writes for its rules")
	}
}

func TestParse(t *testing.T) {
	s, err := Parse(strings.NewReader(`// header
// ===BEGIN ICANN DOMAINS===
com
co.uk   some comment after white space
*.ck
!www.ck
// 公司.cn
公司.cn
com
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
GitHub.IO
// ===END PRIVATE DOMAINS===
`))
	if err != nil {
		t.Fatal(err)
	}
	want := Snapshot{ICANN: []string{"!www.ck", "*.ck", "co.uk", "com", "xn--55qx5d.cn"}, Private: []string{"github.io"}}
	if strings.Join(s.ICANN, ",") != strings.Join(want.ICANN, ",") || strings.Join(s.Private, ",") != strings.Join(want.Private, ",") {
		t.Fatalf("parsed %+v, want %+v", s, want)
	}
	for _, bad := range []string{
		"com\n",                                // outside both sections
		"// ===BEGIN ICANN DOMAINS===\nco_m\n", // not a domain
		"// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n", // no private section
	} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
