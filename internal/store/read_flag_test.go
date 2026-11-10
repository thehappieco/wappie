package store_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestReadFlagClearedOnlyBySetDevicePermission pins what DS48 rests on (the
// platform's F3): a lone grant.revoke takes Read only from a person with
// the Read flag, and a dormant grant's revoke ends nothing, because the
// flag is cleared on one path only, setDevicePermissionTx, which ends the
// person's connections when it takes Read (DS47). Every other write of
// device_permissions, in the code and in the migrations, either inserts
// the flag true and never updates a row (the 0023 trigger, a move to
// Personal), or deletes whole rows after the person's connections ended
// (a member disabled or removed, a connection's account removed, the
// others' rows on a move to Personal). A new path that clears the flag
// must end the connections too, and change this test.
func TestReadFlagClearedOnlyBySetDevicePermission(t *testing.T) {
	type statement struct{ file, sql string }
	var statements []statement
	quoted := regexp.MustCompile("`[^`]*`")
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path) //nolint:gosec // G304: the module's own sources
			if err != nil {
				return err
			}
			for _, q := range quoted.FindAllString(string(src), -1) {
				statements = append(statements, statement{filepath.ToSlash(path), q})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	migrations, err := filepath.Glob("../../internal/migrate/sql/*.sql")
	if err != nil || len(migrations) < 50 {
		t.Fatalf("migrations: %d %v", len(migrations), err)
	}
	comment := regexp.MustCompile(`--[^\n]*`)
	for _, f := range migrations {
		src, err := os.ReadFile(f) //nolint:gosec // G304: the module's own migrations
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range strings.Split(comment.ReplaceAllString(string(src), ""), ";") {
			statements = append(statements, statement{filepath.ToSlash(f), s})
		}
	}

	write := regexp.MustCompile(`(?is)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+device_permissions\b`)
	setsRead := regexp.MustCompile(`(?i)\bcan_read\s*=`)
	insert := regexp.MustCompile(`(?is)INSERT\s+INTO\s+device_permissions\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)`)
	var clears, deletes []string
	for _, s := range statements {
		m := write.FindStringSubmatch(s.sql)
		if m == nil {
			continue
		}
		base := filepath.Base(s.file)
		switch {
		case setsRead.MatchString(s.sql):
			clears = append(clears, base)
		case strings.HasPrefix(strings.ToUpper(m[1]), "DELETE"):
			deletes = append(deletes, base)
		case strings.HasPrefix(strings.ToUpper(m[1]), "UPDATE"):
			t.Errorf("%s updates device_permissions: %s", base, s.sql)
		default:
			// An insert that is no upsert of the flag: it writes the flag
			// true, or a new row without it, and never changes a row.
			if regexp.MustCompile(`(?i)DO\s+UPDATE`).MatchString(s.sql) {
				t.Errorf("%s upserts device_permissions: %s", base, s.sql)
			}
			for _, v := range insert.FindAllStringSubmatch(s.sql, -1) {
				cols, vals := strings.Split(v[1], ","), strings.Split(v[2], ",")
				for i, c := range cols {
					if strings.TrimSpace(c) == "can_read" && (i >= len(vals) || strings.TrimSpace(vals[i]) != "true") {
						t.Errorf("%s inserts can_read %v: %s", base, vals, s.sql)
					}
				}
			}
		}
	}
	if !slices.Equal(clears, []string{"permissions.go"}) {
		t.Errorf("the statements that set can_read: %v, want setDevicePermissionTx's alone", clears)
	}
	src, err := os.ReadFile("permissions.go")
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := strings.Cut(string(src), "\nfunc setDevicePermissionTx(")
	body, _, _ = strings.Cut(body, "\n}\n")
	if !strings.Contains(body, "can_read=excluded.can_read") {
		t.Error("setDevicePermissionTx no longer writes the flag")
	}
	slices.Sort(deletes)
	if want := []string{"device_transfer.go", "members.go", "members.go"}; !slices.Equal(deletes, want) {
		t.Errorf("the statements that delete device_permissions rows: %v, want %v", deletes, want)
	}
}
