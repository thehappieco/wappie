package store_test

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestReadFlagClearedOnlyBySetDevicePermission pins what DS48 rests on (the
// platform's F3): a lone grant.revoke takes Read only from a person with
// the Read flag, and a dormant grant's revoke ends nothing, because the
// flag is cleared on one path only, setDevicePermissionTx, which ends the
// person's connections when it takes Read (DS47). Every other write of
// device_permissions, in the code and in the migrations, either inserts
// the flag true and never updates a row (the 0023 trigger and its
// backfill, a move to Personal), moves rows to another workspace without
// touching a flag (a move to Personal), or deletes whole rows after the
// person's connections ended (a member disabled or removed, a
// connection's account removed, the others' rows on a move to Personal).
// A new path that clears the flag must end the connections too, and
// change this test.
//
// It reads every string literal of the module's Go code, as the Go
// scanner reads them, and every migration statement. A statement whose
// table is joined in (`UPDATE `+table+` SET …`) counts as a write of
// device_permissions when its file names that table in a literal of its
// own, as a list of tables does. A table name built any other way, or
// held in another file, is beyond it.
func TestReadFlagClearedOnlyBySetDevicePermission(t *testing.T) {
	type statement struct{ file, sql string }
	var statements []statement
	verb := regexp.MustCompile(`(?is)(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s*$`)
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path) //nolint:gosec // G304: the module's own sources
			if err != nil {
				return err
			}
			file := filepath.ToSlash(path)
			lits := goStrings(t, path, src)
			namesTable := false
			for _, l := range lits {
				statements = append(statements, statement{file, l.value})
				namesTable = namesTable || l.value == "device_permissions"
			}
			if !namesTable {
				return nil
			}
			for _, l := range lits {
				if l.joined && verb.MatchString(l.value) {
					statements = append(statements, statement{file, l.value + "device_permissions " + l.next})
				}
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
	moves := regexp.MustCompile(`(?is)^\s*UPDATE\s+device_permissions\s+SET\s+tenant_id\s*=\s*\$\d+\s+WHERE\s+device_id\s*=\s*\$\d+\s*$`)
	values := regexp.MustCompile(`(?is)INSERT\s+INTO\s+device_permissions\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)`)
	selects := regexp.MustCompile(`(?is)INSERT\s+INTO\s+device_permissions\s*\(([^)]*)\)\s*SELECT\s+(?:DISTINCT\s+)?(.*?)\s+FROM\b`)
	var clears, deletes, moved []string
	for _, s := range statements {
		m := write.FindStringSubmatch(s.sql)
		if m == nil {
			continue
		}
		base := filepath.Base(s.file)
		sql := s.sql
		switch {
		case setsRead.MatchString(sql):
			clears = append(clears, base)
		case strings.HasPrefix(strings.ToUpper(m[1]), "DELETE"):
			deletes = append(deletes, base)
		case strings.HasPrefix(strings.ToUpper(m[1]), "UPDATE"):
			// Only a move of a number's rows to another workspace,
			// flags untouched.
			if !moves.MatchString(sql) {
				t.Errorf("%s updates device_permissions: %s", base, sql)
			}
			moved = append(moved, base)
		default:
			// An insert that is no upsert of the flag: it writes the flag
			// true, or a new row without it, and never changes a row.
			if regexp.MustCompile(`(?i)DO\s+UPDATE`).MatchString(sql) {
				t.Errorf("%s upserts device_permissions: %s", base, sql)
			}
			forms := values.FindAllStringSubmatch(sql, -1)
			forms = append(forms, selects.FindAllStringSubmatch(sql, -1)...)
			if len(forms) == 0 {
				t.Errorf("%s inserts into device_permissions in a form this test cannot read: %s", base, sql)
			}
			for _, v := range forms {
				cols, vals := strings.Split(v[1], ","), strings.Split(v[2], ",")
				for i, c := range cols {
					if strings.TrimSpace(c) == "can_read" && (i >= len(vals) || strings.TrimSpace(vals[i]) != "true") {
						t.Errorf("%s inserts can_read %v: %s", base, vals, sql)
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
	if want := []string{"device_transfer.go"}; !slices.Equal(moved, want) {
		t.Errorf("the statements that move device_permissions rows: %v, want %v", moved, want)
	}
}

// goString is one string literal of a Go file, unquoted. joined is it
// being followed by a + and an operand (a name, or a field of one), and
// next the literal joined after that operand, if any.
type goString struct {
	value, next string
	joined      bool
}

// goStrings reads path's string literals with the Go scanner.
func goStrings(t *testing.T, path string, src []byte) []goString {
	t.Helper()
	type tok struct {
		tok token.Token
		lit string
	}
	var toks []tok
	fset := token.NewFileSet()
	var sc scanner.Scanner
	sc.Init(fset.AddFile(path, fset.Base(), len(src)), src, func(pos token.Position, msg string) {
		t.Fatalf("%s: %s", pos, msg)
	}, 0)
	for {
		_, k, lit := sc.Scan()
		if k == token.EOF {
			break
		}
		toks = append(toks, tok{k, lit})
	}
	unquote := func(lit string) string {
		v, err := strconv.Unquote(lit)
		if err != nil {
			t.Fatalf("%s: %s: %v", path, lit, err)
		}
		return v
	}
	var out []goString
	for i, k := range toks {
		if k.tok != token.STRING {
			continue
		}
		s := goString{value: unquote(k.lit)}
		if i+1 < len(toks) && toks[i+1].tok == token.ADD {
			j := i + 2
			for j < len(toks) && (toks[j].tok == token.IDENT || toks[j].tok == token.PERIOD) {
				j++
			}
			s.joined = j > i+2
			if s.joined && j+1 < len(toks) && toks[j].tok == token.ADD && toks[j+1].tok == token.STRING {
				s.next = unquote(toks[j+1].lit)
			}
		}
		out = append(out, s)
	}
	return out
}
