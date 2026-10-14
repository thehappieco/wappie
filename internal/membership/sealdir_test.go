package membership

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSealDirStates(t *testing.T) {
	dir := SealDir(t.TempDir())
	if err := os.Chmod(string(dir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := dir.Check(); err != nil {
		t.Fatal(err)
	}
	state := func() (SealState, error) { return dir.State() }
	if s, err := state(); err != nil || s != StateNone {
		t.Fatalf("empty: %q %v", s, err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := dir.WriteFile(name, []byte(body)); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(dir.Path(name))
		if err != nil || fi.Mode().Perm() != 0o640 {
			t.Fatalf("%s: %v %v", name, fi.Mode(), err)
		}
	}
	disagree := func(why string) {
		t.Helper()
		if _, err := state(); !errors.Is(err, ErrSealDisagree) {
			t.Fatalf("%s: %v", why, err)
		}
	}
	write(SecretFileName, "current")
	disagree("an envelope without a state")
	if err := dir.WriteState(StateSteady); err != nil {
		t.Fatal(err)
	}
	if s, err := state(); err != nil || s != StateSteady {
		t.Fatalf("steady: %q %v", s, err)
	}
	write(SecretOtherFileName, "other")
	disagree("steady with two files")
	for _, s := range []SealState{StateNext, StatePromoted} {
		if err := dir.WriteState(s); err != nil {
			t.Fatal(err)
		}
		if got, err := state(); err != nil || got != s {
			t.Fatalf("%s: %q %v", s, got, err)
		}
	}
	if err := dir.Remove(SecretOtherFileName); err != nil {
		t.Fatal(err)
	}
	disagree("promoted with one file")
	write(SecretStateFileName, "rotating\n")
	disagree("an unknown word")
	// No temporary file is left behind.
	if left, _ := filepath.Glob(dir.Path(".*")); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
	if err := os.Chmod(string(dir), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := dir.Check(); err == nil {
		t.Fatal("a group-writable directory passed")
	}
	if err := SealDir(dir.Path(SecretFileName)).Check(); err == nil {
		t.Fatal("a file passed as the directory")
	}
	if Fingerprint([]byte("x")) != "2d711642b726" {
		t.Fatalf("fingerprint %s", Fingerprint([]byte("x")))
	}
}

// TestSealDirGivesTheDirectorysGroup: every file WriteFile makes is the
// directory's group, mode 0640. In production seal runs as root in
// /opt/wappie/sealed (root:wappie 0750), where Linux gives a new file the
// process's group, 0: without the chown wappie-api could not read the
// envelope. A directory of another group of this user's shows it here (on
// darwin a new file takes its directory's group anyway; Linux is the test).
func TestSealDirGivesTheDirectorysGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	gid := -1
	for _, g := range groups {
		if g != os.Getgid() {
			gid = g
			break
		}
	}
	if gid < 0 {
		t.Skip("this user is in no group but its own")
	}
	dir := SealDir(t.TempDir())
	if err := os.Chown(string(dir), -1, gid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{SecretFileName, SecretStateFileName} {
		if err := dir.WriteFile(name, []byte("x")); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(dir.Path(name))
		if err != nil {
			t.Fatal(err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int64(st.Gid) != int64(gid) || fi.Mode().Perm() != 0o640 {
			t.Fatalf("%s: group %v mode %v, want the directory's group %d and 0640", name, st.Gid, fi.Mode(), gid)
		}
	}
}
