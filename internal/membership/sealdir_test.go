package membership

import (
	"errors"
	"os"
	"path/filepath"
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
