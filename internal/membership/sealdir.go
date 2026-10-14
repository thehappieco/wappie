package membership

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The sealed directory's files (docs/contract.md, "The secret"): beside each
// other in /opt/wappie/sealed, root:wappie 0750, outside every release so a
// rollback of the release link keeps them.
const (
	// SecretFileName is the envelope of the secret Wappie signs with.
	SecretFileName = "contract-secret.thcseal"
	// SecretOtherFileName is the envelope of the other secret, also
	// accepted on answers during a rotation: the next one before the
	// promote, the old one after it.
	SecretOtherFileName = "contract-secret.other.thcseal"
	// SecretStateFileName holds one word, which step of a rotation the two
	// files are at (SealState).
	SecretStateFileName = "contract-secret.state"
)

// SealState is where the sealed files stand in README 7.3's rotation.
type SealState string

// The states. Each contract-secret command allows only its own.
const (
	// StateNone: nothing is installed, no file at all.
	StateNone SealState = ""
	// StateSteady: the current file only.
	StateSteady SealState = "steady"
	// StateNext: current is the old secret, other the next one (README 7.3
	// step 2 done).
	StateNext SealState = "next"
	// StatePromoted: current is the next secret, other the old one (step
	// 3 done).
	StatePromoted SealState = "promoted"
)

// ErrSealDisagree means the sealed files and the state file do not tell the
// same story: every command refuses until an operator looks.
var ErrSealDisagree = errors.New("membership: the sealed files and their state disagree")

// Fingerprint names an envelope file without saying anything about the
// secret inside it: the first 12 hex digits of the file's sha256, as
// contract-secret prints them and the server publishes them.
func Fingerprint(envelope []byte) string {
	sum := sha256.Sum256(envelope)
	return hex.EncodeToString(sum[:])[:12]
}

// SealDir is the sealed directory.
type SealDir string

// Path is the file name inside the directory.
func (d SealDir) Path(name string) string { return filepath.Join(string(d), name) }

// Check refuses a directory that is not one, or that its group or others
// may write: the files in it are only as safe as it is.
func (d SealDir) Check() error {
	fi, err := os.Lstat(string(d))
	switch {
	case err != nil:
		return fmt.Errorf("membership: the sealed directory: %w", err)
	case fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir():
		return errors.New("membership: the sealed directory is not a directory")
	case fi.Mode().Perm()&0o022 != 0:
		return errors.New("membership: the sealed directory may be written by group or others")
	}
	return nil
}

// State reads the state the files and the state file agree on, or
// ErrSealDisagree.
func (d SealDir) State() (SealState, error) {
	state, current, other, err := d.Files()
	if err != nil {
		return "", err
	}
	switch state {
	case StateNone:
		if current || other {
			return "", fmt.Errorf("%w: envelopes without a state file", ErrSealDisagree)
		}
	case StateSteady:
		if !current || other {
			return "", fmt.Errorf("%w: steady wants the current file only", ErrSealDisagree)
		}
	case StateNext, StatePromoted:
		if !current || !other {
			return "", fmt.Errorf("%w: %s wants both files", ErrSealDisagree, state)
		}
	default:
		return "", fmt.Errorf("%w: the state file holds no known state", ErrSealDisagree)
	}
	return state, nil
}

// Files reads what is on disk without judging it: the state file's word
// (StateNone when there is no state file) and whether each envelope is
// there. State is what a caller wants; a command reads this only to finish
// a step that an earlier run of itself stopped in the middle of.
func (d SealDir) Files() (state SealState, current, other bool, err error) {
	if current, err = d.exists(SecretFileName); err != nil {
		return "", false, false, err
	}
	if other, err = d.exists(SecretOtherFileName); err != nil {
		return "", false, false, err
	}
	raw, err := os.ReadFile(d.Path(SecretStateFileName))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return StateNone, current, other, nil
	case err != nil:
		return "", false, false, fmt.Errorf("membership: read the state file: %w", err)
	}
	if state = SealState(strings.TrimSpace(string(raw))); state == StateNone {
		return "", false, false, fmt.Errorf("%w: the state file is empty", ErrSealDisagree)
	}
	return state, current, other, nil
}

// Reset empties the directory of the secret, from whatever state it is in,
// disagreeing ones included: the state file first, then the other envelope,
// then the current one, each removal synced, then any temporary file a
// crash left. It is a reinstall's first half (after a platform restore
// Wappie may hold a secret the platform no longer has), and running it
// again finishes one a crash stopped.
func (d SealDir) Reset() error {
	for _, name := range []string{SecretStateFileName, SecretOtherFileName, SecretFileName} {
		if err := d.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	left, err := filepath.Glob(d.Path(".contract-secret*.tmp-*"))
	if err != nil {
		return err
	}
	for _, f := range left {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return d.Sync()
}

func (d SealDir) exists(name string) (bool, error) {
	fi, err := os.Lstat(d.Path(name))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("membership: %s: %w", name, err)
	case !fi.Mode().IsRegular():
		return false, fmt.Errorf("%w: %s is not a regular file", ErrSealDisagree, name)
	}
	return true, nil
}

// WriteFile replaces name with data, whole or not at all: a temporary file
// in the same directory, written, made 0640 in the directory's group
// (root:wappie, so the service user reads it and nobody else does), synced,
// renamed over name, and the directory synced.
func (d SealDir) WriteFile(name string, data []byte) (err error) {
	dir := string(d)
	di, err := os.Stat(dir)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()           //nolint:errcheck // already failing; the temporary file goes below
			_ = os.Remove(tmp.Name()) //nolint:errcheck // best effort: a leftover temporary is inert
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(0o640); err != nil {
		return err
	}
	if st, ok := di.Sys().(*syscall.Stat_t); ok {
		if fi, serr := tmp.Stat(); serr == nil {
			if fst, ok := fi.Sys().(*syscall.Stat_t); ok && fst.Gid != st.Gid {
				if err = tmp.Chown(-1, int(st.Gid)); err != nil {
					return err
				}
			}
		}
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), d.Path(name)); err != nil {
		return err
	}
	return d.Sync()
}

// WriteState writes the state file.
func (d SealDir) WriteState(state SealState) error {
	return d.WriteFile(SecretStateFileName, []byte(string(state)+"\n"))
}

// Remove removes name, and syncs the directory.
func (d SealDir) Remove(name string) error {
	if err := os.Remove(d.Path(name)); err != nil {
		return err
	}
	return d.Sync()
}

// Sync makes the directory's entries durable: a rename or a removal
// survives a crash only once its directory is synced.
func (d SealDir) Sync() error {
	f, err := os.Open(string(d))
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
