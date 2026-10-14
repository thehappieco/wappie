//go:build unix

package ledger

import (
	"errors"
	"os"
	"syscall"
)

// lock takes an exclusive flock on path, creating it with mode 0600, and
// waits for it. The lock goes with the process, so a crash never leaves it
// held.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the ledger's own lock file
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close() //nolint:errcheck,gosec // the lock was not taken
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck,gosec // closing releases it anyway
		f.Close()                                   //nolint:errcheck,gosec // as above
	}, nil
}
