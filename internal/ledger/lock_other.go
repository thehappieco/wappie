//go:build !unix

package ledger

import "errors"

// lock needs flock, which only Unix systems have; the server runs on Linux.
func lock(string) (func(), error) {
	return nil, errors.New("the deletion ledger needs a Unix file lock")
}
