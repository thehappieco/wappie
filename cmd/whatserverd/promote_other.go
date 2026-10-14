//go:build !linux

package main

import "errors"

// exchangeFiles needs renameat2(RENAME_EXCHANGE), which only Linux has: on
// any other system promote and unpromote refuse rather than swap the two
// secrets in steps a crash could stop half way. The servers that hold a
// contract secret are Linux; this keeps the command building elsewhere.
func exchangeFiles(string, string, string) error {
	return errors.New("promote needs Linux: renameat2(RENAME_EXCHANGE) swaps the two secrets in one step")
}
