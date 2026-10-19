//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// exchangeFiles swaps the files a and b of dir in one step, with
// renameat2(RENAME_EXCHANGE): a crash leaves either both as they were or
// both swapped, never one file missing or a secret lost.
func exchangeFiles(dir, a, b string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the sealed directory: %w", err)
	}
	defer func() { _ = unix.Close(fd) }() //nolint:errcheck // a directory opened read-only
	if err := unix.Renameat2(fd, a, fd, b, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("exchange the two secrets: %w", err)
	}
	return nil
}
