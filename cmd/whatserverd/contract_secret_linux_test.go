//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExchangeIsOneStep is TB8's exchange case: renameat2(RENAME_EXCHANGE)
// swaps the two files, never leaves one missing, and refuses, changing
// nothing, when either is absent.
func TestExchangeIsOneStep(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	write("current", "old")
	write("other", "next")
	if err := exchangeFiles(dir, "current", "other"); err != nil {
		t.Fatal(err)
	}
	if read("current") != "next" || read("other") != "old" {
		t.Fatal("not swapped")
	}
	if err := exchangeFiles(dir, "current", "other"); err != nil {
		t.Fatal(err)
	}
	if read("current") != "old" || read("other") != "next" {
		t.Fatal("not swapped back")
	}
	if err := os.Remove(filepath.Join(dir, "other")); err != nil {
		t.Fatal(err)
	}
	if err := exchangeFiles(dir, "current", "other"); err == nil {
		t.Fatal("an exchange with a missing file")
	}
	if read("current") != "old" {
		t.Fatal("the failed exchange changed the file")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 1 {
		t.Fatalf("files: %v", left)
	}
}
