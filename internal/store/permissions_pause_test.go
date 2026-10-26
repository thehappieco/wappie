package store_test

import (
	"testing"

	"whatserver2/internal/store"
)

// Pausing and resuming is its own flag, never Manage's (store.ActionPause).
func TestPauseIsNotManage(t *testing.T) {
	if (store.DevicePermission{Read: true, Send: true, Manage: true, HasKey: true}).Allows(store.ActionPause) {
		t.Fatal("Manage pauses")
	}
	if !(store.DevicePermission{Pause: true}).Allows(store.ActionPause) {
		t.Fatal("Pause does not pause")
	}
	if (store.DevicePermission{Pause: true}).Allows(store.ActionManage) {
		t.Fatal("Pause manages")
	}
}
