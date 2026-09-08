package main

import (
	"testing"

	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The supervisor exists because one attempt at boot was one too few.
//
// A restart overlaps with the process it replaces: the outgoing one holds the
// device locks until the end of its HTTP drain, the incoming one asks for them
// milliseconds into boot, loses, logs "device is supervised by another
// instance", and — before this — never asked again. The device row kept saying
// online, every health check stayed green, and no message arrived for hours.
//
// So the property worth pinning is that losing the race is temporary. A device
// nothing is holding stays eligible on the next pass, however many passes that
// takes.

func device(id string, status wa.Status) store.Device {
	return store.Device{
		ID:     id,
		Status: status,
		// Known() needs one identifier. A device with none was never paired.
		Identity: wa.Identity{PN: types.NewJID("5511999999999", types.DefaultUserServer)},
	}
}

func TestADeviceNobodyIsHoldingStaysEligible(t *testing.T) {
	devices := []store.Device{device("a", wa.StatusOnline)}

	// First pass: another instance still holds the lock, so nothing is running
	// here. Nothing marks the device as handled.
	first := needsClaim(devices, map[string]bool{})
	if len(first) != 1 {
		t.Fatalf("first pass claims %d devices, want 1", len(first))
	}

	// Second pass, still unheld. It must come back — the whole bug was that it
	// did not.
	second := needsClaim(devices, map[string]bool{})
	if len(second) != 1 {
		t.Fatalf("second pass claims %d devices, want 1", len(second))
	}
}

func TestADeviceAlreadySupervisedIsLeftAlone(t *testing.T) {
	devices := []store.Device{device("a", wa.StatusOnline), device("b", wa.StatusOffline)}
	got := needsClaim(devices, map[string]bool{"a": true})

	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("claims %+v, want only b — asking for a lock this process already "+
			"holds costs an attempt and a log line every tick", got)
	}
}

func TestTerminalDevicesAreNotRetriedForever(t *testing.T) {
	// A device WhatsApp has thrown out, or one that was never paired, will not
	// come back by trying harder. Retrying spends connection attempts against a
	// server that has already refused.
	for _, status := range []wa.Status{wa.StatusLoggedOut, wa.StatusBanned, wa.StatusNew} {
		if got := needsClaim([]store.Device{device("a", status)}, map[string]bool{}); len(got) != 0 {
			t.Errorf("status %s is claimed; it should not be", status)
		}
	}

	// An unpaired device has no session to resume whatever its status says.
	unpaired := store.Device{ID: "a", Status: wa.StatusOnline}
	if got := needsClaim([]store.Device{unpaired}, map[string]bool{}); len(got) != 0 {
		t.Error("a device with no identity was claimed")
	}
}

func TestEveryLiveStatusIsClaimed(t *testing.T) {
	// The three states that mean "this should be connected": it thinks it is,
	// it knows it is not, or it was mid-pairing when the process died.
	for _, status := range []wa.Status{wa.StatusOnline, wa.StatusOffline, wa.StatusPairing} {
		if got := needsClaim([]store.Device{device("a", status)}, map[string]bool{}); len(got) != 1 {
			t.Errorf("status %s is not claimed; it would stay unsupervised", status)
		}
	}
}
