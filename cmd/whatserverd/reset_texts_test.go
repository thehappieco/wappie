package main

import (
	"strings"
	"testing"
)

// inOrder fails unless text holds each of parts, in this order.
func inOrder(t *testing.T, what, text string, parts ...string) {
	t.Helper()
	at := 0
	for _, p := range parts {
		i := strings.Index(text[at:], p)
		if i < 0 {
			t.Fatalf("%s does not say %q after what came before:\n%s", what, p, text)
		}
		at += i + len(p)
	}
}

// TestResetAndDeviceKeyTexts pins what the archive reset and device-key
// tell an operator (DS48, DS49). A running server hears the reset and each
// device-key at their commit, so nothing restarts. With the numbers kept,
// device-key gives each its key, and a message before it is not stored;
// without them, the numbers are paired again. device-key checks every
// account before it makes the key, so a refusal leaves no key that nobody
// holds. docs/devices.md gives the same runbook.
func TestResetAndDeviceKeyTexts(t *testing.T) {
	kept := resetNext(true)
	inOrder(t, "the reset with -keep-devices", kept,
		`Next, run "whatserverd device-key -device <id> -grant <email>" for each number.`,
		"Until then a message to the number is not stored: it has no key.",
		"A running wappie-api heard the reset and hears each device-key.", "needs no restart.")
	plain := resetNext(false)
	inOrder(t, "the reset", plain, "Next, pair each number again.", "A running wappie-api heard the reset, and needs no restart.")
	if strings.Contains(plain, "device-key") {
		t.Fatalf("the reset without -keep-devices names device-key, which has no number to act on:\n%s", plain)
	}
	inOrder(t, "device-key's last lines", deviceKeyNext, "A running wappie-api hears this key", "It needs no restart.")
	for what, text := range map[string]string{"the reset with -keep-devices": kept, "the reset": plain, "device-key": deviceKeyNext} {
		if strings.Contains(text, "Stop wappie-api") || strings.Contains(text, "until it restarts") {
			t.Fatalf("%s still asks for a restart:\n%s", what, text)
		}
	}

	src := rawCode(t, ".")
	reset := funcBody(t, src, "resetArchive")
	inOrder(t, "reset-archive", reset, "the workspace's ingest waits meanwhile", "needs no restart", "tells their readers)",
		"fmt.Print(resetNext(*keepDevices))")
	inOrder(t, "device-key", funcBody(t, src, "deviceKey"), "keys.CheckGrant(", "keys.CreateArchiveKey(", "keys.PutGrant(",
		"fmt.Print(deviceKeyNext)\n\treturn nil")

	runbook := docSection(t, "../../docs/devices.md", "## Resetting the archive")
	inOrder(t, "devices.md's runbook", runbook, "A running `wappie-api` needs no restart.",
		"1. `whatserverd reset-archive -tenant <id> -keep-devices -yes-destroy-everything`.",
		"2. `whatserverd device-key -device <id> -grant <email>` for each number.")
	if strings.Contains(runbook, "Stop `wappie-api`.") || strings.Contains(runbook, "Start `wappie-api`.") {
		t.Fatalf("devices.md's runbook still stops and starts wappie-api:\n%s", runbook)
	}
}
