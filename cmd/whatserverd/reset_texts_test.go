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
// tell an operator (DS48, the platform's addendum to F4). wappie-api stops
// for any reset, which holds the workspace's lock for its whole run. With
// the numbers kept, device-key gives each its key before the start, since
// a running server keeps sealing to the old key until it restarts; without
// them, the numbers are paired again. device-key ends with the restart
// whatever it printed, and checks every account before it makes the key,
// so a refusal leaves no key that nobody holds. docs/devices.md gives the
// same runbook.
func TestResetAndDeviceKeyTexts(t *testing.T) {
	inOrder(t, "the reset with -keep-devices", resetNext(true),
		"1. Stop wappie-api.", "2. Reset (done).",
		`3. Run "whatserverd device-key -device <id> -grant <email>" for each number.`, "4. Start wappie-api.",
		"A running server keeps sealing to the old key until it restarts.")
	plain := resetNext(false)
	inOrder(t, "the reset", plain, "1. Stop wappie-api.", "2. Reset (done).", "3. Start wappie-api.", "4. Pair each number again.")
	if strings.Contains(plain, "device-key") {
		t.Fatalf("the reset without -keep-devices names device-key, which has no number to act on:\n%s", plain)
	}
	inOrder(t, "device-key's last lines", deviceKeyRestart, "Restart wappie-api now if it is running.",
		"A running server keeps sealing to the\nold key until it restarts.")

	src := rawCode(t, ".")
	reset := funcBody(t, src, "resetArchive")
	inOrder(t, "reset-archive", reset, "Stop wappie-api first", "tells their readers once it runs", "fmt.Print(resetNext(*keepDevices))")
	inOrder(t, "device-key", funcBody(t, src, "deviceKey"), "keys.CheckGrant(", "keys.CreateArchiveKey(", "keys.PutGrant(",
		"fmt.Print(deviceKeyRestart)\n\treturn nil")

	inOrder(t, "devices.md's runbook", docSection(t, "../../docs/devices.md", "## Resetting the archive"),
		"1. Stop `wappie-api`.", "2. `whatserverd reset-archive -tenant <id> -keep-devices -yes-destroy-everything`.",
		"3. `whatserverd device-key -device <id> -grant <email>` for each number.", "4. Start `wappie-api`.")
}
