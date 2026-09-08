package wa

import (
	"testing"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// TestPlaintextBuffersStayOff is a guard on the central promise of this system.
//
// whatsmeow can persist *decrypted* message protobufs in two places:
//
//	whatsmeow_event_buffer.plaintext   inbound, when EnableDecryptedEventBuffer
//	whatsmeow_retry_buffer.plaintext   outbound, when UseRetryMessageStore,
//	                                   retained for at least twelve hours
//
// Either one puts message plaintext on disk, in the same database as everything
// else, and quietly voids the claim that the server cannot read its own
// archive. Both default to false; the risk is not the default, it is somebody
// switching one on later to fix a retry bug without realising what it costs.
//
// This test is the thing that stops that commit.
func TestPlaintextBuffersStayOff(t *testing.T) {
	c := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	applyClientPolicy(c)

	if c.EnableDecryptedEventBuffer {
		t.Error("EnableDecryptedEventBuffer is on: inbound message plaintext would be written to " +
			"whatsmeow_event_buffer, defeating the sealed archive")
	}
	if c.UseRetryMessageStore {
		t.Error("UseRetryMessageStore is on: outbound message plaintext would be written to " +
			"whatsmeow_retry_buffer and kept for hours, defeating the sealed archive")
	}
}

// The v1 server's contacts table was created, queried on every message, and
// never once written to, because app state events are not emitted during a full
// sync unless this is set. Turning it off again would silently reproduce that.
func TestAppStateEventsAreEmittedOnFullSync(t *testing.T) {
	c := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	applyClientPolicy(c)

	if !c.EmitAppStateEventsOnFullSync {
		t.Error("EmitAppStateEventsOnFullSync is off: contacts, pins, mutes and archive state " +
			"will never arrive, exactly as in v1")
	}
}

// Defaults are only reassuring if they are actually the defaults. If upstream
// ever flips one of these on, applyClientPolicy still forces it off — but the
// change is worth knowing about, because it would mean upstream considers the
// buffer normal.
func TestUpstreamDefaultsAreStillSafe(t *testing.T) {
	c := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	if c.EnableDecryptedEventBuffer || c.UseRetryMessageStore {
		t.Error("upstream now enables a plaintext buffer by default; applyClientPolicy still " +
			"disables it, but the change deserves a look")
	}
}
