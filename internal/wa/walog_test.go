package wa

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// whatsmeow logs every binary node at debug level, which is every message in
// the clear. The adapter is the one place that can stop that reaching a log
// file, so it is tested as a property rather than trusted as a comment.
func TestDebugOutputIsDroppedUnlessTheWireLogWasAskedFor(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	NewWALogger(lg, "device").Debugf("<message from=%s>hello</message>", "5511@s.whatsapp.net")
	NewWALogger(lg, "device").Sub("recv").Debugf("node %s", "body")
	if buf.Len() != 0 {
		t.Fatalf("debug output reached the log even though nobody asked for the wire log:\n%s", buf.String())
	}

	NewWALogger(lg, "device").Infof("connected as %s", "device")
	if !strings.Contains(buf.String(), "connected") {
		t.Fatal("info output was dropped too; only debug should be")
	}

	buf.Reset()
	NewWireLogger(lg, "device").Sub("recv").Debugf("node %s", "body")
	if !strings.Contains(buf.String(), "node body") {
		t.Fatal("the wire logger should pass debug output through")
	}
}
