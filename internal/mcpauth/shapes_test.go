package mcpauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// shapesFile pins the JSON this server sends a reader: the consent and
// renewal relays and the status answers. The enclave's tests feed the same
// file to the parsers of the reader that is live
// (packages/mcp-http/enclave/test/go-a0-shapes.test.mjs), so a field added here
// that such a reader would refuse fails there, and a change here that the
// file does not follow fails in this test.
const shapesFile = "../../packages/mcp-http/enclave/test/go-a0-shapes.json"

// readerShapes are the bodies built with the same types and functions the
// handlers use, from fixed values.
func readerShapes() map[string]any {
	expires := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	sealed := make([]byte, 64)
	for i := range sealed {
		sealed[i] = byte(i)
	}
	relay := BundleRelay{
		ConnectionID: "0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b", TenantID: "01a08e0e-c546-7db3-9c44-e6352636d330",
		KID: "fedcba9876543210", Sealed: base64.RawURLEncoding.EncodeToString(sealed), ExpiresAt: expires,
	}
	content, media := relay, relay
	content.Kind = store.KindContent
	media.Kind, media.Media = store.KindContent, true
	service := uuid.MustParse("0199b3c4-0000-7000-8000-00000000c0de")
	answer := store.StatusAnswer{Status: "active", ExpiresAt: expires, Kind: store.KindContent, ServiceUserID: &service, Media: true}
	metadata := store.StatusAnswer{Status: "active", ExpiresAt: expires, Kind: store.KindMetadata}
	return map[string]any{
		"consent_relay_metadata":   relay,
		"consent_relay_content":    content,
		"consent_relay_media":      media,
		"renewal_relay":            content,
		"status_hosted":            standingReply(metadata, false, false, nil),
		"status_attested_metadata": standingReply(metadata, true, false, nil),
		"status_attested_content":  standingReply(answer, true, false, nil),
		"status_attested_media":    standingReply(answer, true, true, []string{"pdf", "zip"}),
	}
}

func TestReaderShapesPinned(t *testing.T) {
	raw, err := os.ReadFile(shapesFile)
	if err != nil {
		t.Fatal(err)
	}
	var pinned map[string]json.RawMessage
	if err := json.Unmarshal(raw, &pinned); err != nil {
		t.Fatal(err)
	}
	shapes := readerShapes()
	for name, body := range shapes {
		got, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		want, ok := pinned[name]
		if !ok {
			t.Errorf("%s is not pinned; add it:\n%s", name, got)
			continue
		}
		// The file is what a reader receives, byte for byte but for white
		// space, field order included.
		var compact bytes.Buffer
		if err := json.Compact(&compact, want); err != nil {
			t.Fatal(err)
		}
		if compact.String() != string(got) {
			t.Errorf("%s:\n got  %s\n file %s", name, got, compact.String())
		}
	}
	for name := range pinned {
		if _, ok := shapes[name]; !ok && name != "_comment" {
			t.Errorf("%s is pinned but no longer built", name)
		}
	}
}
