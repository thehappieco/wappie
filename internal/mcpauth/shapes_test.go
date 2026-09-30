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
// renewal relays, the status answers and, since sending (S0), what the send
// routes answer. The enclave's tests feed the same file to the parsers of
// the reader that is live (packages/mcp-http/enclave/test/
// go-s0-shapes.test.mjs), so a field added here that such a reader would
// refuse fails there, and a change here that the file does not follow fails
// in this test. go-a0-shapes.json keeps what the server sent from A0 until
// S0, for the tests of that era.
const shapesFile = "../../packages/mcp-http/enclave/test/go-s0-shapes.json"

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
	content, media, drafts, everything := relay, relay, relay, relay
	content.Kind = store.KindContent
	media.Kind, media.Media = store.KindContent, true
	drafts.Kind, drafts.Send = store.KindContent, store.SendModeDraft
	everything.Kind, everything.Media, everything.Send, everything.SendSelf, everything.SendGroups = store.KindContent, true, store.SendModeDraft, true, true
	service := uuid.MustParse("0199b3c4-0000-7000-8000-00000000c0de")
	answer := store.StatusAnswer{Status: "active", ExpiresAt: expires, Kind: store.KindContent, ServiceUserID: &service, Media: true}
	metadata := store.StatusAnswer{Status: "active", ExpiresAt: expires, Kind: store.KindMetadata}

	created := time.Date(2026, 10, 1, 9, 30, 15, 123456000, time.UTC)
	decided := created.Add(2 * time.Minute)
	draftID, sendID := uuid.MustParse("0199b3c4-1111-4222-8333-444455556666"), uuid.MustParse("0199b3c4-7777-7888-8999-aaaabbbbcccc")
	messageUID := uuid.MustParse("0199b3c4-dddd-7eee-8fff-000011112222")
	device := uuid.MustParse("0199b3c4-3333-7444-8555-666677778888")
	uid := messageUID.String()
	sentRow := store.Outbound{ID: sendID, Kind: store.OutboundSelf, Status: store.OutboundSent, DeviceID: device,
		ChatKey: "5511999999999@s.whatsapp.net", CreatedAt: created, DecidedAt: &decided, MessageUID: &messageUID}
	draftRow := store.Outbound{ID: draftID, Kind: store.OutboundDraft, Status: store.OutboundPending, DeviceID: device,
		ChatKey: "5511888888888@s.whatsapp.net", CreatedAt: created}
	next := encodeCursor(draftRow)
	return map[string]any{
		"consent_relay_metadata":    relay,
		"consent_relay_content":     content,
		"consent_relay_media":       media,
		"consent_relay_send":        drafts,
		"consent_relay_send_all":    everything,
		"renewal_relay":             content,
		"status_hosted":             standingReply(metadata, false, standingNow{}),
		"status_attested_metadata":  standingReply(metadata, true, standingNow{}),
		"status_attested_content":   standingReply(answer, true, standingNow{}),
		"status_attested_media":     standingReply(answer, true, standingNow{media: true, mediaOff: []string{"pdf", "zip"}}),
		"status_attested_send":      standingReply(answer, true, standingNow{send: store.SendModeDraft}),
		"status_attested_send_self": standingReply(answer, true, standingNow{media: true, send: store.SendModeDraft, sendSelf: true}),
		"draft_created":             draftCreated{ID: draftID.String(), ExpiresAt: created.Add(store.DraftTTL)},
		"send_sent":                 sentReply{ID: sendID.String(), MessageUID: &uid, WAID: "3EB0C0FFEE0123456789", Timestamp: decided},
		"send_sent_unarchived":      sentReply{ID: sendID.String(), WAID: "3EB0C0FFEE0123456789", Timestamp: decided, Duplicate: true},
		"rate_limited":              rateLimited{Code: "rate_limited", Message: "this connection's limit is reached", RetryAt: decided},
		"outbound_page":             outboundPage[outboundItem]{Items: []outboundItem{itemOf(sentRow), itemOf(draftRow)}, Next: &next},
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

// A page's next is opaque to the reader, at most 64 characters, and reads
// back as the row it was made from.
func TestOutboundCursor(t *testing.T) {
	row := store.Outbound{ID: uuid.New(), CreatedAt: time.Date(2026, 10, 1, 9, 30, 15, 123456000, time.UTC)}
	next := encodeCursor(row)
	back, ok := decodeCursor(next)
	if !ok || len(next) > 64 || back.ID != row.ID || !back.CreatedAt.Equal(row.CreatedAt) {
		t.Fatalf("cursor %q = %+v %v", next, back, ok)
	}
	for _, bad := range []string{"", "not base64!", next + "A", base64.RawURLEncoding.EncodeToString(make([]byte, 24))} {
		if _, ok := decodeCursor(bad); ok {
			t.Errorf("decoded %q", bad)
		}
	}
}
