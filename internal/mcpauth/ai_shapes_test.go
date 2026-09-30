package mcpauth

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// aiShapesFile pins the JSON this server sends the enclave for AI
// integrations (docs/mcp-enclave.md §18.11): the AI request, the consent's
// and the renewal's relays, a job, and what the enclave's AI routes answer,
// the status of an AI row included. It lives beside go-s0-shapes.json, with
// the enclave's tests (go-b1-shapes.test.mjs), which put every body through
// the reader's own parsers, so a field added here that the enclave would
// refuse fails there.
const aiShapesFile = "../../packages/mcp-http/enclave/test/go-b1-shapes.json"

// aiShapes are the bodies built with the same types and functions the
// handlers use, from fixed values.
func aiShapes() map[string]any {
	expires := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	sealed := make([]byte, 64)
	for i := range sealed {
		sealed[i] = byte(i)
	}
	relay := BundleRelay{
		ConnectionID: "0199b3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b", TenantID: "01a08e0e-c546-7db3-9c44-e6352636d330",
		KID: "fedcba9876543210", Sealed: base64.RawURLEncoding.EncodeToString(sealed), ExpiresAt: expires, Kind: store.KindAI,
	}
	service := uuid.MustParse("0199b3c4-0000-7000-8000-00000000c0de")
	device := uuid.MustParse("0199b3c4-3333-7444-8555-666677778888")
	requester := uuid.MustParse("0199b3c4-9999-7aaa-8bbb-ccccddddeeee")
	uid := uuid.MustParse("0199b3c4-dddd-7eee-8fff-000011112222")
	config := &store.AIConfig{Functions: map[string]store.AIFunction{
		"audio": {Provider: "google", Model: "gemini-3.8-flash"}, "document": {Provider: "anthropic", Model: "claude-sonnet-5-5"},
	}}
	active := store.StatusAnswer{Status: "active", ExpiresAt: expires, Kind: store.KindAI, ServiceUserID: &service, AIConfig: config}
	capCents := 500
	narrowed := active
	narrowed.AIOff, narrowed.AIPaused, narrowed.AICapCents = []string{"image"}, true, &capCents
	created := time.Date(2026, 10, 1, 9, 30, 15, 123456000, time.UTC)
	record := append([]byte("WDRV"), 1, 0, 1)
	record = append(record, make([]byte, 12+16+8)...)
	job := AIJobRequest{
		AuthorizationID: relay.ConnectionID, DeviceID: device.String(), UID: uid.String(), Feature: "audio",
		Origin: store.AIOriginConsole, RequesterID: requester.String(),
	}
	redo := job
	redo.Redo = true
	return map[string]any{
		"ai_request":             prepareRequest{Nonce: "AAECAwQFBgcICQoLDA0ODw"},
		"consent_relay_ai":       relay,
		"renewal_relay_ai":       relay,
		"ai_job":                 job,
		"ai_job_redo":            redo,
		"status_attested_ai":     aiStanding(active, nil, nil, nil),
		"status_attested_ai_off": aiStanding(narrowed, []string{"pdf", "zip"}, []string{"video"}, []string{"anthropic"}),
		"status_attested_ai_reseal": aiStanding(store.StatusAnswer{Status: "reseal", ExpiresAt: expires, Kind: store.KindAI,
			ServiceUserID: &service, AIConfig: config}, nil, nil, nil),
		"ai_pick_active": aiPickReply{AuthorizationID: relay.ConnectionID, RequesterID: requester.String(), State: "active"},
		"ai_pick_reseal": aiPickReply{AuthorizationID: relay.ConnectionID, RequesterID: requester.String(), State: "reseal"},
		"ai_derived_items": enclaveDerivedItems([]store.AIDerived{{
			MessageUID: uid, Feature: "audio", DeviceID: device, Epoch: 1, Sealed: record, CreatedAt: created,
		}}),
		"ai_derived_none": enclaveDerivedItems(nil),
		"ai_usage_month":  aiMonthReply{Month: "2026-10", CostMicrocents: 240_000, ItemsToday: 2},
	}
}

func TestAIShapesPinned(t *testing.T) {
	checkPinned(t, aiShapesFile, aiShapes())
}
