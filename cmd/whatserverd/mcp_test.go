package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/config"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

var (
	testSecret     = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	testSecretNext = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
)

func enclaveConfig() config.MCP {
	return config.MCP{
		Enabled: true, ReaderURL: "http://127.0.0.1:18093", PublicOrigin: "https://api.example.test/",
		Readers: []string{"hosted", "enclave"},
		Attested: []config.MCPReader{{
			ID: "enclave", URL: "https://mcp.example.test:8443", PublicOrigin: "https://mcp.example.test",
			Secret: testSecret, SecretNext: testSecretNext,
			Peers:   []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
			Tenants: []uuid.UUID{uuid.MustParse("01a08e0e-c546-7db3-9c44-e6352636d330")},
		}},
	}
}

// Discovery names each configured reader's address, and nothing when the
// connector is off.
func TestAdvertisedMCP(t *testing.T) {
	cfg := enclaveConfig()
	if got := advertisedMCP(cfg); got.Server != "https://api.example.test/mcp" || got.Attested != "https://mcp.example.test/mcp" {
		t.Fatalf("both = %+v", got)
	}
	cfg.Readers = []string{"enclave"}
	if got := advertisedMCP(cfg); got.Server != "" || got.Attested != "https://mcp.example.test/mcp" {
		t.Fatalf("enclave alone = %+v", got)
	}
	cfg.Enabled = false
	if got := advertisedMCP(cfg); got != (mcpEndpoints{}) {
		t.Fatalf("disabled = %+v", got)
	}
	// Only the reader called enclave is the attested endpoint.
	cfg = enclaveConfig()
	cfg.Attested[0].ID = "staging"
	cfg.ContentEnabled = true
	if got := advertisedMCP(cfg); got.Attested != "" || got.Content {
		t.Fatalf("a staging reader was advertised: %+v", got)
	}
	// Content rides on the enclave and the switch.
	cfg = enclaveConfig()
	if got := advertisedMCP(cfg); got.Content {
		t.Fatalf("content advertised with the switch off: %+v", got)
	}
	cfg.ContentEnabled = true
	if got := advertisedMCP(cfg); !got.Content || got.Media {
		t.Fatalf("content not advertised, or media with its switch off: %+v", got)
	}
	// Media rides on content and its own switch.
	cfg.MediaEnabled = true
	if got := advertisedMCP(cfg); !got.Content || !got.Media {
		t.Fatalf("media not advertised: %+v", got)
	}
	cfg.ContentEnabled = false
	if got := advertisedMCP(cfg); got.Content || got.Media {
		t.Fatalf("media advertised with content off: %+v", got)
	}
	// Sending likewise.
	cfg = enclaveConfig()
	cfg.ContentEnabled = true
	if got := advertisedMCP(cfg); got.Send {
		t.Fatalf("sending advertised with its switch off: %+v", got)
	}
	cfg.SendEnabled = true
	if got := advertisedMCP(cfg); !got.Content || !got.Send {
		t.Fatalf("sending not advertised: %+v", got)
	}
	cfg.ContentEnabled = false
	if got := advertisedMCP(cfg); got.Send {
		t.Fatalf("sending advertised with content off: %+v", got)
	}
}

// The handler's limits are the configuration's, field for field.
func TestSendLimitsFromConfig(t *testing.T) {
	got := sendLimits(config.MCPSendLimits{DraftsPerHour: 1, DraftsPending: 2, PerDay: 3, PerChatPerDay: 4, MinInterval: 5 * time.Minute, TenantPerDay: 6})
	if got != (store.SendLimits{DraftsPerHour: 1, DraftsPending: 2, PerDay: 3, PerChatPerDay: 4, MinInterval: 5 * time.Minute, TenantPerDay: 6}) {
		t.Fatalf("limits = %+v", got)
	}
}

// The send route's answers from the socket, in the connector's words: a
// send refused before it left stays one, whichever the reason.
func TestMCPSendTextErrors(t *testing.T) {
	for in, want := range map[error]error{
		wsapi.ErrDeviceOffline:                      mcpauth.ErrDeviceOffline,
		wsapi.ErrCapturePaused:                      mcpauth.ErrStoragePaused,
		fmt.Errorf("%w: storage", wsapi.ErrNotSent): mcpauth.ErrNotSent,
	} {
		got := mapSendError(in)
		if !errors.Is(got, want) || !errors.Is(got, mcpauth.ErrNotSent) {
			t.Fatalf("%v became %v", in, got)
		}
	}
	transport := errors.New("socket closed")
	if got := mapSendError(transport); !errors.Is(got, transport) || errors.Is(got, mcpauth.ErrNotSent) {
		t.Fatalf("a transport error became %v", got)
	}
}

// The handler's readers carry both secrets during a rotation and sign with
// the current one.
func TestAttestedReadersFromConfig(t *testing.T) {
	readers := attestedReaders(enclaveConfig())
	if len(readers) != 1 {
		t.Fatalf("readers = %v", readers)
	}
	r := readers[0]
	if r.ID != "enclave" || r.PublicOrigin != "https://mcp.example.test" || len(r.Secrets) != 2 ||
		r.Secrets[0] != testSecret || r.Secrets[1] != testSecretNext || len(r.Peers) != 1 || len(r.Tenants) != 1 {
		t.Fatalf("reader = %+v", r)
	}
	if r.Relay.Secret != testSecret || r.Relay.BaseURL != "https://mcp.example.test:8443" || r.Relay.ReaderID != "enclave" {
		t.Fatalf("relay = %s %s", r.Relay.BaseURL, r.Relay.ReaderID)
	}
	cfg := enclaveConfig()
	cfg.Attested[0].SecretNext = ""
	if r := attestedReaders(cfg)[0]; len(r.Secrets) != 1 {
		t.Fatalf("secrets without a rotation = %d", len(r.Secrets))
	}
}

// The rotation command sends the ciphertext as it was given, signed with the
// current secret, and refuses to run when this server would not accept the
// new secret afterwards.
func TestRotateRelaySecret(t *testing.T) {
	var got struct {
		Ciphertext string `json:"ciphertext"`
	}
	var signedOK bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		want := mcpauth.Signature(testSecret, mcpauth.DirectionToReader, "enclave", r.Method, r.RequestURI,
			r.Header.Get(mcpauth.HeaderTimestamp), r.Header.Get(mcpauth.HeaderNonce), body)
		signedOK = r.URL.Path == "/internal/relay-secret" && r.Method == http.MethodPost && r.Header.Get(mcpauth.HeaderSignature) == want
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	relayFor := func(r config.MCPReader) *mcpauth.SignedRelay {
		return mcpauth.NewSignedRelay(r.ID, srv.URL, r.Secret, pool)
	}
	ctx := context.Background()
	ciphertext := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 300))

	var out bytes.Buffer
	if err := rotateRelaySecret(ctx, enclaveConfig(), "enclave", strings.NewReader(ciphertext+"\n"), &out, relayFor); err != nil {
		t.Fatal(err)
	}
	if !signedOK || got.Ciphertext != ciphertext {
		t.Fatalf("signed = %v, ciphertext = %q", signedOK, got.Ciphertext)
	}
	if !strings.Contains(out.String(), "WS_MCP_READER_ENCLAVE_SECRET_NEXT") || strings.Contains(out.String(), testSecretNext) {
		t.Fatalf("output = %q", out.String())
	}

	for name, tc := range map[string]struct {
		cfg    func() config.MCP
		reader string
		stdin  string
		want   string
	}{
		"disabled":        {func() config.MCP { c := enclaveConfig(); c.Enabled = false; return c }, "enclave", ciphertext, "WS_MCP_ENABLED"},
		"unknown reader":  {enclaveConfig, "staging", ciphertext, "not a configured"},
		"hosted":          {enclaveConfig, "hosted", ciphertext, "not a configured"},
		"no next secret":  {func() config.MCP { c := enclaveConfig(); c.Attested[0].SecretNext = ""; return c }, "enclave", ciphertext, "SECRET_NEXT"},
		"empty":           {enclaveConfig, "enclave", "", "standard base64"},
		"url-safe base64": {enclaveConfig, "enclave", strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 30))), "standard base64"},
		"unpadded":        {enclaveConfig, "enclave", strings.TrimRight(base64.StdEncoding.EncodeToString([]byte{1, 2}), "="), "standard base64"},
		"too long":        {enclaveConfig, "enclave", base64.StdEncoding.EncodeToString(make([]byte, 6145)), "standard base64"},
	} {
		t.Run(name, func(t *testing.T) {
			signedOK = false
			err := rotateRelaySecret(ctx, tc.cfg(), tc.reader, strings.NewReader(tc.stdin), io.Discard, relayFor)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if signedOK {
				t.Fatal("a refused rotation reached the reader")
			}
		})
	}
}
