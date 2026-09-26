package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"whatserver2/internal/config"
	"whatserver2/internal/mcpauth"
)

// attestedReaderID is the reader discovery advertises as
// endpoints.mcp_server_attested: the production enclave.
const attestedReaderID = "enclave"

// advertisedMCP is what discovery tells a console about the connector's
// addresses: the hosted reader's and the enclave's, each only when it is
// configured.
func advertisedMCP(cfg config.MCP) mcpEndpoints {
	var out mcpEndpoints
	if !cfg.Enabled {
		return out
	}
	if cfg.Hosted() {
		out.Server = strings.TrimSuffix(cfg.PublicOrigin, "/") + "/mcp"
	}
	if r, ok := cfg.Reader(attestedReaderID); ok {
		out.Attested = strings.TrimSuffix(r.PublicOrigin, "/") + "/mcp"
		out.Content = cfg.ContentEnabled
	}
	return out
}

// attestedReaders turns the configuration into the handler's readers, each
// with its own signed relay. The relay signs with SECRET; the reader's own
// requests are accepted under SECRET or, during a rotation, SECRET_NEXT.
func attestedReaders(cfg config.MCP) []*mcpauth.AttestedReader {
	out := make([]*mcpauth.AttestedReader, 0, len(cfg.Attested))
	for _, r := range cfg.Attested {
		secrets := []string{r.Secret}
		if r.SecretNext != "" {
			secrets = append(secrets, r.SecretNext)
		}
		out = append(out, &mcpauth.AttestedReader{
			ID: r.ID, PublicOrigin: r.PublicOrigin,
			Relay:   mcpauth.NewSignedRelay(r.ID, r.URL, r.Secret, nil),
			Secrets: secrets, Peers: r.Peers, Tenants: r.Tenants, AllTenants: r.AllTenants,
		})
	}
	return out
}

// maxCiphertext bounds the relay secret ciphertext, decoded: what KMS
// returns for a 43-byte plaintext is a few hundred bytes, and the reader
// refuses anything above 6144.
const maxCiphertext = 6144

// mcpRelaySecret hands an attested reader its next relay secret: the second
// step of a rotation. The owner has already encrypted the new secret under
// the reader's boot key and set it as WS_MCP_READER_<ID>_SECRET_NEXT here;
// this sends the ciphertext, signed with the current secret, and the reader
// switches to the new one. The plaintext never passes through this command.
//
//	whatserverd mcp-relay-secret -reader enclave < ciphertext.b64
func mcpRelaySecret(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("mcp-relay-secret", flag.ContinueOnError)
	readerID := fs.String("reader", "", "attested reader id (required), e.g. enclave")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *readerID == "" {
		fs.Usage()
		return errors.New("mcp-relay-secret: -reader is required")
	}
	if err := config.LoadDotEnv(".env"); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return rotateRelaySecret(ctx, cfg.MCP, *readerID, stdin, stdout, func(r config.MCPReader) *mcpauth.SignedRelay {
		return mcpauth.NewSignedRelay(r.ID, r.URL, r.Secret, nil)
	})
}

// rotateRelaySecret is the command without the process around it.
func rotateRelaySecret(ctx context.Context, cfg config.MCP, readerID string, stdin io.Reader, stdout io.Writer,
	relayFor func(config.MCPReader) *mcpauth.SignedRelay) error {
	if !cfg.Enabled {
		return errors.New("mcp-relay-secret: WS_MCP_ENABLED is not set")
	}
	r, ok := cfg.Reader(readerID)
	if !ok {
		return fmt.Errorf("mcp-relay-secret: %q is not a configured attested reader (WS_MCP_READERS)", readerID)
	}
	if r.SecretNext == "" {
		// Once the reader switches it signs with the new secret. Unless
		// this server already accepts it, every call the reader makes from
		// then on is refused, and consents stop.
		return fmt.Errorf("mcp-relay-secret: set WS_MCP_READER_%s_SECRET_NEXT to the new secret and restart the server first",
			strings.ToUpper(readerID))
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 4*maxCiphertext))
	if err != nil {
		return fmt.Errorf("mcp-relay-secret: read the ciphertext: %w", err)
	}
	ciphertext := strings.TrimSpace(string(raw))
	decoded, err := base64.StdEncoding.Strict().DecodeString(ciphertext)
	if err != nil || len(decoded) == 0 || len(decoded) > maxCiphertext {
		return errors.New("mcp-relay-secret: stdin must be the KMS ciphertext in standard base64, 1 to 6144 bytes decoded")
	}
	if err := relayFor(r).RelaySecret(ctx, ciphertext); err != nil {
		return fmt.Errorf("mcp-relay-secret: %w", err)
	}
	//nolint:errcheck // writing to stdout; nothing useful to do on failure
	fmt.Fprintf(stdout, "reader %s now signs with the new secret.\n"+
		"Next: replace boot.json on the parent with this ciphertext, then set WS_MCP_READER_%s_SECRET\n"+
		"to the new secret, unset WS_MCP_READER_%s_SECRET_NEXT, and restart the server.\n",
		readerID, strings.ToUpper(readerID), strings.ToUpper(readerID))
	return nil
}
