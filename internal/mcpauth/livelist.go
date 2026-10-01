package mcpauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
)

// The attested live list (docs/mcp-enclave.md §19.22, live_list_v1). The
// console's list and banner come from this server's ledger, so a server that
// lied could hide a row; the reader is the one party that knows every live
// connection without trusting this server. The console asks for the list
// with a nonce of its own, this server relays the attested answer verbatim,
// and the console compares the ids with the ledger's. It detects; it does
// not remove.

// liveListPerMinute bounds the relay per workspace.
const liveListPerMinute = 10

// liveListBody is the console's request and the relay's: its nonce.
type liveListBody struct {
	Nonce string `json:"nonce"`
}

// liveListPrepared is the part of a live list this server reads.
type liveListPrepared struct {
	DescriptorVersion int      `json:"descriptor_version"`
	Kind              string   `json:"kind"`
	WorkspaceID       string   `json:"workspace_id"`
	Nonce             string   `json:"nonce"`
	ConnectionIDs     []string `json:"connection_ids"`
	At                string   `json:"at"`
	Attestation       *struct {
		Document  string `json:"document"`
		PCR0      string `json:"pcr0"`
		RequestID string `json:"request_id"`
	} `json:"attestation"`
}

// checkLiveList checks a live list's shape: a version-2 live list for this
// workspace and this nonce, connection ids that are lower-case UUIDs, sorted
// and once each, a time, and an attestation of bounded size made for no
// request. It does not verify the document; the console does.
func checkLiveList(raw json.RawMessage, workspace, nonce string) error {
	var p liveListPrepared
	if err := json.Unmarshal(raw, &p); err != nil {
		return errors.New("the live list is not the expected object")
	}
	if p.DescriptorVersion != descriptorV2 || p.Kind != kindLiveList || p.WorkspaceID != workspace || p.Nonce != nonce {
		return errors.New("the live list is not this workspace's, or not for this nonce")
	}
	if p.ConnectionIDs == nil || !slices.IsSorted(p.ConnectionIDs) || len(slices.Compact(slices.Clone(p.ConnectionIDs))) != len(p.ConnectionIDs) {
		return errors.New("the live list's ids are missing, unsorted or repeated")
	}
	for _, id := range p.ConnectionIDs {
		if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
			return errors.New("the live list holds an id that is not a connection's")
		}
	}
	if _, err := time.Parse(time.RFC3339, p.At); err != nil {
		return errors.New("the live list's time is malformed")
	}
	if p.Attestation == nil || p.Attestation.RequestID != "" {
		return errors.New("the live list carries no attestation, or one for a request")
	}
	document, err := base64.RawURLEncoding.Strict().DecodeString(p.Attestation.Document)
	if err != nil || len(document) == 0 || len(document) > maxAttestationDocument {
		return errors.New("the attestation document is missing, malformed or too large")
	}
	if len(p.Attestation.PCR0) != pcr0Len || !isHex(p.Attestation.PCR0) {
		return errors.New("the declared pcr0 is malformed")
	}
	return nil
}

// liveList relays the attested live list of the signed-in person's
// workspace. Any member who may list may ask; ten a minute per workspace.
func (h *Handler) liveList(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	workspace, err := uuid.Parse(r.PathValue("id"))
	if err != nil || workspace.String() != r.PathValue("id") || workspace != user.TenantID {
		fail(w, http.StatusNotFound, "not_found", "no such workspace")
		return
	}
	var req liveListBody
	if !decode(w, r, &req) {
		return
	}
	if !validPrepareNonce(req.Nonce) {
		fail(w, http.StatusBadRequest, "bad_request", "nonce must be 16 to 64 bytes in unpadded base64url")
		return
	}
	if h.LiveListLimits != nil {
		if ok, wait := h.LiveListLimits.Allow("live-list:" + workspace.String()); !ok {
			w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())))
			fail(w, http.StatusTooManyRequests, "rate_limited", "too many live lists for this workspace; try again in "+wait.String())
			return
		}
	}
	rd, ok := h.tokenReader(w, user.TenantID)
	if !ok {
		return
	}
	raw, err := rd.attested.Relay.LiveList(r.Context(), workspace.String(), req.Nonce)
	switch {
	case errors.Is(err, ErrReaderNotFound):
		// A reader before 0.6.0 keeps no such list.
		fail(w, http.StatusNotFound, "not_found", "this assistant connector keeps no attested live list")
		return
	case err != nil:
		h.readerError(w, err)
		return
	}
	if err := checkLiveList(raw, workspace.String(), req.Nonce); err != nil {
		h.log().Warn("an attested reader answered a live list with the wrong shape", "reader", rd.id, "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector answered with something unexpected; try again in a moment")
		return
	}
	sendRaw(w, raw)
}

// LiveList asks the reader for a workspace's live connections, attested over
// the console's nonce. The bytes come back as the reader sent them.
func (c *SignedRelay) LiveList(ctx context.Context, workspace, nonce string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/workspaces/"+url.PathEscape(workspace)+"/live-list", liveListBody{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusBadRequest:
		return nil, &RefusalError{Code: readerCode(body), Status: status}
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%w: live list answered 503 %s", ErrReaderUnavailable, readerCode(body))
	}
	return descriptorAnswer(status, body)
}
