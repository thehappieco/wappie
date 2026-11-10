package wsapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/access"
	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// The grant page's frames (step 7's plan, 5.4), an owner's or admin's:
// token.grant_context draws the page, token.waiting lists the tokens that
// wait for a number's key, and token.grant writes the grant
// (store.Tokens.PutTokenGrant). A token of another workspace answers as an
// unknown one. A grant needs a signed GET of the token's record under a
// minute old when Wappie writes it. The context of a live token, and a
// grant the store finds stale, ask the platform for one first
// (TokenRecords).
//
// A grant also names the archive key it was sealed for, by its fingerprint
// (store.ArchiveKeyFingerprint, DS49). After an archive reset that kept the
// numbers, a number's new key takes epoch 1 again, so the epoch alone
// cannot tell the old key's grant from the new one's. The client computes
// the fingerprint from the key it seals and compares it with the
// context's; an echo of the context's would let the deleted key through.

// TokenRecords is what the grant frames ask of the contract's client: a
// token's record fetched by a signed GET and applied
// (membership.Members.FetchToken).
type TokenRecords interface {
	FetchToken(ctx context.Context, tenant, token uuid.UUID) error
}

// maxTokenGrantNumbers is how many numbers one grant frame may name.
const maxTokenGrantNumbers = 100

// noSuchToken answers a token id this workspace does not hold, one of
// another workspace, and one with no reading key yet, alike.
const noSuchToken = "no such token in this workspace, or it has no reading key yet"

// tokenStore is the store of platform tokens, nil when none is configured.
func (s *Server) tokenStore() *store.Tokens {
	if s.cfg.Access == nil {
		return nil
	}
	return s.cfg.Access.Tokens
}

// fullID reads an id in its full canonical form, the only one these frames
// take.
func fullID(raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	return id, err == nil && id != uuid.Nil && id.String() == raw
}

// fullIDs reads the numbers a grant frame names, each by its full id, at
// most maxTokenGrantNumbers.
func (s *session) fullIDs(reqID string, raws []string) ([]uuid.UUID, bool) {
	if len(raws) > maxTokenGrantNumbers {
		s.replyError(reqID, ErrCodeBadRequest, "name at most 100 numbers")
		return nil, false
	}
	out := make([]uuid.UUID, 0, len(raws))
	for _, raw := range raws {
		id, ok := fullID(raw)
		if !ok {
			s.replyError(reqID, ErrCodeBadRequest, "device_ids must be full ids")
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

// grantFrame is what every grant frame needs first: an owner or admin, the
// workspace, and the token store.
func (s *session) grantFrame(reqID string) (actor, uuid.UUID, *store.Tokens, bool) {
	who, ok := s.requireAdmin(reqID)
	if !ok {
		return actor{}, uuid.Nil, nil, false
	}
	tokens := s.srv.tokenStore()
	if tokens == nil {
		s.replyError(reqID, ErrCodeInternal, "platform tokens are not configured on this server")
		return actor{}, uuid.Nil, nil, false
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(reqID, ErrCodeInternal, "bad tenant")
		return actor{}, uuid.Nil, nil, false
	}
	return who, tenant, tokens, true
}

// fetchToken asks the platform for the token's record now and applies it,
// reporting whether that worked. A failure leaves the record as it was.
func (s *session) fetchToken(ctx context.Context, tenant, token uuid.UUID) bool {
	records := s.srv.cfg.TokenRecords
	if records == nil {
		return false
	}
	err := records.FetchToken(ctx, tenant, token)
	switch {
	case err == nil:
		return true
	case errors.Is(err, membership.ErrTokenNotFound):
		s.log.Info("the platform knows no such token for the grant page", "token", token)
	default:
		s.log.Warn("could not fetch a token's record for the grant page", "token", token, "error", err)
	}
	return false
}

// handleTokenGrantContext answers what the grant page draws from. When the
// token is live and its last signed GET is over a minute old, it asks the
// platform for its record first, and answers what Wappie holds after it.
func (s *session) handleTokenGrantContext(ctx context.Context, f Frame) {
	_, tenant, tokens, ok := s.grantFrame(f.ReqID)
	if !ok {
		return
	}
	var req TokenGrantContextRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	token, ok := fullID(req.TokenID)
	if !ok {
		s.replyError(f.ReqID, ErrCodeBadRequest, "token_id must be a full id")
		return
	}
	devices, ok := s.fullIDs(f.ReqID, req.DeviceIDs)
	if !ok {
		return
	}
	now := time.Now()
	got, err := tokens.TokenGrantContext(ctx, tenant, token, devices, now)
	if err == nil && got.Live && !store.TokenFetchedFresh(got.FetchedAt, now) && s.fetchToken(ctx, tenant, token) {
		got, err = tokens.TokenGrantContext(ctx, tenant, token, devices, now)
	}
	if errors.Is(err, store.ErrNotFound) {
		s.replyError(f.ReqID, ErrCodeNotFound, noSuchToken)
		return
	}
	if err != nil {
		s.log.Error("reading a token's grant context failed", "token", token, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not read the token")
		return
	}
	out := TokenGrantContext{TokenID: got.ID.String(), Name: got.Name, ReadingKey: base64.RawURLEncoding.EncodeToString(got.Key),
		ReadingKeyFingerprint: got.Fingerprint, IdentityID: got.Identity.String(), Live: got.Live, KeyChanged: got.KeyChanged,
		Fresh: store.TokenFetchedFresh(got.FetchedAt, now), FetchedAt: got.FetchedAt, Numbers: make([]TokenGrantNumber, 0, len(got.Numbers))}
	for _, n := range got.Numbers {
		out.Numbers = append(out.Numbers, TokenGrantNumber{DeviceID: n.Device.String(), ArchiveTenantID: n.ArchiveTenantID.String(),
			Epoch: int(n.CurrentEpoch), ArchiveKeyFingerprint: n.ArchiveKeyFingerprint, Read: n.Read, Granted: n.Granted})
	}
	s.reply(TypeTokenGrantContextResult, f.ReqID, out)
}

// handleTokenWaiting lists the tokens that wait for the key of the numbers
// named, or of every number of the workspace.
func (s *session) handleTokenWaiting(ctx context.Context, f Frame) {
	_, tenant, tokens, ok := s.grantFrame(f.ReqID)
	if !ok {
		return
	}
	var req TokenWaitingRequest
	if len(f.Payload) > 0 {
		if err := json.Unmarshal(f.Payload, &req); err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
			return
		}
	}
	devices, ok := s.fullIDs(f.ReqID, req.DeviceIDs)
	if !ok {
		return
	}
	waiting, err := tokens.WaitingTokens(ctx, tenant, devices, time.Now())
	if err != nil {
		s.log.Error("listing the tokens that wait for a key failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list the tokens")
		return
	}
	out := TokenWaitingList{Tokens: make([]TokenWaiting, 0, len(waiting))}
	for _, w := range waiting {
		out.Tokens = append(out.Tokens, TokenWaiting{DeviceID: w.Device.String(), TokenID: w.Token.String(), Name: w.Name})
	}
	s.reply(TypeTokenWaitingList, f.ReqID, out)
}

// handleTokenGrant records a number's key sealed to a token's identity,
// after the person's step-up and their own freshness, as grant.add does.
// The store judges the token's liveness and its record's minute on
// Wappie's clock at the write (0053: under a minute old when Wappie accepts
// the grant), so the time the step-up and the freshness check take counts.
// When the record is stale there, it asks the platform for the record and
// tries once more. It answers the number's readers, its tokens apart, as
// they now stand.
func (s *session) handleTokenGrant(ctx context.Context, f Frame) {
	who, tenant, tokens, ok := s.grantFrame(f.ReqID)
	if !ok {
		return
	}
	var req TokenGrantRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	token, okToken := fullID(req.TokenID)
	device, okDevice := fullID(req.DeviceID)
	switch {
	case !okToken || !okDevice:
		s.replyError(f.ReqID, ErrCodeBadRequest, "token_id and device_id must be full ids")
		return
	case req.Epoch < 1 || req.Epoch > 1<<16-1:
		s.replyError(f.ReqID, ErrCodeBadRequest, "epoch must be between 1 and 65535")
		return
	case !store.ValidArchiveKeyFingerprint(req.ArchiveKeyFingerprint):
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"archive_key_fingerprint must be the fingerprint of the archive key you sealed: 64 lowercase hex characters, computed from that key")
		return
	case len(req.SealedDSK) == 0:
		s.replyError(f.ReqID, ErrCodeBadRequest, "a grant with no sealed key is not a grant")
		return
	}
	// It hands the number's key on, as grant.add does: the person's fresh
	// step-up, and their own freshness (README 7.1).
	if !s.stepUpRecent(ctx, f.ReqID, who) {
		return
	}
	if !s.widening(ctx, f.ReqID, TypeTokenGrant, person(who, membership.IfStale)) {
		return
	}
	g := store.TokenGrant{Workspace: tenant, Token: token, Device: device, Epoch: uint16(req.Epoch), //nolint:gosec // G115: checked above
		ArchiveKeyFingerprint: req.ArchiveKeyFingerprint, SealedDSK: req.SealedDSK, Sealer: who.userID, Now: time.Now()}
	err := tokens.PutTokenGrant(ctx, g)
	if errors.Is(err, store.ErrTokenStale) && s.fetchToken(ctx, tenant, token) {
		g.Now = time.Now()
		err = tokens.PutTokenGrant(ctx, g)
	}
	if err != nil {
		s.tokenGrantRefused(f.ReqID, token, device, err)
		return
	}
	s.log.Info("device key granted to a token", "device", device, "token", token, "by", who.email, "epoch", req.Epoch)
	s.replyReaders(ctx, f.ReqID, tenant, device, device.String())
}

// tokenGrantRefused answers a refused token grant.
func (s *session) tokenGrantRefused(reqID string, token, device uuid.UUID, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.replyError(reqID, ErrCodeNotFound, noSuchToken)
	case errors.Is(err, store.ErrTokenNotLive):
		s.replyError(reqID, ErrCodeTokenNotLive, "this token is not live here: it is revoked, expired or stopped, or platform tokens are off")
	case errors.Is(err, store.ErrTokenKeyChanged):
		s.replyError(reqID, ErrCodeReadingKeyChanged, "this token's reading key is not the one Wappie pinned, so it takes no grant")
	case errors.Is(err, store.ErrTokenStale):
		s.replyError(reqID, ErrCodeTokenUnconfirmed, "Wappie could not confirm this token with the platform in the last minute; try again")
	case errors.Is(err, store.ErrTokenNoRead):
		s.replyError(reqID, ErrCodeTokenNoRead, "this token does not read this number")
	case errors.Is(err, store.ErrNumberGone):
		s.replyError(reqID, ErrCodeNotFound, "this number is no longer in this workspace")
	case errors.Is(err, store.ErrTokenEpoch):
		s.replyError(reqID, ErrCodeConflict, "this number seals under another generation now; reload and seal again")
	case errors.Is(err, store.ErrNoArchiveKey):
		s.replyError(reqID, ErrCodeConflict, "this number has no archive key, so there is nothing to grant")
	case errors.Is(err, store.ErrArchiveKeyChanged):
		// conflict, as grant.add answers it (DS49).
		s.replyError(reqID, ErrCodeConflict, "this number's archive key is not the one the grant was sealed for; reload and seal again")
	case errors.Is(err, store.ErrSealerCannotRead):
		s.replyError(reqID, ErrCodeNotAuthorized, "only an owner or admin who reads this number now can share its key")
	default:
		s.log.Error("recording a token grant failed", "token", token, "device", device, "error", err)
		s.replyError(reqID, ErrCodeInternal, "could not record the grant")
	}
}

// tokenGrants answers grants.list for a token: its identity's grants at
// each number's current epoch, on the numbers it reads now, with user_id
// its identity, as the plan's 5.4 says. A token with no identity (no
// reading key yet) holds none.
func (s *session) tokenGrants(ctx context.Context, f Frame) {
	who := s.actor()
	tenant, err := uuid.Parse(who.tenant)
	tokens := s.srv.tokenStore()
	if err != nil || tokens == nil || s.srv.cfg.Keys2 == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "grants are not configured on this server")
		return
	}
	out := Grants{Grants: []GrantEntry{}}
	identity, err := tokens.Identity(ctx, who.token)
	if errors.Is(err, store.ErrNotFound) {
		s.replyRead(ctx, TypeGrants, f.ReqID, out)
		return
	}
	if err != nil {
		s.log.Error("reading a token's identity failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list the grants")
		return
	}
	live, err := s.checker().TokenSets(ctx, access.Actor{Tenant: tenant, Token: who.token})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check grant permissions")
		return
	}
	grants, err := s.srv.cfg.Keys2.GrantsFor(ctx, tenant, identity)
	if err != nil {
		s.log.Error("listing a token's grants failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list the grants")
		return
	}
	labels := map[uuid.UUID]string{}
	if devices, err := s.srv.cfg.Devices.List(ctx, tenant.String()); err == nil {
		for _, d := range devices {
			if id, err := uuid.Parse(d.ID); err == nil {
				labels[id] = d.Label
			}
		}
	}
	out.UserID = identity.String()
	for _, g := range grants {
		if _, ok := live.Reads[g.DeviceID]; !ok {
			continue
		}
		readUnder(ctx, g.DeviceID)
		out.Grants = append(out.Grants, GrantEntry{ArchiveTenantID: g.ArchiveTenantID.String(), DeviceID: g.DeviceID.String(),
			Label: labels[g.DeviceID], Epoch: int(g.Epoch), SealedDSK: g.SealedDSK})
	}
	s.replyRead(ctx, TypeGrants, f.ReqID, out)
}
