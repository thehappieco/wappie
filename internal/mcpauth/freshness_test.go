package mcpauth_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/membership"
	"whatserver2/internal/pg"
)

// Test 45, the connector's part (the plan's 4.12): a connection's, an AI
// authorization's and a token's creation ask the freshness hook for the
// person IfStale, a renewal always with a fresh GET, each before the store
// and before any bundle reaches the reader (a NOWAIT probe from inside the
// hook finds the workspace unlocked); a connection's send is checked in
// the background on the consenting person's stored freshness and never
// waits or is refused; with the enforce flag the rare acts are refused 503
// memberships_unconfirmed and change nothing.

type hookCall struct {
	act     string
	tenant  uuid.UUID
	parties []membership.Party
	probe   error
}

type hookRecorder struct {
	pool   *pgxpool.Pool
	mu     sync.Mutex
	calls  []hookCall
	refuse error
	// hold, while set, keeps a Stored call waiting.
	hold chan struct{}
}

func (r *hookRecorder) RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...membership.Party) (membership.Verdict, error) {
	probe := pg.InTenantTx(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE NOWAIT`, tenant)
		return err
	})
	r.mu.Lock()
	r.calls = append(r.calls, hookCall{act: act, tenant: tenant, parties: parties, probe: probe})
	refuse, hold := r.refuse, r.hold
	r.mu.Unlock()
	if hold != nil && len(parties) > 0 && parties[0].How == membership.Stored {
		select {
		case <-hold:
		case <-ctx.Done():
		}
	}
	return membership.Verdict{}, refuse
}

func (r *hookRecorder) RequireBackups(context.Context, string, uuid.UUID, uuid.UUID, uuid.UUID) (membership.Verdict, error) {
	panic("the connector narrows nobody's key")
}

func (r *hookRecorder) RequireMover(context.Context, uuid.UUID, uuid.UUID) (membership.Verdict, error) {
	panic("the connector moves no number")
}

func (r *hookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *hookRecorder) setRefuse(err error) {
	r.mu.Lock()
	r.refuse = err
	r.mu.Unlock()
}

// one waits up to a few seconds for the calls since n to be exactly one,
// and checks it.
func (r *hookRecorder) one(t *testing.T, n int, act string, tenant uuid.UUID, parties ...membership.Party) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.count() <= n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r.mu.Lock()
	calls := slices.Clone(r.calls[n:])
	r.mu.Unlock()
	if len(calls) != 1 || calls[0].act != act || calls[0].tenant != tenant || !slices.Equal(calls[0].parties, parties) || calls[0].probe != nil {
		t.Fatalf("%s: %+v, want one with %+v", act, calls, parties)
	}
}

func (h *attestedHarness) connections(t *testing.T) int {
	t.Helper()
	var n int
	if err := pg.InTenantTx(context.Background(), h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM mcp_connections`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFreshnessHook(t *testing.T) {
	ifStale := func(u uuid.UUID) membership.Party { return membership.Party{User: u, How: membership.IfStale} }

	t.Run("a sending connection and its send", func(t *testing.T) {
		h := newSendHarness(t)
		rec := &hookRecorder{pool: h.pool}
		h.handler.Membership = rec
		n := rec.count()
		c := h.consentSending(t, h.ownerToken, nil)
		rec.one(t, n, "mcp.connect", h.tenant, ifStale(h.owner.ID))
		// The send is answered while its check waits.
		hold := make(chan struct{})
		rec.mu.Lock()
		rec.hold = hold
		rec.mu.Unlock()
		n = rec.count()
		start := time.Now()
		expect(t, h.selfSend(t, c, clientRef(), "a note"), http.StatusOK, "")
		// The check waits for hold, up to its 5 s bound; the send did not.
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("the send waited %s for its check", took)
		}
		rec.one(t, n, "mcp.send", h.tenant, membership.Party{User: h.owner.ID, How: membership.Stored})
		close(hold)
		rec.mu.Lock()
		rec.hold = nil
		rec.mu.Unlock()
		// The enforce flag: a new connection is refused, a send goes on.
		rec.setRefuse(membership.ErrMembershipsUnconfirmed)
		before := h.connections(t)
		requestID, service, _, prefix := h.prepareContent(t, h.owner.ID)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", sendBody(t, requestID, prefix, service, true), bearer(h.ownerToken)),
			http.StatusServiceUnavailable, "memberships_unconfirmed")
		if after := h.connections(t); after != before {
			t.Fatalf("a refused consent made a connection: %d, %d", before, after)
		}
		expect(t, h.selfSend(t, c, clientRef(), "another note"), http.StatusOK, "")
	})

	t.Run("an AI authorization", func(t *testing.T) {
		h := newAIHarness(t)
		rec := &hookRecorder{pool: h.pool}
		h.handler.Membership = rec
		n := rec.count()
		h.consentAI(t, h.owner, nil)
		rec.one(t, n, "ai.connect", h.tenant, ifStale(h.owner.ID))
		rec.setRefuse(membership.ErrMembershipsUnconfirmed)
		before := h.connections(t)
		c := h.prepareAI(t, h.owner, nil)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusServiceUnavailable, "memberships_unconfirmed")
		if after := h.connections(t); after != before {
			t.Fatalf("a refused AI consent made a connection: %d, %d", before, after)
		}
	})

	t.Run("a token", func(t *testing.T) {
		h := newClientsHarness(t)
		h.verify(t, h.owner)
		h.activateTokens(t)
		rec := &hookRecorder{pool: h.pool}
		h.handler.Membership = rec
		requestID := h.tokenRequest(t, h.ownerToken)
		_, prefix := h.provisionalKey(t, "token")
		rec.setRefuse(membership.ErrMembershipsUnconfirmed)
		n := rec.count()
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", tokenBody(t, prefix), bearer(h.ownerToken)),
			http.StatusServiceUnavailable, "memberships_unconfirmed")
		rec.one(t, n, "mcp.token", h.tenant, ifStale(h.owner.ID))
		if got := h.connections(t); got != 0 {
			t.Fatalf("a refused token made %d connections", got)
		}
		rec.setRefuse(nil)
		n = rec.count()
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", tokenBody(t, prefix), bearer(h.ownerToken)), http.StatusCreated, "")
		rec.one(t, n, "mcp.token", h.tenant, ifStale(h.owner.ID))
	})

	t.Run("a renewal", func(t *testing.T) {
		h := newAttestedHarness(t)
		h.contentOn.Store(true)
		rec := &hookRecorder{pool: h.pool}
		h.handler.Membership = rec
		owner := h.session(t, h.owner)
		id, oldService, _ := h.consentContent(t, h.owner)
		rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
		expect(t, rs, http.StatusNoContent, "")
		newPub := randomKey(t)
		h.enclave.mu.Lock()
		h.enclave.renewalKey = newPub
		h.enclave.mu.Unlock()
		prepare := func() string {
			r := h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(owner))
			expect(t, r, http.StatusOK, "")
			var renewal struct {
				RenewalID string `json:"renewal_id"`
			}
			r.into(t, &renewal)
			return renewal.RenewalID
		}
		renew := func(renewalID string) reply {
			service, _, prefix := h.serviceFor(t, h.owner.ID, newPub)
			return h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", map[string]any{
				"renewal_id": renewalID, "key_prefix": prefix, "service_user_id": service.String(), "kid": enclaveRenewalKID, "sealed": sealed(t),
			}, bearer(owner))
		}
		// The enforce flag: refused before the bundle reaches the reader.
		rec.setRefuse(membership.ErrMembershipsUnconfirmed)
		renewalID := prepare()
		n := rec.count()
		expect(t, renew(renewalID), http.StatusServiceUnavailable, "memberships_unconfirmed")
		rec.one(t, n, "mcp.renew", h.tenant, membership.Party{User: h.owner.ID, How: membership.Always})
		h.enclave.mu.Lock()
		staged := h.enclave.renewalBundles[renewalID]
		h.enclave.mu.Unlock()
		if staged != nil {
			t.Fatalf("a refused renewal reached the reader: %v", staged)
		}
		if s := h.standing(t, id); s.ServiceUserID == nil || *s.ServiceUserID != oldService.String() {
			t.Fatalf("a refused renewal changed the connection: %+v", s)
		}
		rec.setRefuse(nil)
		n = rec.count()
		expect(t, renew(prepare()), http.StatusOK, "")
		rec.one(t, n, "mcp.renew", h.tenant, membership.Party{User: h.owner.ID, How: membership.Always})
	})
}
