package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// The operator's archive reset counts as Read taken away from everyone (the
// platform's 0061, its third rule; DS48): it deletes every grant and leaves
// none at a number's current epoch. It ends every live connection and AI
// integration of the workspace itself, under the workspace's lock, before
// the deletes: no start follows a reset run from the command line, a
// metadata key asks nothing of a grant, and without -keep-devices no later
// check could find the connections.

// resetSet is what one person made before a reset: a content connection
// and an AI integration on number, a metadata one on number and other, a
// pending metadata one on other, and the owner's content one on other.
type resetSet struct {
	person, number, other uuid.UUID
	live                  []string
	meta                  string
	metaKey               uuid.UUID
	services              []uuid.UUID
	// consent and renewal were prepared before the reset, to be recorded
	// after it: a metadata consent on number, a renewal of content.
	consent store.CreateMCPConnection
	renewal store.RenewMCPConnection
	content string
}

func newResetSet(t *testing.T, w *ownWorld) resetSet {
	t.Helper()
	ctx := context.Background()
	s := resetSet{number: w.number(t, "Reset"), other: w.number(t, "Other")}
	s.person, _ = w.actor(t, "admin", "admin")
	for _, d := range []uuid.UUID{s.number, s.other} {
		w.reads(t, w.owner, d)
		w.reads(t, s.person, d)
	}
	var svc uuid.UUID
	s.content, svc = w.connect(t, s.person, store.KindContent, s.number)
	s.services = append(s.services, svc)
	ai, svc := w.connect(t, s.person, store.KindAI, s.number)
	s.services = append(s.services, svc)
	s.meta, _ = w.connect(t, s.person, store.KindMetadata, s.number, s.other)
	pending, err := w.conns.Create(ctx, w.tenant, s.person, w.prepare(t, s.person, store.KindMetadata, s.other))
	if err != nil {
		t.Fatal(err)
	}
	theirs, svc := w.connect(t, w.owner, store.KindContent, s.other)
	s.services = append(s.services, svc)
	s.live = []string{s.content, ai, s.meta, pending.ID, theirs}
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT api_key_id FROM mcp_connections WHERE id = $1`, s.meta).Scan(&s.metaKey)
	})
	s.consent = w.prepare(t, s.person, store.KindMetadata, s.number)
	s.renewal = w.renewal(t, s.person, s.number)
	return s
}

// ended checks that every connection of s ended revoked and access_lost,
// its key revoked and its service account gone.
func (w *ownWorld) resetEnded(t *testing.T, what string, s resetSet) {
	t.Helper()
	for _, id := range s.live {
		if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("%s: connection %s %+v", what, id, r)
		}
	}
	for _, svc := range s.services {
		if tr := w.trace(t, svc); tr != (serviceTrace{}) {
			t.Fatalf("%s: an ended connection's account remains: %+v", what, tr)
		}
	}
}

// TestResetArchiveEndsConnections: with the numbers kept or not, the reset
// ends every live connection of the workspace, any kind and status, and
// counts them. A consent and a renewal prepared before it and recorded
// after are refused. With the numbers kept, a number given a new key by
// device-key and granted to another account no longer answers the old
// metadata key, which asks nothing of a grant.
func TestResetArchiveEndsConnections(t *testing.T) {
	ctx := context.Background()
	for _, keep := range []bool{true, false} {
		w := newOwnWorld(t)
		s := newResetSet(t, w)
		counts, err := store.ResetArchive(ctx, w.pool, w.tenant, keep)
		if err != nil {
			t.Fatal(err)
		}
		what := map[bool]string{true: "kept numbers", false: "numbers deleted"}[keep]
		if counts.Connections != int64(len(s.live)) {
			t.Fatalf("%s: %d connections ended, want %d", what, counts.Connections, len(s.live))
		}
		w.resetEnded(t, what, s)
		if n := w.count(t, `SELECT count(*) FROM mcp_connections WHERE status IN ('pending', 'active', 'reseal')`); n != 0 {
			t.Fatalf("%s: %d live connections after the reset", what, n)
		}
		if _, err := w.conns.Create(ctx, w.tenant, s.person, s.consent); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("%s: a consent after the reset: %v", what, err)
		}
		if _, err := w.conns.Renew(ctx, w.tenant, s.person, s.content, s.renewal); err == nil {
			t.Fatalf("%s: a renewal after the reset was taken", what)
		}
		if r := w.row(t, s.content); r.status != "revoked" {
			t.Fatalf("%s: the refused renewal changed the connection: %+v", what, r)
		}
		// Nothing left for the check at the next start.
		if ended, err := store.EndConnectionsWithoutRead(ctx, w.pool); err != nil || len(ended) != 0 {
			t.Fatalf("%s: the check after the reset: %+v %v", what, ended, err)
		}
		if !keep {
			continue
		}
		// device-key on a kept number: a new key at epoch 1, sealed to
		// another account only.
		other, _ := w.actor(t, "member", "member")
		pub, _, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := w.keys.CreateArchiveKey(ctx, w.tenant, s.number, 1, pub); err != nil {
			t.Fatal(err)
		}
		if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: s.number, UserID: other, Epoch: 1, SealedDSK: []byte("new key")}, nil); err != nil {
			t.Fatal(err)
		}
		if w.allows(t, s.metaKey, s.number) {
			t.Fatal("the old metadata key reaches the number's new archive")
		}
	}
}
