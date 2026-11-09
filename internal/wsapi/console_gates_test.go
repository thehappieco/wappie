package wsapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// The commands release's gates on the socket (the plan's 6.7 and 6.8).

// TestRetryMarksResumed (a gate; the platform's correction 3): a paused
// registration's pairing retry, with a registry, lifts the pause and marks
// its readers' pause notices resumed.
func TestRetryMarksResumed(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	pending := uuid.MustParse(p.deviceWithKey(t, "pending"))
	reader, _ := p.person(t, "caio", "member")
	p.reads(t, reader, pending)
	_, adminToken := p.person(t, "bia", "admin")
	admin := wsapi.Hello{Session: adminToken}
	if f := ask(t, p.console, admin, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: pending.String()}); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the stop: %s %s", f.Type, f.Payload)
	}
	resumed := func() (open, marked int) {
		p.scoped(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE resumed_at IS NULL), count(*) FILTER (WHERE resumed_at IS NOT NULL)
				FROM device_notices WHERE device_id = $1 AND kind = 'sync_paused'`, pending).Scan(&open, &marked)
		})
		return open, marked
	}
	if open, _ := resumed(); open != 1 {
		t.Fatalf("%d open pause notices after the stop", open)
	}
	f := ask(t, p.console, admin, wsapi.TypePair, wsapi.PairRequest{DeviceID: pending.String(), Resume: true, Method: "qr"})
	if f.Type == wsapi.TypeError {
		t.Fatalf("the retry: %s", f.Payload)
	}
	if p.paused(t, p.tenant, pending) {
		t.Fatal("the retry left the registration paused")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		open, marked := resumed()
		if open == 0 && marked == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the retry: %d open, %d marked", open, marked)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSignOutClosesSockets: a person.sign_out_everywhere closes, within the
// socket's own check of its session, a socket of a family begun before
// the command; one of a newer family stays open and answers.
func TestSignOutClosesSockets(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	user, _ := p.person(t, "caio", "member")
	sub := p.link(t, user, "member")
	old := p.sessionOf(t, p.tenant, user)
	var issued time.Time
	if err := p.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	newer := p.sessionOf(t, p.tenant, user)
	oldConn, newConn := p.watch(t, old), p.watch(t, newer)

	p.cseq++
	id := uuid.New()
	if _, err := p.pool.Exec(ctx, `INSERT INTO contract_commands (id, generation, cseq, kind, section, actor, issued_at, body, body_key,
		signed_at) VALUES ($1, $2, $3, $4, 'person', $5, $6, '{}', $7, clock_timestamp())`,
		id, p.gen, p.cseq, kc.OpPersonSignOutEverywhere, sub, issued, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	act, err := store.NewContract(p.pool).RunSignOutEverywhere(ctx, store.ContractRun{ID: id, Sub: sub, User: user}, issued)
	if err != nil || act.Result.Outcome != store.CommandRan {
		t.Fatalf("the sign-out: %+v %v", act, err)
	}
	closeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		if _, _, err := oldConn.conn.Read(closeCtx); err != nil {
			if closeCtx.Err() != nil {
				t.Fatal("the old family's socket is still open after 3 s")
			}
			break
		}
	}
	send(t, newConn.conn, wsapi.TypeDevicesList, nil)
	if f := read(t, newConn.conn); f.Type != wsapi.TypeDevices {
		t.Fatalf("the newer family's socket: %s %s", f.Type, f.Payload)
	}
}
