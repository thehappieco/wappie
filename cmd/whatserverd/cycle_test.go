package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/bus"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/ledger"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// The plan's test 40, at the level this repository runs: a deletion's
// whole cycle as an owner, a reader and the operator meet it. The owner's
// and the readers' frames go over the WebSocket to the real handlers and
// stores; the operator's steps are the real command lines and the SQL that
// docs/deployment.md documents. Only WhatsApp is a stand-in.
//
//   - Delete a number, its readers and the other owner are told, a reader
//     acknowledges, the owner recovers it (read-only: WhatsApp confirmed the
//     logout), and deletes it again.
//   - The due path: the documented step makes it due, and devices
//     purge-deleted without -now purges it as the janitor does: the
//     "number purged" line and the purged row.
//   - The host simulation's part: a second number whose logout WhatsApp
//     never confirmed, purged with -now, which removes the session left
//     behind by its fingerprint.
//   - The event rows and the ledger lines are all there, in order.
//
// On the pilot the kit runs the same cycle with a test number and a real
// logout, and ends it on the due path: a purged number cannot be deleted
// again, and the pilot has no session whose logout can be made to fail.
func TestDeletionCycle(t *testing.T) {
	ctx := context.Background()
	w := newPurgeWorld(t)
	var team uuid.UUID
	if err := w.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('cycle') RETURNING id`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	person := func(email, role string) (uuid.UUID, string) {
		t.Helper()
		u, err := w.users.Create(ctx, store.NewUser{TenantID: team, Email: email, Role: role, AuthKey: "test",
			KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := w.users.StartSession(ctx, u, "test")
		if err != nil {
			t.Fatal(err)
		}
		return u.ID, token
	}
	owner, ownerTok := person("owner@cycle.test", "owner")
	_, coOwnerTok := person("co-owner@cycle.test", "owner")
	reader, readerTok := person("reader@cycle.test", "member")

	// Two linked numbers with a WhatsApp session each. The reader holds the
	// first one's key and reads it.
	keys := store.NewKeys(w.pool)
	linked := func() (uuid.UUID, types.JID) {
		t.Helper()
		device, _ := w.number(t, team) //nolint:contextcheck // the world's helpers run on a context of their own
		dev, err := w.devices.Get(ctx, team.String(), device.String())
		if err != nil {
			t.Fatal(err)
		}
		pub, _, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.CreateArchiveKey(ctx, team, device, 1, pub); err != nil {
			t.Fatal(err)
		}
		jid := dev.Identity.PN
		if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid, registration_id) VALUES ($1, 7)`, jid.String()); err != nil {
			t.Fatal(err)
		}
		return device, jid
	}
	number, _ := linked()
	if err := keys.PutGrant(ctx, store.Grant{TenantID: team, DeviceID: number, UserID: reader, Epoch: 1, SealedDSK: []byte("grant")}, &owner); err != nil {
		t.Fatal(err)
	}
	if err := w.users.SetDevicePermission(ctx, team, owner, store.DevicePermission{DeviceID: number, UserID: reader, Read: true}); err != nil {
		t.Fatal(err)
	}
	unconfirmed, unconfirmedJID := linked()
	if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_privacy_tokens(our_jid, their_jid, token, timestamp) VALUES ($1, 'someone@s.whatsapp.net', '\x01', 1)`,
		unconfirmedJID.String()); err != nil {
		t.Fatal(err)
	}

	// The server, as serve wires its handlers to the stores and the ledger.
	whatsapp := &cycleWhatsApp{pool: w.pool, unanswered: unconfirmed.String()}
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: store.NewAPIKeys(w.pool), Sessions: w.users, Accounts: w.users, Devices: w.devices,
		Messages: store.NewMessages(w.pool), Keys2: keys, Receipts: store.NewReceipts(w.pool), Bus: bus.New(),
		Unlinker: whatsapp, Log: slog.New(w.log), ExportLedger: w.app.exportLedger,
	}))
	t.Cleanup(srv.Close)
	ask := func(token, frameType string, payload any) wsapi.Frame {
		return askOnce(t, srv, token, frameType, payload)
	}
	notices := func(token string) []wsapi.DeviceNotice {
		t.Helper()
		return decode[wsapi.Devices](t, ask(token, wsapi.TypeDevicesList, nil), wsapi.TypeDevices).Notices
	}
	lists := func(token string, device uuid.UUID) bool {
		t.Helper()
		return slices.ContainsFunc(decode[wsapi.Devices](t, ask(token, wsapi.TypeDevicesList, nil), wsapi.TypeDevices).Devices,
			func(d wsapi.DeviceInfo) bool { return d.ID == device.String() })
	}
	del := func(device uuid.UUID) wsapi.DeviceDeleted {
		t.Helper()
		check := decode[wsapi.DeviceDeleteChecked](t, ask(ownerTok, wsapi.TypeDeviceDeleteCheck, wsapi.DeviceRef{DeviceID: device.String()}),
			wsapi.TypeDeviceDeleteChecked)
		acknowledged := []string{}
		for _, r := range check.Readers {
			acknowledged = append(acknowledged, r.UserID.String())
		}
		return decode[wsapi.DeviceDeleted](t, ask(ownerTok, wsapi.TypeDeviceDelete, wsapi.DeleteRequest{DeviceID: device.String(),
			Confirm: device.String(), Unlink: true, AcknowledgedReaders: acknowledged}), wsapi.TypeDeviceGone)
	}

	// Delete: the readers must be acknowledged, and the logout is confirmed.
	check := decode[wsapi.DeviceDeleteChecked](t, ask(ownerTok, wsapi.TypeDeviceDeleteCheck, wsapi.DeviceRef{DeviceID: number.String()}),
		wsapi.TypeDeviceDeleteChecked)
	if len(check.Readers) != 1 || check.Readers[0].UserID != reader || !check.CanUnlink {
		t.Fatalf("the deletion's preflight: %+v", check)
	}
	wantError(t, ask(ownerTok, wsapi.TypeDeviceDelete, wsapi.DeleteRequest{DeviceID: number.String(), Confirm: number.String(), Unlink: true}),
		wsapi.ErrCodeDeviceHasReaders)
	first := del(number)
	if first.Already || !first.Unlinked || first.NoteCode != "" || first.DeletedAt == nil || first.RecoverableUntil == nil ||
		first.RecoverableUntil.Sub(*first.DeletedAt) != 30*24*time.Hour {
		t.Fatalf("the deletion: %+v", first)
	}
	if lists(readerTok, number) || lists(ownerTok, number) {
		t.Fatal("a deleted number is still listed")
	}

	// The notice: the reader and the other owner are told, the owner is not.
	for _, token := range []string{readerTok, coOwnerTok} {
		got := notices(token)
		if len(got) != 1 || got[0].Kind != "number_deleted" || got[0].DeviceID != number.String() || got[0].Until == nil ||
			!got[0].Until.Equal(*first.RecoverableUntil) || got[0].Label == nil || *got[0].Label != "n1" || got[0].Hint == nil {
			t.Fatalf("the notices after the deletion: %+v", got)
		}
	}
	if got := notices(ownerTok); len(got) != 0 {
		t.Fatalf("the deleting owner was told: %+v", got)
	}
	seen := decode[wsapi.DeviceNotices](t, ask(readerTok, wsapi.TypeDeviceNoticeSeen, wsapi.DeviceNoticeSeen{NoticeIDs: []int64{notices(readerTok)[0].ID}}),
		wsapi.TypeDeviceNotices)
	if len(seen.Notices) != 0 || len(notices(readerTok)) != 0 {
		t.Fatalf("the reader's notices after seeing them: %+v", seen.Notices)
	}

	// Recover: the owner sees it among the deleted numbers, and it comes back
	// paused and read-only, since WhatsApp confirmed the logout.
	deleted := decode[wsapi.DeletedNumbers](t, ask(ownerTok, wsapi.TypeDevicesDeleted, nil), wsapi.TypeDeletedNumbers)
	if len(deleted.Numbers) != 1 || deleted.Numbers[0].DeviceID != number.String() || !deleted.Numbers[0].Recoverable || !deleted.Numbers[0].LoggedOut {
		t.Fatalf("the deleted numbers: %+v", deleted.Numbers)
	}
	recoverCheck := decode[wsapi.DeviceRecoverChecked](t, ask(ownerTok, wsapi.TypeDeviceRecoverCheck, wsapi.DeviceRef{DeviceID: number.String()}),
		wsapi.TypeDeviceRecoverChecked)
	if !recoverCheck.Recoverable || len(recoverCheck.Readers) != 1 || recoverCheck.Readers[0].UserID != reader {
		t.Fatalf("the recovery's preflight: %+v", recoverCheck)
	}
	recovered := decode[wsapi.DeviceRecovered](t, ask(ownerTok, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: number.String(), Confirm: number.String()}),
		wsapi.TypeDeviceRecovered)
	if recovered.Already || !recovered.Device.Paused || !recovered.LoggedOut || recovered.CanResume {
		t.Fatalf("the recovery: %+v", recovered)
	}
	if !lists(readerTok, number) || len(notices(coOwnerTok)) != 0 {
		t.Fatal("after the recovery: the reader does not read it again, or the other owner's notice stayed")
	}

	// Delete again: no session is left to log out.
	second := del(number)
	if second.Already || !second.Unlinked || second.NoteCode != store.NoteAlreadyDisconnected || !second.DeletedAt.After(*first.DeletedAt) {
		t.Fatalf("the second deletion: %+v", second)
	}
	if got := notices(readerTok); len(got) != 1 || got[0].Kind != "number_deleted" || got[0].PurgedAt != nil {
		t.Fatalf("the reader's notice after the second deletion: %+v", got)
	}

	// The host simulation's second number: WhatsApp never confirms its
	// logout, so its session is left, fingerprinted.
	left := del(unconfirmed)
	if left.Unlinked || left.NoteCode != store.NoteUnlinkUnconfirmed {
		t.Fatalf("the unconfirmed logout: %+v", left)
	}
	if got := whatsapp.asked(); !slices.Equal(got, []string{number.String(), unconfirmed.String()}) {
		t.Fatalf("WhatsApp was asked to log out %v", got)
	}

	// The operator's view, with the server's own configuration.
	commandEnv(t, w.pool, w.ledger)
	t.Setenv("WS_LOG_LEVEL", "info")
	t.Setenv("WS_LOG_FORMAT", "json")
	out, err := operator(t, "devices", "list-deleted", "-tenant", team.String())
	if err != nil {
		t.Fatalf("devices list-deleted: %v\n%s", err, out)
	}
	if !strings.Contains(out, "2 deleted number(s)") || !strings.Contains(out, "is writable") ||
		!strings.Contains(listedRow(out, number), "recoverable") || !strings.Contains(listedRow(out, unconfirmed), "true") {
		t.Fatalf("devices list-deleted:\n%s", out)
	}

	// The due path: the documented step makes the number due, and the
	// command purges what is due, as the janitor does, and nothing else.
	backdate(t, w, team, number)
	due, _, err := w.devices.DueDeletions(ctx, team, 5)
	if err != nil || len(due) != 1 || due[0].DeviceID != number {
		t.Fatalf("due after the documented step: %+v %v", due, err)
	}
	out, err = operator(t, "devices", "purge-deleted", "-tenant", team.String())
	if err != nil {
		t.Fatalf("devices purge-deleted: %v\n%s", err, out)
	}
	purged := purgedLines(t, out)
	if len(purged) != 1 || purged[0]["device"] != number.String() || purged[0]["tenant"] != team.String() ||
		!strings.Contains(out, "purged "+number.String()+" in "+team.String()) {
		t.Fatalf("the due path's output:\n%s", out)
	}
	if w.exists(t, team, number) || !w.exists(t, team, unconfirmed) {
		t.Fatalf("after the due path: purged %v, the other number kept %v", !w.exists(t, team, number), w.exists(t, team, unconfirmed))
	}

	// The host simulation only: -now, and the session the logout left.
	out, err = operator(t, "devices", "purge-deleted", "-device", unconfirmed.String(), "-now")
	if err != nil {
		t.Fatalf("devices purge-deleted -now: %v\n%s", err, out)
	}
	if purged := purgedLines(t, out); len(purged) != 1 || purged[0]["device"] != unconfirmed.String() || purged[0]["session_removed"] != true {
		t.Fatalf("the early purge's output:\n%s", out)
	}
	var sessions, tokens int
	if err := w.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM whatsmeow_device WHERE jid = $1),
		(SELECT count(*) FROM whatsmeow_privacy_tokens WHERE our_jid = $1)`, unconfirmedJID.String()).Scan(&sessions, &tokens); err != nil ||
		sessions != 0 || tokens != 0 {
		t.Fatalf("the session the logout left: %d sessions, %d tokens, %v", sessions, tokens, err)
	}
	out, err = operator(t, "devices", "list-deleted")
	if err != nil || !strings.Contains(out, "0 deleted number(s)") {
		t.Fatalf("devices list-deleted after both purges: %v\n%s", err, out)
	}

	// The reader is still told, after the purge, with no name left.
	if got := notices(readerTok); len(got) != 1 || got[0].PurgedAt == nil || got[0].Label != nil || got[0].Hint != nil {
		t.Fatalf("the reader's notice after the purge: %+v", got)
	}

	// The event rows, in commit order, and the ledger, which has each of them.
	type row struct {
		id                    uuid.UUID
		kind, actor           string
		item                  uuid.UUID
		named, ledgered       bool
		deletedAt, purgeAfter *time.Time
	}
	var rows []row
	if err := pg.InTenantTx(ctx, w.pool, team.String(), func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT event_id, type, actor_kind, item_id, label IS NOT NULL OR hint IS NOT NULL, ledgered_at IS NOT NULL,
			deleted_at, purge_after FROM item_events ORDER BY seq`)
		if err != nil {
			return err
		}
		rows, err = pgx.CollectRows(r, func(r pgx.CollectableRow) (row, error) {
			var x row
			err := r.Scan(&x.id, &x.kind, &x.actor, &x.item, &x.named, &x.ledgered, &x.deletedAt, &x.purgeAfter)
			return x, err
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range rows {
		kinds = append(kinds, r.kind+":"+map[uuid.UUID]string{number: "a", unconfirmed: "b"}[r.item])
		if r.named || !r.ledgered || (r.kind == "purged") != (r.actor == "app") {
			t.Errorf("event row %+v", r)
		}
	}
	if want := []string{"deleted:a", "recovered:a", "deleted:a", "deleted:b", "purged:a", "purged:b"}; !slices.Equal(kinds, want) {
		t.Fatalf("the event rows: %v, want %v", kinds, want)
	}
	lines := w.ledgerLines(t)
	if len(lines) != len(rows) {
		t.Fatalf("%d ledger lines for %d event rows", len(lines), len(rows))
	}
	for i, l := range lines {
		if l.EventID != rows[i].id || l.Type != rows[i].kind || l.DeviceID != rows[i].item || l.WorkspaceID != team {
			t.Fatalf("ledger line %d: %+v, event row %+v", i, l, rows[i])
		}
	}
	// The recovery names the deletion it reverses; each purge keeps its
	// deletion's date, and says it came before the 30 days were over.
	if !lines[1].DeletedAt.Equal(*lines[0].DeletedAt) || !lines[4].DeletedAt.Equal(*lines[2].DeletedAt) ||
		!lines[4].PurgeAfter.Before(*lines[2].PurgeAfter) || !lines[5].PurgeAfter.Before(*lines[3].PurgeAfter) {
		t.Fatalf("the ledger's dates: %+v", lines)
	}
	for _, l := range lines {
		if l.Type == ledger.TypeDeleted && (l.DeletedBy == nil || *l.DeletedBy != owner) {
			t.Fatalf("a deleted line names %v, not the owner", l.DeletedBy)
		}
	}
	if folded, problems := ledger.Fold(lines); len(problems) != 0 || len(folded) != 2 ||
		folded[0].State != ledger.StatePurged || folded[1].State != ledger.StatePurged {
		t.Fatalf("the ledger folds to %+v, %v", folded, problems)
	}
}

// cycleWhatsApp stands in for the WhatsApp logout: it runs the deletion's
// re-check, then logs the session out, removing it from the session store
// as whatsmeow's Logout does, or, for the unanswered number, records that
// WhatsApp did not confirm, as the registry does after a logout that timed
// out.
type cycleWhatsApp struct {
	pool       *pgxpool.Pool
	unanswered string
	mu         sync.Mutex
	logouts    []string
}

func (c *cycleWhatsApp) BeginUnlink(string) func() { return func() {} }

func (c *cycleWhatsApp) Unlink(ctx context.Context, _, device string, jid types.JID,
	recheck func(context.Context) error, record func(context.Context, error)) error {
	if err := recheck(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.logouts = append(c.logouts, device)
	c.mu.Unlock()
	if device == c.unanswered {
		err := errors.New("WhatsApp did not answer the logout")
		record(ctx, err)
		return err
	}
	if _, err := c.pool.Exec(context.WithoutCancel(ctx), `DELETE FROM whatsmeow_device WHERE jid = $1`, jid.String()); err != nil {
		return err
	}
	record(ctx, nil)
	return nil
}

func (c *cycleWhatsApp) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.logouts)
}

// askOnce opens a session with token, sends one frame and returns its reply,
// skipping whatever the server pushes meanwhile. Each call is a connection
// of its own, as a console reconnects after a deletion closes its socket.
func askOnce(t *testing.T, srv *httptest.Server, token, frameType string, payload any) wsapi.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//nolint:bodyclose // coder/websocket: "You never need to close resp.Body yourself."
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow() //nolint:errcheck // the test is done with it
	write := func(f wsapi.Frame) {
		t.Helper()
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatalf("write %s: %v", f.Type, err)
		}
	}
	read := func() wsapi.Frame {
		t.Helper()
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read after %s: %v", frameType, err)
		}
		var f wsapi.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	hello, err := json.Marshal(wsapi.Hello{Session: token, Version: wsapi.Version, ClientID: "test 40"})
	if err != nil {
		t.Fatal(err)
	}
	write(wsapi.Frame{Type: wsapi.TypeHello, Payload: hello})
	if f := read(); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake: %s %s", f.Type, f.Payload)
	}
	frame := wsapi.Frame{Type: frameType, ReqID: "q"}
	if payload != nil {
		if frame.Payload, err = json.Marshal(payload); err != nil {
			t.Fatal(err)
		}
	}
	write(frame)
	for {
		if f := read(); f.ReqID == "q" {
			return f
		}
	}
}

// decode is a reply's payload, which must be of frameType.
func decode[T any](t *testing.T, f wsapi.Frame, frameType string) T {
	t.Helper()
	if f.Type != frameType {
		t.Fatalf("got %s, want %s: %s", f.Type, frameType, f.Payload)
	}
	var out T
	if err := json.Unmarshal(f.Payload, &out); err != nil {
		t.Fatalf("decoding %s: %v", f.Type, err)
	}
	return out
}

func wantError(t *testing.T, f wsapi.Frame, code string) {
	t.Helper()
	if e := decode[wsapi.Error](t, f, wsapi.TypeError); e.Code != code {
		t.Fatalf("error %q, want %q: %s", e.Code, code, e.Message)
	}
}

// operator runs a whatserverd command line as an operator does, with this
// process's environment, and returns everything it wrote to stdout: its
// report and its log lines.
func operator(t *testing.T, args ...string) (string, error) {
	t.Helper()
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r) //nolint:errcheck // a short read shows in the test's output
		read <- b
	}()
	stdout := os.Stdout
	os.Stdout = wr
	func() {
		defer func() { os.Stdout = stdout }()
		err = runCommand(args, func() error { return errors.New("a command line served") })
	}()
	wr.Close() //nolint:errcheck,gosec // the reader sees the end
	return string(<-read), err
}

// listedRow is the line of devices list-deleted that names device.
func listedRow(out string, device uuid.UUID) string {
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, device.String()) {
			return line
		}
	}
	return ""
}

// purgedLines are the "number purged" log records in a command's output.
func purgedLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var found []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if !bytes.HasPrefix(line, []byte("{")) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("a log line that is not JSON: %s", line)
		}
		if rec["msg"] == "number purged" {
			if rec["level"] != "INFO" {
				t.Fatalf("number purged at %v", rec["level"])
			}
			found = append(found, rec)
		}
	}
	return found
}

// backdate runs the operator's step of docs/deployment.md ("Rehearsing a
// purge") exactly as written there, with psql's two variables filled in,
// as the server's own database role.
func backdate(t *testing.T, w *purgeWorld, tenant, device uuid.UUID) {
	t.Helper()
	doc, err := os.ReadFile("../../docs/deployment.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	at := strings.Index(text, "UPDATE devices SET purge_after")
	if at < 0 {
		t.Fatal("docs/deployment.md documents no step that makes a deleted number due")
	}
	begin := strings.LastIndex(text[:at], "BEGIN;")
	end := strings.Index(text[at:], "COMMIT;")
	if begin < 0 || end < 0 {
		t.Fatal("the documented step is not one transaction")
	}
	sql := text[begin : at+end+len("COMMIT;")]
	sql = strings.ReplaceAll(sql, ":'tenant'", "'"+tenant.String()+"'")
	sql = strings.ReplaceAll(sql, ":'device'", "'"+device.String()+"'")
	if strings.Contains(sql, ":'") {
		t.Fatalf("the documented step has a variable this test does not fill:\n%s", sql)
	}
	if _, err := w.pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("the documented step:\n%s\n%v", sql, err)
	}
}

// docs/deployment.md quotes what an operator greps the logs for, and
// names every flag of the deletion commands: each must still be what the
// code says.
func TestDeletionDocsMatchTheCode(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	doc := read("../../docs/deployment.md")
	code := read("deletions.go") + read("maintain.go") + read("../../internal/store/purge.go")
	for _, line := range []string{"deletion ledger writable", "deletion ledger not writable", "deletion ledger export failed",
		"object deletes keep failing", "deleted-number purges are held", "a deleted number is overdue for its purge", "number purged",
		"do not start wappie-api"} {
		if !strings.Contains(code, `"`+line) && !strings.Contains(code, line+`"`) {
			t.Errorf("the code no longer says %q", line)
		}
		if !strings.Contains(doc, line) {
			t.Errorf("docs/deployment.md does not quote %q", line)
		}
	}
	if events := read("../../docs/item-events.md"); !strings.Contains(events, "event rows 30 days old are still not in the deletion ledger") ||
		!strings.Contains(code, "event rows 30 days old are still not in the deletion ledger") {
		t.Error("docs/item-events.md and the janitor disagree on the unledgered rows' ERROR")
	}
	for _, flag := range []string{"devices list-deleted [-tenant ID]", "devices purge-deleted [-tenant ID] [-device ID [-now]]",
		"deletions export-ledger", "deletions replay -ledger FILE -snapshot-time STAMP [-dry-run] [-ledger-adds-nothing] [-leave-excluded ID]..."} {
		if !strings.Contains(doc, flag) {
			t.Errorf("docs/deployment.md does not show %q", flag)
		}
	}
	for _, name := range []string{`"tenant"`, `"device"`, `"now"`, `"ledger"`, `"snapshot-time"`, `"dry-run"`, `"ledger-adds-nothing"`, `"leave-excluded"`} {
		if !strings.Contains(code, name) {
			t.Errorf("no flag %s in deletions.go", name)
		}
	}
}
