package datacheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// Beginner opens a transaction: a *pgx.Conn or a *pgxpool.Pool.
type Beginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// Begin opens the data check's transaction: READ ONLY, REPEATABLE READ, so
// every query sees one snapshot and none can write. The caller rolls it
// back; nothing ever commits it.
func Begin(ctx context.Context, db Beginner) (pgx.Tx, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("datacheck: begin: %w", err)
	}
	return tx, nil
}

// ErrNotReadOnly is a transaction Collect refuses: one that could write, or
// whose queries would not share one snapshot.
var ErrNotReadOnly = errors.New("datacheck: the transaction must be READ ONLY and REPEATABLE READ")

// ErrNoWorkspace is a scope that names no workspace.
var ErrNoWorkspace = errors.New("datacheck: no such workspace")

// Options are what Collect reads besides the database.
type Options struct {
	// Workspace limits the check to one workspace; empty is every one.
	Workspace string
	// Files are the files outside the database, by name: their line count
	// and hash go into the manifest. A path that does not exist is recorded
	// as absent.
	Files map[string]string
}

// Collect computes the manifest's database part and files in tx, which
// must come from Begin. It only reads, and sets nothing but
// transaction-local settings.
func Collect(ctx context.Context, tx pgx.Tx, opts Options) (*Manifest, error) {
	var readOnly, isolation string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_read_only'), current_setting('transaction_isolation')`).
		Scan(&readOnly, &isolation); err != nil {
		return nil, fmt.Errorf("datacheck: read the transaction mode: %w", err)
	}
	if readOnly != "on" || isolation != "repeatable read" {
		return nil, ErrNotReadOnly
	}
	// One text encoding on both sides of any comparison: times in UTC and
	// ISO form, bytea in hex. The check reads for as long as the bucket
	// takes, so no idle bound may end it.
	if _, err := tx.Exec(ctx, `SELECT set_config('TimeZone', 'UTC', true), set_config('DateStyle', 'ISO, YMD', true),
		set_config('IntervalStyle', 'postgres', true), set_config('bytea_output', 'hex', true),
		set_config('extra_float_digits', '1', true), set_config('idle_in_transaction_session_timeout', '0', true)`); err != nil {
		return nil, fmt.Errorf("datacheck: settings: %w", err)
	}
	m := &Manifest{
		Format: Format, Scope: "all", Schema: map[string]Migration{}, Digests: map[string]DigestSpec{},
		Excluded: excluded, Workspaces: map[string]*Workspace{}, Files: map[string]File{},
	}
	if opts.Workspace != "" {
		id, err := uuid.Parse(opts.Workspace)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not a workspace id", ErrNoWorkspace, opts.Workspace)
		}
		m.Scope = id.String()
	}
	for _, s := range tables {
		m.Digests[s.name] = s.digestSpec()
	}
	if err := tx.QueryRow(ctx, `SELECT now()::text`).Scan(&m.TakenAt); err != nil {
		return nil, fmt.Errorf("datacheck: time: %w", err)
	}
	if err := collectSchema(ctx, tx, m); err != nil {
		return nil, err
	}
	ids, err := collectWorkspaces(ctx, tx, m)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := collectWorkspace(ctx, tx, id, m.Workspaces[id]); err != nil {
			return nil, fmt.Errorf("datacheck: workspace %s: %w", id, err)
		}
	}
	if m.Scope == "all" {
		if err := collectReaderState(ctx, tx, m); err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(opts.Files))
	for name := range opts.Files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		f, err := hashFile(opts.Files[name])
		if err != nil {
			return nil, fmt.Errorf("datacheck: file %s: %w", name, err)
		}
		m.Files[name] = f
	}
	return m, nil
}

func collectSchema(ctx context.Context, tx pgx.Tx, m *Manifest) error {
	rows, err := tx.Query(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("datacheck: schema: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int64
		var mig Migration
		if err := rows.Scan(&v, &mig.Name, &mig.Checksum); err != nil {
			return fmt.Errorf("datacheck: schema: %w", err)
		}
		m.Schema[strconv.FormatInt(v, 10)] = mig
	}
	return rows.Err()
}

// collectWorkspaces reads the tenants rows in scope, in id order.
func collectWorkspaces(ctx context.Context, tx pgx.Tx, m *Manifest) ([]string, error) {
	cols := make([]string, len(workspaceFields))
	for i, f := range workspaceFields {
		cols[i] = f + "::text"
	}
	q := `SELECT id::text, ` + strings.Join(cols, ", ") + ` FROM tenants WHERE ($1 = 'all' OR id::text = $1) ORDER BY id::text COLLATE "C"`
	rows, err := tx.Query(ctx, q, m.Scope)
	if err != nil {
		return nil, fmt.Errorf("datacheck: workspaces: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		vals, err := scanText(rows, 1+len(workspaceFields))
		if err != nil {
			return nil, fmt.Errorf("datacheck: workspaces: %w", err)
		}
		id := *vals[0]
		w := &Workspace{
			Fields: map[string]*string{}, Inventory: map[string]Total{}, Users: map[string]User{},
			ReadCheck: ReadCheck{Keyless: []string{}, Orphan: []string{}}, Devices: map[string]*Device{},
		}
		for i, f := range workspaceFields {
			w.Fields[f] = vals[1+i]
		}
		m.Workspaces[id] = w
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("datacheck: workspaces: %w", err)
	}
	if m.Scope != "all" && len(ids) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoWorkspace, m.Scope)
	}
	return ids, nil
}

// collectWorkspace fills w. Every query names the workspace itself, and the
// row-level security setting names it too, so the server's role (subject
// to RLS) and the backup identity (which bypasses it) read the same rows.
func collectWorkspace(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, id); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	steps := []func(context.Context, pgx.Tx, string, *Workspace) error{
		collectDevices, collectMessageStats, collectChatOrder, collectTables, collectMedia,
		collectContentKeys, collectArchiveKeys, collectGrants, collectUsers, collectStorage, collectReadCheck,
	}
	for _, step := range steps {
		if err := step(ctx, tx, id, w); err != nil {
			return err
		}
	}
	return nil
}

// device returns w's entry for a number, making one for a number whose
// devices row is not in this workspace.
func (w *Workspace) device(id string) *Device {
	if d, ok := w.Devices[id]; ok {
		return d
	}
	d := &Device{
		Messages:  MessageStats{ByKind: map[string]int64{}},
		ChatOrder: map[string]string{}, Tables: map[string]*Table{}, Media: map[string]Total{},
		ContentKeys: map[string]ContentKeys{}, ArchiveKeys: map[string]ArchiveKey{}, Grants: map[string]Grant{},
	}
	w.Devices[id] = d
	return d
}

func collectDevices(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	cols := make([]string, len(deviceFields))
	for i, f := range deviceFields {
		cols[i] = f + "::text"
	}
	rows, err := tx.Query(ctx, `SELECT id::text, `+strings.Join(cols, ", ")+` FROM devices WHERE tenant_id = $1`, id)
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		vals, err := scanText(rows, 1+len(deviceFields))
		if err != nil {
			return fmt.Errorf("devices: %w", err)
		}
		d := w.device(*vals[0])
		d.Present = true
		d.Fields = map[string]*string{}
		for i, f := range deviceFields {
			d.Fields[f] = vals[1+i]
		}
	}
	return rows.Err()
}

func collectMessageStats(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT device_id::text, kind, count(*), count(*) FILTER (WHERE ts IS NULL),
		min(ts)::text, max(ts)::text FROM messages WHERE tenant_id = $1 GROUP BY device_id, kind`, id)
	if err != nil {
		return fmt.Errorf("messages: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dev, kind string
		var n, nullTS int64
		var lo, hi *string
		if err := rows.Scan(&dev, &kind, &n, &nullTS, &lo, &hi); err != nil {
			return fmt.Errorf("messages: %w", err)
		}
		st := &w.device(dev).Messages
		st.ByKind[kind] = n
		st.NullTS += nullTS
		if lo != nil && (st.MinTS == nil || *lo < *st.MinTS) {
			st.MinTS = lo
		}
		if hi != nil && (st.MaxTS == nil || *hi > *st.MaxTS) {
			st.MaxTS = hi
		}
	}
	return rows.Err()
}

// collectChatOrder digests each chat's message uids in seq order. The chat
// key is held only while its rows stream; the output names the chat by its
// uid as store.ChatUID derives it (what chats.uid holds, or what the boot's
// backfill will write there), so a chat whose uid is not yet stored, or
// that has no chats row, still has its own entry.
func collectChatOrder(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT device_id, chat_key, uid::text FROM messages
		WHERE tenant_id = $1 ORDER BY device_id, chat_key COLLATE "C", seq`, id)
	if err != nil {
		return fmt.Errorf("chat order: %w", err)
	}
	defer rows.Close()
	type chat struct {
		device uuid.UUID
		key    string
	}
	var cur chat
	var h *digest
	flush := func() {
		if h != nil {
			w.device(cur.device.String()).ChatOrder[store.ChatUID(cur.device, cur.key).String()] = h.sum()
		}
	}
	for rows.Next() {
		var next chat
		var uid string
		if err := rows.Scan(&next.device, &next.key, &uid); err != nil {
			return fmt.Errorf("chat order: %w", err)
		}
		if h == nil || next != cur {
			flush()
			cur, h = next, newDigest()
		}
		h.add(&uid)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("chat order: %w", err)
	}
	flush()
	return nil
}

// seqBases are each number's lowest seq across messages, receipts and
// events: the seq digests hash each seq less it, so a renumbering that
// adds one offset to all of them (an import, plan 2.5) leaves them equal.
func seqBases(ctx context.Context, tx pgx.Tx, id string) (map[string]int64, error) {
	rows, err := tx.Query(ctx, `SELECT device_id::text, min(seq) FROM (
		SELECT device_id, seq FROM messages WHERE tenant_id = $1
		UNION ALL SELECT device_id, seq FROM receipts WHERE tenant_id = $1
		UNION ALL SELECT device_id, seq FROM events WHERE tenant_id = $1) s GROUP BY device_id`, id)
	if err != nil {
		return nil, fmt.Errorf("seq bases: %w", err)
	}
	defer rows.Close()
	bases := map[string]int64{}
	for rows.Next() {
		var dev string
		var b int64
		if err := rows.Scan(&dev, &b); err != nil {
			return nil, fmt.Errorf("seq bases: %w", err)
		}
		bases[dev] = b
	}
	return bases, rows.Err()
}

type tableDigest struct {
	t                *Table
	rows, ct, seqDig *digest
}

func collectTables(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	bases, err := seqBases(ctx, tx, id)
	if err != nil {
		return err
	}
	for _, s := range tables {
		if err := collectTable(ctx, tx, id, w, s, bases); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

func collectTable(ctx context.Context, tx pgx.Tx, id string, w *Workspace, s tableSpec, bases map[string]int64) error {
	nKey, nClear, nSealed, nSeq := len(s.key), len(s.clear), len(s.sealed), len(s.seq)
	n := 1 + nKey + nClear + nSealed + nSeq
	nullAt := map[string]int{}
	for _, c := range s.nulls {
		nullAt[c] = 1 + nKey + slices.Index(s.clear, c)
	}
	rows, err := tx.Query(ctx, s.query(), id)
	if err != nil {
		return err
	}
	defer rows.Close()
	acc := map[string]*tableDigest{}
	get := func(dev *string) *tableDigest {
		key := ""
		if dev != nil {
			key = *dev
		}
		if a, ok := acc[key]; ok {
			return a
		}
		a := &tableDigest{t: &Table{}, rows: newDigest()}
		if nSealed > 0 {
			a.ct = newDigest()
		}
		if nSeq > 0 {
			a.seqDig = newDigest()
		}
		if len(s.nulls) > 0 {
			a.t.Nulls = map[string]int64{}
			for _, c := range s.nulls {
				a.t.Nulls[c] = 0
			}
		}
		acc[key] = a
		return a
	}
	for rows.Next() {
		vals, err := scanText(rows, n)
		if err != nil {
			return err
		}
		a := get(vals[0])
		a.t.Count++
		keys := vals[1 : 1+nKey]
		a.rows.addAll(keys)
		a.rows.addAll(vals[1+nKey : 1+nKey+nClear])
		for c, i := range nullAt {
			if vals[i] == nil {
				a.t.Nulls[c]++
			}
		}
		if a.ct != nil {
			a.ct.addAll(keys)
			a.ct.addAll(vals[1+nKey+nClear : 1+nKey+nClear+nSealed])
		}
		if a.seqDig != nil {
			base := int64(0)
			if vals[0] != nil {
				base = bases[*vals[0]]
			}
			a.seqDig.addAll(keys)
			for i, v := range vals[1+nKey+nClear+nSealed:] {
				if v == nil {
					a.seqDig.add(nil)
					continue
				}
				seq, err := strconv.ParseInt(*v, 10, 64)
				if err != nil {
					return fmt.Errorf("%s: %w", s.seq[i], err)
				}
				rel := strconv.FormatInt(seq-base, 10)
				a.seqDig.add(&rel)
				// The first seq column is the row's own seq: its maximum
				// is reported as stored.
				if i == 0 && s.seq[0] == "seq" && (a.t.MaxSeq == nil || seq > *a.t.MaxSeq) {
					a.t.MaxSeq = &seq
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Every number of the workspace shows every table, empty or not.
	for dev := range w.Devices {
		d := dev
		get(&d)
	}
	for dev, a := range acc {
		a.t.Rows = a.rows.sum()
		if a.ct != nil {
			a.t.Ciphertext = a.ct.sum()
		}
		if a.seqDig != nil {
			a.t.Seq = a.seqDig.sum()
		}
		if dev == "" {
			if w.Unowned == nil {
				w.Unowned = map[string]*Table{}
			}
			w.Unowned[s.name] = a.t
			continue
		}
		w.device(dev).Tables[s.name] = a.t
	}
	return nil
}

func collectMedia(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT m.device_id::text, t.download_status, count(*), coalesce(sum(t.file_length), 0)
		FROM media t LEFT JOIN messages m ON m.uid = t.message_uid AND m.tenant_id = t.tenant_id
		WHERE t.tenant_id = $1 AND m.device_id IS NOT NULL GROUP BY 1, 2`, id)
	if err != nil {
		return fmt.Errorf("media: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dev, status string
		var t Total
		if err := rows.Scan(&dev, &status, &t.Count, &t.Bytes); err != nil {
			return fmt.Errorf("media: %w", err)
		}
		w.device(dev).Media[status] = t
	}
	return rows.Err()
}

func collectContentKeys(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT device_id::text, epoch, id::text, encode(sha256(sealed_key), 'hex'), sealed_count,
		closed_at IS NOT NULL FROM content_keys WHERE tenant_id = $1 ORDER BY device_id, epoch, id`, id)
	if err != nil {
		return fmt.Errorf("content keys: %w", err)
	}
	defer rows.Close()
	type at struct {
		dev   string
		epoch int32
	}
	acc := map[at]*digest{}
	sums := map[at]ContentKeys{}
	for rows.Next() {
		var k at
		var keyID, sealed string
		var count int64
		var closed bool
		if err := rows.Scan(&k.dev, &k.epoch, &keyID, &sealed, &count, &closed); err != nil {
			return fmt.Errorf("content keys: %w", err)
		}
		if acc[k] == nil {
			acc[k] = newDigest()
		}
		acc[k].add(&keyID)
		acc[k].add(&sealed)
		c := sums[k]
		c.Count++
		c.SealedCount += count
		if closed {
			c.Closed++
		}
		sums[k] = c
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("content keys: %w", err)
	}
	for k, c := range sums {
		c.Digest = acc[k].sum()
		w.device(k.dev).ContentKeys[strconv.Itoa(int(k.epoch))] = c
	}
	return nil
}

func collectArchiveKeys(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT device_id::text, epoch, suite, public_key, retired_at::text
		FROM device_archive_keys WHERE tenant_id = $1`, id)
	if err != nil {
		return fmt.Errorf("archive keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dev string
		var epoch int32
		var k ArchiveKey
		var pub []byte
		if err := rows.Scan(&dev, &epoch, &k.Suite, &pub, &k.RetiredAt); err != nil {
			return fmt.Errorf("archive keys: %w", err)
		}
		k.Fingerprint = store.ArchiveKeyFingerprint(pub)
		w.device(dev).ArchiveKeys[strconv.Itoa(int(epoch))] = k
	}
	return rows.Err()
}

// collectGrants reads every grant, of every epoch, retired keys and deleted
// numbers included, joined to the fingerprint of the key at its (device,
// epoch). It does not use GrantsFor's join on the current epoch.
func collectGrants(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT g.device_id::text, g.user_id::text, g.epoch, encode(sha256(g.sealed_dsk), 'hex'),
		k.public_key, g.granted_by::text
		FROM device_key_grants g LEFT JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch
		WHERE g.tenant_id = $1`, id)
	if err != nil {
		return fmt.Errorf("grants: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dev, user string
		var epoch int32
		var g Grant
		var pub []byte
		if err := rows.Scan(&dev, &user, &epoch, &g.SealedDSKSHA256, &pub, &g.GrantedBy); err != nil {
			return fmt.Errorf("grants: %w", err)
		}
		if pub != nil {
			fp := store.ArchiveKeyFingerprint(pub)
			g.Fingerprint = &fp
		}
		w.device(dev).Grants[user+":"+strconv.Itoa(int(epoch))] = g
	}
	return rows.Err()
}

func collectUsers(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT u.id::text, encode(sha256(u.public_key), 'hex'),
		encode(sha256(convert_to(p.product_key_id, 'UTF8')), 'hex'), encode(sha256(p.wrap), 'hex')
		FROM users u LEFT JOIN platform_wraps p ON p.user_id = u.id WHERE u.tenant_id = $1`, id)
	if err != nil {
		return fmt.Errorf("users: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var user, pub string
		var keyID, wrap *string
		if err := rows.Scan(&user, &pub, &keyID, &wrap); err != nil {
			return fmt.Errorf("users: %w", err)
		}
		u := w.Users[user]
		u.PublicKeySHA256 = pub
		if keyID != nil && wrap != nil {
			if u.PlatformWraps == nil {
				u.PlatformWraps = map[string]string{}
			}
			u.PlatformWraps[*keyID] = *wrap
		}
		w.Users[user] = u
	}
	return rows.Err()
}

func collectStorage(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT source, count(*), coalesce(sum(bytes), 0) FROM storage_inventory
		WHERE tenant_id = $1 GROUP BY source`, id)
	if err != nil {
		return fmt.Errorf("storage inventory: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var source string
		var t Total
		if err := rows.Scan(&source, &t.Count, &t.Bytes); err != nil {
			return fmt.Errorf("storage inventory: %w", err)
		}
		w.Inventory[source] = t
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("storage inventory: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(bytes), 0) FROM storage_objects WHERE tenant_id = $1`, id).
		Scan(&w.StorageObjects.Count, &w.StorageObjects.Bytes); err != nil {
		return fmt.Errorf("storage objects: %w", err)
	}
	return nil
}

// collectReadCheck counts the start's read check's numbers (DS48,
// store.EndConnectionsWithoutRead) over every live number, not only those
// a connection holds: keyless has no archive key (epoch 0); orphan has one
// and no grant to anyone but a connection's or a consent's account.
func collectReadCheck(ctx context.Context, tx pgx.Tx, id string, w *Workspace) error {
	rows, err := tx.Query(ctx, `SELECT d.id::text, d.current_epoch = 0 FROM devices d
		WHERE d.tenant_id = $1 AND d.deleted_at IS NULL AND (d.current_epoch = 0 OR NOT EXISTS (
			SELECT 1 FROM device_key_grants g WHERE g.tenant_id = $1 AND g.device_id = d.id
			AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.tenant_id = $1 AND c.service_user_id = g.user_id)
			AND NOT EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = g.user_id
				AND m.expires_at IS NOT NULL)))
		ORDER BY 1`, id)
	if err != nil {
		return fmt.Errorf("read check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dev string
		var keyless bool
		if err := rows.Scan(&dev, &keyless); err != nil {
			return fmt.Errorf("read check: %w", err)
		}
		if keyless {
			w.ReadCheck.Keyless = append(w.ReadCheck.Keyless, dev)
		} else {
			w.ReadCheck.Orphan = append(w.ReadCheck.Orphan, dev)
		}
	}
	return rows.Err()
}

func collectReaderState(ctx context.Context, tx pgx.Tx, m *Manifest) error {
	rows, err := tx.Query(ctx, `SELECT reader_id, name, generation, encode(sha256(blob), 'hex') FROM mcp_reader_state`)
	if err != nil {
		return fmt.Errorf("datacheck: reader state: %w", err)
	}
	defer rows.Close()
	m.ReaderState = map[string]ReaderState{}
	for rows.Next() {
		var reader, name string
		var s ReaderState
		if err := rows.Scan(&reader, &name, &s.Generation, &s.BlobSHA256); err != nil {
			return fmt.Errorf("datacheck: reader state: %w", err)
		}
		m.ReaderState[reader+":"+name] = s
	}
	return rows.Err()
}

// hashFile counts a file's lines and hashes its bytes, streaming. A file
// that does not exist is absent, not an error.
func hashFile(path string) (File, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the ledger and the stop record
	if errors.Is(err, os.ErrNotExist) {
		return File{}, nil
	}
	if err != nil {
		return File{}, err
	}
	defer f.Close() //nolint:errcheck // read only; a close error loses nothing
	h := sha256.New()
	var lines lineCounter
	if _, err := io.Copy(io.MultiWriter(h, &lines), f); err != nil {
		return File{}, err
	}
	return File{Present: true, Lines: int64(lines), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// lineCounter counts the newlines written to it.
type lineCounter int64

func (c *lineCounter) Write(p []byte) (int, error) {
	*c += lineCounter(bytes.Count(p, []byte{'\n'}))
	return len(p), nil
}

// scanText scans n text columns, NULL as nil.
func scanText(rows pgx.Rows, n int) ([]*string, error) {
	vals := make([]*string, n)
	dest := make([]any, n)
	for i := range vals {
		dest[i] = &vals[i]
	}
	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}
	return vals, nil
}

// digest is SHA-256 over a sequence of values, each NULL (one 0 byte) or a
// value (a 1 byte, its length as 8 bytes big-endian, its bytes), so no two
// different sequences hash the same input.
type digest struct{ h hash.Hash }

func newDigest() *digest { return &digest{h: sha256.New()} }

func (d *digest) add(v *string) {
	if v == nil {
		d.h.Write([]byte{0})
		return
	}
	var hdr [9]byte
	hdr[0] = 1
	binary.BigEndian.PutUint64(hdr[1:], uint64(len(*v)))
	d.h.Write(hdr[:])
	d.h.Write([]byte(*v))
}

func (d *digest) addAll(vs []*string) {
	for _, v := range vs {
		d.add(v)
	}
}

func (d *digest) sum() string { return hex.EncodeToString(d.h.Sum(nil)) }
