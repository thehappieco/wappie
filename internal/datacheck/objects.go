package datacheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"whatserver2/internal/blob"
	"whatserver2/internal/pg"
)

// ObjectStore is what the object check needs of the bucket: a listing
// (resumable after a key, "" from the first) and a read. *blob.Store is
// one. Nothing here can write.
type ObjectStore interface {
	List(ctx context.Context, prefix, after string, fn func(blob.ObjectInfo) error) error
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
}

// retryPauses are the pauses before each retry of a listing or an object
// read that failed: one transient error from the bucket, its network or a
// restart of MinIO must not end a run that reads the whole bucket for
// hours. The read client itself never retries (blob.New). A listing
// resumes after the last key it gave; a read starts the object over.
var retryPauses = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute}

// retryable says whether a failed read is worth another try: not when the
// run is ending or the object is not there.
func retryable(ctx context.Context, err error) bool {
	return ctx.Err() == nil && !errors.Is(err, blob.ErrNotFound)
}

func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// listResuming lists prefix through fn, resuming after the last key fn
// took when the listing fails, up to len(retryPauses) failures in a row.
// An error of fn's own ends it at once.
func listResuming(ctx context.Context, src ObjectStore, prefix string, fn func(blob.ObjectInfo) error) error {
	last, failures := "", 0
	for {
		var fnErr error
		err := src.List(ctx, prefix, last, func(o blob.ObjectInfo) error {
			if err := fn(o); err != nil {
				fnErr = err
				return err
			}
			last, failures = o.Key, 0
			return nil
		})
		switch {
		case fnErr != nil:
			return fnErr
		case err == nil || !retryable(ctx, err) || failures >= len(retryPauses):
			return err
		}
		if err := pause(ctx, retryPauses[failures]); err != nil {
			return err
		}
		failures++
	}
}

// ObjectOutput are the object check's files, each optional. Sums gets one
// line per object in sha256sum's format ("<sha256>  <key>"), the format of
// backup.sh's SHA256SUMS; Sizes one "<size>  <key>" line per object, in the
// same order.
type ObjectOutput struct {
	Sums  io.Writer
	Sizes io.Writer
}

// keyBatch is how many database keys the check holds at a time.
const keyBatch = 1000

// CheckObjects lists every object under the manifest's scope (the whole
// bucket, or one workspace's prefix), reads each one through the store and
// hashes its bytes, checks each content-addressed key against its hash, and
// cross-checks the listing with the storage_objects and media.object_key
// rows of tx both ways. Its memory is bounded: the listing streams page by
// page, each object streams through the hash, and the database's keys
// stream through a cursor in the same transaction, merged in key order.
// It fills m.Objects and writes out's files; it writes nothing else.
func CheckObjects(ctx context.Context, tx pgx.Tx, src ObjectStore, m *Manifest, out ObjectOutput) error {
	prefix := ""
	if m.Scope != "all" {
		prefix = m.Scope + "/"
	}
	o := &Objects{Prefix: prefix, Workspaces: map[string]*ObjectSet{}}
	digests := map[*ObjectSet]*digest{}
	set := func(key string) *ObjectSet {
		ws, _, ok := strings.Cut(key, "/")
		if _, known := m.Workspaces[ws]; ok && known {
			s := o.Workspaces[ws]
			if s == nil {
				s = &ObjectSet{}
				o.Workspaces[ws] = s
				digests[s] = newDigest()
			}
			return s
		}
		if o.Other == nil {
			o.Other = &ObjectSet{}
			digests[o.Other] = newDigest()
		}
		return o.Other
	}
	// Every workspace in scope shows its set, empty or not.
	for ws := range m.Workspaces {
		set(ws + "/")
	}
	keys := newDBKeys(tx, m, set)
	head, err := keys.next(ctx)
	if err != nil {
		return err
	}
	advance := func() error {
		var err error
		head, err = keys.next(ctx)
		return err
	}
	err = listResuming(ctx, src, prefix, func(obj blob.ObjectInfo) error {
		for head != nil && head.key < obj.Key {
			set(head.key).Missing++
			if err := advance(); err != nil {
				return err
			}
		}
		sum, n, err := hashObject(ctx, src, obj.Key)
		if err != nil {
			return err
		}
		s := set(obj.Key)
		s.Count++
		s.Bytes += n
		o.Total.Count++
		o.Total.Bytes += n
		size := strconv.FormatInt(n, 10)
		digests[s].add(&obj.Key)
		digests[s].add(&size)
		digests[s].add(&sum)
		switch addressed(obj.Key) {
		case keyHashed:
			if !strings.HasSuffix(obj.Key, "/"+sum) {
				s.HashMismatch++
			}
		case keyUnhashed:
			s.Unchecked++
		default:
			s.Unrecognised++
		}
		if n != obj.Size {
			s.SizeMismatch++
		}
		if head != nil && head.key == obj.Key {
			if head.sizeDiffers(n) {
				s.SizeMismatch++
			}
			if err := advance(); err != nil {
				return err
			}
		} else {
			s.NotInDatabase++
		}
		return writeLines(out, sum, size, obj.Key)
	})
	if err != nil {
		return fmt.Errorf("datacheck: objects: %w", err)
	}
	for head != nil {
		set(head.key).Missing++
		if err := advance(); err != nil {
			return err
		}
	}
	for s, d := range digests {
		s.Listing = d.sum()
	}
	m.Objects = o
	return nil
}

// hashObject reads one object through the store and returns the hex
// SHA-256 of its bytes and how many there were, reading it again from the
// start after a failure, up to len(retryPauses) times.
func hashObject(ctx context.Context, src ObjectStore, key string) (string, int64, error) {
	for i := 0; ; i++ {
		sum, n, err := hashObjectOnce(ctx, src, key)
		if err == nil || !retryable(ctx, err) || i >= len(retryPauses) {
			return sum, n, err
		}
		if err := pause(ctx, retryPauses[i]); err != nil {
			return "", 0, err
		}
	}
}

func hashObjectOnce(ctx context.Context, src ObjectStore, key string) (string, int64, error) {
	r, _, err := src.Get(ctx, key)
	if err != nil {
		return "", 0, fmt.Errorf("read %s: %w", key, err)
	}
	defer r.Close() //nolint:errcheck // read only; the hash is what matters
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, fmt.Errorf("read %s: %w", key, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type keyForm int

const (
	keyOther keyForm = iota
	keyHashed
	keyUnhashed
)

// addressed tells a content-addressed key (media.ObjectKey:
// "<workspace>/<first two hex>/<sha256 hex>") from an unhashed one
// ("<workspace>/unhashed/...") and from anything else.
func addressed(key string) keyForm {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return keyOther
	}
	if parts[1] == "unhashed" {
		return keyUnhashed
	}
	h := parts[2]
	if len(h) != 2*sha256.Size || parts[1] != h[:2] {
		return keyOther
	}
	if _, err := hex.DecodeString(h); err != nil || strings.ToLower(h) != h {
		return keyOther
	}
	return keyHashed
}

// writeLines writes one object's lines. A key holding a backslash or a
// line break is written as sha256sum writes such a name: the line starts
// with a backslash and the name is escaped.
func writeLines(out ObjectOutput, sum, size, key string) error {
	lead := ""
	if strings.ContainsAny(key, "\\\n\r") {
		lead = "\\"
		key = strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r").Replace(key)
	}
	if out.Sums != nil {
		if _, err := io.WriteString(out.Sums, lead+sum+"  "+key+"\n"); err != nil {
			return err
		}
	}
	if out.Sizes != nil {
		if _, err := io.WriteString(out.Sizes, lead+size+"  "+key+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// dbKey is one object key the database names, with what names it.
type dbKey struct {
	key                string
	storage, media     bool
	storageBytes       *int64
	mediaMin, mediaMax *int64
}

func (k *dbKey) sizeDiffers(n int64) bool {
	for _, v := range []*int64{k.storageBytes, k.mediaMin, k.mediaMax} {
		if v != nil && *v != n {
			return true
		}
	}
	return false
}

// dbKeys streams the database's object keys in key order: workspace by
// workspace in id order (each workspace's keys start with its id and a
// slash, so that is the listing's order too), each through a cursor.
type dbKeys struct {
	tx      pgx.Tx
	tenants []string
	at      int
	open    bool
	buf     []dbKey
	set     func(string) *ObjectSet
}

func newDBKeys(tx pgx.Tx, m *Manifest, set func(string) *ObjectSet) *dbKeys {
	d := &dbKeys{tx: tx, set: set}
	for id := range m.Workspaces {
		d.tenants = append(d.tenants, id)
	}
	slices.Sort(d.tenants)
	return d
}

const keysCursor = `DECLARE datacheck_keys NO SCROLL CURSOR FOR
	SELECT k, bool_or(s), bool_or(md), max(sb), min(ms), max(ms) FROM (
		SELECT object_key AS k, true AS s, false AS md, bytes AS sb, NULL::bigint AS ms FROM storage_objects
		 WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		UNION ALL
		SELECT object_key, false, true, NULL::bigint, object_size FROM media
		 WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND object_key IS NOT NULL) x
	GROUP BY k ORDER BY k COLLATE "C"`

// next returns the next key, or nil after the last.
func (d *dbKeys) next(ctx context.Context) (*dbKey, error) {
	for {
		if len(d.buf) > 0 {
			k := d.buf[0]
			d.buf = d.buf[1:]
			return &k, nil
		}
		if d.open {
			if err := d.fetch(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if d.at >= len(d.tenants) {
			return nil, nil
		}
		if _, err := d.tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, d.tenants[d.at]); err != nil {
			return nil, fmt.Errorf("datacheck: objects: scope: %w", err)
		}
		if _, err := d.tx.Exec(ctx, keysCursor); err != nil {
			return nil, fmt.Errorf("datacheck: objects: keys: %w", err)
		}
		d.open = true
	}
}

// fetch reads the next batch of the open cursor, closing it at its end.
// A key outside its workspace's prefix cannot take part in the merge: it is
// counted and left out.
func (d *dbKeys) fetch(ctx context.Context) error {
	tenant := d.tenants[d.at]
	rows, err := d.tx.Query(ctx, `FETCH `+strconv.Itoa(keyBatch)+` FROM datacheck_keys`)
	if err != nil {
		return fmt.Errorf("datacheck: objects: keys: %w", err)
	}
	n := 0
	for rows.Next() {
		n++
		var k dbKey
		if err := rows.Scan(&k.key, &k.storage, &k.media, &k.storageBytes, &k.mediaMin, &k.mediaMax); err != nil {
			rows.Close()
			return fmt.Errorf("datacheck: objects: keys: %w", err)
		}
		s := d.set(tenant + "/")
		if !strings.HasPrefix(k.key, tenant+"/") {
			s.OutsidePrefix++
			continue
		}
		if !k.storage {
			s.NoStorageRow++
		}
		if !k.media {
			s.NoMediaRow++
		}
		d.buf = append(d.buf, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("datacheck: objects: keys: %w", err)
	}
	if n == 0 {
		if _, err := d.tx.Exec(ctx, `CLOSE datacheck_keys`); err != nil {
			return fmt.Errorf("datacheck: objects: keys: %w", err)
		}
		d.open = false
		d.at++
	}
	return nil
}
