// Package datacheck computes the data check's manifest (whatserverd
// datacheck): what the database and the object store hold, per workspace
// and per number, as counts, digests and ids only, so that two runs (before
// and after a change, or a snapshot and its restore) can be compared field
// by field (plan 0063-0066, sections 2.4 and 2.5).
//
// It only reads. The database part runs in one READ ONLY REPEATABLE READ
// transaction that is never committed; the object part lists and reads the
// bucket and writes nothing to it. Nothing it prints names a label, a phone
// number, an e-mail address or any content: a WhatsApp identifier, a chat
// key or a sealed value enters the output only through a SHA-256 digest
// over many rows, or one sealed value's hash.
package datacheck

// Format names this manifest's layout. A change to what a digest covers
// changes the Digests section, so a comparison across two binaries shows it.
const Format = "wappie-datacheck/1"

// Manifest is the whole data check. Every collection is a JSON object keyed
// by an id, so the encoding is sorted and two manifests diff line by line.
type Manifest struct {
	Format string `json:"format"`
	// TakenAt is the database's time of the transaction. Compare ignores it.
	TakenAt string `json:"taken_at"`
	// Scope is "all", or the one workspace's id.
	Scope string `json:"scope"`
	// Schema is schema_migrations: version to name and checksum.
	Schema map[string]Migration `json:"schema"`
	// Digests says, per table, which columns each digest covers and which it
	// leaves out, so a manifest explains itself.
	Digests map[string]DigestSpec `json:"digests"`
	// Excluded names the tables that carry a number's data and are left out
	// on purpose, with the reason.
	Excluded   map[string]string     `json:"excluded"`
	Workspaces map[string]*Workspace `json:"workspaces"`
	// ReaderState is mcp_reader_state, keyed reader:name (scope all only).
	ReaderState map[string]ReaderState `json:"mcp_reader_state,omitempty"`
	// Files are the files outside the database a restore needs: the
	// deletion ledger and the token stop record, by line count and hash.
	Files map[string]File `json:"files"`
	// Objects is the object check, when it ran.
	Objects *Objects `json:"objects,omitempty"`
}

// Migration is one schema_migrations row.
type Migration struct {
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
}

// DigestSpec is what one table's digests cover.
type DigestSpec struct {
	Key  []string `json:"key"`
	Rows []string `json:"rows"`
	// Columns each have their own digest (Table.Columns).
	Columns    []string `json:"columns,omitempty"`
	Ciphertext []string `json:"ciphertext,omitempty"`
	Seq        []string `json:"seq,omitempty"`
	LeftOut    []string `json:"left_out,omitempty"`
	// Absent are the Columns this database's schema lacks (a binary newer
	// than the schema): no digest covers them.
	Absent []string `json:"absent,omitempty"`
}

// ReaderState is one attested reader's sealed collection.
type ReaderState struct {
	Generation int64  `json:"generation"`
	BlobSHA256 string `json:"blob_sha256"`
}

// File is one file outside the database.
type File struct {
	Present bool   `json:"present"`
	Lines   int64  `json:"lines"`
	SHA256  string `json:"sha256,omitempty"`
}

// Workspace is one tenants row and everything filed under it.
type Workspace struct {
	// Fields are the workspace's own clear columns: kind, status, last_seq
	// and the accounted storage totals. Never its name.
	Fields map[string]*string `json:"fields"`
	// Inventory is storage_inventory's total per source.
	Inventory map[string]Total `json:"inventory"`
	// StorageObjects is storage_objects' total.
	StorageObjects Total `json:"storage_objects"`
	// Users are the accounts whose home is this workspace.
	Users map[string]User `json:"users"`
	// ReadCheck is the start's read check over every live number: keyless
	// (no archive key) and orphan (a key no person holds).
	ReadCheck ReadCheck          `json:"read_check"`
	Devices   map[string]*Device `json:"devices"`
	// Unowned are rows whose number cannot be told (media whose message is
	// gone), per table.
	Unowned map[string]*Table `json:"unowned,omitempty"`
}

// Total is a row count and a byte total.
type Total struct {
	Count int64 `json:"count"`
	Bytes int64 `json:"bytes"`
}

// User is one account's keys: the hash of its public key and of each of its
// platform wraps, keyed by the hash of the product key id.
type User struct {
	PublicKeySHA256 string            `json:"public_key_sha256"`
	PlatformWraps   map[string]string `json:"platform_wraps,omitempty"`
}

// ReadCheck lists numbers by id.
type ReadCheck struct {
	Keyless []string `json:"keyless"`
	Orphan  []string `json:"orphan"`
}

// Device is one number (devices.id) of a workspace.
type Device struct {
	// Present is false for a number whose rows are filed under this
	// workspace and whose devices row is not.
	Present bool `json:"present"`
	// Fields are the devices row's clear fields the database re-derives or
	// a change may declare (never the label, the phone number or the LID).
	Fields   map[string]*string `json:"fields,omitempty"`
	Messages MessageStats       `json:"messages"`
	// ChatOrder is, per chat, the SHA-256 over its message uids in seq
	// order. A chat is named by the uid of its first message in that order
	// (a random uuidv7 that a move or an import keeps), never by anything
	// derived from its chat key: store.ChatUID is predictable, and with the
	// number's id it would give a direct chat's phone number away.
	ChatOrder map[string]string `json:"chat_order"`
	// Tables are the per-table digests (see Digests).
	Tables map[string]*Table `json:"tables"`
	// Media is media's count and sum(file_length) by download_status.
	Media map[string]Total `json:"media"`
	// ContentKeys is per epoch.
	ContentKeys map[string]ContentKeys `json:"content_keys"`
	// ArchiveKeys is per epoch.
	ArchiveKeys map[string]ArchiveKey `json:"archive_keys"`
	// Grants is keyed user:epoch.
	Grants map[string]Grant `json:"grants"`
}

// MessageStats are the messages of one number.
type MessageStats struct {
	ByKind map[string]int64 `json:"by_kind"`
	MinTS  *string          `json:"min_ts"`
	MaxTS  *string          `json:"max_ts"`
	NullTS int64            `json:"null_ts"`
}

// Table is one table's rows of one number.
type Table struct {
	Count int64 `json:"count"`
	// Rows is the digest over the row key and every clear column.
	Rows string `json:"rows"`
	// Columns is, per split column, the digest over the row key and that
	// column.
	Columns map[string]string `json:"columns,omitempty"`
	// Ciphertext is the digest over the row key and the SHA-256 of each
	// sealed column.
	Ciphertext string `json:"ciphertext,omitempty"`
	// Seq is the digest over the row key and each seq column less the
	// number's seq base (a 0, "none yet", as itself), so it is the same
	// after a renumbering by an offset (plan 2.5, device_transfer's rule)
	// and changes for anything else.
	Seq string `json:"seq,omitempty"`
	// MaxSeq is the highest seq, as stored.
	MaxSeq *int64 `json:"max_seq,omitempty"`
	// Nulls counts NULLs in the columns the start's LID and chat uid
	// backfills fill.
	Nulls map[string]int64 `json:"nulls,omitempty"`
}

// ContentKeys are one epoch's content keys.
type ContentKeys struct {
	Count       int64 `json:"count"`
	SealedCount int64 `json:"sealed_count"`
	Closed      int64 `json:"closed"`
	// Digest is over (id, SHA-256 of sealed_key), by id.
	Digest string `json:"digest"`
}

// ArchiveKey is one device_archive_keys row.
type ArchiveKey struct {
	Suite       int16   `json:"suite"`
	Fingerprint string  `json:"fingerprint"`
	RetiredAt   *string `json:"retired_at"`
}

// Grant is one device_key_grants row, joined to the fingerprint of the
// archive key at its (device, epoch): null when there is none.
type Grant struct {
	SealedDSKSHA256 string  `json:"sealed_dsk_sha256"`
	Fingerprint     *string `json:"fingerprint"`
	GrantedBy       *string `json:"granted_by"`
}

// Objects is the object check.
type Objects struct {
	// Prefix is the listing's prefix: empty for the whole bucket.
	Prefix string `json:"prefix"`
	Total  Total  `json:"total"`
	// Workspaces are the objects under each workspace's prefix.
	Workspaces map[string]*ObjectSet `json:"workspaces"`
	// Other are the objects under no workspace's prefix.
	Other *ObjectSet `json:"other,omitempty"`
}

// ObjectSet is the objects under one prefix and what the cross-check found.
type ObjectSet struct {
	Count int64 `json:"count"`
	Bytes int64 `json:"bytes"`
	// Listing is the SHA-256 over every "key size sha256" line, in key order.
	Listing string `json:"listing"`
	// HashMismatch counts content-addressed objects whose bytes do not hash
	// to their key; Unchecked those that cannot be checked (unhashed/), and
	// Unrecognised keys of neither form.
	HashMismatch int64 `json:"hash_mismatch"`
	Unchecked    int64 `json:"unchecked"`
	Unrecognised int64 `json:"unrecognised"`
	// NotInDatabase are listed objects no storage_objects or media row
	// names; Missing are keys a row names that the listing lacks.
	NotInDatabase int64 `json:"not_in_database"`
	Missing       int64 `json:"missing"`
	// SizeMismatch are listed objects whose size differs from its
	// storage_objects bytes or media object_size.
	SizeMismatch int64 `json:"size_mismatch"`
	// NoStorageRow are media keys with no storage_objects row; NoMediaRow
	// storage_objects keys no media row names.
	NoStorageRow int64 `json:"no_storage_row"`
	NoMediaRow   int64 `json:"no_media_row"`
	// OutsidePrefix are database keys not under their workspace's prefix.
	OutsidePrefix int64 `json:"outside_prefix"`
}

// Problems is the number of findings that mean the bucket and the database
// disagree, or an object's bytes are not what its key says.
func (o *ObjectSet) Problems() int64 {
	if o == nil {
		return 0
	}
	return o.HashMismatch + o.NotInDatabase + o.Missing + o.SizeMismatch + o.NoStorageRow + o.OutsidePrefix
}
