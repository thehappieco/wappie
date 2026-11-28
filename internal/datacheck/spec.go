package datacheck

import "strings"

// tableSpec is one table's digests: which columns are the row key, which
// are clear, split, sealed or seq, and which are left out. Every column of
// the table is in exactly one list or is tenant_id/device_id
// (TestEveryColumnIsDecided holds it), so a migration that adds a column
// fails a test until someone decides what the digest does with it.
//
// A column a migration adds goes into split, not clear: a split column has
// its own digest, and the schema may lack it (the check then lists it as
// absent), so one binary takes the manifest before the migration and the
// one after, the row digest stays equal, and the new column shows as one
// new digest (compare -expect migration declares exactly that). A clear,
// key, sealed or seq column the schema lacks stops the check.
type tableSpec struct {
	name string
	// from is the FROM clause; the table is aliased t.
	from string
	// device is the expression naming the row's number.
	device string
	// key orders the rows within a number and is hashed into every digest.
	key []string
	// order overrides the ORDER BY built from key (events: by seq).
	order string
	// clear go into the row digest as text, NULL distinct from empty.
	clear []string
	// split each go into their own digest, over the row key and the
	// column as text: the columns a declared change may fill (the start's
	// LID and chat uid backfills) and every column added since.
	split []string
	// sealed go into the ciphertext digest as the SHA-256 of their bytes.
	sealed []string
	// seq go into the seq digest less the number's seq base.
	seq []string
	// nulls are clear or split columns whose NULLs are counted.
	nulls []string
	// leftOut are columns no digest covers: bookkeeping times the database
	// writes and the download worker's retry state, which a restore keeps
	// and an import need not.
	leftOut []string
}

// tables are the digested tables (plan 2.4), in output order.
var tables = []tableSpec{
	{
		name: "messages", key: []string{"uid"},
		clear: []string{"wa_id", "chat_key", "sender_key", "sender_lid", "ts", "is_from_me", "is_group",
			"kind", "type", "target_wa_id", "target_uid", "target_rel", "reply_to", "is_forwarded", "forwarding_score",
			"expiration", "expires_at", "view_once", "ephemeral", "source", "content_key_id", "unsupported_field", "counts_unread"},
		split:   []string{"sender_pn"},
		sealed:  []string{"body_sealed", "raw_sealed", "payload_sealed"},
		seq:     []string{"seq"},
		nulls:   []string{"sender_pn"},
		leftOut: []string{"created_at"},
	},
	{
		name: "chats", key: []string{"chat_key"},
		clear: []string{"chat_lid", "is_group", "name_key_id", "ephemeral_expiration", "last_ts",
			"last_kind", "last_type", "unread", "archived", "pinned", "muted_until", "group_created_at", "participant_count"},
		split:   []string{"chat_pn", "uid"},
		sealed:  []string{"name_sealed"},
		seq:     []string{"last_seq", "read_through_seq"},
		nulls:   []string{"chat_pn", "uid"},
		leftOut: []string{"created_at", "updated_at"},
	},
	{
		name: "contacts", key: []string{"contact_key"},
		clear: []string{"contact_pn", "is_group", "uid", "content_key_id", "avatar_id", "avatar_key_id",
			"avatar_checked_at"},
		split:   []string{"contact_lid"},
		sealed:  []string{"push_name_sealed", "full_name_sealed", "business_name_sealed", "avatar_sealed"},
		nulls:   []string{"contact_lid"},
		leftOut: []string{"created_at", "updated_at"},
	},
	{
		name: "group_participants", key: []string{"chat_key", "participant_key"},
		clear: []string{"participant_lid", "participant_pn", "is_admin", "is_super_admin", "first_seen_at", "left_at"},
	},
	{
		name: "receipts", key: []string{"chat_key", "wa_id", "reader_key", "kind"},
		clear:   []string{"reader_lid", "reader_pn", "is_from_me", "ts"},
		seq:     []string{"seq"},
		leftOut: []string{"created_at"},
	},
	{
		name: "group_changes", key: []string{"id"},
		order: "t.id",
		clear: []string{"chat_key", "ts", "actor_key", "actor_lid", "actor_pn", "action", "subject_key", "subject_lid",
			"subject_pn", "detail"},
		leftOut: []string{"created_at"},
	},
	{
		name:    "events",
		order:   "t.seq",
		clear:   []string{"kind", "chat_key", "message_uid"},
		seq:     []string{"seq"},
		leftOut: []string{"created_at"},
	},
	{
		name: "media", key: []string{"message_uid"},
		from:   "media t LEFT JOIN messages m ON m.uid = t.message_uid AND m.tenant_id = t.tenant_id",
		device: "m.device_id",
		clear: []string{"media_type", "mimetype", "file_length", "file_sha256", "file_enc_sha256", "direct_path", "url",
			"width", "height", "seconds", "waveform", "sidecar", "is_gif", "content_key_id", "download_status",
			"object_key", "object_size", "content_key"},
		sealed:  []string{"media_key_sealed", "thumb_sealed", "filename_sealed"},
		leftOut: []string{"download_error", "attempts", "next_attempt_at", "claimed_at", "downloaded_at", "created_at"},
	},
	{
		name: "ai_derived", key: []string{"message_uid", "feature"},
		clear:   []string{"epoch", "dedupe_tag", "authorization_id"},
		sealed:  []string{"result_sealed"},
		leftOut: []string{"created_at"},
	},
	{
		name: "device_permissions", key: []string{"user_id"},
		clear: []string{"can_read", "can_send", "can_manage"},
	},
	{
		name: "reader_preferences", key: []string{"user_id"},
		clear:   []string{"receipt_mode"},
		leftOut: []string{"updated_at"},
	},
}

// excluded are the tables that carry a number's data and are left out on
// purpose (plan 2.4).
var excluded = map[string]string{
	"mcp_outbound":   "a per-connection ledger of short-lived drafts, not moved with a number (0044)",
	"device_notices": "notices designed to outlive a purge, with no foreign key to devices (0050)",
	"mcp_send_chats": "a per-connection counter, not archive content (0044)",
	"ai_usage_daily": "a per-device usage counter, not archive content (0045)",
}

// deviceFields are the devices columns the manifest shows: those the
// database re-derives (devices_touch, the pause and logout causes) and
// those a change may declare. Never label, pn, lid, push_name,
// status_reason or wa_leftover.
var deviceFields = []string{"archive_tenant_id", "current_epoch", "status", "receipt_mode", "paused", "pause_seq",
	"pause_cause", "logout_cause", "paused_at", "paused_by_kind", "paused_by_user", "unpaused_at", "updated_at",
	"deleted_at", "deleted_by", "purge_after", "purge_started_at"}

// workspaceFields are the tenants columns the manifest shows. Never name
// or avatar.
var workspaceFields = []string{"kind", "status", "personal_owner_id", "last_seq", "storage_archive_bytes",
	"storage_object_bytes", "storage_limit_bytes", "storage_paused_at", "retention_days"}

func (s tableSpec) deviceExpr() string {
	if s.device != "" {
		return s.device
	}
	return "t.device_id"
}

// splitIn are s's split columns the schema has.
func (s tableSpec) splitIn(absent map[string]bool) []string {
	out := []string{}
	for _, c := range s.split {
		if !absent[c] {
			out = append(out, c)
		}
	}
	return out
}

// query is the streaming query of s for one workspace ($1): the number,
// then key, clear, split (less those absent), sealed and seq columns, each
// as text, in a stable order. Every name in it comes from the constants
// above.
func (s tableSpec) query(absent map[string]bool) string {
	cols := []string{s.deviceExpr() + "::text"}
	for _, c := range s.key {
		cols = append(cols, "t."+c+"::text")
	}
	for _, c := range s.clear {
		cols = append(cols, "t."+c+"::text")
	}
	for _, c := range s.splitIn(absent) {
		cols = append(cols, "t."+c+"::text")
	}
	for _, c := range s.sealed {
		cols = append(cols, "encode(sha256(t."+c+"), 'hex')")
	}
	for _, c := range s.seq {
		cols = append(cols, "t."+c+"::text")
	}
	from := s.from
	if from == "" {
		from = s.name + " t"
	}
	order := s.deviceExpr()
	if s.order != "" {
		order += ", " + s.order
	} else {
		for _, k := range s.key {
			order += ", t." + k + `::text COLLATE "C"`
		}
	}
	return "SELECT " + strings.Join(cols, ", ") + " FROM " + from + " WHERE t.tenant_id = $1 ORDER BY " + order
}

func (s tableSpec) digestSpec() DigestSpec {
	d := DigestSpec{Key: s.key, Rows: s.clear, Columns: s.split, Ciphertext: s.sealed, Seq: s.seq, LeftOut: s.leftOut}
	if d.Key == nil {
		d.Key = []string{}
	}
	if s.order != "" && len(s.key) == 0 {
		d.Key = []string{"(order " + strings.TrimPrefix(s.order, "t.") + ")"}
	}
	return d
}
