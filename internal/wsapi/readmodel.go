package wsapi

import "whatserver2/internal/store"

// SealedMessageFromRow keeps HTTP and WebSocket ciphertext representations equal.
func SealedMessageFromRow(row store.Row) SealedMessage { return sealedMessage(row) }

// HistoryFromStore describes revisions without opening their sealed contents.
func HistoryFromStore(history store.MessageHistory) History { return historyFrame(history) }

// ChatFromRow preserves the row identities used as cryptographic associated data.
func ChatFromRow(c store.ChatRow) ChatSummary {
	return ChatSummary{
		UID: c.UID.String(), ChatKey: c.ChatKey, ChatLID: c.ChatLID, ChatPN: c.ChatPN, IsGroup: c.IsGroup,
		LastSeq: c.LastSeq, LastTS: c.LastTS, CreatedAt: c.CreatedAt, GroupCreatedAt: c.GroupCreatedAt,
		LastKind: c.LastKind, LastType: c.LastType, Unread: c.Unread, Archived: c.Archived, Pinned: c.Pinned,
		NameSealed: c.NameSealed, NameKeyID: c.NameKeyID, Keys: c.Keys, Audience: audience(c), Ephemeral: c.Ephemeral,
		LastUID: lastUID(c), LastBodySealed: c.LastBodySealed, LastBodyKeyID: c.LastBodyKeyID,
	}
}

// DeviceFromRow contains stored metadata only. Each transport adds its actor's
// permissions, reader preferences and the local process's connection status.
func DeviceFromRow(d store.Device) DeviceInfo {
	info := DeviceInfo{ArchiveTenantID: d.ArchiveTenantID, ID: d.ID, Label: d.Label, PushName: d.Identity.PushName,
		Status: string(d.Status), StatusReason: d.StatusReason, ReceiptMode: string(d.ReceiptMode), CreatedAt: d.CreatedAt, Paused: d.Paused}
	if d.Identity.Known() {
		info.ProfileKey = d.Identity.Primary().ToNonAD().String()
	}
	if !d.Identity.LID.IsEmpty() {
		info.LID = d.Identity.LID.String()
	}
	if !d.Identity.PN.IsEmpty() {
		info.PN = d.Identity.PN.String()
	}
	if !d.LastConnectedAt.IsZero() {
		at := d.LastConnectedAt
		info.LastConnectedAt = &at
	}
	return info
}

// PageReceipts maps the same per-person receipt counts for either transport.
func PageReceipts(rows []store.Row, folded map[string]store.PageAcks) []MessageAcks {
	out := make([]MessageAcks, 0, len(folded))
	for _, r := range rows {
		if r.Kind.IsControl() {
			continue
		}
		a, ok := folded[r.WAID]
		if !ok {
			continue
		}
		out = append(out, MessageAcks{WAID: r.WAID, Delivered: a.Delivered, Read: a.Read, Played: a.Played,
			DeliveredAt: a.DeliveredAt, ReadAt: a.ReadAt, PlayedAt: a.PlayedAt,
			ReadByUs: a.ReadByUs, Retrying: a.Retrying, Failed: a.Failed})
	}
	return out
}
