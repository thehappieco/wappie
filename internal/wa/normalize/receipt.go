package normalize

import (
	"errors"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/domain"
)

// ErrNotArchived reports a receipt type that carries no archive meaning.
//
// Distinct from ErrSkip only in name; kept separate so a caller counting
// skipped receipts does not have to share a bucket with skipped messages.
var ErrNotArchived = errors.New("normalize: receipt is not archive traffic")

// ReceiptFrom converts a whatsmeow receipt into the canonical form.
//
// The collapsing of receipt types happens here and only here. Upstream has
// eleven of them; five reach the archive. The rest are either housekeeping
// between our own devices (peer_msg, hist_sync) or a duplicate spelling of a
// fact already covered:
//
//   - "" (delivered) and "inactive" are both a delivery. The difference is
//     whether the recipient's client had the chat in the foreground, which is
//     the recipient's business and not a distinction this archive keeps.
//   - "sender" is our own other device confirming it received something we
//     sent. Still a delivery, so it is stored as one with IsFromMe set.
//   - "read-self" and "played-self" are the same events happening on another
//     of our devices, which again is IsFromMe rather than a separate kind.
//
// The alternative — one archive kind per wire spelling — pushes that
// bookkeeping into every reader. v1 had no receipt storage at all, so there is
// no prior art here to inherit or to correct.
func ReceiptFrom(evt *events.Receipt, opts Options) (domain.Receipt, error) {
	if evt == nil {
		return domain.Receipt{}, errors.New("normalize: nil receipt")
	}
	kind, fromMe, ok := receiptKind(evt.Type)
	if !ok {
		return domain.Receipt{}, ErrNotArchived
	}
	if len(evt.MessageIDs) == 0 {
		// A receipt naming nothing acknowledges nothing.
		return domain.Receipt{}, ErrNotArchived
	}

	chat := addressFor(evt.Chat, evt.RecipientAlt, true)
	if chat.Empty() {
		return domain.Receipt{}, errors.New("normalize: receipt with no chat")
	}

	reader := addressFor(evt.Sender, evt.SenderAlt, true)
	if reader.Empty() {
		// Direct chats sometimes omit the sender because it can only be the
		// peer. Falling back to the chat keeps the row keyable; guessing
		// nothing would drop a real acknowledgement.
		reader = chat
	}

	// evt.IsFromMe is set when the acknowledgement came from one of our own
	// devices. The two "self" receipt types imply it even when the flag is
	// not set, because they exist precisely to describe that case.
	ts := evt.Timestamp
	if ts.IsZero() {
		return domain.Receipt{}, errors.New("normalize: receipt with no timestamp")
	}
	if !validTimestamp(ts) {
		return domain.Receipt{}, errors.New("normalize: receipt timestamp is not plausible")
	}

	ids := make([]string, 0, len(evt.MessageIDs))
	for _, id := range evt.MessageIDs {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return domain.Receipt{}, ErrNotArchived
	}

	return domain.Receipt{
		TenantID:   opts.TenantID,
		DeviceID:   opts.DeviceID,
		Chat:       chat,
		Reader:     reader,
		IsFromMe:   fromMe || evt.IsFromMe,
		MessageIDs: ids,
		Kind:       kind,
		TS:         ts,
	}, nil
}

// receiptKind maps a wire receipt type to an archive kind, reporting whether
// the type implies the acknowledgement came from one of our own devices and
// whether it belongs in the archive at all.
func receiptKind(t types.ReceiptType) (domain.ReceiptKind, bool, bool) {
	switch t {
	case types.ReceiptTypeDelivered, types.ReceiptTypeInactive:
		return domain.ReceiptDelivered, false, true
	case types.ReceiptTypeSender:
		return domain.ReceiptDelivered, true, true
	case types.ReceiptTypeRead:
		return domain.ReceiptRead, false, true
	case types.ReceiptTypeReadSelf:
		return domain.ReceiptRead, true, true
	case types.ReceiptTypePlayed:
		return domain.ReceiptPlayed, false, true
	case types.ReceiptTypePlayedSelf:
		return domain.ReceiptPlayed, true, true
	case types.ReceiptTypeRetry:
		return domain.ReceiptRetry, false, true
	case types.ReceiptTypeServerError:
		return domain.ReceiptError, false, true
	default:
		// peer_msg and hist_sync, plus anything upstream adds later. Ignored
		// rather than stored under a guess.
		return "", false, false
	}
}
