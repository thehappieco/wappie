package domain

import "time"

// ReceiptKind is what an acknowledgement says happened.
//
// WhatsApp has more receipt types than these, and the extras are collapsed
// deliberately. "read-self" is a read that happened on another of our own
// devices, and "inactive" is a delivery to a client that was not in the
// foreground; both are still a read and a delivery. Keeping the wire spelling
// would push a distinction that belongs in IsFromMe into the kind, and every
// reader would then have to know five spellings for two facts.
type ReceiptKind string

const (
	// ReceiptDelivered means the message reached the device. It says nothing
	// about anyone having looked at it.
	ReceiptDelivered ReceiptKind = "delivered"

	// ReceiptRead means the chat was opened with the message on screen.
	ReceiptRead ReceiptKind = "read"

	// ReceiptPlayed means a voice note or a view-once media was opened. A
	// separate signal from read, and the only one that exists for PTT.
	ReceiptPlayed ReceiptKind = "played"

	// ReceiptRetry means the message arrived but could not be decrypted, so
	// the sender is being asked to send it again. Kept because a message stuck
	// in retry looks delivered and is not.
	ReceiptRetry ReceiptKind = "retry"

	// ReceiptError means WhatsApp's own servers rejected it.
	ReceiptError ReceiptKind = "error"
)

// Valid reports whether k is a known kind.
func (k ReceiptKind) Valid() bool {
	switch k {
	case ReceiptDelivered, ReceiptRead, ReceiptPlayed, ReceiptRetry, ReceiptError:
		return true
	}
	return false
}

// Receipt is one acknowledgement event.
//
// One reader, one kind, one moment, and every message id that reader
// acknowledged at that moment. That is the shape WhatsApp sends, and keeping it
// is what lets the whole batch take a single sequence number instead of one per
// id — which matters in a group, where a single message produces an
// acknowledgement from every participant.
//
// There is no Content field and nothing here is sealed. A receipt is a party,
// a message id and a time: routing metadata by the same definition that leaves
// chat_key readable, with nothing inside it to hide.
type Receipt struct {
	TenantID string
	DeviceID string

	Chat Address
	// Reader is who acknowledged. In a direct chat it is the peer; in a group,
	// each participant in turn.
	Reader Address
	// IsFromMe marks an acknowledgement from one of our own other devices —
	// "you read this on your phone" rather than "they read it".
	IsFromMe bool

	// MessageIDs are the WhatsApp ids acknowledged. An edit carries an id of
	// its own, so a receipt naming one is proof that that exact version
	// arrived, which is the difference between the projection inferring what a
	// reader saw and knowing it.
	MessageIDs []string

	Kind ReceiptKind
	TS   time.Time
}

// Empty reports whether there is nothing to record.
func (r Receipt) Empty() bool { return len(r.MessageIDs) == 0 }
