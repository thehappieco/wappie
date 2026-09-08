package wa

import (
	"context"

	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

// LIDMap answers "whose phone number is this LID".
//
// WhatsApp addresses group participants by LID -- an identifier that exists
// precisely so a number need not be revealed to a group -- while the contact
// list a phone syncs is keyed by phone number. Nothing joins the two, so on one
// real account 860 of 883 group senders had no name: not because the names were
// missing, but because they were filed under an identifier nobody looked up.
//
// whatsmeow has been writing the join all along. Every group query it makes
// records the pairs it learns (group.go), and they accumulate in
// whatsmeow_lid_map -- 3871 of them on that same account, which resolve 850 of
// the 860.
//
// Taken from the Container rather than through the Client interface. LIDs is a
// field on store.Device, not a method, so surfacing it on Client would need the
// wrapper that client.go exists to forbid; and it is unnecessary, because the
// map is one shared cache per container, reachable with no device and no client
// at all. That matters for history: a backfill resolves senders for devices
// this process may not be supervising.
type LIDMap struct{ container *sqlstore.Container }

// NewLIDMap wraps the container's shared cache. A nil container yields a map
// that resolves nothing, which is what a test without a session store wants.
func NewLIDMap(container *sqlstore.Container) *LIDMap {
	return &LIDMap{container: container}
}

// PhoneFor resolves a LID to the phone number behind it.
//
// The second return is false whenever there is no answer -- unknown LID, not a
// LID at all, no store. A caller must leave the address alone in that case
// rather than guessing.
func (m *LIDMap) PhoneFor(ctx context.Context, lid types.JID) (types.JID, bool) {
	if m == nil || m.container == nil || m.container.LIDMap == nil {
		return types.JID{}, false
	}
	if lid.Server != types.HiddenUserServer {
		return types.JID{}, false
	}

	// The device suffix has to go before the lookup: the cache is keyed on the
	// bare user, and it copies the source's device number onto whatever it
	// returns. Left in, a participant addressed as 4263…:5@lid would resolve to
	// 5511971446866:5@s.whatsapp.net, which matches no contact row and no chat.
	pn, err := m.container.LIDMap.GetPNForLID(ctx, lid.ToNonAD())
	if err != nil || pn.IsEmpty() {
		return types.JID{}, false
	}
	return pn.ToNonAD(), true
}
