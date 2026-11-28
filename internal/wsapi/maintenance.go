package wsapi

import "maps"

// Maintenance is the socket of a maintenance start (whatserverd serve
// -maintenance): a person's session connects, an API key does not, and of
// the frames only the reads in maintenanceReads and the writes Allow names
// are answered. A nil *Maintenance is a normal start.
type Maintenance struct {
	allow map[string]bool
}

// NewMaintenance is a maintenance start's socket that answers the reads
// and the frames allow names: the declared change's writes, none by
// default.
func NewMaintenance(allow ...string) *Maintenance {
	m := &Maintenance{allow: map[string]bool{}}
	for _, frame := range allow {
		m.allow[frame] = true
	}
	return m
}

// maintenanceReads are the frames a maintenance start always answers:
// what lets a person see the numbers, the chats and the messages, and
// open the keys and grants they hold, which is what the key page's checks
// read. None of them writes a row, reaches WhatsApp or writes an object.
// contacts.resolve and contacts.avatar are not here: both write contact
// rows.
var maintenanceReads = map[string]bool{
	TypePing:         true,
	TypeDevicesList:  true,
	TypeUsersList:    true,
	TypeSubscribe:    true,
	TypeContacts:     true,
	TypeChatsList:    true,
	TypeChatPage:     true,
	TypeHistory:      true,
	TypeMessageGet:   true,
	TypeKeysGet:      true,
	TypeDevicesStats: true,
	TypeDeviceInfo:   true,
	TypeKeysList:     true,
	TypeGrantsList:   true,
}

// MaintenanceReads are the frames every maintenance start answers.
func MaintenanceReads() map[string]bool { return maps.Clone(maintenanceReads) }

// Permits reports whether a maintenance start answers frame. A nil
// Maintenance, a normal start, answers every frame.
func (m *Maintenance) Permits(frame string) bool {
	return m == nil || maintenanceReads[frame] || m.allow[frame]
}
