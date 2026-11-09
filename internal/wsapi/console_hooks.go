package wsapi

import "whatserver2/internal/store"

// The console's numbers runners (internal/numberacts; step 12a's commands
// release) act through the store and the registry, and through this server
// for what lives only here: a pairing in progress in a session, and the
// notices pushed to the sessions open on this process. These export the
// frames' own (device.stop and device.delete call them); the status
// broadcast is exported already (BroadcastDeviceStatus).

// CancelPairing cancels a pairing of device in progress in any session of
// tenant, as device.stop and a registration's deletion do.
func (s *Server) CancelPairing(tenant, device string) { s.cancelDevicePairing(tenant, device) }

// PushNotices sends each notice a pause raised to its person's sessions of
// tenant on this process, as device.stop does.
func (s *Server) PushNotices(tenant string, raised []store.RaisedNotice) {
	s.pushNotices(tenant, raised)
}
