package wa

import (
	"fmt"
	"sync"

	"go.mau.fi/whatsmeow/store"
	"google.golang.org/protobuf/proto"
)

var linkedDeviceBrand struct {
	sync.Once
	name string
}

// configureLinkedDeviceName runs before NewRegistry can create any clients.
// whatsmeow's supported OS-name setting is process-global. Initialize it once,
// then never write it while pairing or reconnect goroutines can build payloads.
// A conflicting registry fails instead of changing other clients' identity.
func configureLinkedDeviceName(name string) error {
	if name == "" {
		name = "whappie"
	}
	if name != "whappie" && name != "whappie cloud" {
		return fmt.Errorf("wa: linked device name must be whappie or whappie cloud, got %q", name)
	}
	linkedDeviceBrand.Do(func() {
		// Only the display name changes. Keep the upstream version, platform,
		// history-sync capabilities and registration/login payload generation.
		store.DeviceProps.Os = proto.String(name)
		linkedDeviceBrand.name = name
	})
	if linkedDeviceBrand.name != name {
		return fmt.Errorf("wa: linked device name already initialized as %q; restart to change it", linkedDeviceBrand.name)
	}
	return nil
}
