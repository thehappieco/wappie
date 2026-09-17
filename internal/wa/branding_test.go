package wa

import (
	"os"
	"os/exec"
	"sync"
	"testing"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

// Each installation has one process-wide brand. Run the cases in separate
// processes to exercise that contract without changing globals under other tests.
func TestLinkedDeviceBrandingPayload(t *testing.T) {
	name := os.Getenv("WAPPIE_TEST_LINKED_DEVICE_NAME")
	if name == "" {
		for _, brand := range []string{"whappie", "whappie cloud"} {
			t.Run(brand, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestLinkedDeviceBrandingPayload$")
				cmd.Env = append(os.Environ(), "WAPPIE_TEST_LINKED_DEVICE_NAME="+brand)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("branding process: %v\n%s", err, out)
				}
			})
		}
		return
	}

	base := proto.Clone(store.BaseClientPayload)
	wantProps := proto.Clone(store.DeviceProps).(*waCompanionReg.DeviceProps)
	wantProps.Os = proto.String(name)
	container := &sqlstore.Container{}
	if _, err := NewRegistry(RegistryConfig{Container: container, LinkedDeviceName: "whatsmeow"}); err == nil {
		t.Fatal("accepted an unsupported brand")
	}
	configuredName := name
	if name == "whappie" {
		configuredName = "" // An unconfigured open-source installation is branded.
	}
	registry, err := NewRegistry(RegistryConfig{Container: container, LinkedDeviceName: configuredName})
	if err != nil {
		t.Fatal(err)
	}

	// Both QR and code flows send the registration payload during Connect.
	// Keep code pairing's validated Browser (OS) descriptor separate from branding.
	for _, method := range []PairMethod{PairByQR, PairByCode} {
		opts := PairOptions{Method: method, Phone: "5511999999999"}
		if err := opts.Validate(); err != nil {
			t.Fatal(err)
		}
		if opts.DisplayName != "Chrome (Linux)" {
			t.Fatalf("changed code pairing descriptor: %q", opts.DisplayName)
		}
		client := whatsmeow.NewClient(registry.cfg.Container.NewDevice(), waLog.Noop)
		payload := client.Store.GetClientPayload()
		var props waCompanionReg.DeviceProps
		if err := proto.Unmarshal(payload.GetDevicePairingData().GetDeviceProps(), &props); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(&props, wantProps) {
			t.Fatalf("registration properties = %v, want %v", &props, wantProps)
		}
		if client.GetClientPayload != nil {
			t.Fatal("branding must preserve the upstream WhatsApp handshake")
		}
	}
	if !proto.Equal(base, store.BaseClientPayload) {
		t.Fatal("branding changed the protocol user agent or version")
	}

	// Repeated initialization must not write globals while another client builds
	// its payload. A second, different installation brand must fail unchanged.
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := NewRegistry(RegistryConfig{Container: container, LinkedDeviceName: name}); err != nil {
				t.Error(err)
			}
			_ = container.NewDevice().GetClientPayload()
		})
	}
	wg.Wait()
	other := "whappie"
	if name == other {
		other = "whappie cloud"
	}
	if _, err := NewRegistry(RegistryConfig{Container: container, LinkedDeviceName: other}); err == nil {
		t.Fatal("a live process accepted a conflicting installation brand")
	}
	if store.DeviceProps.GetOs() != name {
		t.Fatal("conflicting initialization changed the active brand")
	}

	// Existing sessions retain their identity. Upstream login does not resend
	// DeviceProps, so reconnecting cannot be advertised as renaming old links.
	device := container.NewDevice()
	jid := types.NewADJID("5511999999999", 0, 2)
	device.ID = &jid
	payload := device.GetClientPayload()
	if payload.GetDevicePairingData() != nil || payload.GetUsername() != jid.UserInt() || !payload.GetPassive() {
		t.Fatal("branding changed the existing-session login")
	}
}
