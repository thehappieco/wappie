package wa

import (
	"context"
	"log/slog"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// NewRegistryForTest is a registry whose sessions come from load instead of
// a session store, so Unlink can be tested with no database.
func NewRegistryForTest(cfg RegistryConfig, load func(context.Context, types.JID) (*store.Device, error)) *Registry {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Registry{cfg: cfg, log: cfg.Log, devices: map[string]*entry{}, unlinking: map[string]int{}, loadSession: load}
}

// AdoptForTest registers a running client under a device id, as a start
// does, without connecting it.
func (r *Registry) AdoptForTest(ctx context.Context, tenantID, deviceID string, client Client) (*Device, error) {
	return r.adopt(ctx, tenantID, deviceID, ReceiptPolicy{}, client)
}

// ReserveForTest holds a reservation with no device, as a start or a
// pairing in progress does.
func (r *Registry) ReserveForTest(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[deviceID] = &entry{}
}
