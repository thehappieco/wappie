package wsapi

import (
	"context"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// SetSubscribeHook installs a hook at the subscribe's seams ("granted",
// "page"), so a test can commit a deletion exactly between two of them.
func SetSubscribeHook(cfg *Config, hook func(stage string)) { cfg.subscribeHook = hook }

// SetTransferHook replaces the move a device.transfer runs, so a test can
// make it fail after the handler paused the number, or commit and then fail.
func SetTransferHook(cfg *Config, hook func(ctx context.Context, source, actor, device, target uuid.UUID) (store.PersonalTransferPreview, error)) {
	cfg.transferHook = hook
}

// AtActsInFlight is how many sends' background checks run at once.
const AtActsInFlight = atActsInFlight
