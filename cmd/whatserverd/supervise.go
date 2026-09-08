package main

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// superviseDevices keeps trying to hold every device that should be held.
//
// resumeDevices runs once, at boot, and that turned out to be one attempt too
// few. A restart overlaps: the outgoing process releases its device locks at
// the very end of shutdown, after the HTTP drain, while the incoming one asks
// for them milliseconds into boot. The new process loses the race, logs "device
// is supervised by another instance" — which is true for about a second — and
// then never asks again.
//
// What that costs is the exact failure the resume file's own comment warns
// about: the device row still says online, the health checks are green, the
// browser reconnects happily, and no message has arrived for hours. It happened
// on this installation, and nothing in the system said so.
//
// So supervision is a loop rather than a moment. It is also what finally makes
// the rolling-deploy comment true: the instance that lost the lock picks the
// device up when the winner exits, instead of leaving it unheld until somebody
// notices and restarts.
func (a *app) superviseDevices(ctx context.Context) {
	// Long enough that a rolling deploy does not thrash, short enough that a
	// lost race costs seconds rather than a working day.
	const interval = 30 * time.Second

	// How often each device has failed, so one that cannot connect is retried
	// less and less rather than every tick forever. Local to the loop: only
	// this goroutine touches it, and a restart should try again promptly
	// because a restart is usually somebody fixing whatever was wrong.
	attempts := map[string]int{}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.claimUnheldDevices(ctx, attempts)
		}
	}
}

// claimUnheldDevices is one pass: start anything that should be running here
// and is not.
func (a *app) claimUnheldDevices(ctx context.Context, attempts map[string]int) {
	tenants, err := a.listTenantIDs(ctx)
	if err != nil {
		a.log.Error("supervise: list tenants", "error", err)
		return
	}

	held := map[string]bool{}
	for _, id := range a.registry.Running() {
		held[id] = true
	}

	for _, tenant := range tenants {
		devices, err := a.devices.List(ctx, tenant.String())
		if err != nil {
			a.log.Error("supervise: listing devices failed", "tenant", tenant, "error", err)
			continue
		}
		for _, d := range needsClaim(devices, held) {
			a.claim(ctx, tenant.String(), d, attempts)
		}
	}
}

// needsClaim picks the devices this process should be holding and is not.
//
// Separated from the I/O around it because it is the whole of the decision, and
// because the two mistakes it can make are opposite and both bad: claiming a
// device that is already supervised burns a lock attempt every tick, and
// skipping one that is not is precisely the bug this file exists to fix.
func needsClaim(devices []store.Device, held map[string]bool) []store.Device {
	var out []store.Device
	for _, d := range devices {
		if held[d.ID] || !shouldResume(d) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (a *app) claim(ctx context.Context, tenant string, d store.Device, attempts map[string]int) {
	// Exponential in the number of consecutive failures, so a device that is
	// simply gone costs one attempt every few minutes rather than one every
	// thirty seconds for the life of the process.
	if n := attempts[d.ID]; n > 0 {
		skip := 1 << min(n, 4) // 2, 4, 8, 16 ticks
		//nolint:gosec // G404: scheduling jitter, not a security decision
		if rand.IntN(skip) != 0 {
			return
		}
	}

	mode, err := wa.ParseReceiptMode(string(d.ReceiptMode))
	if err != nil {
		a.log.Error("supervise: bad receipt mode in the database",
			"device", d.ID, "value", d.ReceiptMode, "error", err)
		return
	}
	policy := wa.ReceiptPolicy{Mode: mode, Recorder: a.recordReceipt}

	_, err = a.registry.StartExisting(ctx, tenant, d.ID, policy, d.Identity.PN, d.Identity.LID)
	switch {
	case err == nil:
		delete(attempts, d.ID)
		a.log.Info("device picked up", "device", d.ID, "identity", d.Identity.String())
	case errors.Is(err, wa.ErrAlreadyRunning):
		// Another instance holds it, or this one is mid-start. Neither is a
		// failure, and neither is worth a log line every thirty seconds.
		attempts[d.ID]++
	case errors.Is(err, wa.ErrNoSession):
		// Terminal: no amount of retrying brings a deleted session back. Say so
		// in the row, which also stops shouldResume returning it again.
		a.log.Warn("device session is gone; it must be paired again",
			"device", d.ID, "identity", d.Identity.String())
		if err := a.devices.SetStatus(ctx, tenant, d.ID, wa.StatusLoggedOut,
			"session missing"); err != nil {
			a.log.Error("supervise: could not record the lost session", "device", d.ID, "error", err)
		}
	default:
		attempts[d.ID]++
		a.log.Error("supervise: could not start device",
			"device", d.ID, "attempt", attempts[d.ID], "error", err)
	}
}
