// Package numberacts runs a number's acts for the platform console's
// commands now (step 12a's commands release; the spec's 14.7), and for
// Wappie's own socket frames later, as internal/relink does for a relink:
// rename, stop and resume its capture, connect it now, delete a
// registration that never linked, and change a person's flags on it
// (flags.go, step 12b).
//
// Each act's checks and writes are one store transaction
// (store/contract_command_acts.go): the number before the role, both roles,
// the published value, the result at the act's seq. Around it, this
// package does what the socket's frame does with the process: it stops and
// starts the number in the registry, and through the socket server it
// cancels a pairing in progress, broadcasts the number's status and pushes
// the notices a pause raised to the sessions open on this process. The
// parity tests (internal/wsapi/console_parity_test.go) hold each runner to
// its frame until the frames move onto these runners.
package numberacts

import (
	"cmp"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Registry is what the runners ask of the process's WhatsApp registry
// (*wa.Registry).
type Registry interface {
	Stop(ctx context.Context, deviceID string)
	StartExisting(ctx context.Context, tenantID, deviceID string, policy wa.ReceiptPolicy, candidates ...types.JID) (*wa.Device, error)
	PairingSince(deviceID string) (time.Time, bool)
}

// Sockets is what the runners ask of the process's socket server
// (*wsapi.Server, its console_hooks.go and access.go).
type Sockets interface {
	CancelPairing(tenant, device string)
	PushNotices(tenant string, raised []store.RaisedNotice)
	BroadcastDeviceStatus(tenant, device, status, reason string)
	// RevalidateAccess wakes the sessions open on this process to check
	// their access again, after a flags act changed it.
	RevalidateAccess()
}

// Run is one command a runner runs: its ledger row, the workspace, the
// actor's sub and the local account linked to it. Its result is written in
// the ledger in the act's transaction.
type Run struct {
	Command   uuid.UUID
	Workspace uuid.UUID
	Actor     uuid.UUID
	User      uuid.UUID
}

func (r Run) contract() store.ContractRun {
	return store.ContractRun{ID: r.Command, Workspace: r.Workspace, Sub: r.Actor, User: r.User}
}

// Runner runs the acts. Store is required; the rest may be nil in a
// process with no WhatsApp connection or no socket server, which then
// skips what they do (the supervisor starts a resumed number within its
// tick).
type Runner struct {
	Store   *store.Contract
	Devices *store.Devices
	// Registry is the process's registry; Sockets its socket server.
	Registry Registry
	Sockets  Sockets
	// Recorder observes the receipt policy's decisions of a number it
	// starts, as the frames' does.
	Recorder func(kind, decision string)
	Log      *slog.Logger
	// StartBound bounds a start (StartBound when zero).
	StartBound time.Duration
	// FailedStartWait is how long a sync now waits after this runner's
	// failed start of its number (FailedStartWait when zero).
	FailedStartWait time.Duration

	mu sync.Mutex
	// failed is when each number's last sync now start failed, kept
	// until its wait ends.
	failed map[string]time.Time
}

// StartBound is how long a resume or a sync now waits for its number to
// connect. The executor runs one command at a time, every workspace's, and
// a connect that keeps failing tries 8 times with up to 30 seconds between
// tries: unbounded, one number's outage would hold every other command for
// a minute and a half. Past it the start is cancelled (the registry stops
// what it began): a sync now answers connect_failed, and a resume, whose
// ran was committed with its lift, is left to the supervisor, which starts
// a number that is not paused within its tick.
const StartBound = 15 * time.Second

// FailedStartWait is how long a sync now of a number waits after this
// runner's last failed start of it. A sync now is a reader's, and its
// connect_failed offers a button to try again (the spec's 14.9): without
// it, readers clicking it on a number WhatsApp does not let connect would
// each hold every workspace's commands for up to StartBound. Within it the
// sync now is answered rate_limited, retry_after the seconds left, without
// a start: the platform issues it again then, so the click is not lost,
// and a number's sync now starts at most once a FailedStartWait while it
// fails.
const FailedStartWait = time.Minute

// startCtx bounds a start of the number under ctx.
func (r *Runner) startCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, cmp.Or(r.StartBound, StartBound))
}

func (r *Runner) log() *slog.Logger {
	if r.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Log
}

// detached is ctx for what follows a committed act, which the leader's
// stop must not cut half way, bounded.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

// ran reports whether an act's transaction ran its kind.
func ran(act store.ContractAct) bool { return !act.Open && act.Result.Outcome == store.CommandRan }

// The process's registry is the runners'.
var _ Registry = (*wa.Registry)(nil)
