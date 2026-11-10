package main

import (
	"context"
	"time"

	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// The remedies the start's read check names for a number nobody reads
// (DS48). A keyless number has no archive key: device-key makes one and
// seals it to the accounts named, and the person consents again. An orphan
// number has a key nobody holds: someone who kept the printed key seals a
// grant with it, or the number is deleted and paired again with -grant
// (device-key refuses a number that has a key).
const (
	remedyKeyless = "whatserverd device-key -device <id> -grant <email>, then a new consent"
	remedyOrphan  = "a grant sealed with the printed key, or delete the number and pair it again with -grant"
)

// checkReadAtStart is the check at every start (DS48): every live
// assistant connection and AI integration whose person does not read one
// of the numbers it holds ends, whole and access_lost
// (store.EndConnectionsWithoutRead). serve runs it in a goroutine once the
// listener is bound; setupWith and the command line never do. It never
// fails the start: a busy workspace or a failure is logged and left for
// the next start. Each end and each busy workspace is a Warn line with ids
// only, an end naming the remedy for a number nobody reads. The readers
// are told within one bound; WatchRevocations tells them again in any case.
func (a *app) checkReadAtStart(ctx context.Context, readers wsapi.MCPReaders) {
	res, err := store.EndConnectionsWithoutRead(ctx, a.pools.API)
	if len(res.Ended) > 0 {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, e := range res.Ended {
			readers.TellRevoked(tctx, e.Reader, e.ID)
		}
	}
	for _, e := range res.Ended {
		args := []any{"workspace", e.Tenant, "connection", e.ID, "reason", store.ReasonAccessLost}
		if len(e.Keyless) > 0 {
			args = append(args, "keyless", e.Keyless, "keyless_remedy", remedyKeyless)
		}
		if len(e.Orphan) > 0 {
			args = append(args, "orphan", e.Orphan, "orphan_remedy", remedyOrphan)
		}
		a.log.Warn("start: an assistant connection ended: its person does not read a number it holds", args...)
	}
	for _, tenant := range res.Busy {
		a.log.Warn("start: the read check skipped a busy workspace; the next start checks it", "workspace", tenant)
	}
	if err != nil {
		a.log.Error("start: the read check failed; the next start checks again", "error", err)
	}
}
