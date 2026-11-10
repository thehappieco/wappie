package main

import (
	"context"
	"fmt"
	"time"

	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// The remedies the start's read check names (DS48). A keyless number has
// no archive key: device-key makes one and seals it to the accounts named,
// and the person consents again. An orphan number has a key nobody holds:
// someone who kept the printed key seals a grant with it, or the number is
// deleted and paired again with -grant (device-key refuses a number that
// has a key). A narrowed connection lost its own account's copy of a
// number its person still reads: the person consents again.
const (
	remedyKeyless  = "whatserverd device-key -device <id> -grant <email>, then a new consent"
	remedyOrphan   = "a grant sealed with the printed key, or delete the number and pair it again with -grant"
	remedyNarrowed = "a new consent"
)

// tellTimeout bounds each reader's notice at the start, so a slow reader
// does not use up the others' time.
var tellTimeout = 5 * time.Second

// checkReadAtStart is the check at every start (DS48): every live
// assistant connection and AI integration whose person does not read one
// of the numbers it holds, or whose own account does not read a number its
// key names, ends, whole and access_lost (store.EndConnectionsWithoutRead).
// serve runs it in a goroutine once the listener is bound; setupWith and
// the command line never do. It never fails the start: a busy workspace,
// a failure or a panic is logged and left for the next start. Each end
// and each busy workspace is a Warn line with ids only, an end naming the
// remedy for its numbers. Each reader is told within its own bound;
// WatchRevocations tells them again in any case.
func (a *app) checkReadAtStart(ctx context.Context, readers wsapi.MCPReaders) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("start: the read check stopped; the next start checks again", "panic", fmt.Sprint(r))
		}
	}()
	res, err := store.EndConnectionsWithoutRead(ctx, a.pools.API)
	a.reportReadCheck(ctx, readers, res, err)
}

// reportReadCheck tells the readers what the check ended and logs it.
func (a *app) reportReadCheck(ctx context.Context, readers wsapi.MCPReaders, res store.ReadCheck, err error) {
	for _, e := range res.Ended {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tellTimeout)
		readers.TellRevoked(tctx, e.Reader, e.ID)
		cancel()
	}
	for _, e := range res.Ended {
		args := []any{"workspace", e.Tenant, "connection", e.ID, "reason", store.ReasonAccessLost}
		if len(e.Keyless) > 0 {
			args = append(args, "keyless", e.Keyless, "keyless_remedy", remedyKeyless)
		}
		if len(e.Orphan) > 0 {
			args = append(args, "orphan", e.Orphan, "orphan_remedy", remedyOrphan)
		}
		if len(e.Narrowed) > 0 {
			args = append(args, "narrowed", e.Narrowed, "narrowed_remedy", remedyNarrowed)
		}
		a.log.Warn("start: an assistant connection ended: a number it holds is not read", args...)
	}
	for _, tenant := range res.Busy {
		a.log.Warn("start: the read check skipped a busy workspace; the next start checks it", "workspace", tenant)
	}
	if err != nil {
		a.log.Error("start: the read check failed; the next start checks again", "error", err)
	}
}
