package wa

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// Relink makes a pairing land in a number Wappie already holds (decision
// 0057): the same row, key, epoch, grants and readers. It is kept only when
// the account that scans is the number's own; another account is refused
// before whatsmeow stores anything of it.
type Relink struct {
	// Expect is the number's account. The user parts of its phone number
	// and of its LID are compared; device numbers never are, since a new
	// link has a new one.
	Expect Identity
	// Recheck runs in the session store's first write of the new link,
	// before anything is written: the number must still be one to link
	// again. Its error refuses the link.
	Recheck func(ctx context.Context) error
	// Attach writes the new link into the number once WhatsApp confirmed
	// it. An error logs the new link out again.
	Attach func(ctx context.Context, linked Identity) error
	// Discarded runs after a refused attach logged the new link out.
	Discarded func(ctx context.Context, jid types.JID)
}

var (
	// ErrOtherAccount is a scan by another WhatsApp account, or by the
	// number's own account under another phone number. Nothing was stored.
	ErrOtherAccount = errors.New("wa: the QR code was scanned by another WhatsApp account")
	// ErrLinkTimeout is WhatsApp's window closing with no scan.
	ErrLinkTimeout = errors.New("wa: the QR code was not scanned in time")
	// ErrLinkFailed is a link that did not start or did not finish.
	ErrLinkFailed = errors.New("wa: the link did not start or did not finish")
)

// OtherAccount is ErrOtherAccount with the half that differed ("phone" or
// "lid"), for the log. Its text is ErrOtherAccount's: whatsmeow logs it.
type OtherAccount struct{ Half string }

func (e *OtherAccount) Error() string { return ErrOtherAccount.Error() }
func (e *OtherAccount) Unwrap() error { return ErrOtherAccount }

// relinkRecheckTimeout bounds Recheck, which runs on whatsmeow's pairing
// goroutine while WhatsApp waits for the answer.
const relinkRecheckTimeout = 3 * time.Second

// sameUser reports whether two JIDs name one account: the same user on the
// same server, whatever their device numbers.
func sameUser(a, b types.JID) bool {
	return a.User != "" && a.User == b.User && a.Server == b.Server
}

// verdict is a relink's answer on the account that scanned. The first
// refusal wins and stays.
type verdict struct {
	mu       sync.Mutex
	err      error
	accepted bool
}

func (v *verdict) refuse(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err == nil {
		v.err = err
	}
}

func (v *verdict) refused() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.err != nil
}

func (v *verdict) accept() {
	v.mu.Lock()
	v.accepted = true
	v.mu.Unlock()
}

func (v *verdict) get() (refused error, accepted bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.err, v.accepted
}

// relinkContainer stands in for the session store on a relink's pairing
// device. whatsmeow's first write of a new link is Store.Save, after it set
// the link's phone JID and LID in memory (pair.go, handlePair). Refusing it
// there stores nothing: whatsmeow answers WhatsApp with a pair error and
// returns before the LID map, the identity key and pair-device-sign. On
// success the inner sqlstore's PutDevice puts itself back as the device's
// container, so later saves skip this one.
type relinkContainer struct {
	inner   store.DeviceContainer
	expect  Identity
	recheck func(context.Context) error
	verdict verdict
}

func newRelinkContainer(inner store.DeviceContainer, rl *Relink) *relinkContainer {
	return &relinkContainer{inner: inner, expect: rl.Expect, recheck: rl.Recheck}
}

// armRelink puts a relink's account check on a pairing's device and its
// client, before GetQRChannel: the check in the session store's first write,
// so another account is refused before anything of it is stored, and
// whatsmeow's PrePairCallback on the phone's user part. The client also
// stops reconnecting by itself after the pairing's 515, so nothing of the
// new link flows before the attach (finishRelink).
func armRelink(ds *store.Device, client Client, rl *Relink) *relinkContainer {
	guard := newRelinkContainer(ds.Container, rl)
	ds.Container = guard
	if real, ok := client.(*whatsmeow.Client); ok {
		real.PrePairCallback = guard.prePair
		real.DisableLoginAutoReconnect = true
	}
	return guard
}

// PutDevice checks the account before the first write of the new link.
func (c *relinkContainer) PutDevice(ctx context.Context, d *store.Device) error {
	if d.ID == nil {
		// whatsmeow's own ErrDeviceIDMustBeSet.
		return c.inner.PutDevice(ctx, d)
	}
	refused, accepted := c.verdict.get()
	switch {
	case refused != nil:
		return refused
	case accepted:
		return c.inner.PutDevice(ctx, d)
	}
	if err := c.check(ctx, *d.ID, d.LID); err != nil {
		c.verdict.refuse(err)
		refused, _ := c.verdict.get()
		return refused
	}
	c.verdict.accept()
	return c.inner.PutDevice(ctx, d)
}

func (c *relinkContainer) check(ctx context.Context, pn, lid types.JID) error {
	if pn.Server != types.DefaultUserServer || !sameUser(pn, c.expect.PN) {
		return &OtherAccount{Half: "phone"}
	}
	if lid.Server != types.HiddenUserServer || lid.User == "" {
		// An empty LID cannot be compared: not another account, but no
		// link either.
		return fmt.Errorf("%w: no LID in WhatsApp's answer", ErrLinkFailed)
	}
	if !sameUser(lid, c.expect.LID) {
		return &OtherAccount{Half: "lid"}
	}
	if c.recheck == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, relinkRecheckTimeout)
	defer cancel()
	return c.recheck(rctx)
}

// DeleteDevice does nothing after a refusal: nothing was written, and a
// stray delete must never reach another session.
func (c *relinkContainer) DeleteDevice(ctx context.Context, d *store.Device) error {
	if c.verdict.refused() {
		return nil
	}
	return c.inner.DeleteDevice(ctx, d)
}

// prePair is the relink's whatsmeow PrePairCallback: the phone's user part,
// before whatsmeow sets anything. It reads no database.
func (c *relinkContainer) prePair(jid types.JID, _, _ string) bool {
	if !sameUser(jid, c.expect.PN) {
		c.verdict.refuse(&OtherAccount{Half: "phone"})
		return false
	}
	return true
}

// relinkEnd names a relink's end other than linked: the verdict when there
// is one; ErrLinkTimeout when WhatsApp's window closed; else ErrLinkFailed,
// with cause for the log only.
func relinkEnd(v *verdict, timedOut bool, cause error) error {
	if refused, _ := v.get(); refused != nil {
		return refused
	}
	if timedOut {
		return ErrLinkTimeout
	}
	if cause == nil {
		return ErrLinkFailed
	}
	return fmt.Errorf("%w (%w)", ErrLinkFailed, cause)
}
