package ingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// ErrNoReceiptStore reports a router asked to archive receipts without one.
var ErrNoReceiptStore = errors.New("ingest: no receipt store configured")

// ingestReceipt records one acknowledgement event.
//
// There is no pipeline type for this and no sealer, because a receipt has
// nothing to seal: a party, a message id and a time, all of which are the same
// routing metadata that leaves chat_key readable. Routing it through the
// message pipeline to look symmetric would mean a sealer on a path with no
// content, which is a misleading kind of tidiness.
func (r *Router) ingestReceipt(ctx context.Context, tenant uuid.UUID, rec domain.Receipt) error {
	if r.cfg.Receipts == nil {
		return ErrNoReceiptStore
	}
	deviceID, err := uuid.Parse(rec.DeviceID)
	if err != nil {
		return fmt.Errorf("ingest: device id %q: %w", rec.DeviceID, err)
	}

	res, err := r.cfg.Receipts.Insert(ctx, store.InsertReceipt{
		TenantID:  tenant,
		DeviceID:  deviceID,
		ChatKey:   rec.Chat.Primary().String(),
		ReaderKey: rec.Reader.Primary().String(),
		ReaderLID: jidString(rec.Reader.LID),
		ReaderPN:  jidString(rec.Reader.PN),
		IsFromMe:  rec.IsFromMe,
		WAIDs:     rec.MessageIDs,
		Kind:      rec.Kind,
		TS:        rec.TS,
	})
	if err != nil {
		return err
	}
	if res.Duplicate {
		// Routine. WhatsApp resends receipts on every resync, and republishing
		// them would make a client redraw ticks that never changed.
		return nil
	}

	// One of our own devices read something. The badge follows, because the
	// person has read it — just not here.
	r.clearOnOwnRead(ctx, tenant, rec.DeviceID, rec)

	if r.cfg.Bus != nil {
		r.cfg.Bus.Publish(tenant, Event{
			Class: ClassReceipt,
			Seq:   res.Seq, TenantID: tenant, DeviceID: deviceID,
			ChatKey: rec.Chat.Primary().String(),
		})
	}
	return nil
}
