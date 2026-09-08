package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// resumeDevices re-attaches to every device that was connected before this
// process started.
//
// Without this a restart silently orphans every paired phone: the Signal
// session is still in the database and the device row still says "online", but
// nothing is holding the connection, so messages stop arriving and nothing
// reports that they have. A rolling deploy would take the whole fleet down
// while every dashboard stayed green.
//
// Failures are logged and skipped rather than fatal. One device whose session
// was deleted from the phone must not stop the other forty from coming back.
func (a *app) resumeDevices(ctx context.Context) error {
	rows, err := a.pools.API.Query(ctx, `SELECT id::text FROM tenants WHERE status = 'active'`)
	if err != nil {
		return fmt.Errorf("resume: list tenants: %w", err)
	}
	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("resume: list tenants: %w", err)
	}

	var resumed, skipped int
	for _, tenant := range tenants {
		// Per tenant, because devices is under row-level security and a
		// cross-tenant scan would return nothing.
		devices, err := a.devices.List(ctx, tenant)
		if err != nil {
			a.log.Error("resume: listing devices failed", "tenant", tenant, "error", err)
			continue
		}
		for _, d := range devices {
			if !shouldResume(d) {
				continue
			}
			mode, err := wa.ParseReceiptMode(string(d.ReceiptMode))
			if err != nil {
				a.log.Error("resume: bad receipt mode in the database",
					"device", d.ID, "value", d.ReceiptMode, "error", err)
				continue
			}
			policy := wa.ReceiptPolicy{Mode: mode, Recorder: a.recordReceipt}

			// Phone number first: whatsmeow keys most sessions by it. LID is
			// the fallback for accounts where a phone number was never known.
			_, err = a.registry.StartExisting(ctx, tenant, d.ID, policy, d.Identity.PN, d.Identity.LID)
			switch {
			case err == nil:
				resumed++
				a.log.Info("resumed device", "device", d.ID, "identity", d.Identity.String())
			case errors.Is(err, wa.ErrNoSession):
				// The session is gone for good. Say so in the row rather than
				// leaving it claiming to be online forever.
				skipped++
				a.log.Warn("device session is gone; it must be paired again",
					"device", d.ID, "identity", d.Identity.String())
				if err := a.devices.SetStatus(ctx, tenant, d.ID, wa.StatusLoggedOut,
					"session missing at startup"); err != nil {
					a.log.Error("resume: could not record the lost session", "device", d.ID, "error", err)
				}
			case errors.Is(err, wa.ErrAlreadyRunning):
				// Another instance holds the advisory lock. Correct and
				// expected during a rolling deploy.
				skipped++
				a.log.Info("device is supervised by another instance", "device", d.ID)
			default:
				skipped++
				a.log.Error("resume: could not start device", "device", d.ID, "error", err)
			}
		}
	}
	if resumed > 0 || skipped > 0 {
		a.log.Info("device resume complete", "resumed", resumed, "skipped", skipped)
	}
	return nil
}

// shouldResume reports whether a device is worth reconnecting.
//
// Terminal states are excluded: retrying a logged-out or banned device burns
// connection attempts against a server that has already refused. A device that
// was never paired has no session to resume.
func shouldResume(d store.Device) bool {
	if !d.Identity.Known() {
		return false
	}
	switch d.Status {
	case wa.StatusOnline, wa.StatusOffline, wa.StatusPairing:
		return true
	default:
		return false
	}
}

// linkPhoneNumbers joins the two ways WhatsApp names a person.
//
// Group participants are addressed by LID, the contact list a phone syncs is
// keyed by phone number, and until now nothing joined them: 860 of 883 group
// senders on this installation had no name, not because the names were missing
// but because they were filed under an identifier nobody looked up.
//
// whatsmeow has been recording the pairs all along. This reads its table.
//
// At boot rather than in a migration, for the same reason backfillChatIdentities
// is: a migration runs with no app.tenant_id, so an UPDATE against these
// policy-protected tables would silently match nothing, and working around that
// means disabling row-level security for a job the app pool already scopes
// correctly. Idempotent, so every boot is free after the first.
func (a *app) linkPhoneNumbers(ctx context.Context) error {
	tenants, err := a.listTenantIDs(ctx)
	if err != nil {
		return err
	}
	var total store.LinkCounts
	for _, tenant := range tenants {
		n, err := store.LinkPhoneNumbers(ctx, a.pools.API, tenant)
		if err != nil {
			a.log.Error("could not link phone numbers", "tenant", tenant, "error", err)
			continue
		}
		total.Messages += n.Messages
		total.Chats += n.Chats
		total.Contacts += n.Contacts
	}
	if total.Messages+total.Chats+total.Contacts > 0 {
		a.log.Info("linked LIDs to phone numbers",
			"messages", total.Messages, "chats", total.Chats, "contacts", total.Contacts)
	}
	return nil
}

// recordReceipt funnels receipt decisions into the metrics counter.
func (a *app) recordReceipt(kind, decision string) {
	if a.metrics != nil {
		a.metrics.ReceiptDecisions.WithLabelValues(kind, decision).Inc()
	}
}

// activeTenants lists the tenants a background job should work through.
//
// The media worker needs it because row level security scopes every query to
// one tenant, so there is no cross-tenant scan even for an internal job. That
// is the isolation behaving correctly rather than an inconvenience to work
// around: a background worker that could read across tenants would be a hole
// in the same policy the API relies on.
func (a *app) activeTenants(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := a.pools.API.Query(ctx, `SELECT id FROM tenants WHERE status = 'active'`)
	if err != nil {
		return nil, fmt.Errorf("list active tenants: %w", err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// backfillChatIdentities gives an identity to chats stored before there was
// one.
//
// A no-op after the first run. It exists because the derivation lives in Go and
// duplicating it in a migration would create two implementations that could
// disagree — silently, and only visibly later as chat names that will not open.
func (a *app) backfillChatIdentities(ctx context.Context) error {
	tenants, err := a.activeTenants(ctx)
	if err != nil {
		return err
	}
	total := 0
	for _, tenant := range tenants {
		n, err := a.messages.BackfillChatUIDs(ctx, tenant)
		if err != nil {
			return err
		}
		total += n
	}
	if total > 0 {
		a.log.Info("gave chat identities to rows that predate them", "chats", total)
	}
	return nil
}

// importContacts copies whatsmeow's cached contact names into the archive.
//
// At every boot, because it is idempotent and because the alternative is
// waiting for five thousand people to each send a message before the archive
// learns who they are. The names came in one history sync payload and went into
// whatsmeow's store; this is what moves them somewhere sealed.
func (a *app) importContacts(ctx context.Context) {
	for _, dev := range a.registry.All() {
		contacts, err := dev.Contacts(ctx)
		if err != nil {
			a.log.Warn("could not read cached contacts", "device", dev.ID(), "error", err)
			continue
		}
		n, err := a.router.ImportContacts(ctx, dev.ID(), contacts)
		if err != nil {
			a.log.Warn("could not import contacts", "device", dev.ID(), "error", err)
			continue
		}
		if n > 0 {
			a.log.Info("imported contact names", "device", dev.ID(), "contacts", n)
		}
	}
}

// syncGroups records every group each device belongs to.
//
// At every boot, because it is idempotent and because two things depend on it
// that nothing else can supply. A group with no message has no conversation row
// — the message path is what writes one — so it is missing from the sidebar
// entirely rather than merely unnamed. And a name arrives only with a history
// sync or with the event that fires when we join, so a group that predates the
// pairing and has been quiet since is reached by neither.
func (a *app) syncGroups(ctx context.Context) {
	for _, dev := range a.registry.All() {
		if !dev.Client().IsLoggedIn() {
			continue
		}
		groups, err := dev.Client().GetJoinedGroups(ctx)
		if err != nil {
			a.log.Warn("could not list groups", "device", dev.ID(), "error", err)
			continue
		}
		tenant, err := uuid.Parse(dev.TenantID())
		if err != nil {
			continue
		}
		device, err := uuid.Parse(dev.ID())
		if err != nil {
			continue
		}
		if n := a.router.SyncGroups(ctx, tenant, device, groups); n > 0 {
			a.log.Info("recorded groups", "device", dev.ID(), "groups", n)
		}
	}
}

// seedGroupIdentities gives every group chat a row in contacts.
//
// A group has a profile picture like anyone else, and the picture belongs with
// the identity rather than with the conversation. Groups stored before that row
// existed would otherwise never be asked about.
func (a *app) seedGroupIdentities(ctx context.Context) {
	tenants, err := a.activeTenants(ctx)
	if err != nil {
		a.log.Warn("could not list tenants", "error", err)
		return
	}
	total := 0
	for _, tenant := range tenants {
		devices, err := a.devices.List(ctx, tenant.String())
		if err != nil {
			continue
		}
		for _, dev := range devices {
			device, err := uuid.Parse(dev.ID)
			if err != nil {
				continue
			}
			chats, err := a.messages.Chats(ctx, tenant, device, 5000)
			if err != nil {
				continue
			}
			total += a.router.SeedGroupIdentities(ctx, tenant, device, chats)
		}
	}
	if total > 0 {
		a.log.Info("group identities seeded for profile pictures", "groups", total)
	}
}
