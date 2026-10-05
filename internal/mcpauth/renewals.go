package mcpauth

import (
	"context"
	"time"

	"whatserver2/internal/mailer"
)

// The renewal round (docs/mcp-enclave.md §19.30). When the attested reader
// holds no key for content connections (it restarted, or their workspace
// turned text off and on again), it reseals them one after the other; each
// person who consented to one gets a single e-mail saying how many wait, in
// their language, once the round has settled, and the console shows a
// banner that opens "Renew all". The e-mail carries no link (renewing asks
// for a passkey or the password, and a spoofed copy would link to a page
// like that); it says where to go instead, and which of the connections
// Renew all leaves to their own Renew. No mail server, no e-mail: the banner
// alone.

// renewalDelay is how long after a reseal the notices are sent: past the
// store's settling time, so one e-mail covers a whole restart.
const renewalDelay = 150 * time.Second

// scheduleRenewalNotices sends the due renewal notices renewalDelay from the
// first reseal of a round; the reseals that follow within it ride on the
// same send. The maintenance loop sends what a restart of this server left.
func (h *Handler) scheduleRenewalNotices(ctx context.Context) {
	if h.MailRenewal == nil {
		return
	}
	h.renewalMu.Lock()
	defer h.renewalMu.Unlock()
	if h.renewalTimer != nil {
		return
	}
	delay := renewalDelay
	if h.renewalAfter > 0 {
		delay = h.renewalAfter
	}
	h.renewalTimer = time.AfterFunc(delay, func() {
		h.renewalMu.Lock()
		h.renewalTimer = nil
		h.renewalMu.Unlock()
		// The reseal that started the round has long been answered.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), noticeMailTimeout)
		defer cancel()
		h.SendRenewalNotices(ctx)
	})
}

// SendRenewalNotices sends every renewal notice that is due: one per person
// and workspace, claimed before it goes so two processes never both send it.
// A failure is logged; the banner still says it.
func (h *Handler) SendRenewalNotices(ctx context.Context) {
	if h.MailRenewal == nil {
		return
	}
	due, err := h.Connections.DueRenewalNotices(ctx)
	if err != nil {
		h.log().Warn("could not list the renewal notices due", "error", err)
		return
	}
	for _, n := range due {
		claimed, err := h.Connections.ClaimRenewalNotice(ctx, n.TenantID, n.UserID, n.ConnectionIDs)
		if err != nil {
			h.log().Warn("could not claim a renewal notice", "tenant", n.TenantID, "error", err)
			continue
		}
		if !claimed {
			continue
		}
		if err := h.MailRenewal(ctx, n.Email, mailer.MCPRenewal{Workspace: n.Workspace, Assistants: n.Assistants, OneByOne: n.OneByOne,
			Since: n.Since, Lang: n.Locale}); err != nil {
			// The address is the recipient's; the error is the mail
			// server's.
			h.log().Warn("a renewal notice was not delivered", "tenant", n.TenantID, "connections", len(n.ConnectionIDs), "error", err)
			continue
		}
		h.log().Info("renewal notice sent", "tenant", n.TenantID, "connections", len(n.ConnectionIDs), "lang", n.Locale)
	}
}

// WatchRenewalNotices sends the due renewal notices once at start and then
// every hour: the ones a restart of this server left before its timer fired.
func (h *Handler) WatchRenewalNotices(ctx context.Context) {
	if h.MailRenewal == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			h.SendRenewalNotices(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
