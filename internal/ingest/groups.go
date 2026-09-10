package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// handleJoinedGroup gives a group we have just joined a conversation.
//
// Reported from the field: an invitation was accepted, WhatsApp created the
// group on the phone, and nothing appeared in the sidebar. The reason is that a
// chats row is written by the message path, so a conversation exists here only
// once somebody speaks in it. A group joined in silence is a group that is not
// there — for hours, sometimes for good.
//
// It covers being ADDED as well as joining, which is the far commoner case and
// had the same symptom. And it is where a group's name comes from now: the
// event embeds the full GroupInfo, so the name arrives with no extra round
// trip. Until this existed, names came only from a history sync, which is why a
// group created after the last sync showed as a numeric id forever.
func (r *Router) handleJoinedGroup(ctx context.Context, deviceID string, evt *events.JoinedGroup) {
	if r.cfg.Messages == nil || evt == nil || evt.JID.IsEmpty() {
		return
	}
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		return
	}
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return
	}
	r.recordGroup(ctx, info.TenantID, device, evt.JID,
		evt.GroupName, &evt.GroupEphemeral, evt.GroupCreated,
		audienceOf(&evt.GroupInfo))
}

// recordGroup writes what is known about a group onto its conversation.
//
// The name is sealed like any other, because it is one: for a group it is what
// the members called themselves, and a database dump that listed them would
// hand over most of what a social graph is.
func (r *Router) recordGroup(ctx context.Context, tenant, device uuid.UUID,
	chat types.JID, name types.GroupName, ephemeral *types.GroupEphemeral,
	created time.Time, participants int) {
	addr := domain.AddressOf(chat)
	meta := store.ChatMeta{
		TenantID: tenant, DeviceID: device,
		ChatKey: chat.String(),
		ChatLID: jidString(addr.LID),
		ChatPN:  jidString(addr.PN),
		IsGroup: true,
	}
	if name.Name != "" {
		sealed, keyID, err := r.SealFor(ctx, tenant, device,
			store.ChatUID(device, chat.String()), seal.KindContactName, []byte(name.Name))
		if err != nil {
			// The conversation matters more than its label. Refusing to record
			// the group because its name could not be sealed would leave the
			// sidebar exactly as empty as before.
			r.log.Error("could not seal a group name", "chat", chat, "error", err)
		} else {
			meta.NameSealed, meta.NameKeyID = sealed, keyID
		}
	}
	if participants > 0 {
		//nolint:gosec // G115: a count of people in a group
		n := int32(min(participants, 1<<31-1))
		meta.ParticipantCount = &n
	}
	if !created.IsZero() {
		at := created
		meta.GroupCreatedAt = &at
	}
	// A pointer, so that "the group says the timer is off" and "this caller
	// knows nothing about the timer" stay different facts. UpsertChatMeta
	// coalesces a nil into the stored value, which is right for the second and
	// was silently wrong for the first: turning a group's timer off wrote an
	// entry in its change log and left the conversation drawn as temporary
	// forever, because nothing else can lower it — the per-message ratchet
	// only ever raises.
	if ephemeral != nil {
		var seconds int32
		if ephemeral.IsEphemeral {
			//nolint:gosec // G115: a timer in seconds
			seconds = int32(min(ephemeral.DisappearingTimer, 1<<31-1))
		}
		meta.EphemeralExpiration = &seconds
	}
	if err := r.cfg.Messages.UpsertChatMeta(ctx, meta); err != nil {
		r.log.Error("could not record a group", "chat", chat, "error", err)
		return
	}
	if meta.EphemeralExpiration != nil {
		r.announceTimer(tenant, device, chat.String(), *meta.EphemeralExpiration)
	}
	// And an identity row, so the group's picture has somewhere to hang.
	r.EnsureIdentity(ctx, tenant, device, chat)
}

// SyncGroups records every group this device is in.
//
// Two symptoms, one cause, and both were reported from the field: groups whose
// name never appeared, and groups joined without a message that were not in the
// sidebar at all.
//
// A conversation row is written by the message path, so a group nobody has
// spoken in does not exist here — not nameless, absent. And a name reaches the
// archive from exactly two places, a history sync and the event that fires when
// we join, so a group that was already there when the device was paired and has
// been quiet since is reached by neither.
//
// Idempotent, so it runs at every boot: names are upserted and nothing
// overwrites a known value with an empty one. Counts successfully stored snapshots.
func (r *Router) SyncGroups(ctx context.Context, tenant, device uuid.UUID,
	groups []*types.GroupInfo) int {
	var n int
	for _, g := range groups {
		if ctx.Err() != nil {
			return n
		}
		if g == nil || g.JID.IsEmpty() {
			continue
		}
		r.recordGroup(ctx, tenant, device, g.JID, g.GroupName, &g.GroupEphemeral,
			g.GroupCreated, audienceOf(g))
		if err := r.SnapshotGroup(ctx, tenant, device, g); err != nil {
			r.log.Debug("could not snapshot a group", "chat", g.JID, "error", err)
			continue
		}
		n++
	}
	return n
}

// audienceOf is how many people are in a group.
//
// ParticipantCount when WhatsApp filled it in, and the length of the list
// otherwise — the two disagree often enough that trusting either alone leaves
// groups without a denominator, and a group without one can never show more
// than a single grey tick.
func audienceOf(g *types.GroupInfo) int {
	if g == nil {
		return 0
	}
	if g.ParticipantCount > 0 {
		return g.ParticipantCount
	}
	return len(g.Participants)
}

// handleGroupInfo records a change somebody made to a group.
//
// This is where "who removed Fulano" comes from, and it is the only place it
// can come from: WhatsApp delivers a group's current composition and its live
// changes, never its past. So the record starts when this archive does, and the
// panel says so rather than presenting an empty history as a peaceful one.
//
// Every branch carries the actor and the time from the event. A change with no
// author is recorded with none rather than attributed to a guess — WhatsApp
// often omits it for an invite link, and inventing one would be the archive
// making something up about a person.
func (r *Router) handleGroupInfo(ctx context.Context, deviceID string, evt *events.GroupInfo) {
	if r.cfg.Groups == nil || evt == nil || evt.JID.IsEmpty() {
		return
	}
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		return
	}
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return
	}
	chat := evt.JID.ToNonAD().String()

	actor := domain.Address{}
	if evt.Sender != nil {
		actor = domain.AddressOf(*evt.Sender)
	}
	if evt.SenderPN != nil {
		actor = actor.Merge(domain.AddressOf(*evt.SenderPN))
	}
	at := evt.Timestamp
	if at.IsZero() {
		at = time.Now()
	}

	write := func(action string, subject types.JID, detail string) {
		addr := domain.AddressOf(subject)
		c := store.GroupChange{
			TS: at, Action: action, Detail: detail,
			ActorKey: jidString(actor.Primary()),
			ActorLID: jidString(actor.LID), ActorPN: jidString(actor.PN),
		}
		if !subject.IsEmpty() {
			c.SubjectKey = addr.Primary().ToNonAD().String()
			c.SubjectLID, c.SubjectPN = jidString(addr.LID), jidString(addr.PN)
		}
		if err := r.cfg.Groups.Record(ctx, info.TenantID, device, chat, c); err != nil {
			r.log.Debug("could not record a group change", "chat", chat, "error", err)
		}
	}

	for _, j := range evt.Join {
		write(store.ChangeAdd, j, "")
	}
	for _, j := range evt.Leave {
		write(store.ChangeRemove, j, "")
	}
	for _, j := range evt.Promote {
		write(store.ChangePromote, j, "")
	}
	for _, j := range evt.Demote {
		write(store.ChangeDemote, j, "")
	}
	if evt.Name != nil {
		// The new name itself is content and goes to the sealed chat row; the
		// history records only that it changed, and by whom.
		write(store.ChangeName, types.EmptyJID, "")
		// nil, not a zero value: a rename says nothing about the timer, and a
		// zero here would clear it.
		r.recordGroup(ctx, info.TenantID, device, evt.JID, *evt.Name,
			nil, time.Time{}, 0)
	}
	if evt.Topic != nil {
		write(store.ChangeTopic, types.EmptyJID, "")
	}
	if evt.Ephemeral != nil {
		detail := "desativadas"
		if evt.Ephemeral.IsEphemeral {
			detail = fmt.Sprintf("%d s", evt.Ephemeral.DisappearingTimer)
		}
		write(store.ChangeEphemeral, types.EmptyJID, detail)
		r.recordGroup(ctx, info.TenantID, device, evt.JID, types.GroupName{},
			evt.Ephemeral, time.Time{}, 0)
	}
	if evt.Announce != nil {
		detail := "todos podem enviar"
		if evt.Announce.IsAnnounce {
			detail = "só admins enviam"
		}
		write(store.ChangeAnnounce, types.EmptyJID, detail)
	}
	if evt.Locked != nil {
		detail := "todos editam os dados"
		if evt.Locked.IsLocked {
			detail = "só admins editam os dados"
		}
		write(store.ChangeLocked, types.EmptyJID, detail)
	}
}

// SnapshotGroup records a complete composition. Missing or partial responses
// must not remove members from the previous snapshot or report a refresh.
func (r *Router) SnapshotGroup(ctx context.Context, tenant, device uuid.UUID,
	g *types.GroupInfo) error {
	if r.cfg.Groups == nil {
		return fmt.Errorf("ingest: group membership store is not configured")
	}
	if g == nil || g.JID.User == "" || g.JID.Server != types.GroupServer {
		return fmt.Errorf("ingest: group snapshot has no group identity")
	}
	members := make([]store.Participant, 0, len(g.Participants))
	seen := make(map[string]struct{}, len(g.Participants))
	for _, p := range g.Participants {
		if p.Error != 0 {
			return fmt.Errorf("ingest: group snapshot includes a failed participant")
		}
		addr := domain.AddressOf(p.JID)
		if !p.LID.IsEmpty() {
			addr = addr.Merge(domain.AddressOf(p.LID))
		}
		if !p.PhoneNumber.IsEmpty() {
			addr = addr.Merge(domain.AddressOf(p.PhoneNumber))
		}
		key := addr.Primary()
		if key.User == "" || (key.Server != types.DefaultUserServer && key.Server != types.HiddenUserServer) {
			return fmt.Errorf("ingest: group snapshot includes an unidentified participant")
		}
		if _, duplicate := seen[key.ToNonAD().String()]; duplicate {
			return fmt.Errorf("ingest: group snapshot includes duplicate participants")
		}
		seen[key.ToNonAD().String()] = struct{}{}
		members = append(members, store.Participant{
			Key: key.ToNonAD().String(),
			LID: jidString(addr.LID), PN: jidString(addr.PN),
			IsAdmin: p.IsAdmin || p.IsSuperAdmin, IsSuperAdmin: p.IsSuperAdmin,
		})
	}
	if len(members) == 0 || g.ParticipantCount > len(members) {
		return fmt.Errorf("ingest: group snapshot has an incomplete participant list")
	}
	_, err := r.cfg.Groups.Snapshot(ctx, tenant, device, g.JID.ToNonAD().String(),
		members, time.Now())
	return err
}
