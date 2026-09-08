package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/wsapi"
)

// cmdWatch streams the archive and opens it locally.
//
// This is the end-to-end proof of the design, not a convenience: the server
// hands over ciphertext and sealed keys, and the plaintext appears only here,
// after the private key does work the server cannot do. Run it without -key and
// you see exactly what an attacker with full database access sees.
func cmdWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	keyArg := fs.String("key", "", "archive private key, as printed by `whatserverd archive-key`")
	since := fs.Int64("since", 0, "resume from this sequence; 0 replays everything")
	live := fs.Bool("live", false, "skip the replay and show only new messages")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var priv seal.PrivateKey
	if *keyArg != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*keyArg))
		if err != nil {
			return fmt.Errorf("-key is not a valid archive key: %w", err)
		}
		priv, err = seal.ParsePrivateKey(raw)
		if err != nil {
			return err
		}
	} else {
		fmt.Println("No -key given: message bodies will show as sealed.")
		fmt.Println("That is what the server itself sees.")
		fmt.Println()
	}

	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	tenant, err := uuid.Parse(c.tenant)
	if err != nil {
		return fmt.Errorf("server reported an unusable tenant: %w", err)
	}
	opener := newOpener(c, tenant, priv)

	if err := c.send(ctx, wsapi.TypeSubscribe, "sub", wsapi.Subscribe{
		SinceSeq: *since, LiveOnly: *live,
	}); err != nil {
		return err
	}

	for f := range c.Stream() {
		switch f.Type {
		case wsapi.TypeReplayBegin:
			var p wsapi.ReplayBegin
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			fmt.Printf("replaying up to sequence %d\n", p.ThroughSeq)

		case wsapi.TypeReplayEnd:
			var p wsapi.ReplayEnd
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			fmt.Printf("replay done: %d messages, now at sequence %d. Waiting for live traffic...\n\n",
				p.Count, p.LastSeq)

		case wsapi.TypeMessage:
			var m wsapi.SealedMessage
			if err := json.Unmarshal(f.Payload, &m); err != nil {
				return err
			}
			printMessage(ctx, m, opener)

		case wsapi.TypeReceipt:
			var r wsapi.ReceiptEvent
			if err := json.Unmarshal(f.Payload, &r); err != nil {
				return err
			}
			printReceipt(r)

		case wsapi.TypeLag:
			var p wsapi.Lag
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "\n! the stream was interrupted; resume from sequence %d (%d dropped)\n\n",
				p.FromSeq, p.Dropped)

		case wsapi.TypeError:
			return protocolError(f)
		}
	}
	return c.Err()
}

// printReceipt shows an acknowledgement.
//
// Nothing to unseal: a receipt is a party, a message id and a time, all of it
// readable. Worth watching go by, because this is the traffic that tells you
// who read what — and it keeps arriving in passive mode, where this device
// sends no read receipts of its own.
func printReceipt(r wsapi.ReceiptEvent) {
	who := userPart(r.ReaderKey)
	if r.IsFromMe {
		who = "eu (outro aparelho)"
	}
	ids := make([]string, 0, len(r.WAIDs))
	for _, id := range r.WAIDs {
		ids = append(ids, short(id))
	}
	shown := strings.Join(ids, " ")
	if len(ids) > 4 {
		shown = strings.Join(ids[:4], " ") + fmt.Sprintf(" +%d", len(ids)-4)
	}
	fmt.Printf("%6d  %-22s %s  %-14s %s %s\n",
		r.Seq, "", r.TS.Local().Format("02/01 15:04"), truncate(who, 14), r.Kind, shown)
}

func printMessage(ctx context.Context, m wsapi.SealedMessage, o *opener) {
	ts := ""
	if m.TS != nil {
		ts = m.TS.Local().Format("02/01 15:04")
	}
	who := userPart(m.SenderKey)
	if m.IsFromMe {
		who = "eu"
	}

	body := o.open(ctx, m.DeviceID, m.ContentKeyID, m.UID, seal.KindBody, m.BodySealed)
	switch m.Kind {
	case "edit":
		body = "edited " + short(m.TargetWAID) + " -> " + body
	case "delete":
		// Which of the two this is was resolved during ingest, so nothing here
		// has to guess. v1 answered this at render time, in two places that
		// disagreed, and showed "message deleted" where someone had merely
		// taken back a thumbs-up.
		if m.TargetRel == "reaction" {
			body = "withdrew a reaction"
		} else {
			body = "deleted " + short(m.TargetWAID)
		}
	case "reaction":
		if body == "" {
			body = "(reaction removed)"
		}
		body = "reacted " + body + " to " + short(m.TargetWAID)
	}

	var tags []string
	if m.IsForwarded {
		if m.ForwardingScore >= 5 {
			tags = append(tags, "forwarded many times")
		} else {
			tags = append(tags, "forwarded")
		}
	}
	if m.ViewOnce {
		tags = append(tags, "view once")
	}
	if m.ExpiresAt != nil {
		// Kept, and marked. The sender meant it to vanish; the archive says so
		// rather than presenting it as an ordinary message.
		tags = append(tags, "expires "+m.ExpiresAt.Local().Format("02/01 15:04"))
	}
	if m.ReplyTo != "" {
		tags = append(tags, "reply to "+short(m.ReplyTo))
	}
	if pl, ok := o.payload(ctx, m.DeviceID, m.ContentKeyID, m.UID, m.PayloadSealed); ok {
		tags = append(tags, describePayload(pl)...)
	} else if len(m.PayloadSealed) > 0 {
		tags = append(tags, fmt.Sprintf("structured payload, sealed, %d bytes", len(m.PayloadSealed)))
	}
	if m.Media != nil {
		name := o.open(ctx, m.DeviceID, m.ContentKeyID, m.UID, seal.KindContactName, m.Media.FileNameSealed)
		desc := m.Media.MediaType
		if name != "" {
			desc += " " + name
		}
		if m.Media.Seconds > 0 {
			desc += fmt.Sprintf(" %ds", m.Media.Seconds)
		}
		desc += " [" + m.Media.DownloadStatus + "]"
		tags = append(tags, desc)
	}

	suffix := ""
	if len(tags) > 0 {
		suffix = "  (" + strings.Join(tags, ", ") + ")"
	}
	// The WhatsApp id in full, not shortened. It is what edit, revoke, react
	// and history all take, and an identifier you cannot type back is a trap —
	// the same one the truncated device ids were.
	fmt.Printf("%6d  %-22s %s  %-14s %s%s\n",
		m.Seq, m.WAID, ts, truncate(who, 14), body, suffix)
}

// describePayload renders the structured content of a message for a terminal.
//
// Location, poll, contact cards, event and link preview all arrive as
// structure, not as a line of text, and this is where that structure stops
// being an opaque blob. Everything below was sealed on the way in and has just
// been opened locally.
func describePayload(pl domain.Payload) []string {
	var out []string
	if loc := pl.Location; loc != nil {
		desc := fmt.Sprintf("location %.5f,%.5f", loc.Latitude, loc.Longitude)
		if loc.Name != "" {
			desc += " " + loc.Name
		} else if loc.Address != "" {
			desc += " " + loc.Address
		}
		if loc.SequenceNumber > 0 {
			desc += " (live)"
		}
		out = append(out, desc)
	}
	if p := pl.Poll; p != nil {
		out = append(out, fmt.Sprintf("poll %q: %s", p.Question, strings.Join(p.Options, " | ")))
	}
	for _, c := range pl.Contacts {
		out = append(out, "contact "+c.DisplayName)
	}
	if ev := pl.Event; ev != nil {
		desc := "event " + ev.Name
		if !ev.StartTime.IsZero() {
			desc += " at " + ev.StartTime.Local().Format("02/01 15:04")
		}
		if ev.Location != nil && ev.Location.Name != "" {
			desc += " in " + ev.Location.Name
		}
		if ev.IsCanceled {
			desc += " (CANCELLED)"
		}
		out = append(out, desc)
	}
	if lp := pl.LinkPreview; lp != nil {
		desc := "link " + lp.URL
		if lp.Title != "" {
			desc += " — " + lp.Title
		}
		out = append(out, desc)
	}
	if n := len(pl.Mentions); n > 0 {
		names := make([]string, 0, n)
		for _, m := range pl.Mentions {
			names = append(names, userPart(m))
		}
		out = append(out, "mentions "+strings.Join(names, ", "))
	}
	return out
}

// opener unwraps sealed values, fetching content keys as it meets them.
// keySlot names one content key. Ids are counted per device, so id 7 is a
// different key on every account and the device has to be part of the cache key
// as well as of the request.
type keySlot struct {
	device uuid.UUID
	id     uint32
}

type opener struct {
	c      *client
	tenant uuid.UUID
	priv   seal.PrivateKey
	cache  map[keySlot]*seal.ContentKey
}

func newOpener(c *client, tenant uuid.UUID, priv seal.PrivateKey) *opener {
	return &opener{c: c, tenant: tenant, priv: priv, cache: map[keySlot]*seal.ContentKey{}}
}

// deviceOf reads the device a row belongs to. Every archived row carries it,
// which is what lets one opener serve several accounts at once.
func deviceOf(deviceID string) (uuid.UUID, error) {
	return uuid.Parse(deviceID)
}

func (o *opener) open(ctx context.Context, deviceID string, keyID uint32, uidStr string,
	kind seal.Kind, sealed []byte) string {
	if len(sealed) == 0 {
		return ""
	}
	if !o.priv.Valid() {
		return fmt.Sprintf("<sealed, %d bytes>", len(sealed))
	}
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return "<bad uid>"
	}
	device, err := deviceOf(deviceID)
	if err != nil {
		return "<bad device>"
	}
	ck, err := o.key(ctx, device, keyID)
	if err != nil {
		return "<key unavailable>"
	}
	pt, err := ck.Open(kind, o.tenant, uid, sealed)
	if err != nil {
		// Not a generic failure: authentication failing here means the stored
		// bytes were altered or moved, which is exactly what the binding
		// exists to catch.
		return "<TAMPERED OR WRONG KEY>"
	}
	return string(pt)
}

// payload opens the structured content. The bool is false when there is
// nothing to open, or nothing to open it with.
func (o *opener) payload(ctx context.Context, deviceID string, keyID uint32, uidStr string,
	sealed []byte) (domain.Payload, bool) {
	if len(sealed) == 0 || !o.priv.Valid() {
		return domain.Payload{}, false
	}
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return domain.Payload{}, false
	}
	device, err := deviceOf(deviceID)
	if err != nil {
		return domain.Payload{}, false
	}
	ck, err := o.key(ctx, device, keyID)
	if err != nil {
		return domain.Payload{}, false
	}
	pt, err := ck.Open(seal.KindPayload, o.tenant, uid, sealed)
	if err != nil {
		return domain.Payload{}, false
	}
	pl, err := domain.ParsePayload(pt)
	if err != nil {
		return domain.Payload{}, false
	}
	return pl, true
}

// key fetches and caches a content key.
//
// One asymmetric unwrap per key rather than per message: that batching is the
// difference between a conversation opening instantly and a phone stalling for
// half a minute.
func (o *opener) key(ctx context.Context, device uuid.UUID, id uint32) (*seal.ContentKey, error) {
	slot := keySlot{device: device, id: id}
	if ck, ok := o.cache[slot]; ok {
		return ck, nil
	}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// A correlated request rather than a raw read: reading the socket directly
	// here would steal frames from the stream, which is precisely the bug that
	// made this command stop after one message.
	f, err := o.c.request(deadline, fmt.Sprintf("keys-%s-%d", device, id), wsapi.TypeKeysGet,
		wsapi.KeysRequest{DeviceID: device.String(), IDs: []uint32{id}}, wsapi.TypeKeys)
	if err != nil {
		return nil, err
	}
	var reply wsapi.Keys
	if err := json.Unmarshal(f.Payload, &reply); err != nil {
		return nil, err
	}
	for _, k := range reply.Keys {
		ck, err := seal.OpenContentKey(o.priv, o.tenant, device, k.ID, k.Sealed)
		if err != nil {
			return nil, err
		}
		o.cache[keySlot{device: device, id: k.ID}] = ck
	}
	if ck, ok := o.cache[slot]; ok {
		return ck, nil
	}
	return nil, errors.New("the server did not return that content key")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
