package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/wsapi"
)

// cmdHistory shows the whole life of one message.
//
// The one screen this project exists for. An ordinary WhatsApp client shows the
// current text and, once a message is revoked, nothing at all. Here every
// revision is a row that was never overwritten, the deleted text is still
// there, and the receipts say which revision each reader had in front of them.
//
// Every body on this screen arrives sealed and is opened locally, by the same
// key the server has never held. Run it without -key to see what the server
// sees.
func cmdHistory(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	keyArg := fs.String("key", "", "archive private key, as printed by `whatserverd archive-key`")
	uid := fs.String("uid", "", "message uid, as shown by wsctl watch")
	device := fs.String("device", "", "device id or unique prefix; only needed with -chat")
	chat := fs.String("chat", "", "chat jid, when identifying the message by its WhatsApp id")
	waID := fs.String("id", "", "WhatsApp message id, used with -chat")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *uid == "" && (*chat == "" || *waID == ""):
		return errors.New("give -uid, or -chat with -id and -device")
	case *uid == "" && *device == "":
		return errors.New("-chat and -id need -device: the same WhatsApp id can exist " +
			"under two paired devices")
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

	chatKey := ""
	if *chat != "" {
		// A bare phone number is accepted here for the same reason -to accepts
		// one: typing the server half every time is tedious and easy to get
		// wrong.
		chatKey = normaliseJID(*chat)
	}
	frame, err := c.request(ctx, "hist", wsapi.TypeHistory, wsapi.HistoryRequest{
		DeviceID: *device, UID: *uid, ChatKey: chatKey, WAID: *waID,
	}, wsapi.TypeHistoryFrame)
	if err != nil {
		return err
	}
	var h wsapi.History
	if err := json.Unmarshal(frame.Payload, &h); err != nil {
		return err
	}
	printHistory(ctx, h, opener)
	return nil
}

func printHistory(ctx context.Context, h wsapi.History, o *opener) {
	fmt.Printf("message %s in %s\n", h.WAID, h.ChatKey)

	if len(h.Versions) > 0 {
		root := h.Versions[0].Message
		who := userPart(root.SenderKey)
		if root.IsFromMe {
			who = "eu"
		}
		fmt.Printf("  from %s, %s\n", who, stamp(root.TS))
	}

	fmt.Println()
	if len(h.Versions) == 1 {
		fmt.Println("  never edited:")
	} else {
		fmt.Printf("  %d versions:\n", len(h.Versions))
	}
	for _, v := range h.Versions {
		m := v.Message
		body := o.open(ctx, m.DeviceID, m.ContentKeyID, m.UID, seal.KindBody, m.BodySealed)
		mark := "  "
		if v.Until == nil {
			mark = "->" // the text a normal client would be showing
		}
		if extra := describeVersionPayload(ctx, m, o); extra != "" {
			body += extra
		}
		fmt.Printf("   %s r%-2d %s  %s\n", mark, v.Revision, stamp(v.From), body)
	}

	if h.Deletion != nil {
		by := "the author"
		if !h.Deletion.ByAuthor {
			by = userPart(h.Deletion.Message.SenderKey)
		}
		fmt.Println()
		fmt.Printf("  DELETED %s by %s\n", stamp(h.Deletion.At), by)
		fmt.Println("  The text above is what was removed. A normal client shows nothing here.")
	}

	if len(h.Reactions) > 0 {
		fmt.Println()
		fmt.Println("  reactions:")
		for _, r := range h.Reactions {
			m := r.Message
			emoji := o.open(ctx, m.DeviceID, m.ContentKeyID, m.UID, seal.KindBody, m.BodySealed)
			// An empty body is how WhatsApp removes a reaction. The server
			// cannot see that, because the body is sealed; this can, having
			// just opened it.
			if emoji == "" {
				emoji = "(removed)"
			}
			var notes []string
			if r.Superseded {
				notes = append(notes, "replaced later")
			}
			if r.Revoked {
				notes = append(notes, "revoked "+stamp(r.RevokedAt))
			}
			suffix := ""
			if len(notes) > 0 {
				suffix = "  (" + strings.Join(notes, ", ") + ")"
			}
			who := userPart(m.SenderKey)
			if m.IsFromMe {
				who = "eu"
			}
			fmt.Printf("    %s  %-16s %s%s\n", stamp(m.TS), truncate(who, 16), emoji, suffix)
		}
	}

	if len(h.Readers) > 0 {
		fmt.Println()
		fmt.Println("  readers:")
		for _, r := range h.Readers {
			who := userPart(r.Key)
			if r.IsFromMe {
				who = "eu (outro aparelho)"
			}
			line := fmt.Sprintf("    %-20s", truncate(who, 20))
			line += "  delivered " + stampOr(r.Delivered, "-")
			line += "  read " + stampOr(r.Read, "-")
			if r.Played != nil {
				line += "  played " + stamp(r.Played)
			}
			if r.Read != nil && len(h.Versions) > 1 {
				line += fmt.Sprintf("  saw r%d", r.SawRevision)
				if !r.Confirmed {
					// The distinction the projection exists to preserve: a
					// timestamp comparison is not the reader's device saying
					// the edit arrived.
					line += fmt.Sprintf("  [inferred; only r%d confirmed delivered]",
						r.ConfirmedRevision)
				}
			}
			fmt.Println(line)

			// Then version by version, because the line above cannot answer the
			// question a corrected message raises. Its "delivered" is the
			// earliest across every version — when this reached them at all —
			// and "saw rN" describes only the device that read earliest. A
			// reader whose phone read the original and whose laptop later read
			// the correction is summarised above as having seen the original.
			if len(h.Versions) > 1 {
				for _, rev := range r.Revisions {
					fmt.Printf("      r%-3d delivered %s  read %s%s%s\n",
						rev.Revision,
						stampOr(rev.Delivered, "never"),
						stampOr(rev.Read, "-"),
						playedNote(rev.Played),
						attributionNote(rev),
					)
				}
			}
		}
	}
	fmt.Println()
}

func playedNote(at *time.Time) string {
	if at == nil {
		return ""
	}
	return "  played " + stamp(at)
}

// attributionNote says how much weight to put on a per-version read.
//
// Only ever on the read. A delivery receipt names that version's own stanza, so
// there is nothing to qualify — it is the reader's device stating that exact
// text arrived. A read receipt names a stanza whose meaning nothing here
// settles, so which text was on screen is worked out from what that device had
// been delivered, and this is where that shows.
func attributionNote(rev wsapi.ReaderRevision) string {
	if rev.Read == nil {
		return ""
	}
	if rev.Confirmed {
		return "  [confirmed]"
	}
	return "  [inferred from clocks]"
}

// describeVersionPayload appends the structured content of a version, when it
// has any. An edit is always text, but the message it edits may be a location,
// a poll or an event.
func describeVersionPayload(ctx context.Context, m wsapi.SealedMessage, o *opener) string {
	pl, ok := o.payload(ctx, m.DeviceID, m.ContentKeyID, m.UID, m.PayloadSealed)
	if !ok {
		if len(m.PayloadSealed) > 0 {
			return fmt.Sprintf("  <structured payload, sealed, %d bytes>", len(m.PayloadSealed))
		}
		return ""
	}
	parts := describePayload(pl)
	if len(parts) == 0 {
		return ""
	}
	return "  (" + strings.Join(parts, ", ") + ")"
}

func stamp(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "??/?? --:--"
	}
	return t.Local().Format("02/01 15:04")
}

func stampOr(t *time.Time, fallback string) string {
	if t == nil || t.IsZero() {
		return fmt.Sprintf("%-11s", fallback)
	}
	return t.Local().Format("02/01 15:04")
}
