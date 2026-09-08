package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"

	"whatserver2/internal/wsapi"
)

// cmdSend sends a text message.
//
// The flags map one-to-one onto the ContextInfo the server builds, so what you
// can express here is exactly what WhatsApp can carry: a quote, the forwarded
// badge, a disappearing timer, view-once.
func cmdSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required; see: wsctl devices)")
	to := fs.String("to", "", "recipient JID or phone number in international form (required)")
	body := fs.String("body", "", "message text (required)")
	forwarded := fs.Bool("forwarded", false, "mark as forwarded")
	score := fs.Uint("score", 0, "forwarding score; 5 or more shows \"forwarded many times\"")
	expires := fs.Uint("expires", 0,
		"deprecated: disappearing messages are a chat setting, see wsctl chat-timer")
	viewOnce := fs.Bool("view-once", false, "send as view once (media only; not yet supported)")
	replyTo := fs.String("reply-to", "", "message id being replied to")
	replyBody := fs.String("reply-body", "",
		"preview text for the quote, shown only if the recipient no longer has the "+
			"original; optional")
	replySender := fs.String("reply-sender", "", "JID of the quoted message's author (needed in groups)")
	mentions := fs.String("mention", "",
		"comma-separated JIDs or phone numbers to tag; each must also appear in the text")
	previewURL := fs.String("preview-url", "",
		"url for the link card; must appear verbatim in -body")
	previewTitle := fs.String("preview-title", "", "title on the link card")
	previewDesc := fs.String("preview-desc", "", "description on the link card")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *device == "":
		return errors.New("-device is required; run \"wsctl devices\" to see them")
	case *to == "":
		return errors.New("-to is required")
	case *body == "":
		return errors.New("-body is required")
	case *replyBody != "" && *replyTo == "":
		// A preview with no link quotes nothing: the recipient sees text
		// attributed to a message that is not identified.
		return errors.New("-reply-body needs -reply-to: the id is what links the quote " +
			"to the original, and without it the preview points at nothing")
	case *expires > 0:
		// The flag used to set a field and nothing else, which produced a
		// message every client treated as ordinary. WhatsApp has no
		// per-message expiry at all.
		return fmt.Errorf("-expires does not make one message disappear: WhatsApp has "+
			"no per-message expiry, only a timer on the whole chat.\n"+
			"After you turn it on, every message in that chat disappears and the "+
			"timer is applied for you, so this flag is not needed:\n\n"+
			"    wsctl chat-timer -device %s -to %s -seconds %d",
			*device, *to, *expires)
	case *viewOnce:
		return errors.New("view once is a media feature and does not work on text; " +
			"WhatsApp shows it as \"sent from an older version\". It arrives with media support")
	case *previewURL != "" && !strings.Contains(*body, *previewURL):
		// WhatsApp matches the card to the text by this exact substring, and a
		// mismatch renders as nothing at all rather than as an error.
		return errors.New("-preview-url must appear verbatim in -body, or WhatsApp " +
			"attaches no card and says nothing about why")
	case (*previewTitle != "" || *previewDesc != "") && *previewURL == "":
		return errors.New("-preview-title and -preview-desc need -preview-url")
	}

	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	req := wsapi.SendRequest{
		DeviceID: *device,
		Chat:     normaliseJID(*to),
		Body:     *body,
		//nolint:gosec // G115: a forwarding score is a small user-supplied count
		ForwardingScore: uint32(*score),
		Forwarded:       *forwarded || *score > 0,
		//nolint:gosec // G115: a timer in seconds
		Expiration:  uint32(*expires),
		ViewOnce:    *viewOnce,
		ReplyTo:     *replyTo,
		ReplyBody:   *replyBody,
		ReplySender: *replySender,
	}
	for _, m := range strings.Split(*mentions, ",") {
		if m = strings.TrimSpace(m); m != "" {
			req.Mentions = append(req.Mentions, normaliseJID(m))
		}
	}
	if *previewURL != "" {
		// No thumbnail from here. Producing one means fetching the page, which
		// is exactly the thing the server refuses to do, and a terminal client
		// has no better claim to doing it.
		req.Preview = &wsapi.LinkPreviewRequest{
			URL: *previewURL, Title: *previewTitle, Description: *previewDesc,
		}
	}

	f, err := c.request(ctx, "send-1", wsapi.TypeSend, req, wsapi.TypeSendResult)
	if err != nil {
		return err
	}
	var res wsapi.SendResult
	if err := json.Unmarshal(f.Payload, &res); err != nil {
		return err
	}

	fmt.Printf("sent   %s\n", res.ID)
	if res.UID != "" {
		fmt.Printf("stored %s at sequence %d, sealed\n", short(res.UID), res.Seq)
	} else {
		// Worth saying rather than hiding: the message reached WhatsApp, so a
		// retry would deliver it twice, but the archive does not have it.
		fmt.Println("warning: sent but not archived; check the server log")
	}
	return nil
}

// normaliseJID accepts a bare phone number as well as a full JID, since typing
// the server half every time is tedious and easy to get wrong.
func normaliseJID(s string) string {
	if strings.Contains(s, "@") {
		return s
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	return digits + "@s.whatsapp.net"
}
