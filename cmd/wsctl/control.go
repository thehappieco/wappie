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

// The control commands: edit, revoke, react and read.
//
// They exist so the phase 3 projection can be produced end to end from here.
// A history of an edited and deleted message is only a real feature if
// something can create one, and driving it from the CLI is what keeps the
// protocol honest — the same reason the rest of wsctl exists.

// cmdEdit replaces the text of a message already sent.
func cmdEdit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "chat JID or phone number (required)")
	target := fs.String("id", "", "id of the message to replace (required)")
	body := fs.String("body", "", "the new text (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{
		"-device": *device, "-to": *to, "-id": *target, "-body": *body,
	}); err != nil {
		return err
	}

	return withSendResult(ctx, "edit-1", wsapi.TypeEdit, wsapi.EditRequest{
		DeviceID: *device, Chat: normaliseJID(*to), TargetID: *target, Body: *body,
	}, func(res wsapi.SendResult) {
		fmt.Printf("edited %s\n", *target)
		reportArchive(res)
		fmt.Println("The previous text is still stored. See: wsctl history -uid <uid>")
	})
}

// cmdRevoke deletes a message for everyone. The archive keeps it, which is the
// whole point of the archive.
func cmdRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "chat JID or phone number (required)")
	target := fs.String("id", "", "id of the message to delete (required)")
	sender := fs.String("sender", "",
		"the original author's JID, when deleting somebody else's message as a group admin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{
		"-device": *device, "-to": *to, "-id": *target,
	}); err != nil {
		return err
	}

	return withSendResult(ctx, "revoke-1", wsapi.TypeRevoke, wsapi.RevokeRequest{
		DeviceID: *device, Chat: normaliseJID(*to), TargetID: *target, Sender: *sender,
	}, func(res wsapi.SendResult) {
		fmt.Printf("deleted %s for everyone\n", *target)
		reportArchive(res)
		fmt.Println("The text is still stored. See: wsctl history -uid <uid>")
	})
}

// cmdReact adds or removes a reaction. An empty emoji removes.
func cmdReact(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("react", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "chat JID or phone number (required)")
	target := fs.String("id", "", "id of the message to react to (required)")
	emoji := fs.String("emoji", "", "the emoji; empty removes the reaction")
	sender := fs.String("sender", "", "the message author's JID (needed in groups)")
	remove := fs.Bool("remove", false, "withdraw the reaction, same as an empty -emoji")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{
		"-device": *device, "-to": *to, "-id": *target,
	}); err != nil {
		return err
	}
	if *remove {
		*emoji = ""
	}
	if *emoji == "" && !*remove {
		return errors.New("-emoji is required; pass -remove to withdraw a reaction instead")
	}

	return withSendResult(ctx, "react-1", wsapi.TypeReact, wsapi.ReactRequest{
		DeviceID: *device, Chat: normaliseJID(*to), TargetID: *target,
		Sender: *sender, Emoji: *emoji,
	}, func(res wsapi.SendResult) {
		if *emoji == "" {
			fmt.Printf("withdrew the reaction on %s\n", *target)
		} else {
			fmt.Printf("reacted %s to %s\n", *emoji, *target)
		}
		reportArchive(res)
	})
}

// cmdChatTimer turns disappearing messages on or off for a chat.
//
// A chat setting, because that is all WhatsApp has. There is no way to make one
// message vanish and leave the next one alone, which is why "send -expires"
// never worked and now says so instead of pretending.
func cmdChatTimer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("chat-timer", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "chat JID or phone number (required)")
	seconds := fs.Uint("seconds", 0,
		"timer in seconds; 0 turns it off. WhatsApp's presets are 86400 (24h), "+
			"604800 (7 days) and 7776000 (90 days)")
	off := fs.Bool("off", false, "turn disappearing messages off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{"-device": *device, "-to": *to}); err != nil {
		return err
	}
	if *off {
		*seconds = 0
	}
	// Zero is a real value here, so an accidental "chat-timer -to X" that
	// silently turns the timer off is worth refusing.
	if *seconds == 0 && !*off {
		return errors.New("pass -seconds N to set a timer, or -off to turn it off; " +
			"leaving both out would quietly disable disappearing messages")
	}

	return withResult(ctx, "timer-1", wsapi.TypeChatTimer, wsapi.ChatTimerRequest{
		DeviceID: *device, Chat: normaliseJID(*to),
		//nolint:gosec // G115: validated against a one-year ceiling by the server
		Seconds: uint32(*seconds),
	}, wsapi.TypeChatTimerSet, func(payload []byte) error {
		var res wsapi.ChatTimerResult
		if err := json.Unmarshal(payload, &res); err != nil {
			return err
		}
		if res.Seconds == 0 {
			fmt.Printf("disappearing messages are off for %s\n", res.Chat)
			return nil
		}
		fmt.Printf("disappearing messages on for %s: %s\n", res.Chat, humanTimer(res.Seconds))
		fmt.Println("Every later message in this chat disappears, and WhatsApp has " +
			"announced the change to everyone in it.")
		fmt.Println("The archive keeps them all, marked with when they were meant to vanish.")
		return nil
	})
}

// humanTimer renders a timer the way WhatsApp's own presets read.
func humanTimer(seconds uint32) string {
	switch seconds {
	case 86400:
		return "24 hours"
	case 604800:
		return "7 days"
	case 7776000:
		return "90 days"
	}
	switch {
	case seconds%86400 == 0:
		return plural(seconds/86400, "day")
	case seconds%3600 == 0:
		return plural(seconds/3600, "hour")
	case seconds%60 == 0:
		return plural(seconds/60, "minute")
	default:
		return plural(seconds, "second")
	}
}

func plural(n uint32, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// cmdRead sends a read receipt.
//
// The only thing in this whole program that emits one. Nothing on the ingest
// side does, which is what makes the default posture incognito: a device
// receives without telling anyone that it did.
func cmdRead(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "chat JID or phone number (required)")
	ids := fs.String("ids", "", "comma-separated message ids to mark read (required)")
	sender := fs.String("sender", "", "the message author's JID (needed in groups)")
	played := fs.Bool("played", false,
		"mark as played rather than read, for voice notes and view-once media")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{
		"-device": *device, "-to": *to, "-ids": *ids,
	}); err != nil {
		return err
	}
	list := strings.Split(*ids, ",")
	for i := range list {
		list[i] = strings.TrimSpace(list[i])
	}

	return withSendResult(ctx, "read-1", wsapi.TypeMarkRead, wsapi.MarkReadRequest{
		DeviceID: *device, Chat: normaliseJID(*to), Sender: *sender,
		IDs: list, Played: *played,
	}, func(wsapi.SendResult) {
		what := "read"
		if *played {
			what = "played"
		}
		fmt.Printf("marked %d message(s) %s. This is the one place that leaves a receipt.\n",
			len(list), what)
	})
}

// withResult performs one request and hands the payload to a reporter.
func withResult(ctx context.Context, reqID, frameType string, payload any,
	wantType string, report func([]byte) error) error {
	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	f, err := c.request(ctx, reqID, frameType, payload, wantType)
	if err != nil {
		return err
	}
	return report(f.Payload)
}

// withSendResult performs one request that answers with a send result.
func withSendResult(ctx context.Context, reqID, frameType string, payload any,
	report func(wsapi.SendResult)) error {
	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	f, err := c.request(ctx, reqID, frameType, payload, wsapi.TypeSendResult)
	if err != nil {
		return err
	}
	var res wsapi.SendResult
	if err := json.Unmarshal(f.Payload, &res); err != nil {
		return err
	}
	report(res)
	return nil
}

func reportArchive(res wsapi.SendResult) {
	if res.UID != "" {
		fmt.Printf("stored %s at sequence %d, sealed\n", short(res.UID), res.Seq)
		return
	}
	// Worth saying rather than hiding: it reached WhatsApp, so retrying would
	// do it twice, but the archive does not have it.
	fmt.Println("warning: sent but not archived; check the server log")
}

func requireAll(flags map[string]string) error {
	missing := make([]string, 0, len(flags))
	for name, value := range flags {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sortStrings(missing)
	return fmt.Errorf("%s %s required", strings.Join(missing, ", "),
		map[bool]string{true: "is", false: "are"}[len(missing) == 1])
}

// sortStrings keeps the error message stable; a required-flag list that
// reorders between runs is needlessly hard to read.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// cmdBackfill asks WhatsApp for messages older than the archive holds.
//
// A history sync brings what the phone still has and stops. Anything earlier
// has to be asked for, one conversation at a time, anchored on the oldest
// message already stored — asking with the newest would return what is already
// here.
//
// The answer does not arrive on this call. WhatsApp replies minutes later with
// an on-demand sync that is ingested like a bootstrap, so the way to see the
// result is to run "wsctl chats" or watch the log again afterwards.
func cmdBackfill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	to := fs.String("to", "", "chat JID or phone number (required)")
	count := fs.Int("count", 50, "how many older messages to ask for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAll(map[string]string{"-device": *device, "-to": *to}); err != nil {
		return err
	}

	return withResult(ctx, "backfill-1", wsapi.TypeBackfill, wsapi.BackfillRequest{
		DeviceID: *device, Chat: normaliseJID(*to), Count: *count,
	}, wsapi.TypeBackfillSent, func(payload []byte) error {
		var res wsapi.BackfillSent
		if err := json.Unmarshal(payload, &res); err != nil {
			return err
		}
		fmt.Printf("asked for %d messages before %s in %s\n",
			res.Count, res.AnchorID, res.Chat)
		fmt.Println("WhatsApp answers in its own time, as an on-demand sync that is " +
			"ingested like any other. Nothing comes back on this call.")
		fmt.Println("Run it again afterwards: if the anchor has not moved, the phone " +
			"has nothing older.")
		return nil
	})
}
