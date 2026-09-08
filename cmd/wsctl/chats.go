package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/wsapi"
)

// cmdChats lists the conversations.
//
// The names come from the history sync and are sealed like any other content:
// for a direct chat a name is a person's name. Without -key this prints
// identifiers, which is what the server itself has — and what a group looked
// like in v1, which was the state that made it unusable.
func cmdChats(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("chats", flag.ContinueOnError)
	keyArg := fs.String("key", "", "archive private key, as printed by `whatserverd archive-key`")
	device := fs.String("device", "", "device id (required)")
	limit := fs.Int("n", 40, "how many chats to show")
	all := fs.Bool("all", false, "include archived chats")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *device == "" {
		return errors.New("-device is required; run \"wsctl devices\" to see them")
	}

	var priv seal.PrivateKey
	if *keyArg != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*keyArg))
		if err != nil {
			return fmt.Errorf("-key is not a valid archive key: %w", err)
		}
		if priv, err = seal.ParsePrivateKey(raw); err != nil {
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

	f, err := c.request(ctx, "chats-1", wsapi.TypeChatsList,
		wsapi.DeviceRef{DeviceID: *device}, wsapi.TypeChats)
	if err != nil {
		return err
	}
	var page wsapi.Chats
	if err := json.Unmarshal(f.Payload, &page); err != nil {
		return err
	}

	rows := page.Chats
	if !*all {
		kept := rows[:0]
		for _, ch := range rows {
			if !ch.Archived {
				kept = append(kept, ch)
			}
		}
		rows = kept
	}
	// Pinned first, then by recency — the order a client would draw them in.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Pinned != rows[j].Pinned {
			return rows[i].Pinned
		}
		return rows[i].LastSeq > rows[j].LastSeq
	})
	if len(rows) > *limit {
		rows = rows[:*limit]
	}

	// Names for people live in contacts, not on the chat: only groups carry a
	// name in the history sync. Fetched once and resolved locally, which is
	// what a real client does too.
	names := contactNames(ctx, c, *device, opener)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	//nolint:errcheck // writing to stdout; nothing useful to do on failure
	fmt.Fprintln(w, "SEQ\tWHEN\tUNREAD\tNAME\tCHAT")
	for _, ch := range rows {
		name := opener.open(ctx, page.DeviceID, ch.NameKeyID, ch.UID, seal.KindContactName, ch.NameSealed)
		if name == "" || strings.HasPrefix(name, "<") {
			name = names[ch.ChatKey]
		}
		if name == "" {
			// Nobody has told us who this is. A push name arrives with any
			// message they send, so this is usually a chat nothing has come
			// from since the last sync.
			name = "—"
		}
		when := ""
		if ch.LastTS != nil {
			when = ch.LastTS.Local().Format("02/01 15:04")
		}
		unread := ""
		if ch.Unread > 0 {
			unread = fmt.Sprintf("%d", ch.Unread)
		}
		marks := ""
		if ch.Pinned {
			marks += " [pinned]"
		}
		if ch.Archived {
			marks += " [archived]"
		}
		if ch.IsGroup {
			marks += " [group]"
		}
		//nolint:errcheck // writing to stdout
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s%s\n",
			ch.LastSeq, when, unread, truncate(name, 28), userPart(ch.ChatKey), marks)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if !priv.Valid() {
		fmt.Println()
		fmt.Println("No -key given, so names show as sealed. That is what the server sees.")
	}
	return nil
}

// contactNames builds a lookup from identifier to a display name.
//
// Three names arrive per contact and the server does not choose between them,
// because the right choice depends on what the client is for. This one prefers
// what the account saved, then what WhatsApp verified about a business, then
// what the person calls themselves — which is the order WhatsApp's own clients
// use. An archive reader wanting the sender's chosen name has all three.
func contactNames(ctx context.Context, c *client, device string, o *opener) map[string]string {
	out := map[string]string{}
	f, err := c.request(ctx, "contacts-1", wsapi.TypeContacts,
		wsapi.DeviceRef{DeviceID: device}, wsapi.TypeContactList)
	if err != nil {
		return out
	}
	var list wsapi.Contacts
	if err := json.Unmarshal(f.Payload, &list); err != nil {
		return out
	}
	for _, ct := range list.Contacts {
		for _, candidate := range []struct {
			kind   seal.Kind
			sealed []byte
		}{
			{seal.KindFullName, ct.FullNameSealed},
			{seal.KindBusinessName, ct.BusinessNameSealed},
			{seal.KindPushName, ct.PushNameSealed},
		} {
			if len(candidate.sealed) == 0 {
				continue
			}
			name := o.open(ctx, list.DeviceID, ct.ContentKeyID, ct.UID, candidate.kind, candidate.sealed)
			if name != "" && !strings.HasPrefix(name, "<") {
				out[ct.ContactKey] = name
				break
			}
		}
	}
	return out
}

// cmdAvatar writes one contact's profile picture to a file.
//
// Sealed by this server rather than kept as received: WhatsApp serves profile
// pictures over plain HTTP with no encryption at all, unlike message media
// where the CDN hands over ciphertext. There was nothing to preserve, so the
// bytes were sealed on the way in — and are opened here.
func cmdAvatar(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("avatar", flag.ContinueOnError)
	keyArg := fs.String("key", "", "archive private key (required)")
	device := fs.String("device", "", "device id (required)")
	contact := fs.String("contact", "", "contact JID or phone number (required)")
	out := fs.String("o", "", "where to write; defaults to the contact's number")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *keyArg == "":
		return errors.New("-key is required; the picture is sealed")
	case *device == "" || *contact == "":
		return errors.New("-device and -contact are required")
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*keyArg))
	if err != nil {
		return fmt.Errorf("-key is not a valid archive key: %w", err)
	}
	priv, err := seal.ParsePrivateKey(raw)
	if err != nil {
		return err
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

	key := normaliseJID(*contact)
	f, err := c.request(ctx, "avatar-1", wsapi.TypeAvatar,
		wsapi.AvatarRequest{DeviceID: *device, ContactKey: key}, wsapi.TypeAvatarFrame)
	if err != nil {
		return err
	}
	var av wsapi.Avatar
	if err := json.Unmarshal(f.Payload, &av); err != nil {
		return err
	}
	if len(av.Sealed) == 0 {
		return fmt.Errorf("no profile picture stored for %s: either they have none, "+
			"their privacy settings hide it, or the worker has not reached them yet", key)
	}

	uid, err := uuid.Parse(av.UID)
	if err != nil {
		return err
	}
	// The resolved id from the reply, not the prefix that was typed.
	deviceUUID, err := uuid.Parse(av.DeviceID)
	if err != nil {
		return fmt.Errorf("the server named a device this client cannot parse: %w", err)
	}
	ck, err := newOpener(c, tenant, priv).key(ctx, deviceUUID, av.KeyID)
	if err != nil {
		return err
	}
	picture, err := ck.Open(seal.KindAvatar, tenant, uid, av.Sealed)
	if err != nil {
		return fmt.Errorf("could not open the picture: %w", err)
	}

	dest := *out
	if dest == "" {
		dest = userPart(key) + ".jpg"
	}
	if err := os.WriteFile(dest, picture, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d bytes\n", dest, len(picture))
	return nil
}
