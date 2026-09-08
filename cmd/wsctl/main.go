// Command wsctl is a terminal client for whatserver2.
//
// It exists to dogfood the websocket protocol. Every phase of this project is
// meant to be verifiable from here, which keeps the protocol honest: if
// something is awkward to drive from a client, that shows up immediately rather
// than after a web UI has been built on top of it.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/google/uuid"
	"whatserver2/internal/config"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/wsapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `wsctl - terminal client for whatserver2

usage:
  wsctl devices
  wsctl pair    [-method code|qr] [-phone NUMBER] [-label NAME] [-mode passive|active]
                [-display-name "Browser (OS)"]
  wsctl chats   -device ID [-key ARCHIVE_KEY] [-n COUNT] [-all]
  wsctl avatar  -device ID -key ARCHIVE_KEY -contact NUMBER [-o FILE]
  wsctl watch   [-key ARCHIVE_KEY] [-since SEQ] [-live]
  wsctl send    -device ID -to NUMBER -body TEXT
                [-forwarded] [-score N] [-view-once]
                [-reply-to ID [-reply-body TEXT] [-reply-sender JID]]
                [-mention JID,JID] [-preview-url URL -preview-title T]
  wsctl edit    -device ID -to NUMBER -id MSGID -body TEXT
  wsctl revoke  -device ID -to NUMBER -id MSGID [-sender JID]
  wsctl react   -device ID -to NUMBER -id MSGID (-emoji X | -remove) [-sender JID]
  wsctl read    -device ID -to NUMBER -ids ID[,ID...] [-played] [-sender JID]
  wsctl chat-timer -device ID -to NUMBER (-seconds N | -off)
  wsctl backfill -device ID -to NUMBER [-count N]
  wsctl send-media -device ID -to NUMBER -file PATH
                [-type image|video|ptv|audio|ptt|document|sticker] [-caption TEXT]
                [-view-once] [-gif] [-seconds N] [-width N -height N]
  wsctl media   -uid UID [-key ARCHIVE_KEY] [-o FILE] [-raw]
  wsctl media-retry -device ID -key ARCHIVE_KEY (-uid UID | -n COUNT)
  wsctl history [-key ARCHIVE_KEY] -uid UID
                [-key ARCHIVE_KEY] -device ID -chat JID -id WAID
  wsctl stop    -device ID
  wsctl service-key
  wsctl grants  [-service-key KEY] [-device ID]

A device id may be given as a unique prefix, the way git takes short hashes,
so the short form shown by "wsctl devices" works everywhere.

environment (also read from .env in the working directory):
  WS_API_KEY    api key. Issue one with:
                  ./bin/whatserverd tenants           # find your tenant
                  ./bin/whatserverd key -tenant <ID>  # issue a key for it
                Use "bootstrap" only to create a brand new tenant.
  WS_HTTP_ADDR  server address, shared with the server (default :8080)
  WS_URL        full websocket url, overrides WS_HTTP_ADDR

Disappearing messages are a property of the chat, not of a message: WhatsApp
has no way to make one vanish and leave the next alone. Turn them on with
"chat-timer" and every later message in that chat disappears, with the timer
applied automatically. The archive keeps them all, marked.

"read" is the only command that sends a receipt. Nothing else in this program
does, which is what incognito means here.

"history" is the screen this project exists for: every version of an edited
message, the text of a deleted one, and which version each reader had on
screen. Without -key it prints what the server itself can see, which is the
structure and none of the words.

Pairing by code is easier over a terminal than by QR: you type an eight
character code into your phone instead of photographing your own screen.
Find it under Settings, Linked devices, Link with phone number instead.

Run "wsctl <command> -h" for the flags of one command.
`)
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}
	// Same .env the server reads, so a non-default port does not have to be
	// repeated here. Real environment variables still win.
	if err := config.LoadDotEnv(".env"); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "pair":
		return cmdPair(ctx, os.Args[2:])
	case "devices":
		return cmdDevices(ctx)
	case "chats":
		return cmdChats(ctx, os.Args[2:])
	case "avatar":
		return cmdAvatar(ctx, os.Args[2:])
	case "stop":
		return cmdStop(ctx, os.Args[2:])
	case "service-key":
		return cmdServiceKey(ctx, os.Args[2:])
	case "grants":
		return cmdGrants(ctx, os.Args[2:])
	case "watch":
		return cmdWatch(ctx, os.Args[2:])
	case "send":
		return cmdSend(ctx, os.Args[2:])
	case "edit":
		return cmdEdit(ctx, os.Args[2:])
	case "revoke":
		return cmdRevoke(ctx, os.Args[2:])
	case "react":
		return cmdReact(ctx, os.Args[2:])
	case "read":
		return cmdRead(ctx, os.Args[2:])
	case "chat-timer":
		return cmdChatTimer(ctx, os.Args[2:])
	case "backfill":
		return cmdBackfill(ctx, os.Args[2:])
	case "history":
		return cmdHistory(ctx, os.Args[2:])
	case "media":
		return cmdMedia(ctx, os.Args[2:])
	case "send-media":
		return cmdSendMedia(ctx, os.Args[2:])
	case "media-retry":
		return cmdMediaRetry(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func cmdPair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	method := fs.String("method", "code", "code or qr")
	phone := fs.String("phone", "", "phone number in full international form, required for -method=code")
	label := fs.String("label", "", "a name for this device")
	mode := fs.String("mode", "passive", "receipt mode: passive (incognito) or active")
	display := fs.String("display-name", "", `name shown under Linked devices, formatted "Browser (OS)"`)
	orphan := fs.Bool("orphan", false,
		"pair even though no account can read this device; prints the key once")
	var grantTo emails
	fs.Var(&grantTo, "grant", "email of an account that may read this device (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *method == "code" && *phone == "" {
		return errors.New("-phone is required with -method=code, in full international form (for example +5511999999999)")
	}

	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	// The archive key is generated here, sealed to every account that should be
	// able to read this device, and then dropped. It has to exist before the
	// device does: the first message can land seconds after the phone accepts,
	// and a device with no key cannot seal.
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		return err
	}
	raw, err := priv.Bytes()
	if err != nil {
		return err
	}
	// Chosen here because the grant binds to it, and sealing has to happen
	// before the device row exists.
	device, err := uuid.NewV7()
	if err != nil {
		return err
	}
	grants, accounts, err := sealGrants(ctx, c, device, raw, grantTo)
	if err != nil {
		return err
	}
	if len(grants) == 0 && !*orphan {
		return errors.New("no account exists to hold this device's archive key, so nothing " +
			"could ever read it.\n\nCreate one first:\n" +
			"  ./bin/whatserverd invite -tenant <ID>\n" +
			"then sign up in the web client. Pass -orphan to pair anyway and print the key")
	}

	req := wsapi.PairRequest{
		Label: *label, Method: *method, Phone: *phone,
		DisplayName: *display, ReceiptMode: *mode,
		DeviceID: device.String(), ArchivePublicKey: pub.Bytes(), Grants: grants,
		Orphan: *orphan,
	}
	if err := c.send(ctx, wsapi.TypePair, "pair-1", req); err != nil {
		return err
	}
	if len(grants) > 0 {
		fmt.Printf("Archive key generated and sealed to %d account(s):\n", len(grants))
		for _, a := range accounts {
			fmt.Printf("  %s\n", a)
		}
		fmt.Println("They open this device by signing in. Nothing needs to be written down.")
		fmt.Println()
	} else {
		fmt.Printf(`NO ACCOUNT HOLDS THIS KEY, so it is printed once and stored nowhere.

archive key  %s

Without it every message this device archives is permanently unreadable.

`, base64.RawURLEncoding.EncodeToString(raw))
	}
	if *mode == "passive" {
		fmt.Println("Receipt mode: passive. This device will not announce presence,")
		fmt.Println("and read receipts are only sent when you ask for them.")
		fmt.Println()
	}

	for f := range c.Stream() {
		switch f.Type {
		case wsapi.TypePairCode:
			var p wsapi.PairCode
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			printCode(p)

		case wsapi.TypePairQR:
			var p wsapi.PairQR
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			printQR(p)

		case wsapi.TypePairSuccess:
			var p wsapi.PairResult
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			fmt.Printf("\nPaired. Device %s\n", p.DeviceID)
			// Keep reading briefly: the device reports online just after.
			return waitForOnline(ctx, c, p.DeviceID)

		case wsapi.TypePairTimeout:
			return errors.New("the pairing window closed before the phone accepted; run the command again")

		case wsapi.TypeDeviceStatus:
			var p wsapi.DeviceStatus
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				return err
			}
			fmt.Printf("  status: %s%s\n", p.Status, reasonSuffix(p.Reason))

		case wsapi.TypeError:
			return protocolError(f)
		}
	}
	return c.Err()
}

// waitForOnline reports status changes for a few seconds after pairing, so the
// user sees the device actually come up rather than just "paired".
func waitForOnline(ctx context.Context, c *client, deviceID string) error {
	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			// Not a failure: pairing already succeeded.
			return nil
		case f, ok := <-c.Stream():
			if !ok {
				return nil
			}
			if f.Type != wsapi.TypeDeviceStatus {
				continue
			}
			var p wsapi.DeviceStatus
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				continue
			}
			if p.DeviceID != deviceID && p.DeviceID != "" {
				continue
			}
			fmt.Printf("  status: %s%s\n", p.Status, reasonSuffix(p.Reason))
			if p.Status == "online" {
				return nil
			}
		}
	}
}

func printCode(p wsapi.PairCode) {
	// Grouped in fours: an eight character code is much easier to read off a
	// screen and type into a phone in two chunks.
	code := p.Code
	if len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}
	fmt.Println("On your phone, open WhatsApp and go to:")
	fmt.Println("  Settings -> Linked devices -> Link a device")
	fmt.Println("  -> Link with phone number instead")
	fmt.Println()
	fmt.Printf("  code:  %s\n", code)
	fmt.Printf("  valid: %s\n", time.Until(p.Expires).Round(time.Second))
	fmt.Println()
	fmt.Println("Waiting for your phone...")
}

func printQR(p wsapi.PairQR) {
	fmt.Println("\nScan this with WhatsApp on your phone:")
	fmt.Println("  Settings -> Linked devices -> Link a device")
	qrterminal.GenerateHalfBlock(p.Code, qrterminal.L, os.Stdout)
	fmt.Printf("  this code expires in %s; a new one follows automatically\n",
		time.Until(p.Expires).Round(time.Second))
}

func cmdDevices(ctx context.Context) error {
	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	f, err := c.request(ctx, "list-1", wsapi.TypeDevicesList, nil, wsapi.TypeDevices)
	if err != nil {
		return err
	}
	var p wsapi.Devices
	if err := json.Unmarshal(f.Payload, &p); err != nil {
		return err
	}
	printDevices(p.Devices)
	return nil
}

func printDevices(devices []wsapi.DeviceInfo) {
	if len(devices) == 0 {
		fmt.Println("No devices. Run: wsctl pair -phone +5511999999999")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// LID and phone number are separate columns because either may be empty:
	// LID exists to withhold the phone number, so for some accounts one never
	// becomes known.
	//nolint:errcheck // writing to stdout; nothing useful to do on failure
	fmt.Fprintln(w, "ID\tLABEL\tSTATUS\tMODE\tLID\tPHONE\tNAME")
	for _, d := range devices {
		running := ""
		if d.Running {
			running = " *"
		}
		//nolint:errcheck // writing to stdout
		fmt.Fprintf(w, "%s\t%s\t%s%s\t%s\t%s\t%s\t%s\n",
			short(d.ID), or(d.Label, "-"), d.Status, running, d.ReceiptMode,
			or(userPart(d.LID), "-"), or(userPart(d.PN), "-"), or(d.PushName, "-"))
	}
	//nolint:errcheck // writing to stdout
	_ = w.Flush()
	fmt.Println("\n* supervised by this server right now")
	fmt.Println("The short ID works wherever a device id is asked for.")
}

func cmdStop(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	device := fs.String("device", "", "device id (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *device == "" {
		return errors.New("-device is required")
	}
	c, err := dial(ctx)
	if err != nil {
		return err
	}
	defer c.close()

	if _, err := c.request(ctx, "stop-1", wsapi.TypeDeviceStop,
		wsapi.DeviceRef{DeviceID: *device}, wsapi.TypeDeviceStatus); err != nil {
		return err
	}
	fmt.Println("stopped")
	return nil
}

func protocolError(f wsapi.Frame) error {
	var e wsapi.Error
	if err := json.Unmarshal(f.Payload, &e); err != nil {
		return errors.New("the server returned an unreadable error")
	}
	return fmt.Errorf("%s: %s", e.Code, e.Message)
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// userPart trims the server half of a JID, which is noise in a table.
func userPart(jid string) string {
	user, _, _ := strings.Cut(jid, "@")
	return user
}

// isRefused reports whether err is a refused TCP connection.
func isRefused(err error) bool {
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return errors.Is(sysErr.Err, syscall.ECONNREFUSED)
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// emails collects a repeatable -grant flag.
type emails []string

func (e *emails) String() string { return strings.Join(*e, ", ") }
func (e *emails) Set(v string) error {
	*e = append(*e, strings.ToLower(strings.TrimSpace(v)))
	return nil
}

// sealGrants seals a device archive key to the accounts that may read it.
//
// Who those are is asked for rather than assumed. Sealing to every account of
// the tenant would hand one operator's WhatsApp number to every other operator,
// which is the separation a per-device key exists to provide — a default that
// undoes the property is worse than no default. One account is unambiguous and
// is used; more than one has to be named.
//
// The private key is used here and dropped. The server receives ciphertext per
// account plus the matching public key, and at no point holds anything that
// could open the archive it is about to start filling.
//
// The device id is chosen by this client rather than by the database, because
// the grant binds to it: sealing has to happen before the row exists, and a
// second round trip to learn an id would leave a device that exists with no key
// for however long that took.
func sealGrants(ctx context.Context, c *client, device uuid.UUID,
	deviceKey []byte, want emails) ([]wsapi.KeyGrant, []string, error) {
	f, err := c.request(ctx, "users-1", wsapi.TypeUsersList, wsapi.UsersRequest{}, wsapi.TypeUsers)
	if err != nil {
		return nil, nil, err
	}
	var list wsapi.Users
	if err := json.Unmarshal(f.Payload, &list); err != nil {
		return nil, nil, err
	}
	tenant, err := uuid.Parse(c.tenant)
	if err != nil {
		return nil, nil, fmt.Errorf("server reported an unusable tenant: %w", err)
	}

	chosen, err := chooseAccounts(list.Users, want)
	if err != nil {
		return nil, nil, err
	}

	const epoch = 1
	grants := make([]wsapi.KeyGrant, 0, len(chosen))
	names := make([]string, 0, len(chosen))
	for _, u := range chosen {
		pub, err := seal.ParsePublicKey(u.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("account %s has an unusable public key: %w", u.Email, err)
		}
		user, err := uuid.Parse(u.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("account %s has an unusable id: %w", u.Email, err)
		}
		sealed, err := seal.SealDirect(pub, seal.KindDeviceGrant, tenant,
			seal.GrantRow(tenant, device, user, epoch), epoch, deviceKey)
		if err != nil {
			return nil, nil, err
		}
		grants = append(grants, wsapi.KeyGrant{UserID: u.ID, SealedDSK: sealed})
		names = append(names, u.Email)
	}
	return grants, names, nil
}

// chooseAccounts resolves -grant, or decides there is nothing to decide.
func chooseAccounts(all []wsapi.UserSummary, want emails) ([]wsapi.UserSummary, error) {
	if len(want) == 0 {
		switch len(all) {
		case 0:
			return nil, nil
		case 1:
			// Nothing to choose between.
			return all, nil
		default:
			return nil, fmt.Errorf(
				"this tenant has %d accounts, so -grant is required: "+
					"a device key sealed to everybody would let each operator read "+
					"every WhatsApp number, which is what a key per device exists to "+
					"prevent.\n\nAvailable:\n%s\n\nFor example:  -grant %s",
				len(all), listAccounts(all), all[0].Email)
		}
	}

	byEmail := map[string]wsapi.UserSummary{}
	for _, u := range all {
		byEmail[strings.ToLower(u.Email)] = u
	}
	out := make([]wsapi.UserSummary, 0, len(want))
	for _, email := range want {
		u, ok := byEmail[email]
		if !ok {
			return nil, fmt.Errorf("no account %q in this tenant.\n\nAvailable:\n%s",
				email, listAccounts(all))
		}
		out = append(out, u)
	}
	return out, nil
}

func listAccounts(all []wsapi.UserSummary) string {
	var b strings.Builder
	for _, u := range all {
		fmt.Fprintf(&b, "  %s (%s)\n", u.Email, u.Role)
	}
	return strings.TrimRight(b.String(), "\n")
}
