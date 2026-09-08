package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"whatserver2/internal/blob"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// inviteTTL is how long an invite code stays usable. Long enough to send it and
// have somebody act on it, short enough that a forgotten one stops working.
const inviteTTL = 7 * 24 * time.Hour

// issueInvite prints a one-time code for creating an account.
//
// An account is what makes an archive readable without anybody keeping a
// 32-byte secret in a file, so this is the first thing to run after bootstrap
// and before pairing anything.
func issueInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	tenantArg := fs.String("tenant", "", "tenant id (required; see: whatserverd tenants)")
	role := fs.String("role", "owner", "owner, admin, member, or service (a system with a keypair and no password)")
	email := fs.String("email", "", "restrict the invite to one address (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantArg == "" {
		fs.Usage()
		return errors.New("invite: -tenant is required")
	}
	switch *role {
	case "owner", "admin", "member", store.RoleService:
	default:
		return fmt.Errorf("invite: role must be owner, admin, member or service, got %q", *role)
	}
	tenant, err := uuid.Parse(*tenantArg)
	if err != nil {
		return fmt.Errorf("invite: %q is not a tenant id: %w", *tenantArg, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	users := store.NewUsers(a.pools.API)
	code, err := users.CreateInvite(ctx, tenant, *role, *email, nil, inviteTTL)
	if err != nil {
		return err
	}

	fmt.Printf(`Invite for tenant %s, role %s.

code  %s

Valid once, for %s. Open the web client and sign up with it.

The account's password never reaches this server: the browser derives a key
from it, keeps the half that opens things, and sends only the half that proves
who it is. Print the recovery code it offers — it is the other way back.

For a service invite: the system generates a keypair ("wsctl service-key"),
registers the public half with this code under "Registrar um sistema" on the
sign-in screen, and an owner then grants it devices and mints an API key that
acts as it in the console.
`, tenant, *role, code, inviteTTL)
	return nil
}

// resetArchive removes everything sealed for a tenant.
//
// Separate from any migration and deliberately awkward to run. A change to the
// key scheme cannot re-seal what is already stored — re-sealing means opening,
// and this server has never been able to open it — so the only way forward from
// one is to throw the archive away and pair again. That is a decision an
// operator makes, not a side effect of a boot.
func resetArchive(args []string) error {
	fs := flag.NewFlagSet("reset-archive", flag.ContinueOnError)
	tenantArg := fs.String("tenant", "", "tenant id (required)")
	confirm := fs.Bool("yes-destroy-everything", false, "required; there is no undo")
	keepDevices := fs.Bool("keep-devices", false,
		"leave the device rows in place (their sessions stay paired but cannot seal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantArg == "" {
		fs.Usage()
		return errors.New("reset-archive: -tenant is required")
	}
	if !*confirm {
		return errors.New("reset-archive: refusing without -yes-destroy-everything")
	}
	tenant, err := uuid.Parse(*tenantArg)
	if err != nil {
		return fmt.Errorf("reset-archive: %q is not a tenant id: %w", *tenantArg, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	// The objects are listed before the rows go, because afterwards there is
	// nothing left to ask. Every object of the tenant is fair game: the
	// prefix is the tenant's, and no row of any tenant will name it again.
	objects, err := store.ObjectKeysForTenant(ctx, a.pools.API, tenant)
	if err != nil {
		return err
	}

	counts, err := store.ResetArchive(ctx, a.pools.API, tenant, *keepDevices)
	if err != nil {
		return err
	}

	removed, failed := removeObjects(ctx, a, objects)

	fmt.Printf(`Archive removed for tenant %s.

messages  %d
chats     %d
contacts  %d
media     %d
devices   %d
objects   %d removed from storage, %d failed

An object that failed to delete is ciphertext whose keys no longer exist:
useless to anyone, but still occupying space. Run again to retry, or empty the
tenant's prefix in the bucket yourself.

Next: create an account with "whatserverd invite", sign up in the browser, then
pair a device. Pairing generates that device's archive key and seals it to the
accounts that may read it, so there is nothing to write down.
`, tenant, counts.Messages, counts.Chats, counts.Contacts, counts.Media, counts.Devices,
		removed, failed)
	return nil
}

// removeObjects deletes attachment objects, best effort, and counts.
//
// Opens the object store itself: the command-line setup does not, because
// most commands never touch it.
func removeObjects(ctx context.Context, a *app, keys []string) (removed, failed int) {
	if len(keys) == 0 {
		return 0, 0
	}
	store, err := blob.New(a.cfg.Storage)
	if err != nil || !store.Configured() {
		fmt.Fprintf(os.Stderr, "object storage is not configured; %d object(s) left in place\n", len(keys))
		return 0, len(keys)
	}
	for _, key := range keys {
		if err := store.Delete(ctx, key); err != nil {
			fmt.Fprintf(os.Stderr, "could not remove %s: %v\n", key, err)
			failed++
			continue
		}
		removed++
	}
	return removed, failed
}

// setRetention records how long a tenant keeps its archive.
func setRetention(args []string) error {
	fs := flag.NewFlagSet("retention", flag.ContinueOnError)
	tenantArg := fs.String("tenant", "", "tenant id (required)")
	days := fs.Int("days", 0, "keep messages, receipts and attachments this many days")
	forever := fs.Bool("forever", false, "keep everything, which is the default for a new tenant")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantArg == "" {
		fs.Usage()
		return errors.New("retention: -tenant is required")
	}
	if (*days <= 0) == !*forever {
		return errors.New("retention: pass -days N or -forever, one of the two")
	}
	tenant, err := uuid.Parse(*tenantArg)
	if err != nil {
		return fmt.Errorf("retention: %q is not a tenant id: %w", *tenantArg, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	if err := store.SetRetention(ctx, a.pools.API, tenant, *days); err != nil {
		return fmt.Errorf("retention: %w", err)
	}
	if *forever {
		fmt.Printf("Tenant %s keeps its archive indefinitely.\n", tenant)
		return nil
	}
	fmt.Printf(`Tenant %s keeps %d days of archive.

The running server applies it once an hour: messages, receipts and attachments
older than the window are removed, along with their objects in storage. Chats
and contacts stay. The first pass after a change may take a while.
`, tenant, *days)
	return nil
}

// eraseContact removes one person from a tenant's archive.
//
// The right to erasure arrives as an identifier — a phone number, a LID, a
// group — not as a device, so it applies across every device of the tenant.
func eraseContact(args []string) error {
	fs := flag.NewFlagSet("erase", flag.ContinueOnError)
	tenantArg := fs.String("tenant", "", "tenant id (required)")
	confirm := fs.Bool("yes-erase", false, "required; there is no undo")
	var ids emails
	fs.Var(&ids, "id", "identifier to erase: a JID, a bare phone number, or a LID (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantArg == "" || len(ids) == 0 {
		fs.Usage()
		return errors.New("erase: -tenant and at least one -id are required")
	}
	if !*confirm {
		return errors.New("erase: refusing without -yes-erase")
	}
	tenant, err := uuid.Parse(*tenantArg)
	if err != nil {
		return fmt.Errorf("erase: %q is not a tenant id: %w", *tenantArg, err)
	}
	keys := expandIdentifiers(ids)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	counts, err := store.Erase(ctx, a.pools.API, tenant, keys)
	if err != nil {
		return fmt.Errorf("erase: %w", err)
	}
	removed, failed := removeObjects(ctx, a, counts.ObjectKeys)
	fmt.Printf(`Erased from tenant %s: %s

messages      %d
receipts      %d
contacts      %d
participants  %d
group events  %d
attachments   %d rows; %d object(s) removed from storage, %d failed

Messages other people sent in groups the person was in stay; they are not the
person's. The whatsmeow session store keeps its own contact cache, which is
refreshed from the phone and is not part of the archive.
`, tenant, strings.Join(keys, ", "), counts.Messages, counts.Receipts, counts.Contacts,
		counts.Participants, counts.Changes, counts.Media, removed, failed)
	return nil
}

// expandIdentifiers turns what an operator typed into every key form the
// archive might hold it under. A bare number becomes the phone JID; a JID
// is kept as typed. Both are tried, so an erasure cannot miss a row over a
// suffix.
func expandIdentifiers(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		id = strings.TrimPrefix(id, "+")
		if strings.Contains(id, "@") {
			add(id)
			continue
		}
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, id)
		add(digits + "@s.whatsapp.net")
		add(digits + "@lid")
	}
	return out
}

// emails collects a repeatable -grant flag.
type emails []string

func (e *emails) String() string { return strings.Join(*e, ", ") }
func (e *emails) Set(v string) error {
	*e = append(*e, strings.ToLower(strings.TrimSpace(v)))
	return nil
}

// chooseAccounts resolves -grant, or decides there is nothing to decide.
//
// One account is unambiguous and is used. More than one has to be named,
// because sealing a device key to everybody would let each operator read every
// WhatsApp number of the tenant — the separation a per-device key exists to
// provide, undone by a convenient default.
func chooseAccounts(all []store.User, want emails) ([]store.User, error) {
	if len(want) == 0 {
		switch len(all) {
		case 0, 1:
			return all, nil
		default:
			return nil, fmt.Errorf(
				"this tenant has %d accounts, so -grant is required.\n\nAvailable:\n%s\n\n"+
					"For example:  -grant %s", len(all), listAccounts(all), all[0].Email)
		}
	}

	byEmail := map[string]store.User{}
	for _, u := range all {
		byEmail[strings.ToLower(u.Email)] = u
	}
	out := make([]store.User, 0, len(want))
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

func listAccounts(all []store.User) string {
	var b strings.Builder
	for _, u := range all {
		fmt.Fprintf(&b, "  %s (%s)\n", u.Email, u.Role)
	}
	return strings.TrimRight(b.String(), "\n")
}
