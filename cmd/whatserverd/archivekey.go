package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// deviceKey creates one device's archive keypair.
//
// Per device rather than per tenant: with one key for a whole tenant, "this
// operator may read that WhatsApp account and not this one" is a rule the
// server enforces, and the premise of this system is that server-enforced rules
// do not survive a compromised server.
//
// The private half is generated here, sealed to every account that should be
// able to read the device, and then discarded. It is printed only when there is
// nobody to seal it to — because a key that exists solely as text somebody has
// to remember to save is exactly how the first archive of this project was
// lost.
func deviceKey(args []string) error {
	fs := flag.NewFlagSet("device-key", flag.ContinueOnError)
	deviceArg := fs.String("device", "", "device id or unique prefix (required; see: wsctl devices)")
	show := fs.Bool("print", false, "print the private key even when it was granted to accounts")
	confirmPrint := fs.Bool("i-understand-this-prints-a-private-key", false,
		"required with -print: the key goes to this terminal, its scrollback and its history")
	var grantTo emails
	fs.Var(&grantTo, "grant", "email of an account that may read this device (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *deviceArg == "" {
		fs.Usage()
		return errors.New("device-key: -device is required")
	}
	if *show && !*confirmPrint {
		return errors.New("device-key: -print writes a private archive key to this terminal; " +
			"pass -i-understand-this-prints-a-private-key as well, or grant it to accounts instead")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()

	dev, tenant, err := resolveDeviceAnywhere(ctx, a, *deviceArg)
	if err != nil {
		return err
	}
	deviceID := uuid.MustParse(dev.ID)

	keys := store.NewKeys(a.pools.API)

	// Refuse to replace an existing key. Overwriting would orphan every
	// message sealed under the old one, with no way back.
	if _, epoch, err := keys.ArchiveKey(ctx, tenant, deviceID); err == nil {
		return fmt.Errorf("device-key: device %s already has an archive key at epoch %d; "+
			"replacing it would make everything sealed under the old key unreadable", dev.ID, epoch)
	} else if !errors.Is(err, store.ErrNoArchiveKey) {
		return err
	}

	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		return err
	}
	raw, err := priv.Bytes()
	if err != nil {
		return err
	}
	const epoch = 1
	if err := keys.CreateArchiveKey(ctx, tenant, deviceID, epoch, pub); err != nil {
		return err
	}

	// Sealed to the accounts named, so reading this archive is a matter of
	// signing in rather than of keeping a secret in a file.
	//
	// Named rather than "all of them": sealing to every account of the tenant
	// would hand one operator's WhatsApp number to every other operator, which
	// is the separation a per-device key exists to provide.
	users := store.NewUsers(a.pools.API)
	all, err := users.List(ctx, tenant)
	if err != nil {
		return err
	}
	accounts, err := chooseAccounts(all, grantTo)
	if err != nil {
		return err
	}
	granted := 0
	for _, u := range accounts {
		userPub, err := seal.ParsePublicKey(u.PublicKey)
		if err != nil {
			return fmt.Errorf("device-key: account %s has an unusable public key: %w", u.Email, err)
		}
		sealed, err := seal.SealDirect(userPub, seal.KindDeviceGrant, tenant,
			seal.GrantRow(tenant, deviceID, u.ID, epoch), epoch, raw)
		if err != nil {
			return err
		}
		if err := keys.PutGrant(ctx, store.Grant{
			TenantID: tenant, DeviceID: deviceID, UserID: u.ID,
			Epoch: epoch, SealedDSK: sealed,
		}, nil); err != nil {
			return err
		}
		granted++
	}

	fmt.Printf("Archive key created for device %s (%s), epoch %d.\n", dev.ID, dev.Label, epoch)
	switch {
	case granted > 0 && !*show:
		fmt.Printf(`
Granted to %d account(s). They open this archive by signing in; nothing here
needs to be written down.

Every account with a grant can read every message this device archives. Adding
one later is a grant; removing one stops them obtaining the key again, but not
any copy they already unlocked.
`, granted)
	case granted > 0:
		fmt.Printf(`
Granted to %d account(s), and printed below because you asked.

private key  %s
`, granted, base64.RawURLEncoding.EncodeToString(raw))
	default:
		fmt.Printf(`
NO ACCOUNT EXISTS TO GRANT THIS TO, so it is printed once and stored nowhere.

private key  %s

This is the only copy. The server kept the public half and cannot derive this
from it, so nothing here can recover it and neither can we. Without it every
message this device archives becomes permanently unreadable.

Create an account and run this again for the next device, and there will be
nothing to save by hand.
`, base64.RawURLEncoding.EncodeToString(raw))
	}
	return nil
}

// resolveDeviceAnywhere finds a device without being told its tenant.
//
// Device ids are unique across the installation, but every read is scoped by
// row-level security, so the tenant has to be discovered before the row can be
// fetched. An operator holding a device id should not also have to look up
// which tenant it belongs to.
func resolveDeviceAnywhere(ctx context.Context, a *app, idOrPrefix string) (store.Device, uuid.UUID, error) {
	tenants, err := a.listTenantIDs(ctx)
	if err != nil {
		return store.Device{}, uuid.Nil, err
	}
	var found store.Device
	var owner uuid.UUID
	matches := 0
	for _, tenant := range tenants {
		dev, err := a.devices.Resolve(ctx, tenant.String(), idOrPrefix)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return store.Device{}, uuid.Nil, err
		}
		found, owner = dev, tenant
		matches++
	}
	switch matches {
	case 0:
		return store.Device{}, uuid.Nil, fmt.Errorf("device-key: no device matches %q", idOrPrefix)
	case 1:
		return found, owner, nil
	default:
		return store.Device{}, uuid.Nil,
			fmt.Errorf("device-key: %q matches devices in more than one tenant", idOrPrefix)
	}
}
