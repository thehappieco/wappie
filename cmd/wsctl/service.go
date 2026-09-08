package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/wsapi"
)

// A service account is how a system reads the archive without anybody
// handing it a device key by hand. The system generates a keypair here,
// registers the public half under an invite, an owner grants it devices and
// mints an API key that acts as it, and the grants then open with the
// private half — which never left this machine.

// cmdServiceKey generates the keypair a service account is registered with.
func cmdServiceKey(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("service-key", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
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
	fmt.Printf(`public   %s
private  %s

Register the PUBLIC half with a service invite ("whatserverd invite -role
service"), under "Registrar um sistema" on the sign-in screen. Keep the
private half where this system keeps secrets: every device granted to the
account opens with it, and it cannot be recovered from the server.
`, base64.StdEncoding.EncodeToString(pub.Bytes()), base64.RawURLEncoding.EncodeToString(raw))
	return nil
}

// cmdGrants lists the devices the connection's account may open, and with the
// account's private key, opens them.
func cmdGrants(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("grants", flag.ContinueOnError)
	keyArg := fs.String("service-key", "", "the account's private key, as printed by wsctl service-key")
	device := fs.String("device", "", "print this device's archive key, for -key on other commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *device != "" && *keyArg == "" {
		return errors.New("-device needs -service-key: a grant opens only with the account's private key")
	}
	var priv seal.PrivateKey
	if *keyArg != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*keyArg))
		if err != nil {
			return fmt.Errorf("-service-key is not a valid key: %w", err)
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

	f, err := c.request(ctx, "grants-1", wsapi.TypeGrantsList, wsapi.GrantsRequest{}, wsapi.TypeGrants)
	if err != nil {
		return err
	}
	var list wsapi.Grants
	if err := json.Unmarshal(f.Payload, &list); err != nil {
		return err
	}
	tenant, err := uuid.Parse(c.tenant)
	if err != nil {
		return fmt.Errorf("server reported an unusable tenant: %w", err)
	}
	user, err := uuid.Parse(list.UserID)
	if err != nil {
		return fmt.Errorf("server reported an unusable account id: %w", err)
	}
	if len(list.Grants) == 0 {
		fmt.Println("This account holds no grants. An owner grants devices to it in the console.")
		return nil
	}

	for _, g := range list.Grants {
		dev, err := uuid.Parse(g.DeviceID)
		if err != nil {
			return fmt.Errorf("server reported an unusable device id: %w", err)
		}
		if *device != "" && !strings.HasPrefix(g.DeviceID, *device) {
			continue
		}
		status := "sealed"
		var opened []byte
		if priv.Valid() {
			//nolint:gosec // G115: an epoch is bounded by the column that stores it
			epoch := uint16(g.Epoch)
			opened, err = seal.OpenDirect(priv, seal.KindDeviceGrant, tenant,
				seal.GrantRow(tenant, dev, user, epoch), g.SealedDSK)
			if err != nil {
				status = "does not open with this key"
			} else {
				status = "opens"
			}
		}
		fmt.Printf("%s  %-20s epoch %d  %s\n", g.DeviceID, g.Label, g.Epoch, status)
		if *device != "" && opened != nil {
			fmt.Printf("\narchive key  %s\n\nUse it as -key on chats, history, watch and media.\n",
				base64.RawURLEncoding.EncodeToString(opened))
		}
	}
	return nil
}
