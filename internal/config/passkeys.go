package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Passkeys is deliberately opt-in: an RP is not inferred from untrusted Host
// or proxy headers. A shared parent RP may have a small explicit origin list.
type Passkeys struct {
	RPID    string
	Origins []string
}

func (p Passkeys) Validate(prod bool) error {
	if p.RPID == "" && len(p.Origins) == 0 {
		return nil
	}
	if p.RPID == "" || len(p.Origins) == 0 {
		return errors.New("WS_PASSKEY_RP_ID and WS_PASSKEY_ORIGINS must be configured together")
	}
	if p.RPID != strings.ToLower(p.RPID) || strings.ContainsAny(p.RPID, "/:* \t\n") || net.ParseIP(p.RPID) != nil {
		return errors.New("WS_PASSKEY_RP_ID must be a domain name without scheme, port or wildcard")
	}
	if len(p.RPID) > 253 {
		return errors.New("WS_PASSKEY_RP_ID is too long")
	}
	for _, label := range strings.Split(p.RPID, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("WS_PASSKEY_RP_ID contains an invalid domain label")
		}
		for _, char := range label {
			validCharacter := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-'
			if !validCharacter {
				return errors.New("WS_PASSKEY_RP_ID must use ASCII domain labels (punycode for IDNs)")
			}
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(p.RPID); suffix == p.RPID && p.RPID != "localhost" {
		return errors.New("WS_PASSKEY_RP_ID cannot be a public suffix")
	}
	for _, origin := range p.Origins {
		u, err := url.Parse(origin)
		if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return fmt.Errorf("WS_PASSKEY_ORIGINS contains an invalid origin: %q", origin)
		}
		host := u.Hostname()
		if host != p.RPID && !strings.HasSuffix(host, "."+p.RPID) {
			return errors.New("WS_PASSKEY_ORIGINS must belong to WS_PASSKEY_RP_ID")
		}
		secure := u.Scheme == "https" || u.Scheme == "http" && !prod && host == "localhost"
		if !secure {
			return errors.New("WS_PASSKEY_ORIGINS requires HTTPS, except localhost in development")
		}
	}
	return nil
}
