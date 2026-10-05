package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strings"

	"github.com/thehappieco/kit/oidcrp"
)

// LocalLogin is what remains of the installation's own password sign-in once
// an identity provider is configured.
type LocalLogin string

const (
	// LocalLoginOn keeps every password route: the self-hosted default, and
	// the cloud's "both doors" while accounts are being linked.
	LocalLoginOn LocalLogin = "on"
	// LocalLoginLinkOnly keeps only what the browser's link ceremony needs:
	// the challenge (a salt to derive the old password's keys with) and the
	// link routes. Signing in, signing up, recovery, passkeys and credential
	// changes answer local_login_disabled.
	LocalLoginLinkOnly LocalLogin = "link_only"
	// LocalLoginOff refuses every password route.
	LocalLoginOff LocalLogin = "off"
)

// PlatformProduct is the product label of Wappie's key at the provider: its
// keys are "wappie:<epoch>".
const PlatformProduct = "wappie"

// Platform is sign-in through an external identity provider: The Happie Co's
// id. for the hosted cloud. Empty Issuer is off, the self-hosted default:
// nothing of it is mounted and every legacy route behaves as before.
type Platform struct {
	// Issuer is the provider's origin exactly, as its ID tokens name it:
	// https://id.thehappie.co, or http://id.thehappie.localhost:8290 in
	// development.
	Issuer string
	// ClientID is this installation's client at the provider (wappie-app).
	ClientID string
	// AppOrigin is the one page origin that may post a sign-in to this
	// server; by default the origin of WS_APP_URL.
	AppOrigin string
	// IDAddr, development only, is the address the userinfo request dials:
	// *.localhost is not a name Go resolves, so the request goes there while
	// its Host header still names the issuer.
	IDAddr string
	// LocalLogin is on unless set.
	LocalLogin LocalLogin
	// AlertEmail, when set and mail is configured, also receives the alert
	// raised when a sign-in presents another account key than the pinned one.
	AlertEmail string
}

// Enabled reports whether sign-in through the provider is configured.
func (p Platform) Enabled() bool { return p.Issuer != "" }

func loadPlatform(appURL string) Platform {
	p := Platform{
		Issuer:     strings.TrimSpace(os.Getenv("WS_PLATFORM_ISSUER")),
		ClientID:   strings.TrimSpace(os.Getenv("WS_PLATFORM_CLIENT_ID")),
		AppOrigin:  strings.TrimSpace(os.Getenv("WS_PLATFORM_APP_ORIGIN")),
		IDAddr:     strings.TrimSpace(os.Getenv("WS_PLATFORM_ID_ADDR")),
		LocalLogin: LocalLogin(strings.TrimSpace(str("WS_LOCAL_LOGIN", string(LocalLoginOn)))),
		AlertEmail: strings.TrimSpace(os.Getenv("WS_SECURITY_ALERT_EMAIL")),
	}
	if p.AppOrigin == "" && p.Issuer != "" && appURL != "" {
		if u, err := url.Parse(appURL); err == nil && u.Scheme != "" && u.Host != "" {
			p.AppOrigin = u.Scheme + "://" + u.Host
		}
	}
	return p
}

// Validate refuses a half or unsafe configuration: an issuer that is not a
// bare origin (https in prod), no client id or page origin beside it, the
// development dial address in prod, and a local login narrowed with no
// provider to sign in with instead.
func (p Platform) Validate(prod bool, mailConfigured bool) error {
	var errs []error
	switch p.LocalLogin {
	case LocalLoginOn, LocalLoginLinkOnly, LocalLoginOff:
	default:
		errs = append(errs, fmt.Errorf("WS_LOCAL_LOGIN: want on, link_only or off, got %q", p.LocalLogin))
	}
	if p.Issuer == "" {
		if p.LocalLogin == LocalLoginLinkOnly || p.LocalLogin == LocalLoginOff {
			errs = append(errs, errors.New("WS_LOCAL_LOGIN=link_only or off needs WS_PLATFORM_ISSUER: nobody could sign in otherwise"))
		}
		if p.ClientID != "" || p.IDAddr != "" || p.AppOrigin != "" {
			errs = append(errs, errors.New("WS_PLATFORM_CLIENT_ID, WS_PLATFORM_APP_ORIGIN and WS_PLATFORM_ID_ADDR need WS_PLATFORM_ISSUER"))
		}
		if p.AlertEmail != "" {
			errs = append(errs, errors.New("WS_SECURITY_ALERT_EMAIL needs WS_PLATFORM_ISSUER"))
		}
		return errors.Join(errs...)
	}
	client := oidcrp.Client{Issuer: p.Issuer, ClientID: p.ClientID, Product: PlatformProduct}
	if err := client.Check(); err != nil {
		errs = append(errs, fmt.Errorf("WS_PLATFORM_ISSUER / WS_PLATFORM_CLIENT_ID: %w", err))
	}
	if prod && !strings.HasPrefix(p.Issuer, "https://") {
		errs = append(errs, errors.New("WS_PLATFORM_ISSUER must be https in prod"))
	}
	if err := checkPageOrigin(p.AppOrigin, prod); err != nil {
		errs = append(errs, err)
	}
	if p.IDAddr != "" {
		if prod {
			errs = append(errs, errors.New("WS_PLATFORM_ID_ADDR is for development only and is refused in prod"))
		} else if host, port, err := net.SplitHostPort(p.IDAddr); err != nil || host == "" || port == "" {
			errs = append(errs, errors.New("WS_PLATFORM_ID_ADDR must be host:port"))
		}
	}
	if p.AlertEmail != "" {
		if a, err := mail.ParseAddress(p.AlertEmail); err != nil || a.Address != p.AlertEmail {
			errs = append(errs, errors.New("WS_SECURITY_ALERT_EMAIL must be a bare e-mail address"))
		} else if !mailConfigured {
			errs = append(errs, errors.New("WS_SECURITY_ALERT_EMAIL needs a configured mail sender (WS_SMTP_ADDR, WS_MAIL_FROM, WS_APP_URL)"))
		}
	}
	return errors.Join(errs...)
}

// checkPageOrigin requires the exact origin browsers send: scheme, lowercase
// host and port only; https, or in development http on a loopback or
// *.localhost host.
func checkPageOrigin(raw string, prod bool) error {
	invalid := errors.New("WS_PLATFORM_APP_ORIGIN (or the origin of WS_APP_URL) must be the console's exact origin, https in prod")
	if raw == "" {
		return invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || u.ForceQuery || u.Scheme+"://"+u.Host != raw || strings.ToLower(raw) != raw {
		return invalid
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !prod && devHost(u.Hostname()) {
			return nil
		}
	}
	return invalid
}

// devHost is a host plain http is acceptable on in development: localhost, a
// *.localhost name (RFC 6761), or a loopback address.
func devHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// String says whether the provider is on and what remains of local login,
// for the startup line. The issuer is public; nothing here is secret.
func (p Platform) String() string {
	if !p.Enabled() {
		return "platform_login=off local_login=" + string(p.LocalLogin)
	}
	return "platform_login=on platform_issuer=" + p.Issuer + " local_login=" + string(p.LocalLogin)
}
