package config

import (
	"encoding/hex"
	"errors"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// Signup is opt-in. Mail links use an explicit browser URL, never Host headers.
type Signup struct {
	Enabled             bool
	AppURL              string
	InviteEncryptionKey []byte
	SMTP                SMTP
}

type SMTP struct {
	Address  string
	Username string
	Password string
	From     string
	TLSMode  string // starttls or implicit; cleartext is never supported
}

func (s SMTP) Configured() bool { return s.Address != "" && s.From != "" }

func loadSignup(errs *[]error) Signup {
	s := Signup{
		Enabled: boolean("WS_PUBLIC_SIGNUP", false, errs),
		AppURL:  strings.TrimSpace(os.Getenv("WS_APP_URL")),
		SMTP:    SMTP{Address: strings.TrimSpace(os.Getenv("WS_SMTP_ADDR")), Username: os.Getenv("WS_SMTP_USERNAME"), Password: os.Getenv("WS_SMTP_PASSWORD"), From: strings.TrimSpace(os.Getenv("WS_MAIL_FROM")), TLSMode: str("WS_SMTP_TLS", "starttls")},
	}
	if value := os.Getenv("WS_INVITE_ENCRYPTION_KEY_HEX"); value != "" {
		key, err := hex.DecodeString(value)
		if err != nil || len(key) != 32 {
			*errs = append(*errs, errors.New("WS_INVITE_ENCRYPTION_KEY_HEX must be a 32-byte hex key"))
		} else {
			s.InviteEncryptionKey = key
		}
	}
	return s
}

func (s Signup) Validate(prod bool) error {
	var errs []error
	if s.AppURL != "" {
		if _, err := AccountBrowserOrigin(s.AppURL, !prod && !s.SMTP.Configured()); err != nil {
			errs = append(errs, err)
		}
	}
	mailSet := s.SMTP.Address != "" || s.SMTP.From != "" || s.SMTP.Username != "" || s.SMTP.Password != ""
	if mailSet {
		if !s.SMTP.Configured() || s.AppURL == "" {
			errs = append(errs, errors.New("mail requires WS_SMTP_ADDR, WS_MAIL_FROM and WS_APP_URL"))
		}
		if host, port, err := net.SplitHostPort(s.SMTP.Address); err != nil || host == "" || port == "" {
			errs = append(errs, errors.New("WS_SMTP_ADDR must be host:port"))
		}
		if _, err := mail.ParseAddress(s.SMTP.From); err != nil || strings.ContainsAny(s.SMTP.From, "\r\n") {
			errs = append(errs, errors.New("WS_MAIL_FROM must be a valid sender address"))
		}
		if (s.SMTP.Username == "") != (s.SMTP.Password == "") {
			errs = append(errs, errors.New("WS_SMTP_USERNAME and WS_SMTP_PASSWORD must be configured together"))
		}
		if s.SMTP.TLSMode != "starttls" && s.SMTP.TLSMode != "implicit" {
			errs = append(errs, errors.New("WS_SMTP_TLS must be starttls or implicit"))
		}
	}
	if s.Enabled && !s.SMTP.Configured() {
		errs = append(errs, errors.New("WS_PUBLIC_SIGNUP requires a configured verification mail sender"))
	}
	return errors.Join(errs...)
}

// AccountBrowserOrigin is shared by configuration and every email template.
// Local browser origins are useful without mail in development, but an email
// recipient must never be sent to their own computer, even by a local sender.
func AccountBrowserOrigin(raw string, allowLocal bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	invalid := errors.New("WS_APP_URL must be an HTTPS browser origin; localhost links cannot be sent by email")
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, invalid
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return nil, invalid
	}
	local := host == "localhost" || strings.HasSuffix(host, ".localhost")
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		local = local || ip.Unmap().IsLoopback() || ip.IsUnspecified()
	} else if numericHost(host) {
		// Browsers interpret abbreviated, octal and hexadecimal IPv4 forms
		// differently from net/url. Require canonical IP literals instead.
		return nil, invalid
	}
	secure := u.Scheme == "https" || allowLocal && local && u.Scheme == "http"
	if !secure || local && !allowLocal {
		return nil, invalid
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

func numericHost(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		allowed := "0123456789"
		if strings.HasPrefix(label, "0x") {
			label = label[2:]
			allowed += "abcdef"
		}
		if label == "" || strings.Trim(label, allowed) != "" {
			return false
		}
	}
	return true
}

// String prevents accidental logging of mail credentials or invite secrets.
func (s Signup) String() string {
	if s.Enabled {
		return "signup=enabled"
	}
	return "signup=invite-only"
}
func (s SMTP) String() string {
	if s.Configured() {
		return "smtp=configured"
	}
	return "smtp=unconfigured"
}
