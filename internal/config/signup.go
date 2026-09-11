package config

import (
	"encoding/hex"
	"errors"
	"net"
	"net/mail"
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
		u, err := url.Parse(s.AppURL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && (prod || u.Scheme != "http" || u.Hostname() != "localhost")) {
			errs = append(errs, errors.New("WS_APP_URL must be an HTTPS browser origin (localhost HTTP is allowed in development)"))
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
