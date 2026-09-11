// Package mailer delivers account verification and invitation messages over TLS.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"whatserver2/internal/config"
)

type Sender struct {
	Config config.SMTP
	AppURL string
}

func (s Sender) SignupVerification(ctx context.Context, email, token string) error {
	link, err := accountLink(s.AppURL, url.Values{"email": {email}, "verification": {token}})
	if err != nil {
		return err
	}
	return s.send(ctx, email, "Confirm your Wappie account", "Confirm your email to create your Wappie account and personal workspace.\n\n"+link+"\n\nOr paste this verification code into Wappie:\n"+token+"\n\nThis link expires in 30 minutes. If you did not request it, ignore this email.\n")
}

func (s Sender) WorkspaceInvite(ctx context.Context, email, code, workspace string) error {
	link, err := accountLink(s.AppURL, url.Values{"invite": {code}, "email": {email}})
	if err != nil {
		return err
	}
	return s.send(ctx, email, "Wappie workspace invitation", "You have been invited to join "+workspace+" on Wappie.\n\n"+link+"\n\nInvitation code:\n"+code+"\n\nSign in with this email address, or create your account. A new account includes a personal workspace. This invitation expires in 7 days.\n")
}

func accountLink(base string, values url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "localhost")) {
		return "", errors.New("mailer: invalid browser origin")
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/console", "", "signup=1", values.Encode()
	return u.String(), nil
}

func message(from, recipient, subject, body string) ([]byte, string, string, error) {
	if strings.ContainsAny(from+recipient+subject, "\r\n") {
		return nil, "", "", errors.New("mailer: invalid header")
	}
	f, err := mail.ParseAddress(from)
	if err != nil {
		return nil, "", "", errors.New("mailer: invalid sender")
	}
	r, err := mail.ParseAddress(recipient)
	if err != nil {
		return nil, "", "", errors.New("mailer: invalid recipient")
	}
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	data := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s", f.String(), r.String(), mime.QEncoding.Encode("UTF-8", subject), body)
	return []byte(data), f.Address, r.Address, nil
}

func (s Sender) send(ctx context.Context, email, subject, body string) error {
	data, from, to, err := message(s.Config.From, email, subject, body)
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(s.Config.Address)
	if err != nil {
		return errors.New("mailer: invalid SMTP address")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	switch s.Config.TLSMode {
	case "implicit":
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", s.Config.Address)
	case "starttls":
		conn, err = dialer.DialContext(ctx, "tcp", s.Config.Address)
	default:
		return errors.New("mailer: TLS is required")
	}
	if err != nil {
		return errors.New("mailer: SMTP connection failed")
	}
	defer conn.Close() //nolint:errcheck // Best-effort connection cleanup.
	stop := context.AfterFunc(ctx, func() {
		//nolint:errcheck // Cancellation only interrupts pending SMTP I/O.
		_ = conn.Close()
	})
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return errors.New("mailer: SMTP deadline failed")
		}
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return errors.New("mailer: SMTP handshake failed")
	}
	defer client.Close() //nolint:errcheck // Best-effort SMTP cleanup.
	if s.Config.TLSMode == "starttls" {
		if err := client.StartTLS(tlsConfig); err != nil {
			return errors.New("mailer: SMTP requires verified TLS")
		}
	}
	if s.Config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.Config.Username, s.Config.Password, host)); err != nil {
			return errors.New("mailer: SMTP authentication failed")
		}
	}
	if err := client.Mail(from); err != nil {
		return errors.New("mailer: sender rejected")
	}
	if err := client.Rcpt(to); err != nil {
		return errors.New("mailer: recipient rejected")
	}
	w, err := client.Data()
	if err != nil {
		return errors.New("mailer: message rejected")
	}
	if _, err := w.Write(data); err != nil {
		return errors.New("mailer: message delivery failed")
	}
	if err := w.Close(); err != nil {
		return errors.New("mailer: message delivery failed")
	}
	// DATA acceptance is success; a failed QUIT must not provoke duplicate mail.
	//nolint:errcheck // The accepted message is already delivered to the relay.
	_ = client.Quit()
	return nil
}
