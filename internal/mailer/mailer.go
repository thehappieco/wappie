// Package mailer delivers account verification and invitation messages over TLS.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"net/url"
	"time"

	"whatserver2/internal/config"
)

type Sender struct {
	Config config.SMTP
	AppURL string
}

func (s Sender) SignupVerification(ctx context.Context, email, token string) error {
	model, err := signupEmail(s.AppURL, email, token)
	if err != nil {
		return err
	}
	return s.send(ctx, email, model)
}

func (s Sender) WorkspaceInvite(ctx context.Context, email, code, workspace string) error {
	model, err := invitationEmail(s.AppURL, email, code, workspace)
	if err != nil {
		return err
	}
	return s.send(ctx, email, model)
}

func accountLink(base string, values url.Values) (string, error) {
	u, err := config.AccountBrowserOrigin(base, false)
	if err != nil {
		return "", errors.New("mailer: invalid browser origin")
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/console", "", "signup=1", values.Encode()
	return u.String(), nil
}

func (s Sender) send(ctx context.Context, email string, model accountEmail) error {
	data, from, to, err := message(s.Config.From, email, model)
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
