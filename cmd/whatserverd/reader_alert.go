package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"whatserver2/internal/config"
	"whatserver2/internal/mailer"
	"whatserver2/internal/mcpauth"
)

// The reader clock alerts (docs/mcp-enclave.md §5.1): built when an
// operator address (WS_SECURITY_ALERT_EMAIL) and a mail server are
// configured, whether or not sign-in through the platform is wired, and
// kept in the API unit's state directory, the deletion ledger's.

// readerAlertsOff is why the reader clock alerts are off, or "" when they
// can be on.
func readerAlertsOff(cfg config.Config) string {
	switch {
	case cfg.Platform.AlertEmail == "":
		return "no operator address (WS_SECURITY_ALERT_EMAIL)"
	case !cfg.Signup.SMTP.Configured():
		return "no mail server (WS_SMTP_ADDR, WS_MAIL_FROM)"
	case cfg.Deletion.Ledger == "":
		return "no state directory (WS_DELETION_LEDGER)"
	}
	return ""
}

// readerAlertsDir is where the alerts keep their state.
func readerAlertsDir(cfg config.Config) string { return filepath.Dir(cfg.Deletion.Ledger) }

// readerClockAlerts builds the reader clock alerts, or nil, and logs once
// which: "reader clock alerts on" or "reader clock alerts off" with why.
func readerClockAlerts(cfg config.Config, lg *slog.Logger) *mcpauth.ClockAlerts {
	reason := readerAlertsOff(cfg)
	if reason == "" && !cfg.MCP.Enabled {
		reason = "the assistant connector is off"
	}
	if reason != "" {
		lg.Info("reader clock alerts off", "reason", reason)
		return nil
	}
	sender := mailer.Sender{Config: cfg.Signup.SMTP, AppURL: cfg.Signup.AppURL}
	to := cfg.Platform.AlertEmail
	alerts := &mcpauth.ClockAlerts{
		Dir: readerAlertsDir(cfg), Log: lg,
		Mail: func(ctx context.Context, word string, nums []mailer.ReaderAlertNum) error {
			return sender.ReaderClockAlert(ctx, to, word, nums)
		},
	}
	lg.Info("reader clock alerts on", "readers", len(cfg.MCP.Attested), "dir", alerts.Dir)
	return alerts
}

// readerAlertTest is whatserverd reader-alert-test: it sends the test alert
// to the operator's address, at most once per 23 hours (its own window, in
// reader-alerts-test.json), and refuses without an address and a mail
// server.
func readerAlertTest(args []string, out io.Writer) error {
	if len(args) != 0 {
		return usageError{arg: "reader-alert-test " + args[0]}
	}
	if err := config.LoadDotEnv(".env"); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	sender := mailer.Sender{Config: cfg.Signup.SMTP, AppURL: cfg.Signup.AppURL}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runReaderAlertTest(ctx, cfg, time.Now(), sender.ReaderClockAlertTest, out)
}

// runReaderAlertTest is reader-alert-test with its configuration, clock and
// mail given.
func runReaderAlertTest(ctx context.Context, cfg config.Config, now time.Time, send func(ctx context.Context, to string) error, out io.Writer) error {
	if reason := readerAlertsOff(cfg); reason != "" {
		return exitError{code: 1, err: errors.New("reader-alert-test: refused, " + reason)}
	}
	to := cfg.Platform.AlertEmail
	err := mcpauth.SendReaderAlertTest(ctx, readerAlertsDir(cfg), now, func(ctx context.Context) error { return send(ctx, to) })
	var soon *mcpauth.AlertTooSoonError
	switch {
	case errors.As(err, &soon):
		return exitError{code: 1, err: fmt.Errorf("reader-alert-test: refused, %w", err)}
	case err != nil:
		return exitError{code: 1, err: fmt.Errorf("reader-alert-test: %w", err)}
	}
	//nolint:errcheck // the mail is sent; the line is a courtesy
	fmt.Fprintf(out, "reader-alert-test: sent \"Wappie reader alert: %s\" to WS_SECURITY_ALERT_EMAIL at %s; the next is allowed after %s\n",
		mailer.ReaderAlertTest, now.UTC().Format(time.RFC3339), now.Add(mcpauth.ReaderAlertWindow).UTC().Format(time.RFC3339))
	return nil
}
