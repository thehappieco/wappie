package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/config"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
)

// alertConfig is a configuration with an operator address, a mail server
// and the deletion ledger in dir, and no sign-in through the platform.
func alertConfig(dir string) config.Config {
	return config.Config{
		Platform: config.Platform{AlertEmail: "ops@example.test"},
		Signup:   config.Signup{SMTP: config.SMTP{Address: "smtp.example.test:587", From: "Wappie <alerts@example.test>", TLSMode: "starttls"}},
		Deletion: config.Deletion{Ledger: filepath.Join(dir, "deletion-ledger.jsonl")},
		MCP:      enclaveConfig(),
	}
}

// startLines are the start lines readerClockAlerts logs.
func startLines(t *testing.T, cfg config.Config) (*mcpauth.ClockAlerts, string) {
	t.Helper()
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	alerts := readerClockAlerts(cfg, lg)
	return alerts, buf.String()
}

// The alerts are on with an address, a mail server and a state directory,
// platform sign-in or not, and off with why otherwise; either way one line
// says so.
func TestReaderClockAlertsOnOff(t *testing.T) {
	dir := t.TempDir()
	alerts, log := startLines(t, alertConfig(dir))
	if alerts == nil || alerts.Dir != dir || alerts.Mail == nil ||
		!strings.Contains(log, `msg="reader clock alerts on"`) || strings.Count(log, "\n") != 1 {
		t.Fatalf("on: %+v\n%s", alerts, log)
	}
	for _, tc := range []struct {
		name   string
		change func(*config.Config)
		reason string
	}{
		{"no address", func(c *config.Config) { c.Platform.AlertEmail = "" }, "WS_SECURITY_ALERT_EMAIL"},
		{"no mail server", func(c *config.Config) { c.Signup.SMTP = config.SMTP{} }, "WS_SMTP_ADDR"},
		{"no state directory", func(c *config.Config) { c.Deletion.Ledger = "" }, "WS_DELETION_LEDGER"},
		{"no connector", func(c *config.Config) { c.MCP = config.MCP{} }, "the assistant connector is off"},
	} {
		cfg := alertConfig(dir)
		tc.change(&cfg)
		alerts, log := startLines(t, cfg)
		if alerts != nil || !strings.Contains(log, `msg="reader clock alerts off"`) || !strings.Contains(log, tc.reason) ||
			strings.Count(log, "\n") != 1 {
			t.Errorf("%s: %+v\n%s", tc.name, alerts, log)
		}
	}
}

// reader-alert-test refuses without an address or a mail server, sends the
// test alert to the operator's address once, and refuses a second run with
// when the next is allowed.
func TestReaderAlertTestCommand(t *testing.T) {
	dir := t.TempDir()
	var to []string
	send := func(_ context.Context, addr string) error { to = append(to, addr); return nil }
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	for _, change := range []func(*config.Config){
		func(c *config.Config) { c.Platform.AlertEmail = "" },
		func(c *config.Config) { c.Signup.SMTP.Address = "" },
	} {
		cfg := alertConfig(dir)
		change(&cfg)
		var exit exitError
		if err := runReaderAlertTest(context.Background(), cfg, now, send, &bytes.Buffer{}); !errors.As(err, &exit) || exit.code != 1 ||
			!strings.Contains(err.Error(), "refused") {
			t.Fatalf("refusal: %v", err)
		}
	}
	if len(to) != 0 {
		t.Fatalf("sent while refusing: %v", to)
	}

	var out bytes.Buffer
	if err := runReaderAlertTest(context.Background(), alertConfig(dir), now, send, &out); err != nil {
		t.Fatal(err)
	}
	if len(to) != 1 || to[0] != "ops@example.test" || !strings.Contains(out.String(), "Wappie reader alert: test") {
		t.Fatalf("sent to %v: %s", to, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, mcpauth.ReaderAlertsTestFile)); err != nil {
		t.Fatalf("no test state: %v", err)
	}
	err := runReaderAlertTest(context.Background(), alertConfig(dir), now.Add(time.Hour), send, &out)
	var exit exitError
	if !errors.As(err, &exit) || exit.code != 1 || !strings.Contains(err.Error(), "next is allowed after 2026-11-20T11:00:00Z") || len(to) != 1 {
		t.Fatalf("second run: %v (%d sent)", err, len(to))
	}
	if _, err := os.Stat(filepath.Join(dir, mcpauth.ReaderAlertsFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the real alerts' state was touched: %v", err)
	}
}

// reader-alert-test takes no argument, and a stray one opens nothing.
func TestReaderAlertTestTakesNoArguments(t *testing.T) {
	var usage usageError
	if err := runCommand([]string{"reader-alert-test", "--now"}, func() error { return errors.New("served") }); !errors.As(err, &usage) {
		t.Fatalf("err = %v", err)
	}
}

// serve hands the MCP handler the alerts when an address and a mail server
// are set, with no platform sign-in, and none otherwise.
func TestServeWiresClockAlerts(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ledger := filepath.Join(t.TempDir(), "deletions.ledger")
	commandEnv(t, pool, ledger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, closeAll, err := setup(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	a.cfg.MCP = enclaveConfig()
	a.routes()
	if a.mcp == nil || a.mcp.ClockAlerts != nil {
		t.Fatalf("alerts without an address: %+v", a.mcp)
	}
	a.cfg.Platform = config.Platform{AlertEmail: "ops@example.test"}
	a.cfg.Signup.SMTP = config.SMTP{Address: "smtp.example.test:587", From: "Wappie <alerts@example.test>", TLSMode: "starttls"}
	a.routes()
	if a.mcp.ClockAlerts == nil || a.mcp.ClockAlerts.Dir != filepath.Dir(ledger) || a.platform != nil {
		t.Fatalf("alerts %+v, platform %v", a.mcp.ClockAlerts, a.platform)
	}
}
