package config

import (
	"strings"
	"testing"
	"time"
)

// minimalEnv is the smallest set of variables that must load cleanly.
func minimalEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"WS_POSTGRES_DSN":  "postgres://user:hunter2@localhost:5433/whatserver2?sslmode=disable",
		"WS_S3_BUCKET":     "whatserver2-media",
		"WS_S3_ACCESS_KEY": "whatserver",
		"WS_S3_SECRET_KEY": "devdevdev",
	} {
		t.Setenv(k, v)
	}
}

func TestLoadDefaults(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != EnvDev {
		t.Errorf("Env = %q, want dev", cfg.Env)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.Log.Format != "text" {
		t.Errorf("dev should default to text logs, got %q", cfg.Log.Format)
	}
	// History gets a smaller pool than live on purpose: a bulk backfill must
	// not be able to starve live ingest, which is what SetMaxOpenConns(1) let
	// happen in v1.
	if cfg.Postgres.HistoryConns >= cfg.Postgres.LiveConns {
		t.Errorf("history pool (%d) should be smaller than live (%d)",
			cfg.Postgres.HistoryConns, cfg.Postgres.LiveConns)
	}
}

func TestProdDefaultsToJSONLogs(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_ENV", "prod")
	t.Setenv("WS_POSTGRES_DSN", "postgres://user:hunter2@db/whatserver2")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("prod should default to json logs, got %q", cfg.Log.Format)
	}
}

// The whole point of an env-only loader is that a missing variable stops the
// process instead of silently falling back to something insecure.
func TestRequiredVarsAreRequired(t *testing.T) {
	for _, missing := range []string{
		"WS_POSTGRES_DSN", "WS_S3_BUCKET", "WS_S3_ACCESS_KEY", "WS_S3_SECRET_KEY",
	} {
		t.Run(missing, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv(missing, "")
			if _, err := Load(); err == nil {
				t.Fatalf("Load succeeded without %s", missing)
			}
		})
	}
}

// Load reports every problem at once so a bad deployment is fixable in one
// pass rather than one restart per typo.
func TestLoadReportsAllErrorsAtOnce(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_POSTGRES_DSN", "")
	t.Setenv("WS_S3_BUCKET", "")
	t.Setenv("WS_LOG_LEVEL", "verbose")
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"WS_POSTGRES_DSN", "WS_S3_BUCKET", "WS_LOG_LEVEL"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %s:\n%s", want, msg)
		}
	}
}

func TestInvalidValues(t *testing.T) {
	for name, kv := range map[string][2]string{
		"log level":     {"WS_LOG_LEVEL", "verbose"},
		"log format":    {"WS_LOG_FORMAT", "xml"},
		"env":           {"WS_ENV", "staging"},
		"non-numeric":   {"WS_PG_LIVE_CONNS", "many"},
		"zero conns":    {"WS_PG_LIVE_CONNS", "0"},
		"bad duration":  {"WS_PG_STATEMENT_TIMEOUT", "30 seconds"},
		"zero duration": {"WS_PG_STATEMENT_TIMEOUT", "0s"},
		"bad bool":      {"WS_S3_USE_SSL", "yes-please"},
	} {
		t.Run(name, func(t *testing.T) {
			minimalEnv(t)
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %s=%q", kv[0], kv[1])
			}
		})
	}
}

// Settings that are fine in dev and dangerous in production are checked, not
// merely defaulted.
func TestProdGuards(t *testing.T) {
	t.Run("rejects sslmode=disable", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("WS_ENV", "prod")
		err := mustFail(t)
		if !strings.Contains(err.Error(), "sslmode=disable") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("rejects cleartext object storage", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("WS_ENV", "prod")
		t.Setenv("WS_POSTGRES_DSN", "postgres://user:pw@db/whatserver2")
		t.Setenv("WS_S3_ENDPOINT", "http://minio:9000")
		t.Setenv("WS_S3_USE_SSL", "false")
		err := mustFail(t)
		if !strings.Contains(err.Error(), "cleartext") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("rejects the wire log", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("WS_ENV", "prod")
		t.Setenv("WS_POSTGRES_DSN", "postgres://user:pw@db/whatserver2")
		t.Setenv("WS_LOG_WIRE", "true")
		err := mustFail(t)
		if !strings.Contains(err.Error(), "plaintext") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("allows both in dev", func(t *testing.T) {
		minimalEnv(t)
		t.Setenv("WS_S3_ENDPOINT", "http://localhost:9000")
		t.Setenv("WS_S3_USE_SSL", "false")
		if _, err := Load(); err != nil {
			t.Fatalf("dev should allow local plaintext: %v", err)
		}
	})
}

func mustFail(t *testing.T) error {
	t.Helper()
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error")
	}
	return err
}

// The v1 server logged its whole config, and its config held live secrets.
// Nothing that renders configuration may ever emit a credential.
func TestNoSecretsInRenderedConfig(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_S3_SECRET_KEY", "s3-secret-please-do-not-print")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	rendered := cfg.String() + " " + cfg.Postgres.RedactedDSN()
	for _, secret := range []string{"hunter2", "s3-secret-please-do-not-print", "devdevdev"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("rendered config leaks %q:\n%s", secret, rendered)
		}
	}
	// Redaction must not destroy the parts that make the log useful.
	for _, want := range []string{"localhost:5433", "whatserver2", "user"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered config lost %q, which makes it useless for debugging:\n%s", want, rendered)
		}
	}
}

func TestRedactedDSNEdgeCases(t *testing.T) {
	for name, tc := range map[string]struct{ dsn, wantContains, wantNotContains string }{
		"no password":  {"postgres://user@db/x", "user", "xxxxx"},
		"no user info": {"postgres://db/x", "db", "xxxxx"},
		"unparseable":  {"://:::", "unparseable", ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := Postgres{DSN: tc.dsn}.RedactedDSN()
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("RedactedDSN(%q) = %q, want it to contain %q", tc.dsn, got, tc.wantContains)
			}
			if tc.wantNotContains != "" && strings.Contains(got, tc.wantNotContains) {
				t.Errorf("RedactedDSN(%q) = %q, should not contain %q", tc.dsn, got, tc.wantNotContains)
			}
		})
	}
}

func TestDurationsParse(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_PG_STATEMENT_TIMEOUT", "45s")
	t.Setenv("WS_PG_CONN_MAX_LIFETIME", "2h")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Postgres.StatementTimeout != 45*time.Second {
		t.Errorf("StatementTimeout = %v", cfg.Postgres.StatementTimeout)
	}
	if cfg.Postgres.ConnMaxLifetime != 2*time.Hour {
		t.Errorf("ConnMaxLifetime = %v", cfg.Postgres.ConnMaxLifetime)
	}
}

// Object storage is not required until media exists in phase 4. Demanding
// credentials for an unimplemented subsystem is friction with no safety
// benefit, and it blocked commands that never touch storage at all.
func TestStorageIsOptional(t *testing.T) {
	t.Setenv("WS_POSTGRES_DSN", "postgres://user:pw@localhost:5432/db?sslmode=disable")
	for _, k := range []string{"WS_S3_BUCKET", "WS_S3_ACCESS_KEY", "WS_S3_SECRET_KEY"} {
		t.Setenv(k, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load should succeed without object storage: %v", err)
	}
	if cfg.Storage.Configured {
		t.Error("Configured should be false when nothing is set")
	}
	if !strings.Contains(cfg.String(), "unconfigured") {
		t.Errorf("the startup line should say storage is unconfigured: %s", cfg.String())
	}
}

// All three or none. A bucket with no credentials is a mistake worth catching
// at boot rather than at the first upload.
func TestHalfConfiguredStorageIsRejected(t *testing.T) {
	for name, set := range map[string][]string{
		"bucket only":      {"WS_S3_BUCKET"},
		"credentials only": {"WS_S3_ACCESS_KEY", "WS_S3_SECRET_KEY"},
		"missing secret":   {"WS_S3_BUCKET", "WS_S3_ACCESS_KEY"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("WS_POSTGRES_DSN", "postgres://user:pw@localhost:5432/db?sslmode=disable")
			for _, k := range []string{"WS_S3_BUCKET", "WS_S3_ACCESS_KEY", "WS_S3_SECRET_KEY"} {
				t.Setenv(k, "")
			}
			for _, k := range set {
				t.Setenv(k, "value")
			}
			_, err := Load()
			if err == nil {
				t.Fatal("a half-configured store was accepted")
			}
			if !strings.Contains(err.Error(), "half configured") {
				t.Errorf("error should explain: %v", err)
			}
		})
	}
}

func TestFullyConfiguredStorage(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Storage.Configured {
		t.Error("Configured should be true when all three are set")
	}
}
