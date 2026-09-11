// Package config loads configuration from the environment.
//
// Environment only, deliberately. The v1 server read a config.yaml that was
// tracked in git, and that file ended up holding a live api_key and a real
// media_signing_key_hex. A file that is convenient to edit is a file that gets
// committed. Secrets here arrive through the process environment and are never
// written back out, and String() redacts them so a debug log cannot leak one.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env      Env
	HTTPAddr string
	// MetricsAddr serves /metrics, /healthz and /readyz on a listener of
	// their own when set, so the public port carries only what clients need
	// and the probes stay on the private network. Empty keeps them on
	// HTTPAddr, which is right for a single-host deployment behind nothing.
	MetricsAddr string
	// TrustedProxies are the addresses whose X-Forwarded-For header names
	// the real client. Empty means the connection's own address is the
	// client, which is right for a server exposed directly and wrong behind
	// a reverse proxy — where every caller would then share one rate limit.
	TrustedProxies []netip.Prefix
	Postgres       Postgres
	Storage        Storage
	Web            Web
	Passkeys       Passkeys
	Signup         Signup
	Log            Log
}

// Web is the browser client, served as files from disk.
//
// Not embedded in the binary. Embedding would make `go build` depend on a
// frontend toolchain being installed, and CI has no Node; serving from a
// directory keeps the two builds independent and lets the client be replaced
// without restarting the server.
type Web struct {
	// Dir holds the built client. Empty, or a directory that does not exist,
	// means the server runs headless and says so once at boot rather than
	// answering every request with a mystery 404.
	Dir string
}

type Env string

const (
	EnvDev  Env = "dev"
	EnvProd Env = "prod"
)

func (e Env) IsProd() bool { return e == EnvProd }

type Postgres struct {
	// DSN carries credentials. Never log it directly; use RedactedDSN.
	DSN string

	// Three pools, sized for three very different workloads. The v1 server
	// ran a single SQLite connection (SetMaxOpenConns(1)) and a 10k-message
	// history sync would monopolise it, stalling live traffic and sends
	// alike. Separate pools make that impossible by construction.
	LiveConns    int32 // ingest and websocket fan-out: latency sensitive
	HistoryConns int32 // bulk backfill: throughput oriented, deliberately capped
	APIConns     int32 // REST handlers

	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
	StatementTimeout time.Duration
}

type Storage struct {
	// Configured reports whether object storage is usable. False is legal
	// until media exists; the server logs that media is disabled and carries
	// on.
	Configured bool

	Endpoint  string // empty means real AWS S3
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool

	// MaxMediaBytes bounds one attachment.
	//
	// A ceiling is not optional. The length in a message is the sender's
	// claim, not a measured fact, and nothing stops a hostile one announcing
	// eight kilobytes and then serving until the disk is full.
	MaxMediaBytes int64
}

type Log struct {
	Level  string // debug | info | warn | error
	Format string // json | text
	// Wire includes whatsmeow's own debug output, which is every protocol
	// node in both directions — message bodies in the clear. Development
	// only; Load refuses it in prod, because a log level is a knob somebody
	// turns during an incident and this one would put everybody's messages
	// into whatever collects the logs.
	Wire bool
}

// Load reads configuration from the environment and validates it.
//
// It returns every problem at once rather than the first: a misconfigured
// deployment should be fixable in one pass, not one restart per typo.
func Load() (Config, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	env := Env(str("WS_ENV", string(EnvDev)))
	if env != EnvDev && env != EnvProd {
		bad("WS_ENV: want %q or %q, got %q", EnvDev, EnvProd, env)
	}

	cfg := Config{
		Signup:         loadSignup(&errs),
		Passkeys:       Passkeys{RPID: strings.TrimSpace(os.Getenv("WS_PASSKEY_RP_ID"))},
		Env:            env,
		HTTPAddr:       str("WS_HTTP_ADDR", ":8080"),
		MetricsAddr:    os.Getenv("WS_METRICS_ADDR"),
		TrustedProxies: prefixes("WS_TRUSTED_PROXIES", &errs),
		Postgres: Postgres{
			DSN:              os.Getenv("WS_POSTGRES_DSN"),
			LiveConns:        conns("WS_PG_LIVE_CONNS", 16, &errs),
			HistoryConns:     conns("WS_PG_HISTORY_CONNS", 4, &errs),
			APIConns:         conns("WS_PG_API_CONNS", 16, &errs),
			ConnMaxLifetime:  dur("WS_PG_CONN_MAX_LIFETIME", time.Hour, &errs),
			ConnMaxIdleTime:  dur("WS_PG_CONN_MAX_IDLE", 30*time.Minute, &errs),
			StatementTimeout: dur("WS_PG_STATEMENT_TIMEOUT", 30*time.Second, &errs),
		},
		Storage: Storage{
			Endpoint:  os.Getenv("WS_S3_ENDPOINT"),
			Region:    str("WS_S3_REGION", "us-east-1"),
			Bucket:    os.Getenv("WS_S3_BUCKET"),
			AccessKey: os.Getenv("WS_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("WS_S3_SECRET_KEY"),
			UseSSL:    boolean("WS_S3_USE_SSL", true, &errs),
			// WhatsApp's own ceiling is 2 GB for documents; this default is
			// well under it because most deployments would rather refuse a
			// two gigabyte attachment than store one.
			MaxMediaBytes: bytes("WS_MEDIA_MAX_BYTES", 256<<20, &errs),
		},
		Web: Web{
			Dir: str("WS_WEB_DIR", "web/dist"),
		},
		Log: Log{
			Level:  strings.ToLower(str("WS_LOG_LEVEL", "info")),
			Format: strings.ToLower(str("WS_LOG_FORMAT", defaultLogFormat(env))),
			Wire:   boolean("WS_LOG_WIRE", false, &errs),
		},
	}
	for _, origin := range strings.Split(os.Getenv("WS_PASSKEY_ORIGINS"), ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			cfg.Passkeys.Origins = append(cfg.Passkeys.Origins, origin)
		}
	}
	if err := cfg.Passkeys.Validate(env.IsProd()); err != nil {
		errs = append(errs, err)
	}
	if err := cfg.Signup.Validate(env.IsProd()); err != nil {
		errs = append(errs, err)
	}

	if cfg.Postgres.DSN == "" {
		bad("WS_POSTGRES_DSN is required")
	} else if _, err := url.Parse(cfg.Postgres.DSN); err != nil {
		bad("WS_POSTGRES_DSN is not a valid URL: %v", err)
	}
	// Object storage is not required yet: media lands in phase 4 and nothing
	// reads this until then. Demanding credentials for an unimplemented
	// subsystem is friction with no safety benefit.
	//
	// It is all-or-nothing, though. A half-configured deployment — a bucket
	// with no credentials, say — is a mistake worth catching now rather than
	// at the first upload.
	switch n := countSet(cfg.Storage.Bucket, cfg.Storage.AccessKey, cfg.Storage.SecretKey); n {
	case 0:
		cfg.Storage.Configured = false
	case 3:
		cfg.Storage.Configured = true
	default:
		bad("object storage is half configured: set all of WS_S3_BUCKET, " +
			"WS_S3_ACCESS_KEY and WS_S3_SECRET_KEY, or none of them")
	}
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		bad("WS_LOG_LEVEL: want debug|info|warn|error, got %q", cfg.Log.Level)
	}
	switch cfg.Log.Format {
	case "json", "text":
	default:
		bad("WS_LOG_FORMAT: want json|text, got %q", cfg.Log.Format)
	}

	// Production-only guards. These are the settings that are harmless in dev
	// and dangerous in prod, so they are checked rather than merely defaulted.
	if env.IsProd() {
		if cfg.Storage.Configured && !cfg.Storage.UseSSL && cfg.Storage.Endpoint != "" {
			bad("WS_S3_USE_SSL: refusing to talk to object storage in cleartext in prod")
		}
		if strings.Contains(cfg.Postgres.DSN, "sslmode=disable") {
			bad("WS_POSTGRES_DSN: sslmode=disable is not allowed in prod")
		}
		if cfg.Log.Wire {
			bad("WS_LOG_WIRE: the WhatsApp wire log carries message plaintext " +
				"and is not allowed in prod")
		}
	}

	if len(errs) > 0 {
		return Config{}, fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return cfg, nil
}

func defaultLogFormat(e Env) string {
	if e.IsProd() {
		return "json"
	}
	return "text"
}

// RedactedDSN returns the Postgres DSN with the password replaced, for logs.
func (p Postgres) RedactedDSN() string {
	u, err := url.Parse(p.DSN)
	if err != nil {
		return "<unparseable>"
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.String()
}

// String renders the configuration for startup logs with every secret removed.
func (c Config) String() string {
	return fmt.Sprintf(
		"env=%s http=%s postgres=%s pools=live:%d/history:%d/api:%d s3=%s/%s log=%s/%s",
		c.Env, c.HTTPAddr, c.Postgres.RedactedDSN(),
		c.Postgres.LiveConns, c.Postgres.HistoryConns, c.Postgres.APIConns,
		orDefault(c.Storage.Endpoint, "aws"), orDefault(c.Storage.Bucket, "unconfigured"),
		c.Log.Level, c.Log.Format,
	)
}

// countSet reports how many of the given values are non-empty.
func countSet(values ...string) int {
	n := 0
	for _, v := range values {
		if v != "" {
			n++
		}
	}
	return n
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func str(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// maxConns bounds the pool sizes. The ceiling is not arbitrary: it keeps the
// value inside int32 so the conversion below cannot overflow, and a pool larger
// than this would exhaust Postgres max_connections long before it helped.
const maxConns = 10_000

// conns parses a pool size, validating the range so the int32 conversion is
// safe by construction instead of by assumption.
func conns(key string, def int32, errs *[]error) int32 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %q is not a number", key, v))
		return def
	}
	if n < 1 || n > maxConns {
		*errs = append(*errs, fmt.Errorf("%s: must be between 1 and %d, got %d", key, maxConns, n))
		return def
	}
	// Safe by construction: n was just bounded to [1, maxConns].
	//nolint:gosec // G109: range checked immediately above
	return int32(n)
}

func dur(key string, def time.Duration, errs *[]error) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %q is not a duration (try 30s, 5m, 1h)", key, v))
		return def
	}
	if d <= 0 {
		*errs = append(*errs, fmt.Errorf("%s: must be positive, got %v", key, d))
		return def
	}
	return d
}

// bytes reads a byte count, accepting a plain number or a K/M/G suffix.
func bytes(key string, def int64, errs *[]error) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	mult := int64(1)
	switch last := raw[len(raw)-1]; last {
	case 'k', 'K':
		mult, raw = 1<<10, raw[:len(raw)-1]
	case 'm', 'M':
		mult, raw = 1<<20, raw[:len(raw)-1]
	case 'g', 'G':
		mult, raw = 1<<30, raw[:len(raw)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n <= 0 {
		*errs = append(*errs, fmt.Errorf("%s: want a positive byte count, "+
			"optionally suffixed K, M or G, got %q", key, os.Getenv(key)))
		return def
	}
	return n * mult
}

// prefixes reads a comma-separated list of addresses or CIDR blocks.
func prefixes(key string, errs *[]error) []netip.Prefix {
	var out []netip.Prefix
	for _, part := range strings.Split(os.Getenv(key), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %q is not an address or a CIDR block", key, part))
			continue
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out
}

func boolean(key string, def bool, errs *[]error) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %q is not a boolean", key, v))
		return def
	}
	return b
}
