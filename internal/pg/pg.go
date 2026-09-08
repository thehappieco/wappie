// Package pg owns the Postgres connection pools and the tenant transaction
// helper that row-level security depends on.
//
// Two decisions are load-bearing here.
//
// Three pools, not one. The v1 server ran SQLite with SetMaxOpenConns(1), so a
// history sync of ten thousand messages held the only connection and stalled
// live ingest, websocket fan-out and outbound sends behind it. Splitting the
// work across pools sized for their workload makes that starvation impossible
// rather than merely unlikely.
//
// Tenant isolation is enforced by the database, not by remembering to write a
// WHERE clause. Every tenant-scoped query runs inside InTenantTx, which sets a
// transaction-local GUC that the RLS policies read. A handler that forgets the
// filter returns zero rows instead of another tenant's messages.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"whatserver2/internal/config"
)

// TenantGUC is the session variable RLS policies read. It is referenced by the
// SQL migrations too, so changing it means changing both.
const TenantGUC = "app.tenant_id"

// Pools holds the three workload-specific pools.
type Pools struct {
	// Live carries ingest and websocket fan-out. Latency sensitive.
	Live *pgxpool.Pool
	// History carries bulk backfill. Deliberately the smallest pool: it is
	// throughput work that must never crowd out Live.
	History *pgxpool.Pool
	// API carries REST handlers.
	API *pgxpool.Pool
}

// Open connects all three pools and verifies each one.
func Open(ctx context.Context, cfg config.Postgres) (*Pools, error) {
	p := &Pools{}
	specs := []struct {
		name string
		dst  **pgxpool.Pool
		max  int32
	}{
		{"live", &p.Live, cfg.LiveConns},
		{"history", &p.History, cfg.HistoryConns},
		{"api", &p.API, cfg.APIConns},
	}
	for _, s := range specs {
		pool, err := open(ctx, cfg, s.name, s.max)
		if err != nil {
			p.Close() // roll back the pools already opened
			return nil, fmt.Errorf("pg: %s pool: %w", s.name, err)
		}
		*s.dst = pool
	}
	return p, nil
}

func open(ctx context.Context, cfg config.Postgres, name string, maxConns int32) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	pc.MaxConns = maxConns
	pc.MinConns = 0
	pc.MaxConnLifetime = cfg.ConnMaxLifetime
	pc.MaxConnIdleTime = cfg.ConnMaxIdleTime

	// application_name makes pg_stat_activity readable: when something is
	// stuck, you can tell a backfill from a live insert at a glance.
	if pc.ConnConfig.RuntimeParams == nil {
		pc.ConnConfig.RuntimeParams = map[string]string{}
	}
	pc.ConnConfig.RuntimeParams["application_name"] = "whatserver2/" + name

	// A statement timeout is the backstop against one pathological query
	// consuming a connection forever. History gets a longer leash because bulk
	// COPY legitimately takes longer than an interactive query.
	timeout := cfg.StatementTimeout
	if name == "history" {
		timeout = max(timeout, 5*time.Minute)
	}
	pc.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(timeout.Milliseconds())

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// ErrPrivilegedRole reports a database role that row-level security does not
// apply to. Every tenant-scoped table here is protected by a policy, and a
// superuser — or a role with BYPASSRLS — reads through every policy as though
// none existed. The isolation tests pass, the deployment boots, and every
// tenant can read every other tenant's rows.
var ErrPrivilegedRole = errors.New("pg: the database role bypasses row-level security " +
	"(superuser or BYPASSRLS); tenant isolation would not apply")

// CheckRole verifies that the connected role is subject to row-level security.
func (p *Pools) CheckRole(ctx context.Context) error {
	var super, bypass bool
	err := p.API.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&super, &bypass)
	if err != nil {
		return fmt.Errorf("pg: check role: %w", err)
	}
	if super || bypass {
		return ErrPrivilegedRole
	}
	return nil
}

// Close shuts every pool down. Safe to call with partially-opened Pools.
func (p *Pools) Close() {
	for _, pool := range []*pgxpool.Pool{p.Live, p.History, p.API} {
		if pool != nil {
			pool.Close()
		}
	}
}

// Ping verifies every pool, for the readiness probe.
func (p *Pools) Ping(ctx context.Context) error {
	for name, pool := range map[string]*pgxpool.Pool{
		"live": p.Live, "history": p.History, "api": p.API,
	} {
		if pool == nil {
			return fmt.Errorf("pg: %s pool is not open", name)
		}
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("pg: %s pool: %w", name, err)
		}
	}
	return nil
}

// ErrNoTenant is returned when a tenant-scoped transaction is started without a
// tenant. Failing loudly beats running the query with the GUC unset, which RLS
// would answer with an empty result set that looks like "no data" rather than
// "you asked wrong".
var ErrNoTenant = errors.New("pg: tenant id is required for a tenant-scoped transaction")

// InTenantTx runs fn inside a transaction scoped to one tenant.
//
// The tenant is applied with set_config(..., is_local => true) rather than a
// literal SET LOCAL because set_config takes a bind parameter. SET LOCAL does
// not, and building that statement by string concatenation would put a
// caller-supplied value directly into SQL.
//
// The setting is transaction-local, so it is discarded on commit or rollback
// and cannot leak to the next user of a pooled connection.
func InTenantTx(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: begin: %w", err)
	}
	// Rollback after a successful commit is a no-op, so this is safe
	// unconditionally and covers every early return inside fn.
	//nolint:errcheck // deferred rollback is a no-op once committed
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", TenantGUC, tenantID); err != nil {
		return fmt.Errorf("pg: set tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg: commit: %w", err)
	}
	return nil
}

// InTx runs fn in a transaction with no tenant scoping. Use it only for
// genuinely global work: migrations, the tenant registry, cross-tenant
// maintenance. Anything touching tenant data belongs in InTenantTx.
func InTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: begin: %w", err)
	}
	//nolint:errcheck // deferred rollback is a no-op once committed
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg: commit: %w", err)
	}
	return nil
}

// RegisterCollectors exports pool saturation to Prometheus. Saturation on the
// live pool is the early warning that ingest is falling behind.
func (p *Pools) RegisterCollectors(reg prometheus.Registerer) error {
	for name, pool := range map[string]*pgxpool.Pool{
		"live": p.Live, "history": p.History, "api": p.API,
	} {
		if pool == nil {
			continue
		}
		if err := reg.Register(newPoolCollector(name, pool)); err != nil {
			return fmt.Errorf("pg: register %s collector: %w", name, err)
		}
	}
	return nil
}

type poolCollector struct {
	pool                    *pgxpool.Pool
	acquired, idle, maxDesc *prometheus.Desc
	waitCount               *prometheus.Desc
}

func newPoolCollector(name string, pool *pgxpool.Pool) *poolCollector {
	lbl := prometheus.Labels{"pool": name}
	d := func(metric, help string) *prometheus.Desc {
		return prometheus.NewDesc("whatserver_pg_"+metric, help, nil, lbl)
	}
	return &poolCollector{
		pool:      pool,
		acquired:  d("conns_acquired", "Connections currently checked out."),
		idle:      d("conns_idle", "Connections currently idle."),
		maxDesc:   d("conns_max", "Maximum connections for this pool."),
		waitCount: d("acquire_waits_total", "Acquires that had to wait for a free connection."),
	}
}

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.acquired
	ch <- c.idle
	ch <- c.maxDesc
	ch <- c.waitCount
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.Stat()
	ch <- prometheus.MustNewConstMetric(c.acquired, prometheus.GaugeValue, float64(s.AcquiredConns()))
	ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(s.IdleConns()))
	ch <- prometheus.MustNewConstMetric(c.maxDesc, prometheus.GaugeValue, float64(s.MaxConns()))
	ch <- prometheus.MustNewConstMetric(c.waitCount, prometheus.CounterValue, float64(s.EmptyAcquireCount()))
}
