package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Usage (docs/mcp-enclave.md §18.10): plain counters per day, authorization,
// number, function, provider, model, key, origin and requester, which the
// console shows and the enclave reads back as a lower bound at install: the
// attachments, the tokens each provider reported, the seconds, and the tokens
// the enclave counted toward the cap. The enclave's own counters bound the
// use; these can only understate it. Never content, and never money: prices
// vary with each person's plan and model, and billing is theirs at each
// provider.

// aiUsageRetention is how long a day's counters are kept.
const aiUsageRetention = 400 * 24 * time.Hour

// AIUsage is one increment the reader posts after a provider answered (or
// a call it sent was never answered). ChargedTokens is what it counted
// toward the cap: the tokens reported, a duration's seconds at 25 tokens
// each, or a bound where the answer reported none.
type AIUsage struct {
	DeviceID      uuid.UUID
	Feature       string
	Provider      string
	Model         string
	Origin        string
	RequesterID   uuid.UUID
	Items         int
	Reused        int
	Failures      int
	InputTokens   int64
	OutputTokens  int64
	Seconds       int
	ChargedTokens int64
}

// ErrAIUsageKey is an increment for a provider the authorization holds no
// key for.
var ErrAIUsageKey = errors.New("store: the authorization has no key for that provider")

// RecordAIUsage adds an increment to today's (UTC) row of an authorization.
// The key that paid is the one its configuration names for the provider as
// it records, so the rows of a key rotated by a renewal stay the old key's.
func (a *AI) RecordAIUsage(ctx context.Context, tenant uuid.UUID, authorization string, u AIUsage) error {
	if !slices.Contains(AIFeatures, u.Feature) || !slices.Contains(AIProviders, u.Provider) || !ValidAIModel(u.Model) ||
		u.Origin != AIOriginConsole && u.Origin != AIOriginConnector {
		return errors.New("store: a usage increment needs a function, a provider, a model and an origin")
	}
	return pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ai_usage_daily (tenant_id, day, authorization_id, device_id, feature, provider, model,
			    keychain_id, origin, requester_id, items, reused, failures, input_tokens, output_tokens, seconds, charged_tokens)
			SELECT $1, (now() AT TIME ZONE 'UTC')::date, c.id, $3, $4, $5, $6, (c.ai_config->'keys'->$5->>'keychain_id')::uuid,
			       $7, $8, $9, $10, $11, $12, $13, $14, $15
			  FROM mcp_connections c WHERE c.id=$2 AND c.tenant_id=$1 AND c.kind='ai' AND c.ai_config->'keys' ? $5
			ON CONFLICT (tenant_id, day, authorization_id, device_id, feature, provider, model, keychain_id, origin, requester_id)
			DO UPDATE SET items = ai_usage_daily.items + excluded.items, reused = ai_usage_daily.reused + excluded.reused,
			    failures = ai_usage_daily.failures + excluded.failures,
			    input_tokens = ai_usage_daily.input_tokens + excluded.input_tokens,
			    output_tokens = ai_usage_daily.output_tokens + excluded.output_tokens,
			    seconds = ai_usage_daily.seconds + excluded.seconds,
			    charged_tokens = ai_usage_daily.charged_tokens + excluded.charged_tokens`,
			tenant, authorization, u.DeviceID, u.Feature, u.Provider, u.Model, u.Origin, u.RequesterID,
			u.Items, u.Reused, u.Failures, u.InputTokens, u.OutputTokens, u.Seconds, u.ChargedTokens)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrAIUsageKey
		}
		return nil
	})
}

// AIMonthTotal is what the enclave reads back for one authorization: the
// month's tokens counted toward the cap and today's items.
type AIMonthTotal struct {
	ChargedTokens int64
	ItemsToday    int64
}

// monthBounds is a month's first day and the next month's, in UTC.
func monthBounds(month time.Time) (time.Time, time.Time) {
	start := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

// AIMonthUsage totals one authorization's month (UTC) and today's items.
func (a *AI) AIMonthUsage(ctx context.Context, tenant uuid.UUID, authorization string, month time.Time) (AIMonthTotal, error) {
	start, end := monthBounds(month)
	var out AIMonthTotal
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			coalesce(sum(charged_tokens) FILTER (WHERE day >= $3 AND day < $4), 0)::bigint,
			coalesce(sum(items) FILTER (WHERE day = (now() AT TIME ZONE 'UTC')::date), 0)::bigint
			FROM ai_usage_daily WHERE tenant_id=$1 AND authorization_id=$2`, tenant, authorization, start, end).
			Scan(&out.ChargedTokens, &out.ItemsToday)
	})
	if err != nil {
		return AIMonthTotal{}, fmt.Errorf("store: total AI usage: %w", err)
	}
	return out, nil
}

// AIUsageRow is a month's counters for one authorization, number, function,
// provider, model, key, origin and requester, with today's (UTC) calls
// answered and failed, which the console shows against the daily cap.
type AIUsageRow struct {
	AuthorizationID, DeviceID uuid.UUID
	Feature, Provider, Model  string
	KeychainID                uuid.UUID
	Origin                    string
	RequesterID               uuid.UUID
	Items, Reused, Failures   int64
	InputTokens, OutputTokens int64
	Seconds, ChargedTokens    int64
	ItemsToday, FailuresToday int64
}

// AIUsageMonth lists a month's (UTC) counters: all of the workspace's when
// all is set (an owner or an admin asking), otherwise those of the viewer's
// own authorizations.
func (a *AI) AIUsageMonth(ctx context.Context, tenant, viewer uuid.UUID, all bool, month time.Time) ([]AIUsageRow, error) {
	start, end := monthBounds(month)
	out := []AIUsageRow{}
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT u.authorization_id, u.device_id, u.feature, u.provider, u.model, u.keychain_id, u.origin, u.requester_id,
			       sum(u.items)::bigint, sum(u.reused)::bigint, sum(u.failures)::bigint, sum(u.input_tokens)::bigint,
			       sum(u.output_tokens)::bigint, sum(u.seconds)::bigint, sum(u.charged_tokens)::bigint,
			       coalesce(sum(u.items) FILTER (WHERE u.day = (now() AT TIME ZONE 'UTC')::date), 0)::bigint,
			       coalesce(sum(u.failures) FILTER (WHERE u.day = (now() AT TIME ZONE 'UTC')::date), 0)::bigint
			FROM ai_usage_daily u JOIN mcp_connections c ON c.id = u.authorization_id
			WHERE u.tenant_id=$1 AND u.day >= $2 AND u.day < $3 AND ($4 OR c.created_by=$5)
			GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
			ORDER BY 1, 2, 3, 4, 5, 6, 7, 8`, tenant, start, end, all, viewer)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r AIUsageRow
			if err := rows.Scan(&r.AuthorizationID, &r.DeviceID, &r.Feature, &r.Provider, &r.Model, &r.KeychainID, &r.Origin, &r.RequesterID,
				&r.Items, &r.Reused, &r.Failures, &r.InputTokens, &r.OutputTokens, &r.Seconds, &r.ChargedTokens, &r.ItemsToday, &r.FailuresToday); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list AI usage: %w", err)
	}
	return out, nil
}

// SettledAI is what one pass of SettleAI removed.
type SettledAI struct {
	UsageRows, KeychainRows int64
}

// SettleAI applies the AI tables' retention in every workspace: a day's
// usage counters go 400 days after the day, and a deleted keychain item's
// row 30 days after its deletion. One workspace failing does not keep the
// rest from settling.
func SettleAI(ctx context.Context, pool *pgxpool.Pool) (SettledAI, error) {
	var out SettledAI
	rows, err := pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return out, fmt.Errorf("store: settle AI: %w", err)
	}
	var tenants []uuid.UUID
	for rows.Next() {
		var tenant uuid.UUID
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			return out, fmt.Errorf("store: settle AI: %w", err)
		}
		tenants = append(tenants, tenant)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("store: settle AI: %w", err)
	}
	var errs []error
	for _, tenant := range tenants {
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `DELETE FROM ai_usage_daily WHERE tenant_id=$1 AND day <= (now() AT TIME ZONE 'UTC' - $2::interval)::date`,
				tenant, aiUsageRetention)
			if err != nil {
				return err
			}
			out.UsageRows += tag.RowsAffected()
			tag, err = tx.Exec(ctx, `DELETE FROM ai_keychain WHERE tenant_id=$1 AND deleted_at < now() - $2::interval`, tenant, aiKeychainRetention)
			if err != nil {
				return err
			}
			out.KeychainRows += tag.RowsAffected()
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return out, fmt.Errorf("store: settle AI: %w", err)
	}
	return out, nil
}
