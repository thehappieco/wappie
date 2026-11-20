package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
)

// The judge (the plan's 4.2, JudgeTokenGrants): each grant instance a record
// brought is judged once, apart from the commit that brought it, workspace by
// workspace under each one's app.tenant_id, so the 1 s bound of a narrowing
// never waits on it. A grant is never effective until it is applied.

// TokenJudgeResult counts a judge's verdicts.
type TokenJudgeResult struct {
	Applied, Refused, Waiting int
}

// pendingGrant is a perm row the judge decides.
type pendingGrant struct {
	token      uuid.UUID
	device     uuid.UUID
	perm       string
	grantedBy  uuid.UUID
	grantedAt  time.Time
	version    int64
	state      string
	createdBy  uuid.UUID
	keyChanged bool
}

// localPerson is a sub's local account, and what it may do in a workspace.
type localPerson struct {
	user  uuid.UUID
	doc   bool
	admin bool
}

// JudgeTokenGrants judges every pending perm of the current generation, and
// every waiting one again, in order:
//  1. item_unknown: the number is no longer a live one of the workspace;
//  2. waiting: the giver or the creator has a local account, but Wappie holds
//     no account document for their sub yet (the round PUTs every linked
//     sub, so Wappie never subscribes a stranger);
//  3. local_role (before enforce): the giver or the creator is not a local
//     owner or admin of the workspace (a personal workspace's person is its
//     owner), or has no local account;
//  4. giver_not_reader (Read only): the giver cannot read the number now: the
//     flag, a grant at the current epoch, an active membership and account;
//  5. reading_key_changed (Read only): the token's reading key changed.
//
// Otherwise the perm is applied. Each verdict is a compare-and-set on the
// state and the generation, so a perm a reset deleted or replaced is never
// judged. A refusal is queued for the acknowledgement with the version that
// carried its grant, and its instance never comes back.
func (t *Tokens) JudgeTokenGrants(ctx context.Context, now time.Time) (TokenJudgeResult, error) {
	var out TokenJudgeResult
	var gen *uuid.UUID
	if err := t.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&gen); err != nil || gen == nil {
		return out, err
	}
	var workspaces []uuid.UUID
	if err := pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
		var err error
		workspaces, err = tokenWorkspacesTx(ctx, tx)
		return err
	}); err != nil {
		return out, err
	}
	for _, ws := range workspaces {
		err := retryDeadlock(ctx, func() error {
			return pg.InTenantTx(ctx, t.pool, ws.String(), func(tx pgx.Tx) error {
				got, err := judgeWorkspaceTx(ctx, tx, ws, *gen, now)
				if err == nil {
					out.Applied += got.Applied
					out.Refused += got.Refused
					out.Waiting += got.Waiting
				}
				return err
			})
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// judgeWorkspaceTx judges one workspace's pending and waiting perms in tx,
// under its app.tenant_id.
func judgeWorkspaceTx(ctx context.Context, tx pgx.Tx, ws, gen uuid.UUID, now time.Time) (TokenJudgeResult, error) {
	var out TokenJudgeResult
	// The perms in key order (DB25 step 5), as the commit locks them.
	rows, err := tx.Query(ctx, `SELECT p.token_id, p.device_id, p.perm, p.granted_by, p.granted_at, p.version, p.state,
			t.created_by, t.key_changed_at IS NOT NULL
		FROM contract_token_perms p JOIN contract_tokens t ON t.id = p.token_id
		WHERE p.state IN ('pending', 'waiting') AND p.generation = $1
		ORDER BY p.token_id, p.device_id, p.perm FOR UPDATE OF p`, gen)
	if err != nil {
		return out, err
	}
	grants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pendingGrant, error) {
		var g pendingGrant
		err := row.Scan(&g.token, &g.device, &g.perm, &g.grantedBy, &g.grantedAt, &g.version, &g.state, &g.createdBy, &g.keyChanged)
		return g, err
	})
	if err != nil || len(grants) == 0 {
		return out, err
	}
	var subs, devices []uuid.UUID
	for _, g := range grants {
		subs = append(subs, g.grantedBy, g.createdBy)
		devices = append(devices, g.device)
	}
	people, err := localPeopleTx(ctx, tx, ws, subs)
	if err != nil {
		return out, err
	}
	live := map[uuid.UUID]bool{}
	rows, err = tx.Query(ctx, `SELECT id FROM devices WHERE id = ANY ($1) AND deleted_at IS NULL`, devices)
	if err != nil {
		return out, err
	}
	if err := forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		if err := row.Scan(&id); err != nil {
			return err
		}
		live[id] = true
		return nil
	}); err != nil {
		return out, err
	}

	type verdict struct {
		g     pendingGrant
		state string
		code  string
	}
	var verdicts []verdict
	for _, g := range grants {
		giver, giverOK := people[g.grantedBy]
		creator, creatorOK := people[g.createdBy]
		v := verdict{g: g, state: tokenApplied}
		switch {
		case !live[g.device]:
			v.state, v.code = tokenRefused, tokenRefusedUnknown
		case (giverOK && !giver.doc) || (creatorOK && !creator.doc):
			v.state = tokenWaiting
		case !giverOK || !creatorOK || !giver.admin || !creator.admin:
			v.state, v.code = tokenRefused, tokenRefusedRole
		case g.perm == kc.CanRead:
			p, err := devicePermissionTx(ctx, tx, ws, giver.user, g.device)
			switch {
			case err != nil && !errors.Is(err, ErrNotFound):
				return out, err
			case err != nil || !p.Allows(ActionRead):
				v.state, v.code = tokenRefused, tokenRefusedGiver
			case g.keyChanged:
				v.state, v.code = tokenRefused, tokenRefusedKey
			}
		}
		if v.state == g.state {
			continue
		}
		verdicts = append(verdicts, v)
	}
	if len(verdicts) == 0 {
		return out, nil
	}
	n := len(verdicts)
	tokens, devs, perms, states, codes := make([]uuid.UUID, n), make([]uuid.UUID, n), make([]string, n), make([]string, n), make([]*string, n)
	for i, v := range verdicts {
		tokens[i], devs[i], perms[i], states[i] = v.g.token, v.g.device, v.g.perm, v.state
		if v.code != "" {
			c := v.code
			codes[i] = &c
		}
	}
	rows, err = tx.Query(ctx, `UPDATE contract_token_perms p SET state = v.state, code = v.code, judged_at = $1
		FROM unnest($2::uuid[], $3::uuid[], $4::text[], $5::text[], $6::text[]) AS v(token, device, perm, state, code)
		WHERE p.token_id = v.token AND p.device_id = v.device AND p.perm = v.perm
		  AND p.state IN ('pending', 'waiting') AND p.generation = $7
		RETURNING p.token_id, p.device_id, p.perm`, now, tokens, devs, perms, states, codes, gen)
	if err != nil {
		return out, err
	}
	judged := map[[3]string]bool{}
	if err := forEachRow(rows, func(row pgx.Rows) error {
		var token, device uuid.UUID
		var perm string
		if err := row.Scan(&token, &device, &perm); err != nil {
			return err
		}
		judged[[3]string{token.String(), device.String(), perm}] = true
		return nil
	}); err != nil {
		return out, err
	}
	var refusals []tokenRefusalRow
	var removed []removedRow
	for _, v := range verdicts {
		if !judged[[3]string{v.g.token.String(), v.g.device.String(), v.g.perm}] {
			continue
		}
		switch v.state {
		case tokenApplied:
			out.Applied++
		case tokenWaiting:
			out.Waiting++
		case tokenRefused:
			out.Refused++
			refusals = append(refusals, tokenRefusalRow{token: v.g.token, version: v.g.version, item: v.g.device.String(), perm: v.g.perm, code: v.code})
			removed = append(removed, removedRow{token: v.g.token, item: v.g.device.String(), perm: v.g.perm, grantedAt: v.g.grantedAt, cause: "refused"})
		}
	}
	if err := insertRemovedTx(ctx, tx, ws, now, removed); err != nil {
		return out, err
	}
	return out, queueRefusalsTx(ctx, tx, refusals)
}

// localPeopleTx is, for each sub with a local account (platform_identities),
// that account, whether Wappie holds an account document for the sub, and
// whether it is an active owner or admin of ws (a personal workspace's
// person is its owner), read under ws's app.tenant_id.
func localPeopleTx(ctx context.Context, tx pgx.Tx, ws uuid.UUID, subs []uuid.UUID) (map[uuid.UUID]localPerson, error) {
	rows, err := tx.Query(ctx, `SELECT pi.sub, pi.user_id, coalesce(a.doc IS NOT NULL, false),
			EXISTS (SELECT 1 FROM workspace_memberships m JOIN users u ON u.id = m.user_id
			         WHERE m.tenant_id = $1 AND m.user_id = pi.user_id AND m.status = 'active' AND u.status = 'active'
			           AND m.role IN ('owner', 'admin') AND (m.expires_at IS NULL OR m.expires_at > clock_timestamp()))
		FROM platform_identities pi LEFT JOIN contract_accounts a ON a.sub = pi.sub
		WHERE pi.sub = ANY ($2)`, ws, subs)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]localPerson{}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var sub uuid.UUID
		var p localPerson
		if err := row.Scan(&sub, &p.user, &p.doc, &p.admin); err != nil {
			return err
		}
		out[sub] = p
		return nil
	})
	return out, err
}

// TokenRecordResult is what applying a by-id GET's record did.
type TokenRecordResult struct {
	// OtherGeneration: the record is of another generation than Wappie
	// holds: nothing was stored, and every contract loop was woken.
	OtherGeneration bool
	// Bad: only its narrowings applied (it fails Validate, or its
	// fingerprint is not its key's: reading_key_changed).
	Bad bool
	// Stamped: its version equals or raises the stored one, and fetched_at
	// is the time the GET was sent.
	Stamped bool
	// Narrowed: it narrowed the token.
	Narrowed bool
}

// ApplyTokenRecord applies a signed by-id GET's record (the plan's 4.2): the
// same judging as a page's, under contract_token_state's lock, with
// compare-and-set on the version and the current generation, and
// ReadingKey.Check run here (the kit's Token runs only Validate). sentAt is
// Wappie's clock when the request was sent: fetched_at takes it when the
// answer's version equals or raises the stored one, never on a lower one,
// so a token whose record has not changed still passes the grant page's
// 60 s rule. A record of another generation is not stored, and wakes every
// contract loop (generation).
func (t *Tokens) ApplyTokenRecord(ctx context.Context, rec kc.TokenRecord, sentAt, now time.Time) (TokenRecordResult, error) {
	var out TokenRecordResult
	raw, err := json.Marshal(rec)
	if err != nil {
		return out, err
	}
	item := tokenItem{raw: raw, rec: rec}
	switch {
	case rec.Validate() != nil:
		item.bad = tokenRefusedInvalid
	case rec.ReadingKey != nil && rec.ReadingKey.Check() != nil:
		item.bad = tokenRefusedKey
	}
	if kc.ValidUUID(rec.ID) {
		item.id = uuid.MustParse(rec.ID)
	}
	out.Bad = item.bad != ""
	if kc.ValidApp(rec.App) && rec.App != t.app {
		obs.LoggerFrom(ctx).Info("contract: a token record of another app is skipped", tokenLogAttrs(rec)...)
		return out, nil
	}
	err = retryDeadlock(ctx, func() error {
		out.OtherGeneration, out.Stamped, out.Narrowed = false, false, false
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			state, err := lockTokenStateTx(ctx, tx)
			if err != nil {
				return err
			}
			if state.Generation == nil {
				return ErrNoGeneration
			}
			gen := *state.Generation
			if kc.ValidUUID(rec.Generation) && rec.Generation != gen.String() {
				out.OtherGeneration = true
				return nil
			}
			applied, err := t.applyItemsTx(ctx, tx, gen, state, []tokenItem{item}, now, false)
			if err != nil {
				return err
			}
			out.Narrowed = applied.narrowed
			if item.bad != "" || item.id == uuid.Nil {
				return nil
			}
			var ws uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT tenant_id FROM contract_token_selectors WHERE token_id = $1`, item.id).Scan(&ws); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil
				}
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE contract_tokens SET fetched_at = GREATEST(coalesce(fetched_at, $2), $2)
				WHERE id = $1 AND generation = $3 AND version = $4`, item.id, sentAt, gen, rec.Version)
			if err != nil {
				return err
			}
			out.Stamped = tag.RowsAffected() == 1
			_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`)
			return err
		})
	})
	if err == nil && out.OtherGeneration {
		if e := NewContract(t.pool).Wake(ctx, "generation"); e != nil {
			obs.LoggerFrom(ctx).Warn("contract: could not wake the contract's loops", "error", e)
		}
	}
	return out, err
}
