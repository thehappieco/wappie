package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The name of a personal workspace whose platform document leaves it null
// (DS54): "Espaço pessoal" in its owner's language, Portuguese when the
// owner has set none. Only the apply at enforce, and a locale change of a
// workspace the apply has named (SetLocale), write it.

// personalNames are PersonalWorkspaceName's, by locale (Locales).
var personalNames = map[string]string{
	"pt": "Espaço pessoal",
	"en": "Personal space",
	"es": "Espacio personal",
	"fr": "Espace personnel",
	"de": "Persönlicher Bereich",
}

// PersonalWorkspaceName is a personal workspace's name in locale, the
// Portuguese one for an empty or unknown locale.
func PersonalWorkspaceName(locale string) string {
	if name, ok := personalNames[locale]; ok {
		return name
	}
	return personalNames["pt"]
}

// docNameNullSQL holds for a workspace (its id is $1) that no stored
// document names: every stored document that lists it leaves its name null.
const docNameNullSQL = `NOT EXISTS (SELECT 1 FROM contract_accounts a
		CROSS JOIN LATERAL jsonb_array_elements(a.doc->'workspaces') x
		WHERE a.doc IS NOT NULL AND x->>'id' = $1::text AND x->>'name' IS NOT NULL)`

// renamePersonalTx renames user's personal workspace to the name of locale
// when the apply has named it (its record's applied_wversion is set) and
// no stored document names it; it reports whether it did. tx holds no
// users row of anyone: the workspace's row is taken here, alone.
func renamePersonalTx(ctx context.Context, tx pgx.Tx, user uuid.UUID, locale string) (bool, error) {
	var personal uuid.UUID
	err := tx.QueryRow(ctx, `SELECT t.id FROM tenants t JOIN contract_workspaces w ON w.workspace_id = t.id
		WHERE t.personal_owner_id = $1 AND w.applied_wversion IS NOT NULL`, user).Scan(&personal)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE tenants SET name = $2 WHERE id = $1 AND name <> $2 AND `+docNameNullSQL,
		personal, PersonalWorkspaceName(locale))
	return tag.RowsAffected() == 1, err
}
