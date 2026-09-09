package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

var ErrInvalidWorkspaceProfile = errors.New("store: invalid workspace name or avatar")

const maxWorkspaceAvatarBytes = 32 << 10

// normalizeWorkspaceAvatar accepts only small, decoded raster images. Re-encoding
// strips metadata, trailing payloads and animation; URLs and SVG never enter the
// profile. Dimensions are checked before allocating pixel buffers.
func normalizeWorkspaceAvatar(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	kind := ""
	for _, format := range []string{"png", "jpeg"} {
		if strings.HasPrefix(value, "data:image/"+format+";base64,") {
			kind = format
			break
		}
	}
	if kind == "" || len(value) > 44000 {
		return "", ErrInvalidWorkspaceProfile
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(value, "data:image/"+kind+";base64,"))
	if err != nil || len(raw) > maxWorkspaceAvatarBytes {
		return "", ErrInvalidWorkspaceProfile
	}
	config, actualKind, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || actualKind != kind || config.Width < 1 || config.Height < 1 || config.Width > 512 || config.Height > 512 {
		return "", ErrInvalidWorkspaceProfile
	}
	pixels, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return "", ErrInvalidWorkspaceProfile
	}
	var encoded bytes.Buffer
	if kind == "jpeg" {
		err = jpeg.Encode(&encoded, pixels, &jpeg.Options{Quality: 85})
	} else {
		err = png.Encode(&encoded, pixels)
	}
	if err != nil || encoded.Len() > maxWorkspaceAvatarBytes {
		return "", ErrInvalidWorkspaceProfile
	}
	return "data:image/" + kind + ";base64," + base64.StdEncoding.EncodeToString(encoded.Bytes()), nil
}

// UpdateWorkspaceProfile uses the same workspace lock as role changes, so a
// concurrent demotion cannot authorize a stale manager. The workspace comes
// from the immutable authenticated session, never from the request body.
func (u *Users) UpdateWorkspaceProfile(ctx context.Context, tenant, actor uuid.UUID, name, avatar string) (Workspace, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 80 || strings.ContainsFunc(name, unicode.IsControl) {
		return Workspace{}, ErrInvalidWorkspaceProfile
	}
	avatar, err := normalizeWorkspaceAvatar(avatar)
	if err != nil {
		return Workspace{}, err
	}
	var space Workspace
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := lockWorkspaceManager(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		space.Role = role
		return tx.QueryRow(ctx, `UPDATE tenants SET name=$2,avatar=$3 WHERE id=$1
			RETURNING id,name,avatar,status,created_at`, tenant, name, avatar).
			Scan(&space.ID, &space.Name, &space.Avatar, &space.Status, &space.CreatedAt)
	})
	return space, err
}
