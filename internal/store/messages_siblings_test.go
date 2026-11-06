package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// One person's conversation may be stored under its phone number and its
// LID (siblings.go). A history sync after a relink sends messages again
// under either: the same wa_id under a sibling key is a duplicate, never a
// second row, a second unread or a second attachment. Fictional numbers.
func TestInsertDropsAMessageUnderItsOtherChatKey(t *testing.T) {
	const (
		pnKey  = "155501000301@s.whatsapp.net"
		lidKey = "100000000000301@lid"
	)
	at := time.Now().Truncate(time.Second)
	direct := func(waID, chatKey, chatLID string, probe ...string) store.InsertMessage {
		return store.InsertMessage{
			UID: uuid.New(), WAID: waID, ChatKey: chatKey, ChatPN: pnKey, ChatLID: chatLID, ProbeKeys: probe,
			TS: at, Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceHistory,
			ContentKeyID: 1, BodySealed: []byte("sealed"),
			Media: &store.InsertMedia{MediaType: "image", MimeType: "image/jpeg", FileEncSHA256: []byte(waID)},
		}
	}
	for name, tc := range map[string]struct{ first, again store.InsertMessage }{
		"phone first, then the LID with a probe": {
			first: direct("A1", pnKey, ""), again: direct("A1", lidKey, lidKey, pnKey)},
		"the LID first, then the phone with a probe": {
			first: direct("B1", lidKey, lidKey, pnKey), again: direct("B1", pnKey, "", lidKey)},
		"the LID first, then the phone the map does not know": {
			first: direct("C1", lidKey, lidKey, pnKey), again: direct("C1", pnKey, "")},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			m, tenant, device, pool := chatFixtureWithPool(t)
			first, again := tc.first, tc.again
			first.TenantID, first.DeviceID, again.TenantID, again.DeviceID = tenant, device, tenant, device
			stored, err := m.Insert(ctx, first)
			if err != nil || stored.Duplicate {
				t.Fatalf("first insert %+v %v", stored, err)
			}
			res, err := m.Insert(ctx, again)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Duplicate || res.UID != stored.UID || res.Seq != stored.Seq {
				t.Fatalf("the copy under the other key = %+v, want the stored row %s", res, stored.UID)
			}
			var messages, media int
			inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM messages WHERE device_id = $1),
					(SELECT count(*) FROM media WHERE tenant_id = $2)`, device, tenant).Scan(&messages, &media)
			})
			if messages != 1 || media != 1 {
				t.Fatalf("%d messages and %d attachments, want one of each", messages, media)
			}
		})
	}

	t.Run("groups never fold", func(t *testing.T) {
		ctx := context.Background()
		m, tenant, device := chatFixture(t)
		for _, key := range []string{"120363000000000301@g.us", "120363000000000302@g.us"} {
			res, err := m.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: tenant, DeviceID: device,
				WAID: "G1", ChatKey: key, IsGroup: true, ProbeKeys: []string{"120363000000000301@g.us"},
				TS: at, Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceHistory, ContentKeyID: 1, BodySealed: []byte("x")})
			if err != nil || res.Duplicate {
				t.Fatalf("a group message under %s = %+v %v", key, res, err)
			}
		}
	})

	t.Run("a LID with no phone number stays apart", func(t *testing.T) {
		ctx := context.Background()
		m, tenant, device := chatFixture(t)
		insert(t, m, tenant, device, pnKey, "D1", domain.KindMessage, at, "x")
		res, err := m.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: tenant, DeviceID: device,
			WAID: "D1", ChatKey: lidKey, ChatLID: lidKey,
			TS: at, Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceHistory, ContentKeyID: 1, BodySealed: []byte("x")})
		if err != nil || res.Duplicate {
			t.Fatalf("a LID chat nothing ties to the phone = %+v %v", res, err)
		}
	})
}

// A reaction filed under the LID finds its message filed under the phone
// number.
func TestTargetsResolveAcrossChatKeys(t *testing.T) {
	ctx := context.Background()
	const (
		pnKey  = "155501000302@s.whatsapp.net"
		lidKey = "100000000000302@lid"
	)
	m, tenant, device, pool := chatFixtureWithPool(t)
	at := time.Now().Truncate(time.Second)
	insert(t, m, tenant, device, pnKey, "M1", domain.KindMessage, at, "x")
	res, err := m.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: "R1", ChatKey: lidKey, ChatLID: lidKey, ChatPN: pnKey, ProbeKeys: []string{pnKey}, TargetWAID: "M1",
		TS: at, Kind: domain.KindReaction, Type: domain.TypeReaction, Source: domain.SourceLive, ContentKeyID: 1, BodySealed: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if res.TargetRel != domain.TargetMessage {
		t.Fatalf("target %q", res.TargetRel)
	}
	var target *uuid.UUID
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT target_uid FROM messages WHERE uid = $1`, res.UID).Scan(&target)
	})
	if target == nil {
		t.Fatal("the reaction did not find its message under the other key")
	}
}
