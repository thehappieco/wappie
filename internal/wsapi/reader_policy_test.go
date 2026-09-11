package wsapi

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

func TestPersonalReadPolicyGatesUnreadPlayedAndTypingBeforeAnyEffects(t *testing.T) {
	for _, sharedMode := range []wa.ReceiptMode{wa.ModePassive, wa.ModeActive} {
		t.Run(string(sharedMode), func(t *testing.T) {
			pool := pgtest.Fresh(t, migrate.Run)
			ctx := context.Background()
			var tenant uuid.UUID
			if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('Readers') RETURNING id`).Scan(&tenant); err != nil {
				t.Fatal(err)
			}
			users := store.NewUsers(pool)
			dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), "shared", sharedMode)
			if err != nil {
				t.Fatal(err)
			}
			device := uuid.MustParse(dev.ID)
			keys := store.NewKeys(pool)
			pub, _, err := seal.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.CreateArchiveKey(ctx, tenant, device, 1, pub); err != nil {
				t.Fatal(err)
			}
			makeUser := func(email string) store.User {
				u, err := users.Create(ctx, store.NewUser{TenantID: tenant, Email: email, Role: "member", AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
				if err != nil {
					t.Fatal(err)
				}
				if err := keys.PutGrant(ctx, store.Grant{TenantID: tenant, DeviceID: device, UserID: u.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
					t.Fatal(err)
				}
				return u
			}
			discreet, normal := makeUser("discreet@policy.test"), makeUser("normal@policy.test")
			if err := users.SetReaderMode(ctx, tenant, normal.ID, device, wa.ModeActive); err != nil {
				t.Fatal(err)
			}
			fake := fakewa.New()
			live, err := wa.NewDevice(wa.DeviceConfig{ID: device.String(), TenantID: tenant.String(), Client: fake, Policy: wa.ReceiptPolicy{Mode: sharedMode}})
			if err != nil {
				t.Fatal(err)
			}
			unread := store.NewUnread(pool)
			srv := &Server{cfg: Config{Sessions: users, Unread: unread}}
			makeSession := func(user store.User) *session {
				return &session{srv: srv, tenant: tenant.String(), who: actor{person: true, userID: user.ID, tenant: tenant.String()}, out: make(chan Frame, 4), log: slog.New(slog.DiscardHandler)}
			}
			a, b := makeSession(discreet), makeSession(normal)
			chat := types.NewJID("5511999999999", types.DefaultUserServer)
			_, err = store.NewMessages(pool).Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: tenant, DeviceID: device, WAID: "unread-1", ChatKey: chat.String(), ChatPN: chat.String(), TS: time.Now(), Kind: domain.KindMessage, Type: domain.TypeAudio, Source: domain.SourceLive, ContentKeyID: 1, BodySealed: []byte("sealed")})
			if err != nil {
				t.Fatal(err)
			}
			target := sendTarget{tenant: tenant, device: live, deviceID: device, chat: chat}
			read := MarkReadRequest{DeviceID: device.String(), Chat: chat.String(), IDs: []string{"unread-1"}}
			for _, played := range []bool{false, true} {
				read.Played = played
				a.markRead(ctx, Frame{ReqID: "quiet"}, target, read, types.JID{})
				if reply := <-a.out; reply.Type != TypeSendResult {
					t.Fatalf("quiet reply=%s %s", reply.Type, reply.Payload)
				}
			}
			if count, err := unread.Count(ctx, tenant, device, chat.String()); err != nil || count != 1 {
				t.Fatalf("discreet changed badge: %d %v", count, err)
			}
			if fake.MarkReadCalls() != 0 {
				t.Fatal("discreet read/played reached WhatsApp")
			}
			for _, viewer := range []*session{a, b} {
				policy, ok := viewer.readerPolicy(ctx, Frame{}, live)
				if !ok {
					t.Fatal("policy unavailable")
				}
				if err := policy.ChatPresence(ctx, fake, chat, types.ChatPresenceComposing, ""); err != nil {
					t.Fatal(err)
				}
			}
			if len(fake.ChatPresences()) != 1 {
				t.Fatal("only normal user's typing should be visible")
			}
			for _, played := range []bool{false, true} {
				read.Played = played
				b.markRead(ctx, Frame{ReqID: "normal"}, target, read, types.JID{})
				if reply := <-b.out; reply.Type != TypeSendResult {
					t.Fatalf("normal reply=%s %s", reply.Type, reply.Payload)
				}
			}
			if count, err := unread.Count(ctx, tenant, device, chat.String()); err != nil || count != 0 {
				t.Fatalf("normal badge: %d %v", count, err)
			}
			receipts := fake.ReadReceipts()
			if len(receipts) != 2 || len(receipts[1].Types) != 1 || receipts[1].Types[0] != types.ReceiptTypePlayed {
				t.Fatalf("read/played=%+v", receipts)
			}
			if live.Policy().Mode != sharedMode || fake.SendPresenceCalls() != 0 || fake.ForceActiveReceipts() {
				t.Fatal("personal actions changed shared availability")
			}
			if mode, err := users.ReaderMode(ctx, tenant, discreet.ID, device); err != nil || mode != wa.ModePassive {
				t.Fatal("teammate changed discreet user's preference")
			}
		})
	}
}
