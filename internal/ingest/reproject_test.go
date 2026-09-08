package ingest_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// Looking again at a message the archive could not classify when it arrived.
//
// Classification happens once, on ingest, so a message that reached the archive
// before its type was supported stays "unsupported" for good — the row is
// written and nothing revisits it. That is survivable only because the protobuf
// that produced it was sealed and kept, and this is the path that goes back for
// it.
//
// The split of labour is the design: the browser holds the archive key and
// opens the stored protobuf, this server holds the classifier and re-seals with
// the public half. So the test hands over the plaintext the way a client would.
func TestReprojectionReclassifiesAStoredMessage(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	// A group invitation, of exactly the shape that was landing in
	// "unsupported" before the type was implemented.
	msg := &waE2E.Message{
		GroupInviteMessage: &waE2E.GroupInviteMessage{
			GroupJID:   proto.String("120363429965256963@g.us"),
			InviteCode: proto.String("SEGREDO123"),
			GroupName:  proto.String("Churrasco"),
			Caption:    proto.String("bora?"),
		},
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Stored the way ingest stored it back then: type unsupported, the field
	// named, the protobuf sealed beside it.
	res, err := store.NewMessages(f.pool).Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: f.tenant, DeviceID: f.device,
		WAID: "OLD1", ChatKey: chat.String(), ChatPN: chat.String(),
		SenderKey: chat.String(),
		TS:        time.Now().Truncate(time.Second),
		Kind:      domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, Unsupported: "groupInviteMessage",
		ContentKeyID: 1, RawSealed: []byte("does not matter here"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The listing must offer it.
	rows, err := r.UnsupportedRows(ctx, f.tenant, f.device, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, row := range rows {
		if row.UID == res.UID {
			found = true
		}
	}
	if !found {
		t.Fatal("the row was not offered for reprojection")
	}

	// And reprojecting it with the opened protobuf must reclassify it.
	out, err := r.Reproject(ctx, f.tenant, f.device, res.UID, raw)
	if err != nil {
		t.Fatalf("Reproject: %v", err)
	}
	if !out.Changed {
		t.Fatalf("nothing changed: type=%q note=%q", out.Type, out.Note)
	}
	if out.Type != domain.TypeGroupInvite {
		t.Errorf("type = %q, want %q", out.Type, domain.TypeGroupInvite)
	}

	// The row itself, and its sealed values, must all have moved together.
	row, err := store.NewMessages(f.pool).Get(ctx, f.tenant, res.UID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Type != domain.TypeGroupInvite {
		t.Errorf("stored type = %q", row.Type)
	}
	if row.Unsupported != "" {
		t.Errorf("the unsupported field survived reclassification: %q", row.Unsupported)
	}
	if len(row.PayloadSealed) == 0 {
		t.Error("the invitation was reclassified and its payload was not stored")
	}
}

// A second pass must not touch a row the first one already fixed.
//
// A client works through a listing it fetched a moment ago, and the row may
// have been reclassified since — by another tab, or by the same one retrying.
// The type is part of the lookup rather than checked afterwards, so a stale
// client finds nothing rather than rewriting something.
func TestReprojectingAnAlreadyClassifiedRowIsRefused(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	res, err := store.NewMessages(f.pool).Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: f.tenant, DeviceID: f.device,
		WAID: "OLD2", ChatKey: chat.String(), ChatPN: chat.String(),
		TS:   time.Now().Truncate(time.Second),
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, ContentKeyID: 1, BodySealed: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reproject(ctx, f.tenant, f.device, res.UID, []byte{0x0a, 0x00}); err == nil {
		t.Error("a row that is no longer unsupported was reprojected anyway")
	}
}

// A message whose attachment the archive never knew about.
//
// Ninety-three of the first two hundred rows reprojected on the real archive
// carried one, and the pass refused every one of them — so the commonest thing
// waiting to be reclassified was also the thing that could not be. The refusal
// was right while there was nowhere to put the attachment; it stopped being
// right once there was.
//
// What matters here is that the message and its attachment move together. The
// key id on the message names the key ALL of its sealed values share, so
// sealing the media key in a separate call would produce a row where the body
// opens and the attachment reports tampering — with the correct key in hand,
// which reads as an attack rather than a bug.
func TestReprojectionAttachesTheMediaItFinds(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	msg := &waE2E.Message{
		ImageMessage: &waE2E.ImageMessage{
			Mimetype:      proto.String("image/jpeg"),
			Caption:       proto.String("olha"),
			MediaKey:      []byte("0123456789abcdef0123456789abcdef"),
			FileSHA256:    []byte("sha"),
			FileEncSHA256: []byte("enc"),
			FileLength:    proto.Uint64(1234),
			URL:           proto.String("https://mmg.whatsapp.net/expired"),
			DirectPath:    proto.String("/v/t62/expired"),
			Width:         proto.Uint32(800),
			Height:        proto.Uint32(600),
		},
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	res, err := store.NewMessages(f.pool).Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: f.tenant, DeviceID: f.device,
		WAID: "OLDMEDIA", ChatKey: chat.String(), ChatPN: chat.String(),
		SenderKey: chat.String(), TS: time.Now().Truncate(time.Second),
		Kind: domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, ContentKeyID: 1, RawSealed: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := r.Reproject(ctx, f.tenant, f.device, res.UID, raw)
	if err != nil {
		t.Fatalf("Reproject: %v", err)
	}
	if !out.Changed || out.Type != domain.TypeImage {
		t.Fatalf("result = %+v, want a changed image", out)
	}
	// Said plainly rather than implied: the attachment is queued and the URL
	// is months old, so it may never arrive.
	if out.Note == "" {
		t.Error("the caller was not told the attachment had only been queued")
	}

	row, err := store.NewMessages(f.pool).Get(ctx, f.tenant, res.UID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Media == nil {
		t.Fatal("the message was reclassified as an image with no attachment row, " +
			"so nothing will ever download it")
	}
	if row.Media.MimeType != "image/jpeg" || row.Media.FileLength != 1234 {
		t.Errorf("attachment = %+v", row.Media)
	}
	if len(row.Media.MediaKeySealed) == 0 {
		t.Fatal("the media key was not stored; the stored ciphertext would be noise")
	}
	// One key for the whole row, checked against the column itself because the
	// client opens every sealed value on a message — the body, the media key,
	// the thumbnail — with the id carried on the MESSAGE. Two keys here and
	// half the row reports tampering with the correct key in hand.
	var mediaKeyID uint32
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT coalesce(content_key_id,0) FROM media WHERE message_uid = $1`,
			res.UID).Scan(&mediaKeyID)
	}); err != nil {
		t.Fatal(err)
	}
	if mediaKeyID != row.ContentKeyID {
		t.Errorf("media key id %d, message key id %d — the row is sealed under two "+
			"keys and half of it will report tampering", mediaKeyID, row.ContentKeyID)
	}
	if row.Media.DownloadStatus != "pending" {
		t.Errorf("download status = %q, want pending: the media table is the queue",
			row.Media.DownloadStatus)
	}
}

// The chat list carries a projection, and a reclassified message has to reach it.
//
// The sidebar shows the type of each conversation's newest message, written
// when the row was stored. Reclassifying the message and leaving the projection
// alone produces a list that says "tipo não suportado" about a photograph — the
// row right, the summary of it wrong, which is the failure a projection always
// has and the one nobody thinks to look for.
func TestReprojectionRefreshesTheChatPreview(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	res, err := store.NewMessages(f.pool).Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: f.tenant, DeviceID: f.device,
		WAID: "PREVIEW1", ChatKey: chat.String(), ChatPN: chat.String(),
		SenderKey: chat.String(), TS: time.Now().Truncate(time.Second),
		Kind: domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, ContentKeyID: 1, RawSealed: []byte("x"),
		Unsupported: "groupInviteMessage",
	})
	if err != nil {
		t.Fatal(err)
	}

	msg := &waE2E.Message{
		GroupInviteMessage: &waE2E.GroupInviteMessage{
			GroupJID:   proto.String("120363429965256963@g.us"),
			InviteCode: proto.String("X"),
			GroupName:  proto.String("Churrasco"),
		},
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reproject(ctx, f.tenant, f.device, res.UID, raw); err != nil {
		t.Fatal(err)
	}

	chats, err := store.NewMessages(f.pool).Chats(ctx, f.tenant, f.device, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chats {
		if c.ChatKey != chat.String() {
			continue
		}
		if c.LastType != string(domain.TypeGroupInvite) {
			t.Errorf("the sidebar still says %q about a message now classified as %q",
				c.LastType, domain.TypeGroupInvite)
		}
		return
	}
	t.Fatal("the conversation is not in the list")
}

// Protocol traffic is reported as what it is, not as a failure.
//
// An older build stored key distribution and its like as "unsupported"; the
// current one skips them on the way in and would never write such a row. There
// is nothing to reclassify them as. Returning an error put five hundred
// failures in front of somebody whose archive was fine.
func TestProtocolTrafficIsNotReportedAsAFailure(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	chat := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	res, err := store.NewMessages(f.pool).Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: f.tenant, DeviceID: f.device,
		WAID: "MACHINERY1", ChatKey: chat.String(), ChatPN: chat.String(),
		TS:   time.Now().Truncate(time.Second),
		Kind: domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, ContentKeyID: 1, RawSealed: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := proto.Marshal(&waE2E.Message{
		SenderKeyDistributionMessage: &waE2E.SenderKeyDistributionMessage{
			GroupID: proto.String("120363000000000000@g.us"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := r.Reproject(ctx, f.tenant, f.device, res.UID, raw)
	if err != nil {
		t.Fatalf("protocol traffic was reported as an error: %v", err)
	}
	if !out.Machinery {
		t.Error("a key distribution message was not reported as protocol traffic")
	}
	// Retyped as protocol, which is a change — and the change is the point.
	// Left unsupported, the row was offered again on every press, for good.
	if !out.Changed || out.Type != domain.TypeProtocol {
		t.Errorf("changed = %v type = %q; machinery must be retyped as protocol "+
			"so it leaves the list instead of being offered on every press", out.Changed, out.Type)
	}
}
