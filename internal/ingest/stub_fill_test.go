package ingest_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// queued records the media downloads a pipeline asked for.
type queued struct {
	mu   sync.Mutex
	uids []uuid.UUID
}

func (q *queued) Enqueue(_ context.Context, _, uid uuid.UUID) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.uids = append(q.uids, uid)
	return nil
}

func (q *queued) all() []uuid.UUID {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]uuid.UUID(nil), q.uids...)
}

// stubPipeline is the fixture's pipeline with a media queue and the
// archive key named, as the router builds it.
func stubPipeline(t *testing.T, f *fixture) (*ingest.Pipeline, *queued) {
	t.Helper()
	pipe, q, _ := clockedPipeline(t, f, time.Now)
	return pipe, q
}

// clockedPipeline is stubPipeline with the sealer's clock and the
// pipeline's metrics in the test's hands. The sealer reads its clock on
// each seal, before it seals.
func clockedPipeline(t *testing.T, f *fixture, now func() time.Time) (*ingest.Pipeline, *queued, *obs.Metrics) {
	t.Helper()
	ctx := context.Background()
	pub, epoch, err := f.keys.ArchiveKey(ctx, f.tenant, f.device)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.NewSealerWithArchiveTenant(f.tenant, f.tenant, f.device, pub, epoch, f.keys, seal.WithClock(now))
	if err != nil {
		t.Fatal(err)
	}
	q := &queued{}
	metrics := obs.NewMetrics()
	pipe, err := ingest.New(ingest.Config{
		Tenant: f.tenant, Sealer: sealer, ArchiveKey: pub, Messages: store.NewMessages(f.pool),
		Bus: f.bus, Media: q, Metrics: metrics, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pipe, q, metrics
}

// stored is one message row and its media row as a reader gets them.
type stored struct {
	uid                     uuid.UUID
	typ                     string
	keyID                   uint32
	body, raw, payload      []byte
	hasMedia                bool
	mediaKeyID              uint32
	mediaKey, thumb, name   []byte
	downloadStatus, chatTyp string
}

func readStored(t *testing.T, f *fixture, chat, waID string) stored {
	t.Helper()
	ctx := context.Background()
	var s stored
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		var k int32
		if err := tx.QueryRow(ctx, `
			SELECT uid, type, coalesce(content_key_id, 0), body_sealed, raw_sealed, payload_sealed
			  FROM messages WHERE device_id = $1 AND chat_key = $2 AND wa_id = $3`,
			f.device, chat, waID).Scan(&s.uid, &s.typ, &k, &s.body, &s.raw, &s.payload); err != nil {
			return err
		}
		s.keyID = uint32(k)
		if err := tx.QueryRow(ctx, `SELECT coalesce(last_type, '') FROM chats
			WHERE device_id = $1 AND chat_key = $2`, f.device, chat).Scan(&s.chatTyp); err != nil {
			return err
		}
		var mk int32
		err := tx.QueryRow(ctx, `
			SELECT coalesce(content_key_id, 0), media_key_sealed, thumb_sealed, filename_sealed, download_status
			  FROM media WHERE message_uid = $1`, s.uid).Scan(&mk, &s.mediaKey, &s.thumb, &s.name, &s.downloadStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		s.hasMedia, s.mediaKeyID = err == nil, uint32(mk)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// opens opens one sealed value the way a reader does: under the content
// key the row names, bound to the row's own uid.
func (f *fixture) opens(t *testing.T, uid uuid.UUID, kind seal.Kind, keyID uint32, sealed []byte) ([]byte, error) {
	t.Helper()
	blob, err := f.keys.SealedContentKey(context.Background(), f.tenant, f.device, keyID)
	if err != nil {
		return nil, err
	}
	ck, err := seal.OpenContentKey(f.priv, f.tenant, f.device, keyID, blob)
	if err != nil {
		return nil, err
	}
	return ck.Open(kind, f.tenant, uid, sealed)
}

// TestARealMessageFillsItsPlaceholder (DS51): a placeholder took a
// message's slot, and the real message then arrives through the
// pipeline. The row keeps the placeholder's uid, so every value it now
// holds must be sealed to that uid, or a reader finds it tampered. The
// attachment's row is written too, and its download queued.
func TestARealMessageFillsItsPlaceholder(t *testing.T) {
	f := newFixture(t)
	pipe, q := stubPipeline(t, f)
	ctx := context.Background()
	group := types.JID{User: "120363000000000001", Server: types.GroupServer}
	chat := group.String()
	const waID = "3AD9FC72C86E3D46A831"
	at := time.Now().Truncate(time.Second)

	env := func(typ domain.Type, content domain.Content) domain.Envelope {
		return domain.Envelope{
			TenantID: f.tenant.String(), DeviceID: f.device.String(), MessageID: waID,
			Chat: domain.AddressOf(group), Sender: domain.AddressOf(senderJID), IsGroup: true,
			Timestamp: at, Kind: domain.KindMessage, Type: typ, Source: domain.SourceLive,
			Content: content,
		}
	}

	// The placeholder: a field this build did not know, raw protobuf only.
	first, err := pipe.Ingest(ctx, env(domain.TypeUnsupported, domain.Content{
		Raw: []byte("the placeholder's raw protobuf"), Unsupported: "someFutureMessage",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate {
		t.Fatal("the placeholder was reported a duplicate")
	}
	events := len(f.bus.all())

	// The real message, under the same id: a document with a caption, a
	// mention, a thumbnail and a file name.
	doc := domain.Content{
		Body:     "o contrato assinado",
		Raw:      []byte("the real message's raw protobuf"),
		Mentions: []string{"5511988887777@s.whatsapp.net"},
		Media: &domain.Media{
			MimeType: "application/pdf", FileLength: 1234,
			FileSHA256: []byte("sha"), FileEncSHA256: []byte("enc sha"),
			DirectPath: "/v/t62.7119-24/1", URL: "https://mmg.whatsapp.net/v/t62.7119-24/1",
			MediaKey:  []byte("0123456789abcdef0123456789abcdef"),
			Thumbnail: []byte("a small preview"),
			FileName:  "contrato.pdf",
		},
	}
	second, err := pipe.Ingest(ctx, env(domain.TypeDocument, doc))
	if err != nil {
		t.Fatal(err)
	}
	if second.UID != first.UID || second.Seq != first.Seq {
		t.Errorf("the fill moved the row: %v/%d, want %v/%d", second.UID, second.Seq, first.UID, first.Seq)
	}

	row := readStored(t, f, chat, waID)
	if row.uid != first.UID {
		t.Fatalf("row uid = %v, want the placeholder's %v", row.uid, first.UID)
	}
	if row.typ != string(domain.TypeDocument) {
		t.Fatalf("type = %s, want document: the placeholder still holds the row", row.typ)
	}
	payload, err := domain.Content{Mentions: doc.Mentions}.Payload().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		name   string
		kind   seal.Kind
		keyID  uint32
		sealed []byte
		want   string
	}{
		{"body", seal.KindBody, row.keyID, row.body, doc.Body},
		{"raw", seal.KindRawProto, row.keyID, row.raw, string(doc.Raw)},
		{"payload", seal.KindPayload, row.keyID, row.payload, string(payload)},
		{"media key", seal.KindMediaKey, row.keyID, row.mediaKey, string(doc.Media.MediaKey)},
		{"thumbnail", seal.KindThumbnail, row.keyID, row.thumb, string(doc.Media.Thumbnail)},
		{"file name", seal.KindContactName, row.keyID, row.name, doc.Media.FileName},
	} {
		if len(v.sealed) == 0 {
			t.Errorf("%s: nothing stored", v.name)
			continue
		}
		got, err := f.opens(t, row.uid, v.kind, v.keyID, v.sealed)
		if err != nil {
			t.Errorf("%s does not open under the row's uid: %v", v.name, err)
			continue
		}
		if string(got) != v.want {
			t.Errorf("%s = %q, want %q", v.name, got, v.want)
		}
	}
	if !row.hasMedia {
		t.Fatal("no media row: the attachment was dropped")
	}
	if row.mediaKeyID != row.keyID {
		t.Errorf("media content key %d, message %d: one row, one key", row.mediaKeyID, row.keyID)
	}
	if row.downloadStatus != "pending" {
		t.Errorf("download_status = %q, want pending (the media table is the queue)", row.downloadStatus)
	}
	if got := q.all(); len(got) != 1 || got[0] != row.uid {
		t.Errorf("downloads nudged for %v, want [%v]", got, row.uid)
	}
	if row.chatTyp != string(domain.TypeDocument) {
		t.Errorf("chat last_type = %q, want document: the list still says unsupported", row.chatTyp)
	}
	// No new sequence and no new event: the row was there already.
	if n := len(f.bus.all()); n != events {
		t.Errorf("the fill published %d events", n-events)
	}

	// The same message again changes nothing.
	again, err := pipe.Ingest(ctx, env(domain.TypeDocument, doc))
	if err != nil {
		t.Fatal(err)
	}
	if !again.Duplicate || again.UID != first.UID {
		t.Errorf("a redelivery after the fill: %+v", again)
	}
	if after := readStored(t, f, chat, waID); string(after.body) != string(row.body) {
		t.Error("a redelivery rewrote the filled row")
	}
}

// TestTwoCopiesFillAPlaceholderOnce (DS51): live delivery and a history
// sync can bring the real message at the same moment. Both are sealed
// again to the placeholder's uid; one fills it, the other is a duplicate,
// and neither fails.
func TestTwoCopiesFillAPlaceholderOnce(t *testing.T) {
	f := newFixture(t)
	pipe, _ := stubPipeline(t, f)
	ctx := context.Background()
	const waID = "3AD9FC72C86E3D46A832"
	env := f.envelope(waID, domain.KindMessage, domain.TypeUnsupported, "")
	env.Content = domain.Content{Raw: []byte("placeholder"), Unsupported: "someFutureMessage"}
	first, err := pipe.Ingest(ctx, env)
	if err != nil {
		t.Fatal(err)
	}

	env.Type = domain.TypeImage
	env.Content = domain.Content{
		Body: "a foto", Raw: []byte("the real message"),
		Media: &domain.Media{MimeType: "image/jpeg", MediaKey: []byte("0123456789abcdef0123456789abcdef")},
	}
	results := make([]ingest.Result, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = pipe.Ingest(ctx, env)
		}()
	}
	wg.Wait()

	filled := 0
	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("copy %d: %v", i, errs[i])
		}
		if res.UID != first.UID || !res.Duplicate {
			t.Errorf("copy %d: %+v, want the placeholder's row", i, res)
		}
		if res.Filled {
			filled++
		}
	}
	if filled != 1 {
		t.Errorf("%d copies filled the placeholder, want 1", filled)
	}
	row := readStored(t, f, chatJID.String(), waID)
	if got, err := f.opens(t, row.uid, seal.KindBody, row.keyID, row.body); err != nil || string(got) != "a foto" {
		t.Errorf("body = %q, %v", got, err)
	}
	if got, err := f.opens(t, row.uid, seal.KindMediaKey, row.keyID, row.mediaKey); err != nil || len(got) != 32 {
		t.Errorf("media key = %x, %v", got, err)
	}
}

// photo is the real message of the race tests: an image with a caption.
func photo(f *fixture, waID string) domain.Envelope {
	env := f.envelope(waID, domain.KindMessage, domain.TypeImage, "a foto")
	env.Content.Raw = []byte("the real message")
	env.Content.Media = &domain.Media{MimeType: "image/jpeg", MediaKey: []byte("0123456789abcdef0123456789abcdef")}
	return env
}

// TestAnotherSendersMessageDoesNotFillThroughThePipeline (DS51): a message
// under a placeholder's id from someone else is a plain duplicate. It is
// sealed once and stored nowhere.
func TestAnotherSendersMessageDoesNotFillThroughThePipeline(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pipe, q, m := clockedPipeline(t, f, time.Now)
	group := types.JID{User: "120363000000000002", Server: types.GroupServer}
	const waID = "3AD9FC72C86E3D46A835"

	stub := f.envelope(waID, domain.KindMessage, domain.TypeUnsupported, "")
	stub.Chat, stub.IsGroup = domain.AddressOf(group), true
	stub.Content = domain.Content{Raw: []byte("placeholder"), Unsupported: "someFutureMessage"}
	first, err := pipe.Ingest(ctx, stub)
	if err != nil {
		t.Fatal(err)
	}

	other := photo(f, waID)
	other.Chat, other.IsGroup = domain.AddressOf(group), true
	other.Sender = domain.AddressOf(types.JID{User: "5511977776666", Server: types.DefaultUserServer})
	res, err := pipe.Ingest(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Duplicate || res.Filled || res.UID != first.UID {
		t.Errorf("result = %+v, want a plain duplicate of %v", res, first.UID)
	}
	if n := testutil.ToFloat64(m.Sealed.WithLabelValues(seal.KindBody.String())); n != 1 {
		t.Errorf("%v seals of the body, want 1", n)
	}
	row := readStored(t, f, group.String(), waID)
	if row.typ != string(domain.TypeUnsupported) || len(row.body) != 0 || row.hasMedia {
		t.Errorf("row = %s, body %d bytes, media %v: another sender filled the placeholder", row.typ, len(row.body), row.hasMedia)
	}
	if got := q.all(); len(got) != 0 {
		t.Errorf("downloads nudged for %v", got)
	}
}
