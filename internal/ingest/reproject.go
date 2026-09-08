package ingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa/normalize"
)

// ReprojectResult is what looking again at one stored message produced.
type ReprojectResult struct {
	Type    domain.Type
	Changed bool
	Note    string
	// Machinery reports a row that is not a message at all.
	//
	// Key distribution, retry receipts and the rest: protocol traffic that the
	// current build skips on the way in and an older one stored. It is not a
	// failure and not a type waiting to be implemented — there is nothing to
	// classify it as, and saying so is more useful than an error that reads
	// like something went wrong.
	Machinery bool
}

// Reproject reclassifies one stored message from the protobuf a client opened.
//
// The division of labour is the point. The browser holds the archive key and
// opens raw_sealed; this server holds the classifier and the public half, and
// sealing needs only the public half. So a row can be looked at again without
// the key ever leaving the tab, and without a second implementation of what a
// message is — FromRaw is a third door into the same normaliser the ingest path
// uses, not a copy of it.
//
// Refuses more than it accepts, and each refusal is a way the archive could be
// made to disagree with itself:
//
//   - The row must still be unsupported. A row already classified is not
//     reopened, so a stale client replaying an old listing changes nothing.
//   - The protobuf must produce the same message id. Otherwise a caller could
//     hand over any message it liked and have it stored as another one.
//   - A result carrying an attachment is refused rather than half-applied. The
//     media pipeline is a separate machine — a download queue, object storage,
//     a retry ladder — and writing a media row from here would fabricate the
//     half that records what was actually fetched.
func (r *Router) Reproject(ctx context.Context, tenant, device uuid.UUID,
	uid uuid.UUID, raw []byte) (ReprojectResult, error) {
	if r.cfg.Messages == nil {
		return ReprojectResult{}, fmt.Errorf("ingest: no message store")
	}
	row, err := r.cfg.Messages.UnsupportedByUID(ctx, tenant, device, uid)
	if err != nil {
		return ReprojectResult{}, err
	}

	var msg waE2E.Message
	if err := proto.Unmarshal(raw, &msg); err != nil {
		return ReprojectResult{}, fmt.Errorf("ingest: that is not a message protobuf: %w", err)
	}

	chat, err := types.ParseJID(row.ChatKey)
	if err != nil {
		return ReprojectResult{}, fmt.Errorf("ingest: stored chat key %q: %w", row.ChatKey, err)
	}
	sender := chat
	if row.SenderKey != "" {
		if j, err := types.ParseJID(row.SenderKey); err == nil {
			sender = j
		}
	}
	info, ok := r.cfg.Lookup(device.String())
	own := domain.Address{}
	if ok {
		own = info.Own
	}

	env, err := normalize.FromRaw(types.MessageInfo{
		ID: row.WAID,
		MessageSource: types.MessageSource{
			Chat: chat, Sender: sender,
			IsFromMe: row.IsFromMe, IsGroup: row.IsGroup,
		},
	}, &msg, normalize.Options{TenantID: tenant.String(), Own: own})
	if errors.Is(err, normalize.ErrSkip) {
		// Not a message. An older build stored key distribution and other
		// protocol traffic as "unsupported"; the current one skips it on the
		// way in and would never write such a row. There is nothing to
		// reclassify it as — so it is retyped as what it is, which takes it
		// out of the list for good. Leaving it unsupported meant it was
		// offered again on every press, and an archive whose real backlog was
		// done went on reporting a hundred and thirty rows of work.
		if err := r.cfg.Messages.MarkProtocol(ctx, tenant, device, row.UID); err != nil {
			return ReprojectResult{}, err
		}
		return ReprojectResult{Type: domain.TypeProtocol, Changed: true, Machinery: true}, nil
	}
	if err != nil {
		return ReprojectResult{}, fmt.Errorf("ingest: reclassify: %w", err)
	}
	if env.MessageID != "" && env.MessageID != row.WAID {
		// The bytes describe a different message. Refused rather than stored:
		// a caller could otherwise overwrite any row with any content.
		return ReprojectResult{}, fmt.Errorf(
			"ingest: that protobuf is message %q, not %q", env.MessageID, row.WAID)
	}
	if env.Type == domain.TypeUnsupported {
		return ReprojectResult{Type: env.Type}, nil
	}

	pipe, err := r.pipelineFor(ctx, tenant, device)
	if err != nil {
		return ReprojectResult{}, err
	}
	values := map[seal.Kind][]byte{}
	if env.Content.Body != "" {
		values[seal.KindBody] = []byte(env.Content.Body)
	}
	if p := env.Content.Payload(); !p.Empty() {
		blob, err := p.Marshal()
		if err != nil {
			return ReprojectResult{}, err
		}
		values[seal.KindPayload] = blob
	}
	// The raw protobuf is re-sealed with the rest, and it has to be: the key id
	// on the row names the key ALL of its sealed values share, so leaving this
	// one behind under the old key produces a row where the body opens and the
	// raw reports tampering — with the right key in hand, which reads as an
	// attack rather than a bug.
	values[seal.KindRawProto] = raw

	// An attachment reaches the archive too. Its key, thumbnail and file name
	// are sealed in the same call as the body, because the key id on the
	// message names the key ALL of its sealed values share — sealing them
	// separately would produce a row where half of it opens and half reports
	// tampering with the correct key in hand.
	if m := env.Content.Media; m != nil {
		if len(m.MediaKey) > 0 {
			values[seal.KindMediaKey] = m.MediaKey
		}
		if len(m.Thumbnail) > 0 {
			values[seal.KindThumbnail] = m.Thumbnail
		}
		if m.FileName != "" {
			values[seal.KindContactName] = []byte(m.FileName)
		}
	}

	sealed, keyID, err := pipe.sealer.SealAll(ctx, uid, values)
	if err != nil {
		return ReprojectResult{}, err
	}

	var media *store.InsertMedia
	if env.Content.Media != nil {
		media = mediaRow(env.Type, env.Content.Media, sealed)
	}

	if err := r.cfg.Messages.Reproject(ctx, tenant, device, uid, env.Type, keyID,
		sealed[seal.KindBody], sealed[seal.KindPayload], sealed[seal.KindRawProto],
		media); err != nil {
		return ReprojectResult{}, err
	}

	out := ReprojectResult{Type: env.Type, Changed: true}
	if media != nil {
		// The row is in the download queue now — the media table IS the queue.
		// Said plainly because the attachment may never arrive: a URL minted
		// months ago has very likely expired, and WhatsApp signs the direct
		// path with the same signature, so there is no second address to try.
		// The message stops being "unsupported" either way, which is the part
		// that was wrong.
		out.Note = "anexo enfileirado para download; a url pode ter expirado"
		if r.cfg.Media != nil {
			if err := r.cfg.Media.Enqueue(ctx, tenant, uid); err != nil {
				r.log.Debug("could not nudge the media worker", "error", err)
			}
		}
	}
	return out, nil
}

// UnsupportedRows lists what a client should try to open.
func (r *Router) UnsupportedRows(ctx context.Context, tenant, device uuid.UUID,
	beforeSeq int64, limit int) ([]store.Reprojection, error) {
	if r.cfg.Messages == nil {
		return nil, fmt.Errorf("ingest: no message store")
	}
	return r.cfg.Messages.Unsupported(ctx, tenant, device, beforeSeq, limit)
}
