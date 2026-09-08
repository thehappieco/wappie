package wsapi

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// reprojectLimit bounds one listing. A run walks the list repeatedly; the point
// of a page is that an interrupted run has still made progress.
const reprojectLimit = 200

// handleReprojectList names messages this build might now understand.
//
// Carries raw_sealed, which no other frame does and which is why this is a
// frame of its own rather than a field on a message: including it everywhere
// would roughly double every message frame to serve an operation run once in a
// while, deliberately, by somebody watching.
func (s *session) handleReprojectList(ctx context.Context, f Frame) {
	var req ReprojectRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Router == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "reprojection is not configured on this server")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > reprojectLimit {
		limit = reprojectLimit
	}
	rows, err := s.srv.cfg.Router.UnsupportedRows(ctx, tenant, device, req.BeforeSeq, limit)
	if err != nil {
		s.log.Error("could not list unsupported messages", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list unsupported messages")
		return
	}
	out := make([]UnsupportedRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, UnsupportedRow{
			UID: r.UID.String(), Seq: r.Seq, WAID: r.WAID, Field: r.Unsupported,
			ContentKeyID: r.ContentKeyID, RawSealed: r.RawSealed,
		})
	}
	s.reply(TypeUnsupported, f.ReqID, Unsupported{DeviceID: device.String(), Rows: out})
}

// handleReprojectApply reclassifies one message from the protobuf a client
// opened.
//
// The archive key never reaches this process: the browser opens raw_sealed and
// hands back the protobuf, and sealing the result needs only the public half
// this server already holds. What passes through in the clear is the message
// itself, for the rows an operator explicitly asked about — the same exposure
// outbound text already carries, and strictly smaller than the alternative,
// which was pasting the archive key into a shell.
func (s *session) handleReprojectApply(ctx context.Context, f Frame) {
	var req ReprojectRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Router == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "reprojection is not configured on this server")
		return
	}
	if len(req.Raw) == 0 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "raw is required")
		return
	}
	uid, err := uuid.Parse(req.UID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "uid is required and must be a uuid")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}

	res, err := s.srv.cfg.Router.Reproject(ctx, tenant, device, uid, req.Raw)
	if err != nil {
		// Not logged as an error: "that row is no longer unsupported" and
		// "that protobuf is a different message" are both ordinary answers to
		// a client working through a list.
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	s.reply(TypeReprojected, f.ReqID, Reprojected{
		UID: uid.String(), Type: string(res.Type), Changed: res.Changed,
		Note: res.Note, Machinery: res.Machinery,
	})
}
