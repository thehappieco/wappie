package wsapi

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/google/uuid"

	"whatserver2/internal/access"
	"whatserver2/internal/store"
)

// A platform token on the socket (the plan's 3.4 and 7). Its hello is its
// text in api_key, as it is; every frame it sends meets tokenRules before
// anything else; it names a number by its full id only, checked before any
// lookup, and every refusal on a number is one answer that holds no id. The
// session keeps what the token reaches now (store.TokenLive), refreshed
// before every frame it reads, before every batch it writes, every second
// and at once on the token's NOTIFY: a narrowing that bumps no version (a
// switch, a rotation, the workspace closed) stops what it carries, and one
// that bumps it, or a token no longer live, closes the socket.

// The texts of a token's refusals: one for a frame a token never sends, one
// for every act on a number, missing included, one for a hello, and one for
// every failed device.start of a token that cannot read the number.
const (
	tokenFrameRefused  = "a platform token cannot do this"
	tokenNumberRefused = "this token cannot do that on this number"
	tokenHelloRefused  = "credential expired, revoked or invalid" //nolint:gosec // G101: a refusal's text, not a credential
	tokenStartRefused  = "this number cannot be resumed now"
)

// tokenRule is what a frame needs of a token: its action on the number the
// frame names (store.ActionRead and the rest), whether it fetches an
// attachment (the attachments switch), or that a token never sends it.
// A read frame's reply is full; an act's reply is full only with Read on
// the number, and TokenAct otherwise.
type tokenRule struct {
	action  store.DeviceAction
	media   bool
	refused bool
}

// tokenRules has a rule for every frame dispatch answers
// (TestEveryFrameHasATokenRule): a frame without one is refused to a token,
// never let through to frameAction's read default.
var tokenRules = func() map[string]tokenRule {
	rules := map[string]tokenRule{TypePing: {}}
	set := func(r tokenRule, kinds ...string) {
		for _, k := range kinds {
			rules[k] = r
		}
	}
	set(tokenRule{action: store.ActionRead},
		TypeDevicesList, TypeSubscribe, TypeChatsList, TypeChatPage, TypeHistory, TypeMessageGet, TypeKeysGet,
		TypeContacts, TypeResolve, TypeAvatar, TypeGroupGet, TypePresenceWatch)
	// View is Read for a token: nothing without Read, not even metadata
	// (decision 0053).
	set(tokenRule{action: store.ActionView}, TypeDevicesStats, TypeDeviceInfo)
	set(tokenRule{action: store.ActionRead, media: true}, TypeMediaRetry, TypeMediaExpired)
	set(tokenRule{action: store.ActionSend},
		TypeSend, TypeSendMedia, TypeEdit, TypeRevoke, TypeReact, TypePollVote, TypePollCreate, TypeLocationSend,
		TypeEventCreate, TypeMarkRead, TypeChatTyping, TypeChatTimer, TypeChatStart)
	// Groups and backfill need Manage alone, never Send.
	set(tokenRule{action: store.ActionManage},
		TypeGroupCreate, TypeGroupParticipants, TypeGroupLeave, TypeGroupJoin, TypeBackfill, TypeDeviceRename, TypeDeviceMode)
	// Pause is Manage for a token (decision 0053).
	set(tokenRule{action: store.ActionPause}, TypeDeviceStop, TypeDeviceStart)
	// Never a token's: pairing in every form, the retry and a relink
	// included (F1: linking an account into a number is a signed-in owner's
	// or admin's act, after a step-up); calls; the accounts; a reader's
	// own mode; reprojection, which reseals a protobuf the caller supplies
	// (H4); moving, deleting and recovering numbers; notices; keys and
	// grants (PR 7 opens grants.list).
	set(tokenRule{refused: true},
		TypePair, TypePairCancel, TypeUsersList, TypeCallsList, TypeCallStart, TypeCallInvite, TypeCallAnswer,
		TypeCallReject, TypeCallHangup, TypeCallMedia, TypeReaderMode, TypeReprojectGet, TypeReprojectPut,
		TypeDeviceTransferPreview, TypeDeviceTransfer, TypeDeviceDelete, TypeDeviceDeleteCheck, TypeDevicesDeleted,
		TypeDeviceRecoverCheck, TypeDeviceRecover, TypeDeviceNoticeSeen, TypeKeysList, TypeKeyCreate, TypeKeyRevoke,
		TypeGrantAdd, TypeGrantRevoke, TypeGrantsList)
	return rules
}()

// ruleOf is a frame's rule for a token; a frame with none is refused.
func ruleOf(kind string) tokenRule {
	r, ok := tokenRules[kind]
	if !ok {
		return tokenRule{refused: true}
	}
	return r
}

// tokenFeatures is the welcome's feature list for a token: only the frames
// its rules let through, so a client never offers what is refused.
func tokenFeatures() []string {
	out := make([]string, 0, len(features))
	for _, f := range features {
		if r, ok := tokenRules[f]; ok && !r.refused {
			out = append(out, f)
		}
	}
	return out
}

// TokenAct is the reply to an act of a token without Read on the number,
// sent under the frame's usual reply type: the number, that it went
// through, and the one field it changed. Nothing else of the number goes
// to a token that cannot read it.
type TokenAct struct {
	DeviceID    string  `json:"device_id"`
	OK          bool    `json:"ok"`
	Label       *string `json:"label,omitempty"`
	ReceiptMode *string `json:"receipt_mode,omitempty"`
	Chat        *string `json:"chat,omitempty"`
	Paused      *bool   `json:"paused,omitempty"`
}

// isToken reports whether a platform token authenticated.
func (a actor) isToken() bool { return a.token.ID != uuid.Nil }

// tokenCredentials authenticates a token's hello: its text in api_key, as
// it is, and never beside a session. Every refusal is the one answer.
func (s *session) tokenCredentials(ctx context.Context, hello Hello) (actor, error) {
	if hello.Session != "" {
		return actor{}, errTokenHello
	}
	who, err := s.srv.checker().AuthenticateToken(ctx, hello.APIKey, s.peer)
	if err != nil {
		return actor{}, errTokenHello
	}
	return actor{tenant: who.Tenant.String(), token: who.Token}, nil
}

// errTokenHello is every refusal of a token's hello: it never echoes the
// text.
var errTokenHello = tokenError(tokenHelloRefused)

type tokenError string

func (e tokenError) Error() string { return string(e) }

// checker is the server's Checker for what is not a session's: a token's.
func (s *Server) checker() *access.Checker {
	if s.cfg.Access != nil {
		return s.cfg.Access
	}
	return &access.Checker{Keys: s.cfg.Keys, Users: s.cfg.Accounts, Log: s.log}
}

// tokenSets is what the session's token reaches, as last checked.
func (s *session) tokenSets() store.TokenLive {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenLive
}

// refreshToken reads what the token reaches now and returns it. It keeps
// what it read unless a check that started after this one already kept its
// own: readLoop, writeLoop and accessLoop all check, and their reads land
// in any order. It reports false once the token is no longer live or its
// version changed: the socket closes.
func (s *session) refreshToken(ctx context.Context, who actor) (store.TokenLive, bool) {
	tenant, err := uuid.Parse(who.tenant)
	if err != nil {
		return store.TokenLive{}, false
	}
	s.mu.Lock()
	s.tokenAsked++
	asked := s.tokenAsked
	s.mu.Unlock()
	s.tokenHook("asked")
	live, err := s.checker().TokenSets(ctx, access.Actor{Tenant: tenant, Token: who.token})
	if err != nil || !live.Live {
		return store.TokenLive{}, false
	}
	s.tokenHook("queried")
	s.mu.Lock()
	if asked > s.tokenStored {
		s.tokenLive, s.tokenStored = live, asked
	}
	s.mu.Unlock()
	s.tokenHook("checked")
	return live, true
}

// tokenHook runs the tests' hook at a seam of a token session.
func (s *session) tokenHook(stage string) {
	if s.srv.cfg.tokenHook != nil {
		s.srv.cfg.tokenHook(stage)
	}
}

// narrower is what both a and b let a token reach. The writer judges each
// frame under the narrower of its own check and the newest one kept: its
// own started after the batch's frames were queued, and the newest kept
// may have seen a narrowing since. A check that started later can still
// have read earlier (a wait for a connection), so neither alone is enough.
func narrower(a, b store.TokenLive) store.TokenLive {
	both := func(x, y map[uuid.UUID]struct{}) map[uuid.UUID]struct{} {
		out := make(map[uuid.UUID]struct{}, len(x))
		for d := range x {
			if _, ok := y[d]; ok {
				out[d] = struct{}{}
			}
		}
		return out
	}
	return store.TokenLive{Live: a.Live && b.Live, Closed: a.Closed || b.Closed, MediaOn: a.MediaOn && b.MediaOn,
		Reads: both(a.Reads, b.Reads), Sends: both(a.Sends, b.Sends), Manages: both(a.Manages, b.Manages)}
}

// tokenReqKey carries a token's request through its handler: the numbers
// whose Read its reply was built under.
type tokenReqKey struct{}

type tokenReq struct {
	mu    sync.Mutex
	reads map[uuid.UUID]struct{}
}

func withTokenReq(ctx context.Context) context.Context {
	return context.WithValue(ctx, tokenReqKey{}, &tokenReq{reads: map[uuid.UUID]struct{}{}})
}

// readUnder records that the request's reply holds what device's Read
// allowed.
func readUnder(ctx context.Context, devices ...uuid.UUID) {
	r, ok := ctx.Value(tokenReqKey{}).(*tokenReq)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range devices {
		r.reads[d] = struct{}{}
	}
}

// readTag is the numbers a reply was read under: the writer drops it,
// answering the one refusal in its place, unless the token still reads
// every one when it goes out. A rotation or a switch turned off bumps no
// version, so a reply built just before one must not be written after it.
type readTag struct{ devices []uuid.UUID }

// replyRead is reply for a read frame's answer: a token's is tagged with
// the numbers its handler read under.
func (s *session) replyRead(ctx context.Context, frameType, reqID string, payload any) {
	f, err := encode(frameType, reqID, payload)
	if err != nil {
		s.log.Error("encoding a frame failed", "type", frameType, "error", err)
		return
	}
	if r, ok := ctx.Value(tokenReqKey{}).(*tokenReq); ok {
		r.mu.Lock()
		tag := &readTag{devices: make([]uuid.UUID, 0, len(r.reads))}
		for d := range r.reads {
			tag.devices = append(tag.devices, d)
		}
		r.mu.Unlock()
		f.reads = tag
		s.tokenHook("reply")
		s.send(f)
		s.tokenHook("queued")
		return
	}
	s.send(f)
}

// tokenWritable is the writer's last word on a token session's frame: a
// reply read under a number the token no longer reads becomes the one
// refusal; a frame that carries rows with attachments is withheld while
// the attachments switch is off.
func (s *session) tokenWritable(f Frame, live store.TokenLive) (Frame, bool) {
	if f.reads != nil {
		for _, d := range f.reads.devices {
			if _, ok := live.Reads[d]; !ok {
				refusal, err := encode(TypeError, f.ReqID, Error{Code: ErrCodeNotAuthorized, Message: tokenNumberRefused})
				return refusal, err == nil
			}
		}
	}
	if live.MediaOn {
		return f, true
	}
	return withheldFrame(f)
}

// withheldFrame is f with its rows' attachments withheld, for the frames
// that carry rows; any other frame is unchanged.
func withheldFrame(f Frame) (Frame, bool) {
	var payload interface{ WithholdAttachments() }
	switch f.Type {
	case TypeMessage, TypeMessageFrame:
		payload = &SealedMessage{}
	case TypePage:
		payload = &Page{}
	case TypeHistoryFrame:
		payload = &History{}
	case TypeChats:
		payload = &Chats{}
	default:
		return f, true
	}
	if err := json.Unmarshal(f.Payload, payload); err != nil {
		return f, false
	}
	payload.WithholdAttachments()
	b, err := json.Marshal(payload)
	if err != nil {
		return f, false
	}
	f.Payload = b
	return f, true
}

// replyTokenAct answers an act of a token: in full (full is called) when it
// reads the number, with TokenAct otherwise.
func (s *session) replyTokenAct(ctx context.Context, frameType, reqID string, device uuid.UUID, act TokenAct, full func(ctx context.Context)) {
	if s.tokenReadsNow(ctx, device) {
		full(ctx)
		return
	}
	act.DeviceID, act.OK = device.String(), true
	s.reply(frameType, reqID, act)
}

// tokenReadsNow asks whether the token reads device now, never counted.
func (s *session) tokenReadsNow(ctx context.Context, device uuid.UUID) bool {
	who := s.actor()
	tenant, err := uuid.Parse(who.tenant)
	if err != nil {
		return false
	}
	ok, err := s.checker().Probe(ctx, access.Actor{Tenant: tenant, Token: who.token}, device, store.ActionRead)
	if err == nil && ok {
		readUnder(ctx, device)
	}
	return err == nil && ok
}

// tokenResolve is resolveDevice for a token: a full canonical id, its
// rule's check before any lookup, and one answer for every refusal.
func (s *session) tokenResolve(ctx context.Context, f Frame, tenant uuid.UUID, deviceID string) (uuid.UUID, uuid.UUID, bool) {
	id, err := uuid.Parse(deviceID)
	if err != nil || id.String() != deviceID {
		s.replyError(f.ReqID, ErrCodeBadRequest, "device_id must be a full id")
		return uuid.Nil, uuid.Nil, false
	}
	rule := ruleOf(f.Type)
	if !s.authorizeToken(ctx, f, id, store.TokenNeed{Action: rule.action, Media: rule.media}) {
		return uuid.Nil, uuid.Nil, false
	}
	return tenant, id, true
}

// authorizeToken is authorizeDevice for a token: counted, one answer.
func (s *session) authorizeToken(ctx context.Context, f Frame, device uuid.UUID, need store.TokenNeed) bool {
	who := s.actor()
	tenant, err := uuid.Parse(who.tenant)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "invalid workspace")
		return false
	}
	v, err := s.checker().TokenAllows(ctx, access.Actor{Tenant: tenant, Token: who.token}, device, need)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check device permissions")
		return false
	}
	if !v.OK {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, tokenNumberRefused)
		return false
	}
	if need.Action == store.ActionRead || need.Action == store.ActionView {
		readUnder(ctx, device)
	}
	return true
}
