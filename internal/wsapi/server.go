package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/blob"
	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
	"whatserver2/internal/media"
	"whatserver2/internal/obs"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Config wires the websocket handler to the rest of the server.
type Config struct {
	Keys *store.APIKeys
	// Sessions resolves a browser sign-in. Without it only API keys are
	// accepted, which is a headless deployment rather than a broken one.
	Sessions *store.Users
	Devices  *store.Devices
	Messages *store.Messages
	// Receipts archives and serves acknowledgements. Without it the message
	// history still assembles, minus the readers.
	Receipts *store.Receipts
	// Unread is the badge, cleared when this client reports having read
	// something. Separate from the receipt policy on purpose: whether a read
	// receipt leaves for WhatsApp is a question about the other side, and
	// whether the badge clears is a question about this reader. Conflating
	// them is why a discreet device — the default — could never clear a badge
	// at all: nothing went out, so nothing came back to clear it.
	Unread *store.Unread
	// Retrier asks senders to re-upload attachments whose URLs expired, and
	// Media is where the list of those lives.
	Retrier  *media.Retrier
	Media    *store.Media
	Contacts *store.Contacts
	// Groups is who is in a group and what has happened to it.
	Groups *store.Groups
	// Avatars is the profile-picture worker, reached only to ask it to look at
	// a contact ahead of its ordinary sweep. Optional: without it a face still
	// arrives, just on the sweep's own schedule.
	Avatars *media.AvatarWorker
	// Keys2 serves sealed content keys, archive keys and grants. Named apart
	// from Keys, which is the API-key store; the two are unrelated despite the
	// word.
	Keys2 *store.Keys
	// Accounts is the same store as Sessions, reached for a different reason:
	// listing the public keys a device key can be granted to.
	Accounts *store.Users
	// Router archives outbound messages through the same pipeline inbound
	// uses, so a message we sent is stored exactly like one we received.
	Router   *ingest.Router
	Registry *wa.Registry
	Bus      *bus.Bus
	Metrics  *obs.Metrics
	// Blob is object storage, reached only to remove what a deleted device
	// held. Optional: without it the bytes stay, inert, as they always did.
	Blob *blob.Store
	// Pool is the API pool, for the object-key queries a delete needs.
	Pool *pgxpool.Pool
	// Limits bounds hello attempts per address and per credential. An API
	// key is verified with Argon2id, so an unlimited hello is both a guessing
	// surface and a way to make this process spend memory on demand.
	Limits *ratelimit.Auth
	Log    *slog.Logger
}

// Server serves the websocket endpoint.
type Server struct {
	cfg Config
	log *slog.Logger

	mu       sync.RWMutex
	sessions map[*session]struct{}
}

// NewServer builds the handler.
func NewServer(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Server{cfg: cfg, log: cfg.Log, sessions: map[*session]struct{}{}}
}

const (
	// helloTimeout bounds how long an unauthenticated connection may sit idle.
	// Without it an attacker can hold sockets open for free.
	helloTimeout = 10 * time.Second

	// pingInterval keeps intermediaries from dropping an idle connection.
	pingInterval = 30 * time.Second

	// readLimit caps a single frame. Commands are small; anything larger is a
	// mistake or an attack.
	readLimit = 1 << 20 // 1 MiB

	// outboundBuffer is how many frames may queue for a slow reader before the
	// server stops waiting for it.
	outboundBuffer = 256
)

// features is what this build answers, announced in the welcome frame.
//
// It had drifted: eight implemented frames were missing from it, including
// every one phases 4 to 6 added. A client that branched on this list would
// have concluded that attachments, contacts and disappearing timers were not
// available on a server that has served all three for months. The list is here,
// as one value, so the next addition has somewhere obvious to go.
//
// It drifted again anyway — message.poll.vote and device.stop were dispatched
// and unannounced — which is why the list is no longer maintained by hand.
// TestEveryDispatchedFrameIsAnnounced walks the dispatch switch and fails on
// anything missing, because a comment asking people to remember has now been
// tried twice and lost twice.
//
// Two entries name no frame at all. "pair.qr" and "pair.code" are the two
// values of PairRequest.Method, and a client genuinely has to know which this
// build supports — code pairing is much better over a terminal, and asking for
// it on a server that only does QR fails after a round trip. They are
// capabilities, which is what this list is for; the frame is "pair".
var features = []string{
	"pair", "pair.cancel", "pair.qr", "pair.code",
	"devices.list", "users.list",
	"subscribe", "chats.list", "chat.page", "keys.get",
	"contacts.list", "contacts.resolve", "contacts.avatar",
	"message.get", "message.history",
	"message.send", "message.send.media", "message.send.location", "message.edit", "message.revoke",
	"message.react", "message.read", "message.poll.vote", "message.poll.create",
	"chat.start", "group.create", "group.participants.update", "group.leave",
	"chat.timer", "chat.presence", "presence.subscribe", "device.mode", "device.stop", "device.start", "device.rename",
	"group.join", "group.info", "reproject.list", "reproject.apply", "media.retry", "media.expired", "history.backfill",
	"devices.stats", "device.info", "device.delete",
	"apikeys.list", "apikeys.create", "apikeys.revoke",
	"grant.add", "grant.revoke", "grants.list",
}

// ServeHTTP upgrades and runs one session.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Same-origin only. The browser client is served from this origin, and
		// anything else should be using an API key over a non-browser client.
		OriginPatterns: nil,
	})
	if err != nil {
		s.log.Debug("websocket upgrade failed", "error", err)
		return
	}
	conn.SetReadLimit(readLimit)

	var proxies []netip.Prefix
	if s.cfg.Limits != nil {
		proxies = s.cfg.Limits.Proxies
	}
	sess := &session{
		srv:        s,
		conn:       conn,
		out:        make(chan Frame, outboundBuffer),
		log:        s.log,
		peer:       ratelimit.ClientIP(r, proxies),
		accessWake: make(chan struct{}, 1),
	}
	sess.run(r.Context())
}

func (s *Server) register(sess *session) {
	s.mu.Lock()
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.WSConnections.Inc()
	}
}

func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.WSConnections.Dec()
	}
}

// disconnectKey hangs up every connection authenticated with one API key.
//
// Called on revocation. The alternative — letting existing sockets run until
// they happen to drop — makes "revoked" mean "revoked for anyone who reconnects
// later", which is not what the word promises in a UI.
//
// Only this process. Another instance holding a socket on the same key keeps it
// until that instance notices, which is a real limit and not one this can fix
// from here.
func (s *Server) disconnectKey(prefix string) {
	if prefix == "" {
		return
	}
	s.mu.RLock()
	var doomed []*session
	for sess := range s.sessions {
		if sess.actor().keyPrefix == prefix {
			doomed = append(doomed, sess)
		}
	}
	s.mu.RUnlock()
	for _, sess := range doomed {
		sess.log.Info("closing a connection whose key was revoked", "prefix", prefix)
		sess.closeWith(websocket.StatusPolicyViolation, "api key revoked")
	}
}

// BroadcastDeviceStatus pushes a status change to every session of that tenant.
func (s *Server) BroadcastDeviceStatus(tenantID, deviceID, status, reason string) {
	f, err := encode(TypeDeviceStatus, "", DeviceStatus{
		DeviceID: deviceID, Status: status, Reason: reason,
	})
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for sess := range s.sessions {
		if sess.tenantID() == tenantID {
			sess.send(f)
		}
	}
}

// actor is who is on the other end of a connection.
//
// Two kinds, and the difference is not cosmetic. An API key belongs to a
// program: it lives until revoked, it is copied into config files, and it is
// the credential most likely to leak. A session belongs to a person who typed a
// password minutes ago and can be revoked by signing out.
//
// So the destructive and self-referential operations — minting a key, revoking
// one, deleting a device and everything it archived — are refused to API keys
// outright. A leaked key that could mint its own successors would survive the
// revocation of the key that leaked, which makes revocation a formality.
type actor struct {
	keyVersion    int64
	sessionID     uuid.UUID
	keyID         uuid.UUID
	accessVersion int64
	tenant        string
	// person is false for an API key. userID, email and role are zero then.
	person bool
	userID uuid.UUID
	email  string
	role   string
	// keyPrefix identifies which API key authenticated a machine, so revoking
	// it can hang up the connections already using it. Without this, revocation
	// would only refuse the next connection — and a consumer that never
	// reconnects would keep receiving traffic indefinitely after being cut off,
	// which is not what anybody means by revoked.
	keyPrefix string
	// scope is the ceiling on what an API key may do. Zero for a person: a
	// person's ceiling is their role.
	scope store.KeyScope
	// service is true for an API key acting as a service account. userID and
	// email are that account's then, and the key reaches only the devices
	// the account holds a grant for — exactly like a member.
	service bool
}

// admin reports whether this actor may change the tenant's configuration.
func (a actor) admin() bool {
	return a.person && (a.role == "owner" || a.role == "admin")
}

// may reports whether this actor reaches an operation of the given scope.
//
// A person may do anything a key may; what a person may not do is decided by
// role, in requireAdmin. The two questions are kept apart because they have
// different answers: "use an account" and "ask for a wider key".
func (a actor) may(need store.KeyScope) bool {
	if a.person {
		return true
	}
	return a.scope.Covers(need)
}

// session is one connection.
type session struct {
	accessWake chan struct{}
	srv        *Server
	conn       *websocket.Conn
	out        chan Frame
	log        *slog.Logger

	// peer is the address the connection came from, for the hello limit.
	peer string

	mu       sync.Mutex
	tenant   string
	who      actor
	clientID string
	closed   bool

	pairMu   sync.Mutex
	pairings map[string]*wa.PairSession

	subMu sync.Mutex
	sub   *bus.Subscription
}

func (s *session) tenantID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tenant
}

func (s *session) actor() actor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.who
}

// requireAdmin refuses the caller unless a person with admin rights is asking,
// replying with the reason. The error says which of the two conditions failed,
// because "use an account instead of an API key" and "ask an owner" are
// different problems with different fixes.
func (s *session) requireAdmin(reqID string) (actor, bool) {
	who := s.actor()
	switch {
	case !who.person:
		s.replyError(reqID, ErrCodeNotAuthorized,
			"this needs a signed-in account; an API key cannot manage the tenant")
		return actor{}, false
	case !who.admin():
		s.replyError(reqID, ErrCodeNotAuthorized,
			"this needs the owner or an admin; "+who.email+" is a member")
		return actor{}, false
	}
	return who, true
}

// requireScope refuses an API key that was not issued for this. A person
// always passes; their limits are their role's.
func (s *session) requireScope(reqID string, need store.KeyScope) bool {
	who := s.actor()
	if who.may(need) {
		return true
	}
	s.replyError(reqID, ErrCodeNotAuthorized, fmt.Sprintf(
		"this api key has scope %q and this needs %q; issue a key with the wider scope",
		who.scope, need))
	return false
}

// requireOperator is requireAdmin, or an API key with full scope.
//
// For the operations the command line legitimately performs — pairing, stopping
// a device — where "sign in with an account" is not an answer a shell script can
// act on, but a read-only key should still be refused.
func (s *session) requireOperator(reqID string) (actor, bool) {
	who := s.actor()
	if !who.person {
		if who.scope.Covers(store.ScopeFull) {
			return who, true
		}
		s.replyError(reqID, ErrCodeNotAuthorized,
			"this needs an api key with full scope, or a signed-in owner or admin")
		return actor{}, false
	}
	return s.requireAdmin(reqID)
}

func (s *session) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	s.pairings = map[string]*wa.PairSession{}

	defer func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()

		s.pairMu.Lock()
		for _, p := range s.pairings {
			p.Cancel()
		}
		s.pairMu.Unlock()

		s.subMu.Lock()
		if s.sub != nil {
			s.sub.Close()
			s.sub = nil
		}
		s.subMu.Unlock()

		s.srv.unregister(s)
		s.closeQuietly()
	}()

	if code, err := s.handshake(ctx); err != nil {
		s.fail(ctx, code, err)
		return
	}
	s.srv.register(s)

	go s.writeLoop(ctx)
	go s.pingLoop(ctx)
	go s.accessLoop(ctx)
	s.readLoop(ctx)
}

// handshake reads and validates the hello frame. It returns the error code to
// report alongside the error, so the client can tell a version mismatch from
// bad credentials without parsing prose.
func (s *session) handshake(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()

	var f Frame
	if err := s.read(ctx, &f); err != nil {
		return ErrCodeUnauthorized, fmt.Errorf("no hello frame: %w", err)
	}
	if f.Type != TypeHello {
		return ErrCodeUnauthorized, fmt.Errorf("first frame must be %q, got %q", TypeHello, f.Type)
	}
	var hello Hello
	if err := json.Unmarshal(f.Payload, &hello); err != nil {
		return ErrCodeBadRequest, fmt.Errorf("malformed hello: %w", err)
	}
	if hello.Version != Version {
		return ErrCodeVersion, fmt.Errorf("client speaks version %d, server speaks %d",
			hello.Version, Version)
	}

	// Before the credentials are looked at, so a refused attempt costs this
	// process nothing. The subject is the key's prefix — which is a selector,
	// not a secret — so guesses against one key are bounded on their own.
	subject := ""
	if hello.APIKey != "" {
		subject, _, _ = strings.Cut(hello.APIKey, ".")
	}
	if ok, wait := s.srv.cfg.Limits.Allow(&http.Request{RemoteAddr: s.peer}, subject); !ok {
		return ErrCodeRateLimited, fmt.Errorf("too many attempts from this address; try again in %s", wait)
	}

	who, err := s.credentials(ctx, hello)
	if err != nil {
		// A fixed delay on failure. Without it, response time distinguishes a
		// malformed key from a well-formed but wrong one.
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
		}
		return ErrCodeUnauthorized, err
	}

	tenant := who.tenant
	s.mu.Lock()
	s.tenant, s.who, s.clientID = tenant, who, hello.ClientID
	s.mu.Unlock()
	s.log = s.log.With("tenant", tenant, "client", hello.ClientID)
	if who.person {
		s.log = s.log.With("account", who.email)
	}

	welcome, err := encode(TypeWelcome, f.ReqID, Welcome{
		Version:  Version,
		TenantID: tenant,
		Features: features,
		Account:  who.email,
		Role:     who.role,
		Scope:    string(who.scope),
		ServerTS: time.Now().UnixMilli(),
	})
	if err != nil {
		return ErrCodeInternal, err
	}
	return "", s.write(ctx, welcome)
}

// credentials resolves whichever of the two the caller presented.
//
// A session is tried first: a browser that has signed in should not fall back
// to an API key it happens to also hold, because the session is the one that
// can be revoked and expires.
func (s *session) credentials(ctx context.Context, hello Hello) (actor, error) {
	if hello.Session != "" {
		if s.srv.cfg.Sessions == nil {
			return actor{}, errors.New("this server does not accept sessions")
		}
		// The role is read now rather than trusted from the token: a session
		// issued to an owner who has since been demoted should carry the rights
		// they have, not the ones they had — and a disabled account's token
		// opens nothing, however long it has left.
		sess, user, err := s.srv.cfg.Sessions.ActiveSession(ctx, hello.Session)
		if err != nil {
			return actor{}, errors.New("that session has expired")
		}
		role, version, err := s.srv.cfg.Sessions.ConnectionAccess(ctx, sess.TenantID, user.ID, sess.ID)
		if err != nil {
			return actor{}, errors.New("that session has expired")
		}
		return actor{
			sessionID: sess.ID, accessVersion: version,
			tenant: sess.TenantID.String(),
			person: true,
			userID: user.ID,
			email:  user.Email,
			role:   role,
		}, nil
	}
	if hello.APIKey == "" {
		return actor{}, errors.New("no api key and no session")
	}
	key, err := s.srv.cfg.Keys.VerifyScoped(ctx, hello.APIKey)
	if err != nil {
		return actor{}, errors.New("invalid api key")
	}
	who := actor{tenant: key.TenantID, keyPrefix: key.Prefix, scope: key.Scope, keyID: key.ID, keyVersion: key.AccessVersion}
	if key.ActsAs != nil {
		if s.srv.cfg.Accounts == nil {
			return actor{}, errors.New("service accounts are not configured")
		}
		tenant, err := uuid.Parse(key.TenantID)
		if err != nil {
			return actor{}, errors.New("invalid api key")
		}
		// Read now, like a person's role: a service account that was
		// disabled takes its keys with it.
		user, err := s.srv.cfg.Accounts.Get(ctx, tenant, *key.ActsAs)
		if err != nil || user.Status != "active" || user.Role != store.RoleService {
			return actor{}, errors.New("this key acts as an account that no longer exists")
		}
		who.service, who.userID, who.email = true, user.ID, store.ServiceName(user)
		role, version, err := s.srv.cfg.Accounts.ConnectionAccess(ctx, tenant, user.ID, uuid.Nil)
		if err != nil || role != store.RoleService {
			return actor{}, errors.New("service access expired")
		}
		who.role, who.accessVersion = role, version
	}
	return who, nil
}

func (s *session) readLoop(ctx context.Context) {
	for {
		var f Frame
		if err := s.read(ctx, &f); err != nil {
			if !errors.Is(err, context.Canceled) {
				s.log.Debug("session closed", "error", err)
			}
			return
		}
		if !s.validAccess(ctx) {
			return
		}

		s.dispatch(ctx, f)
	}
}

func (s *session) dispatch(ctx context.Context, f Frame) {
	switch f.Type {
	case TypePing:
		s.reply(TypePong, f.ReqID, nil)
	case TypePair:
		go s.handlePair(ctx, f)
	case TypePairCancel:
		s.handlePairCancel(f)
	case TypeDevicesList:
		go s.handleDevicesList(ctx, f)
	case TypeUsersList:
		go s.handleUsersList(ctx, f)
	case TypeSubscribe:
		go s.handleSubscribe(ctx, f)
	case TypeContacts:
		go s.handleContactsList(ctx, f)
	case TypeResolve:
		go s.handleContactsResolve(ctx, f)
	case TypeAvatar:
		go s.handleAvatar(ctx, f)
	case TypeChatsList:
		go s.handleChatsList(ctx, f)
	case TypeChatPage:
		go s.handleChatPage(ctx, f)
	case TypeHistory:
		go s.handleHistory(ctx, f)
	case TypeMessageGet:
		go s.handleMessageGet(ctx, f)
	case TypeKeysGet:
		go s.handleKeysGet(ctx, f)
	case TypeSendMedia:
		go s.handleSendMedia(ctx, f)
	case TypeSend:
		go s.handleSend(ctx, f)
	case TypeEdit:
		go s.handleEdit(ctx, f)
	case TypeRevoke:
		go s.handleRevoke(ctx, f)
	case TypeReact:
		go s.handleReact(ctx, f)
	case TypePollVote:
		go s.handlePollVote(ctx, f)
	case TypeMediaRetry:
		go s.handleMediaRetry(ctx, f)
	case TypeBackfill:
		go s.handleBackfill(ctx, f)
	case TypeMediaExpired:
		go s.handleExpiredMedia(ctx, f)
	case TypeChatTimer:
		go s.handleChatTimer(ctx, f)
	case TypeGroupJoin:
		go s.handleGroupJoin(ctx, f)
	case TypeChatStart:
		go s.handleChatStart(ctx, f)
	case TypeGroupCreate:
		go s.handleGroupCreate(ctx, f)
	case TypeGroupParticipants:
		go s.handleGroupParticipants(ctx, f)
	case TypeGroupLeave:
		go s.handleGroupLeave(ctx, f)
	case TypePollCreate:
		go s.handlePollCreate(ctx, f)
	case TypeLocationSend:
		go s.handleLocationSend(ctx, f)
	case TypeGroupGet:
		go s.handleGroupInfo(ctx, f)
	case TypeChatTyping:
		go s.handleChatPresence(ctx, f)
	case TypePresenceWatch:
		go s.handlePresenceSubscribe(ctx, f)
	case TypeDeviceMode:
		go s.handleDeviceMode(ctx, f)
	case TypeReprojectGet:
		go s.handleReprojectList(ctx, f)
	case TypeReprojectPut:
		go s.handleReprojectApply(ctx, f)
	case TypeMarkRead:
		go s.handleMarkRead(ctx, f)
	case TypeDeviceStart:
		go s.handleDeviceStart(ctx, f)
	case TypeDeviceRename:
		go s.handleDeviceRename(ctx, f)
	case TypeDeviceStop:
		go s.handleDeviceStop(ctx, f)
	case TypeDevicesStats:
		go s.handleDevicesStats(ctx, f)
	case TypeDeviceInfo:
		go s.handleDeviceInfo(ctx, f)
	case TypeDeviceDelete:
		go s.handleDeviceDelete(ctx, f)
	case TypeKeysList:
		go s.handleAPIKeysList(ctx, f)
	case TypeKeyCreate:
		go s.handleAPIKeyCreate(ctx, f)
	case TypeKeyRevoke:
		go s.handleAPIKeyRevoke(ctx, f)
	case TypeGrantAdd:
		go s.handleGrantAdd(ctx, f)
	case TypeGrantRevoke:
		go s.handleGrantRevoke(ctx, f)
	case TypeGrantsList:
		go s.handleGrantsList(ctx, f)
	default:
		s.replyError(f.ReqID, ErrCodeBadRequest, fmt.Sprintf("unknown frame type %q", f.Type))
	}
}

func (s *session) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-s.out:
			if !s.validAccess(ctx) {
				return
			}
			if f.Type == TypeDeviceStatus {
				var status DeviceStatus
				if err := json.Unmarshal(f.Payload, &status); err != nil {
					continue
				}
				allowed, err := s.actionDevices(ctx, store.ActionView)
				if err != nil {
					s.closeWith(websocket.StatusPolicyViolation, "could not verify device access")
					return
				}
				id, err := uuid.Parse(status.DeviceID)
				if err != nil {
					continue
				}
				if _, ok := allowed[id]; !ok {
					continue
				}
			}
			if err := s.write(ctx, f); err != nil {
				return
			}
			if s.srv.cfg.Metrics != nil {
				s.srv.cfg.Metrics.WSFramesSent.WithLabelValues(f.Type).Inc()
			}
		}
	}
}

func (s *session) pingLoop(ctx context.Context) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := s.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (s *session) read(ctx context.Context, f *Frame) error {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, f)
}

func (s *session) write(ctx context.Context, f Frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.conn.Write(writeCtx, websocket.MessageText, data)
}

// send queues a frame. A full queue means the client is not reading; the
// connection is closed rather than letting the buffer grow without bound.
func (s *session) send(f Frame) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	select {
	case s.out <- f:
	default:
		if s.srv.cfg.Metrics != nil {
			s.srv.cfg.Metrics.WSDisconnects.WithLabelValues("slow_consumer").Inc()
		}
		s.log.Warn("client is not draining its queue; closing")
		s.closeWith(websocket.StatusPolicyViolation, "slow consumer")
	}
}

func (s *session) reply(frameType, reqID string, payload any) {
	f, err := encode(frameType, reqID, payload)
	if err != nil {
		s.log.Error("encoding a frame failed", "type", frameType, "error", err)
		return
	}
	s.send(f)
}

func (s *session) replyError(reqID, code, msg string) {
	s.reply(TypeError, reqID, Error{Code: code, Message: msg})
}

// fail reports a handshake failure and closes.
func (s *session) fail(ctx context.Context, code string, err error) {
	f, encErr := encode(TypeError, "", Error{Code: code, Message: err.Error()})
	if encErr == nil {
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		// Best effort: the peer may already be gone, which is exactly the
		// case this branch exists to handle.
		if writeErr := s.write(writeCtx, f); writeErr != nil {
			s.log.Debug("could not report the handshake failure", "error", writeErr)
		}
		cancel()
	}
	s.closeWith(websocket.StatusPolicyViolation, "handshake failed")
}

// closeQuietly and closeWith centralise websocket teardown.
//
// A close that fails almost always means the peer already went away, which is
// not a problem worth surfacing; the alternative is the same nolint comment
// repeated at every call site.
func (s *session) closeQuietly() {
	if err := s.conn.CloseNow(); err != nil {
		s.log.Debug("closing the connection failed", "error", err)
	}
}

func (s *session) closeWith(status websocket.StatusCode, reason string) {
	if err := s.conn.Close(status, reason); err != nil {
		s.log.Debug("closing the connection failed", "reason", reason, "error", err)
	}
}
