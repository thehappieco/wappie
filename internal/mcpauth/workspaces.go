package mcpauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// Each workspace's own assistant switches (docs/mcp-enclave.md §19.30): what
// its owner lets assistants do in it, beneath what the operator allows. They
// replace the operator's workspace lists (WS_MCP_CONTENT_TENANTS and its
// kin): the operator keeps the kill switches, the deny list and the enclave's
// workspaces; the owner turns text, attachments, drafts and AI on or off for
// one workspace; a switch never set is the deployment's default, on for
// Wappie Cloud and off for a self-hosted server.
//
// The answers are asked on every consent, status check, draft and media
// fetch, so they are read from memory: every workspace's switches, loaded at
// start, refreshed from the database every refreshEvery and at once by the
// owner's own change through this process. A refresh that fails keeps the
// last answers it had: a database hiccup must never read as "off", which
// would drop every live connection's key and cost everyone a renewal.

// OperatorGates are the operator's half of each answer, from the server's
// configuration: the connector, the kill switches, the deny list and the
// enclave reader's workspaces. Nil allows nothing.
type OperatorGates struct {
	Content, Media, Send, SendSelf, SendDirect, AI func(tenant uuid.UUID) bool
}

// WorkspaceSwitches holds every workspace's switches and answers the
// handler's gates with both halves.
type WorkspaceSwitches struct {
	store *store.MCPConnections
	// Default is what a switch never set is (WS_MCP_WORKSPACE_DEFAULT).
	Default  bool
	Operator OperatorGates
	// Platform is the one hook where the platform's workspace state will
	// gate assistants later: plans, trials, a paused or ending workspace,
	// all decided at the platform (thehappieco/platform decisions 0012 to
	// 0016). Wappie keeps no plan of its own and invents no check: nil
	// answers yes for every workspace, and so does every caller today.
	Platform func(tenant uuid.UUID) bool
	Log      *slog.Logger

	mu       sync.RWMutex
	switches map[uuid.UUID]store.AssistantSwitches
}

// refreshEvery is how often the switches are read again: a change made
// through another process reaches this one within it, and the readers within
// their minute after that.
const refreshEvery = 15 * time.Second

// NewWorkspaceSwitches returns the switches over the ledger, empty until
// Load.
func NewWorkspaceSwitches(ledger *store.MCPConnections, def bool, operator OperatorGates) *WorkspaceSwitches {
	return &WorkspaceSwitches{store: ledger, Default: def, Operator: operator, switches: map[uuid.UUID]store.AssistantSwitches{}}
}

// Load reads every workspace's switches. Start calls it before serving: a
// server that cannot read them does not know what it may allow.
func (w *WorkspaceSwitches) Load(ctx context.Context) error {
	all, err := w.store.WorkspaceSwitches(ctx)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.switches = all
	w.mu.Unlock()
	return nil
}

// Watch refreshes the switches every refreshEvery until ctx ends; a failed
// refresh is logged and keeps the last answers.
func (w *WorkspaceSwitches) Watch(ctx context.Context) {
	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := w.Load(ctx); err != nil && ctx.Err() == nil {
			w.log().Warn("could not refresh the workspaces' assistant switches; keeping the last ones", "error", err)
		}
	}
}

func (w *WorkspaceSwitches) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// of is one workspace's switches with the default filled in.
func (w *WorkspaceSwitches) of(tenant uuid.UUID) (text, media, send, ai bool) {
	w.mu.RLock()
	a := w.switches[tenant]
	w.mu.RUnlock()
	pick := func(v *bool) bool {
		if v == nil {
			return w.Default
		}
		return *v
	}
	return pick(a.Text), pick(a.Media), pick(a.Send), pick(a.AI)
}

// put records one workspace's switches, after the owner's change.
func (w *WorkspaceSwitches) put(tenant uuid.UUID, a store.AssistantSwitches) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a.Set() {
		w.switches[tenant] = a
	} else {
		delete(w.switches, tenant)
	}
}

func (w *WorkspaceSwitches) platform(tenant uuid.UUID) bool {
	return w.Platform == nil || w.Platform(tenant)
}

func ask(gate func(uuid.UUID) bool, tenant uuid.UUID) bool { return gate != nil && gate(tenant) }

// Content is whether a workspace may have content connections now: the
// operator allows it, the platform does, and the workspace's text switch is
// on.
func (w *WorkspaceSwitches) Content(tenant uuid.UUID) bool {
	text, _, _, _ := w.of(tenant)
	return text && ask(w.Operator.Content, tenant) && w.platform(tenant)
}

// Media is Content with attachments allowed by the operator and the
// workspace's attachments switch on.
func (w *WorkspaceSwitches) Media(tenant uuid.UUID) bool {
	_, media, _, _ := w.of(tenant)
	return media && w.Content(tenant) && ask(w.Operator.Media, tenant)
}

// Send is Content with sending allowed by the operator and the workspace's
// drafts switch on; SendSelf and SendDirect add the operator's own-chat and
// direct switches.
func (w *WorkspaceSwitches) Send(tenant uuid.UUID) bool {
	_, _, send, _ := w.of(tenant)
	return send && w.Content(tenant) && ask(w.Operator.Send, tenant)
}

func (w *WorkspaceSwitches) SendSelf(tenant uuid.UUID) bool {
	return w.Send(tenant) && ask(w.Operator.SendSelf, tenant)
}

func (w *WorkspaceSwitches) SendDirect(tenant uuid.UUID) bool {
	return w.Send(tenant) && ask(w.Operator.SendDirect, tenant)
}

// AI is Media with AI allowed by the operator and the workspace's AI switch
// on.
func (w *WorkspaceSwitches) AI(tenant uuid.UUID) bool {
	_, _, _, ai := w.of(tenant)
	return ai && w.Media(tenant) && ask(w.Operator.AI, tenant)
}

// ---------------------------------------------------------------------------
// The console's route
// ---------------------------------------------------------------------------

// switchesReply is a workspace's switches as the console's MCP tab shows
// them: whether the viewer may change them (an owner), the default, each
// switch as set (null for the default), what the operator allows, and what
// holds now.
type switchesReply struct {
	CanChange bool           `json:"can_change"`
	Default   bool           `json:"default"`
	Switches  switchesSet    `json:"switches"`
	Operator  switchesValues `json:"operator"`
	Effective switchesValues `json:"effective"`
	// SwitchedAt is when the owner last changed them; null before.
	SwitchedAt *time.Time `json:"switched_at"`
}

type switchesSet struct {
	Text  *bool `json:"text"`
	Media *bool `json:"media"`
	Send  *bool `json:"send"`
	AI    *bool `json:"ai"`
}

type switchesValues struct {
	Text  bool `json:"text"`
	Media bool `json:"media"`
	Send  bool `json:"send"`
	AI    bool `json:"ai"`
}

// switchesBody is the owner's change: every switch, as a boolean.
type switchesBody struct {
	Text  *bool `json:"text"`
	Media *bool `json:"media"`
	Send  *bool `json:"send"`
	AI    *bool `json:"ai"`
}

func (h *Handler) mountWorkspaceSwitches(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/mcp/workspace", h.workspaceSwitches)
	mux.HandleFunc("PUT /v1/mcp/workspace", h.workspaceSwitches)
}

// workspaceSwitches shows the session's workspace's switches to any member,
// and lets its owner change them. Turning text off stops every assistant's
// text in the workspace within the readers' minute; the consents survive,
// but the reader drops their keys, so once text is on again each connection
// is renewed before it reads text.
func (h *Handler) workspaceSwitches(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if h.Workspaces == nil {
		fail(w, http.StatusNotFound, "not_found", "this server has no assistant switches")
		return
	}
	ctx := r.Context()
	tenant := user.TenantID
	var a store.AssistantSwitches
	var err error
	if r.Method == http.MethodPut {
		if !allow(w, r, h.Limits, user.ID.String()) {
			return
		}
		var req switchesBody
		if !decode(w, r, &req) {
			return
		}
		if req.Text == nil || req.Media == nil || req.Send == nil || req.AI == nil {
			fail(w, http.StatusBadRequest, "bad_request", "text, media, send and ai must each be true or false")
			return
		}
		a, err = h.Connections.SetWorkspaceSwitches(ctx, tenant, user.ID, *req.Text, *req.Media, *req.Send, *req.AI)
		if err == nil {
			h.Workspaces.put(tenant, a)
			h.log().Info("mcp workspace switches changed", "tenant", tenant, "by", user.ID, "text", *req.Text, "media", *req.Media,
				"send", *req.Send, "ai", *req.AI)
		}
	} else {
		a, err = h.Connections.WorkspaceSwitchesOf(ctx, tenant)
	}
	if err != nil {
		if errors.Is(err, store.ErrMembershipForbidden) {
			fail(w, http.StatusForbidden, "not_authorized", "only an owner of this workspace may change what assistants may do in it")
			return
		}
		h.connectionError(w, err)
		return
	}
	ws := h.Workspaces
	send(w, http.StatusOK, switchesReply{
		CanChange: user.Role == "owner", Default: ws.Default, SwitchedAt: a.SwitchedAt,
		Switches: switchesSet{Text: a.Text, Media: a.Media, Send: a.Send, AI: a.AI},
		Operator: switchesValues{
			Text: ask(ws.Operator.Content, tenant) && ws.platform(tenant), Media: ask(ws.Operator.Media, tenant) && ws.platform(tenant),
			Send: ask(ws.Operator.Send, tenant) && ws.platform(tenant), AI: ask(ws.Operator.AI, tenant) && ws.platform(tenant),
		},
		Effective: switchesValues{
			Text: h.contentEnabledFor(tenant), Media: h.mediaEnabledFor(tenant), Send: func() bool { s, _, _ := h.sendEnabledFor(tenant); return s }(),
			AI: h.AIAllowedFor(tenant),
		},
	})
}
