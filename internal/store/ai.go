package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AI integrations (docs/mcp-enclave.md §18): the attested reader sends a
// number's attachments to AI providers a person chose, one provider and model
// per function, with that person's own API keys, and stores what comes back
// sealed with a key derived from the number's archive key.
//
// An AI authorization is an mcp_connections row of kind 'ai', with a service
// account of its own exactly as a content connection has, and ai_config: the
// configuration the person sealed in the bundle, which this server keeps as a
// mirror for the console to check and for itself to decide who may ask. What
// binds is the sealed bundle and its tags; this server can only narrow it.
// Nothing here is ever a key or a word of content: the keychain holds opaque
// envelopes only the person's account key opens, and the results are sealed.

// AI stores what the AI integrations keep besides the connections ledger:
// the keychain, the results and the usage counters. Every one of its tables
// forces row-level security, so everything here runs in the workspace's
// transaction.
type AI struct{ pool *pgxpool.Pool }

// NewAI returns the AI integrations' store.
func NewAI(pool *pgxpool.Pool) *AI { return &AI{pool: pool} }

const (
	// KindAI is an AI authorization's kind.
	KindAI = "ai"
	// AIConsentVersion is the AI card's own numbering, which starts again at
	// one: it is not a content consent version.
	AIConsentVersion = 1
	// AIClientName and AIRedirectHost are what an AI row records in the
	// columns an assistant's connection fills: no assistant speaks for it,
	// and the console is where it was made.
	AIClientName   = "Wappie AI"
	AIRedirectHost = "console"
	// AIDevicesMax bounds the numbers one authorization covers
	// (AI_DEVICES_MAX).
	AIDevicesMax = 25
	// ReasonAIKeyDeleted ends an authorization whose keychain item went.
	ReasonAIKeyDeleted = "ai_key_deleted"
	// aiConfigMax bounds ai_config as sent: 32 KiB, as its column does.
	aiConfigMax = 32 << 10
)

// The four functions, as rows, routes and records name them.
const (
	AIAudio    = "audio"
	AIVideo    = "video"
	AIImage    = "image"
	AIDocument = "document"
)

// AIFeatures are the functions, in the contract's order.
var AIFeatures = []string{AIAudio, AIVideo, AIImage, AIDocument}

// AIProviders are the providers, in the contract's order.
var AIProviders = []string{"anthropic", "openai", "google"}

// aiProviderFeatures is AI_FEATURES: which provider may serve which function.
// Anthropic's API takes no audio or video, and OpenAI's no video file.
var aiProviderFeatures = map[string][]string{
	"anthropic": {AIImage, AIDocument},
	"openai":    {AIAudio, AIImage, AIDocument},
	"google":    {AIAudio, AIVideo, AIImage, AIDocument},
}

// AIProviderServes reports whether a provider may serve a function.
func AIProviderServes(provider, feature string) bool {
	return slices.Contains(aiProviderFeatures[provider], feature)
}

// Who may ask for a function on a number (§18.10).
const (
	// AIRequestersSelf is the person who made the authorization and their
	// connectors: the default.
	AIRequestersSelf = "self"
	// AIRequestersReaders is whoever reads the number, and their connectors.
	AIRequestersReaders = "readers"
	// AIRequestersConsole is the person who made it, in the console only.
	AIRequestersConsole = "console"
)

// Where a request for a function comes from.
const (
	AIOriginConsole   = "console"
	AIOriginConnector = "connector"
)

var (
	// aiModelPattern is AI_MODEL_RE: a shape check, since which models exist
	// is each key's own list.
	aiModelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	// aiLangPattern is a BCP 47 tag of the shape the bundle takes.
	aiLangPattern = regexp.MustCompile(`^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$`)
	// aiSuffixPattern is a key's last four characters.
	aiSuffixPattern = regexp.MustCompile(`^[!-~]{4}$`)
)

// ValidAIModel reports whether a model id has the shape every provider's
// ids take.
func ValidAIModel(model string) bool { return aiModelPattern.MatchString(model) }

// ValidAILabel is a keychain item's label: 1 to 60 characters, printable.
func ValidAILabel(label string) bool {
	n := utf8.RuneCountInString(label)
	return utf8.ValidString(label) && n >= 1 && n <= 60 && !strings.ContainsFunc(label, unicode.IsControl)
}

// ValidAISuffix is a key's last four characters, stored readable.
func ValidAISuffix(suffix string) bool { return aiSuffixPattern.MatchString(suffix) }

var (
	// ErrAIConfig wraps what is wrong with an ai_config: its shape, or what
	// it names that is not the actor's or the key's.
	ErrAIConfig = errors.New("store: ai_config refused")
	// ErrAINotEnabled is a function on a number no authorization covers for
	// that requester.
	ErrAINotEnabled = errors.New("store: no AI authorization covers that")
	// ErrAIKeychainFull is a person with as many live keychain items as the
	// workspace allows them.
	ErrAIKeychainFull = errors.New("store: the keychain is full")
	// ErrAIKeychainExists is an item id already taken.
	ErrAIKeychainExists = errors.New("store: that keychain item exists")
	// ErrAINotFound is an item, a record or an authorization the asker may
	// not see.
	ErrAINotFound = errors.New("store: no such AI item")
	// ErrAIDerivedExists is a result already stored for a message and a
	// function, on a write that does not replace.
	ErrAIDerivedExists = errors.New("store: a result is already stored")
	// ErrAIDerivedMismatch is a result for a message that is not on the
	// number named, or whose type the function does not take.
	ErrAIDerivedMismatch = errors.New("store: that message does not take that result")
)

func aiConfigError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrAIConfig}, args...)...)
}

// ---------------------------------------------------------------------------
// ai_config
// ---------------------------------------------------------------------------

// AIConfig is an authorization's configuration as the console sealed it and
// sent it beside the bundle (§18.7 step 5): the mirror this server keeps.
type AIConfig struct {
	Request       string
	KID           string
	ServiceUserID uuid.UUID
	// Epochs, NS, Features and CfgTags are keyed by the same devices.
	Epochs map[uuid.UUID]int
	NS     map[uuid.UUID]uuid.UUID
	// Keys are keyed by provider, and name exactly the providers Functions
	// uses.
	Keys map[string]AIKey
	// Functions are keyed by function.
	Functions map[string]AIFunction
	// Features are keyed by device, then by function.
	Features  map[uuid.UUID]map[string]AIFeature
	Budget    AIBudget
	ExpiresAt time.Time
	KeyMode   string
	CfgTags   map[uuid.UUID]string
	// Raw is the object as it was sent, which is what is stored.
	Raw json.RawMessage
}

// AIKey is what the mirror says of one provider's key: the keychain item it
// came from, its SHA-256, and the label and suffix the console shows.
type AIKey struct {
	KeychainID uuid.UUID
	SHA256     string
	Label      string
	Suffix     string
}

// AIFunction is one function's provider and model.
type AIFunction struct {
	Provider string
	Model    string
}

// AIFeature is one function on one number: its mode ("request" in B1), its
// language, and who may ask.
type AIFeature struct {
	Mode       string
	Lang       string
	Requesters string
}

// AIBudget is the authorization's safety cap: tokens a month and
// attachments a day. Prices vary with each person's plan and model, so no
// price or amount of money is part of it (§18.10).
type AIBudget struct {
	MonthlyTokens      int64
	RequestItemsPerDay int
}

// The wire shapes. Pointers tell a missing field from a zero one; the
// decoder refuses unknown fields at every level.
type (
	aiConfigWire struct {
		Version       *int                                `json:"version"`
		Request       *string                             `json:"request"`
		KID           *string                             `json:"kid"`
		ServiceUserID *string                             `json:"service_user_id"`
		Epochs        map[string]int                      `json:"epochs"`
		NS            map[string]string                   `json:"ns"`
		Keys          map[string]aiKeyWire                `json:"keys"`
		Functions     map[string]aiFunctionWire           `json:"functions"`
		Features      map[string]map[string]aiFeatureWire `json:"features"`
		Budget        *aiBudgetWire                       `json:"budget"`
		ExpiresAt     *string                             `json:"expires_at"`
		KeyMode       *string                             `json:"key_mode"`
		CfgTags       map[string]string                   `json:"cfg_tags"`
	}
	aiKeyWire struct {
		KeychainID *string `json:"keychain_id"`
		SHA256     *string `json:"sha256"`
		Label      *string `json:"label"`
		Suffix     *string `json:"suffix"`
	}
	aiFunctionWire struct {
		Provider *string `json:"provider"`
		Model    *string `json:"model"`
	}
	aiFeatureWire struct {
		Mode       *string         `json:"mode"`
		Lang       json.RawMessage `json:"lang"`
		Requesters *string         `json:"requesters"`
	}
	aiBudgetWire struct {
		MonthlyTokens      *int64 `json:"monthly_tokens"`
		RequestItemsPerDay *int   `json:"request_items_per_day"`
	}
)

// The budget's bounds (AI_MONTHLY_TOKENS_MAX, AI_REQUEST_ITEMS_PER_DAY_MAX).
const (
	aiMonthlyTokensMax = 1_000_000_000
	aiItemsPerDayMax   = 1_000
)

// ParseAIConfig reads an ai_config as the console sends it: a strict object
// of exactly the contract's fields, at most 32 KiB. Each error wraps
// ErrAIConfig and says what is wrong. It checks the object on its own; what
// it names (keychain items, the key's numbers, the switches) is checked where
// that is known.
func ParseAIConfig(raw []byte) (AIConfig, error) {
	if len(raw) == 0 || len(raw) > aiConfigMax {
		return AIConfig{}, aiConfigError("ai_config must be an object of at most %d bytes", aiConfigMax)
	}
	var w aiConfigWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return AIConfig{}, aiConfigError("ai_config is not the expected object: %v", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return AIConfig{}, aiConfigError("ai_config must be one JSON object")
	}
	switch {
	case w.Version == nil || *w.Version != 1:
		return AIConfig{}, aiConfigError("version must be 1")
	case w.Request == nil || !ValidRequestID(*w.Request):
		return AIConfig{}, aiConfigError("request must be 22 base64url characters")
	case w.KID == nil || len(*w.KID) != 16 || !isLowerHex(*w.KID):
		return AIConfig{}, aiConfigError("kid must be 16 hex characters")
	case w.KeyMode == nil || *w.KeyMode != KeyModeEphemeral:
		return AIConfig{}, aiConfigError("key_mode must be ephemeral")
	case w.ExpiresAt == nil:
		return AIConfig{}, aiConfigError("expires_at is required")
	case w.Budget == nil:
		return AIConfig{}, aiConfigError("budget is required")
	}
	c := AIConfig{Request: *w.Request, KID: *w.KID, KeyMode: *w.KeyMode, Raw: append(json.RawMessage(nil), raw...)}
	service, ok := canonicalUUID(deref(w.ServiceUserID))
	if !ok {
		return AIConfig{}, aiConfigError("service_user_id must be a lower-case UUID")
	}
	c.ServiceUserID = service
	at, err := time.Parse(time.RFC3339, *w.ExpiresAt)
	if err != nil {
		return AIConfig{}, aiConfigError("expires_at must be an RFC 3339 timestamp")
	}
	c.ExpiresAt = at.UTC()

	// The devices: epochs names them, and ns, features and cfg_tags name
	// exactly the same ones.
	if len(w.Epochs) < 1 || len(w.Epochs) > AIDevicesMax {
		return AIConfig{}, aiConfigError("epochs must name 1 to %d numbers", AIDevicesMax)
	}
	c.Epochs = map[uuid.UUID]int{}
	for key, epoch := range w.Epochs {
		device, ok := canonicalUUID(key)
		if !ok {
			return AIConfig{}, aiConfigError("epochs must be keyed by lower-case device UUIDs")
		}
		if epoch < 1 || epoch > 65535 {
			return AIConfig{}, aiConfigError("an epoch must be 1 to 65535")
		}
		c.Epochs[device] = epoch
	}
	same := func(name string, keys []string) error {
		if len(keys) != len(c.Epochs) {
			return aiConfigError("%s must name exactly the numbers epochs names", name)
		}
		for _, key := range keys {
			device, ok := canonicalUUID(key)
			if _, known := c.Epochs[device]; !ok || !known {
				return aiConfigError("%s must name exactly the numbers epochs names", name)
			}
		}
		return nil
	}
	if err := same("ns", mapKeys(w.NS)); err != nil {
		return AIConfig{}, err
	}
	c.NS = map[uuid.UUID]uuid.UUID{}
	for key, value := range w.NS {
		ns, ok := canonicalUUID(value)
		if !ok {
			return AIConfig{}, aiConfigError("a namespace must be a lower-case UUID")
		}
		c.NS[uuid.MustParse(key)] = ns
	}
	if err := same("cfg_tags", mapKeys(w.CfgTags)); err != nil {
		return AIConfig{}, err
	}
	c.CfgTags = map[uuid.UUID]string{}
	for key, tag := range w.CfgTags {
		if !validBase64ID(tag, 32) {
			return AIConfig{}, aiConfigError("a cfg_tag must be 43 canonical base64url characters")
		}
		c.CfgTags[uuid.MustParse(key)] = tag
	}

	// The functions, each with a provider that serves it and a model of the
	// right shape; and one key per provider they use.
	if len(w.Functions) == 0 {
		return AIConfig{}, aiConfigError("functions must name at least one function")
	}
	c.Functions = map[string]AIFunction{}
	for feature, f := range w.Functions {
		if !slices.Contains(AIFeatures, feature) {
			return AIConfig{}, aiConfigError("%q is not a function", feature)
		}
		if f.Provider == nil || !AIProviderServes(*f.Provider, feature) {
			return AIConfig{}, aiConfigError("the %s function's provider must be one that serves it", feature)
		}
		if f.Model == nil || !ValidAIModel(*f.Model) || *f.Provider == "google" && strings.Contains(*f.Model, ":") {
			return AIConfig{}, aiConfigError("the %s function's model is not a model id", feature)
		}
		c.Functions[feature] = AIFunction{Provider: *f.Provider, Model: *f.Model}
	}
	if len(w.Keys) != len(c.providers()) {
		return AIConfig{}, aiConfigError("keys must name exactly the providers the functions use")
	}
	c.Keys = map[string]AIKey{}
	for provider, k := range w.Keys {
		if !slices.Contains(c.providers(), provider) {
			return AIConfig{}, aiConfigError("keys must name exactly the providers the functions use")
		}
		keychain, ok := canonicalUUID(deref(k.KeychainID))
		switch {
		case !ok:
			return AIConfig{}, aiConfigError("a key's keychain_id must be a lower-case UUID")
		case k.SHA256 == nil || len(*k.SHA256) != 64 || !isLowerHex(*k.SHA256):
			return AIConfig{}, aiConfigError("a key's sha256 must be 64 hex characters")
		case k.Label == nil || !ValidAILabel(*k.Label):
			return AIConfig{}, aiConfigError("a key's label must be 1 to 60 printable characters")
		case k.Suffix == nil || !ValidAISuffix(*k.Suffix):
			return AIConfig{}, aiConfigError("a key's suffix must be its last 4 characters")
		}
		c.Keys[provider] = AIKey{KeychainID: keychain, SHA256: *k.SHA256, Label: *k.Label, Suffix: *k.Suffix}
	}

	// Each number's functions, each one the configuration has.
	if err := same("features", mapKeys(w.Features)); err != nil {
		return AIConfig{}, err
	}
	c.Features = map[uuid.UUID]map[string]AIFeature{}
	for key, features := range w.Features {
		device := uuid.MustParse(key)
		c.Features[device] = map[string]AIFeature{}
		for feature, f := range features {
			if _, ok := c.Functions[feature]; !ok {
				return AIConfig{}, aiConfigError("a number's %q must be one of functions", feature)
			}
			if f.Mode == nil || *f.Mode != "request" {
				return AIConfig{}, aiConfigError("a function's mode must be request")
			}
			if f.Requesters == nil || !slices.Contains([]string{AIRequestersSelf, AIRequestersReaders, AIRequestersConsole}, *f.Requesters) {
				return AIConfig{}, aiConfigError("requesters must be self, readers or console")
			}
			var lang string
			if f.Lang != nil {
				if json.Unmarshal(f.Lang, &lang) != nil || !aiLangPattern.MatchString(lang) {
					return AIConfig{}, aiConfigError("lang must be a language tag such as pt or pt-BR")
				}
			}
			c.Features[device][feature] = AIFeature{Mode: *f.Mode, Lang: lang, Requesters: *f.Requesters}
		}
	}

	b := w.Budget
	switch {
	case b.MonthlyTokens == nil || *b.MonthlyTokens < 1 || *b.MonthlyTokens > aiMonthlyTokensMax:
		return AIConfig{}, aiConfigError("budget.monthly_tokens must be 1 to %d", aiMonthlyTokensMax)
	case b.RequestItemsPerDay == nil || *b.RequestItemsPerDay < 1 || *b.RequestItemsPerDay > aiItemsPerDayMax:
		return AIConfig{}, aiConfigError("budget.request_items_per_day must be 1 to %d", aiItemsPerDayMax)
	}
	c.Budget = AIBudget{MonthlyTokens: *b.MonthlyTokens, RequestItemsPerDay: *b.RequestItemsPerDay}
	return c, nil
}

// providers are the providers the functions use, sorted.
func (c AIConfig) providers() []string {
	var out []string
	for _, f := range c.Functions {
		if !slices.Contains(out, f.Provider) {
			out = append(out, f.Provider)
		}
	}
	slices.Sort(out)
	return out
}

// Devices are the numbers the configuration covers, sorted.
func (c AIConfig) Devices() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(c.Epochs))
	for device := range c.Epochs {
		out = append(out, device)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// OffFunctions is what a status answer calls off for this configuration:
// the union of the functions switched off everywhere, the row's own, and the
// functions whose provider is switched off, sorted as WS_AI_OFF_FEATURES is.
func (c AIConfig) OffFunctions(offFeatures, offProviders, rowOff []string) []string {
	out := []string{}
	add := func(feature string) {
		if !slices.Contains(out, feature) {
			out = append(out, feature)
		}
	}
	for _, f := range offFeatures {
		add(f)
	}
	for _, f := range rowOff {
		add(f)
	}
	for feature, f := range c.Functions {
		if slices.Contains(offProviders, f.Provider) {
			add(feature)
		}
	}
	slices.Sort(out)
	return out
}

// FunctionsOff reports whether any of the configuration's functions, or
// their providers, are switched off.
func (c AIConfig) FunctionsOff(offFeatures, offProviders []string) bool {
	for feature, f := range c.Functions {
		if slices.Contains(offFeatures, feature) || slices.Contains(offProviders, f.Provider) {
			return true
		}
	}
	return false
}

// sameAIRenewal holds a renewal's configuration to what a renewal may
// change (§18.7 step 7): a key within the same provider, and a function's
// model within the same provider. The numbers, the functions and their
// providers, every number's functions and the budget's two limits stay.
func sameAIRenewal(current, next AIConfig) error {
	if len(current.Epochs) != len(next.Epochs) {
		return aiConfigError("a renewal covers the same numbers")
	}
	for device := range current.Epochs {
		if _, ok := next.Epochs[device]; !ok {
			return aiConfigError("a renewal covers the same numbers")
		}
	}
	if len(current.Functions) != len(next.Functions) {
		return aiConfigError("a renewal keeps the same functions")
	}
	for feature, f := range current.Functions {
		if n, ok := next.Functions[feature]; !ok || n.Provider != f.Provider {
			return aiConfigError("a renewal keeps each function's provider; a new one takes a new authorization")
		}
	}
	for device, features := range current.Features {
		other := next.Features[device]
		if len(other) != len(features) {
			return aiConfigError("a renewal keeps every number's functions as they are")
		}
		for feature, f := range features {
			if n, ok := other[feature]; !ok || n != f {
				return aiConfigError("a renewal keeps every number's functions as they are")
			}
		}
	}
	if current.Budget != next.Budget {
		return aiConfigError("a renewal keeps the budget's limits")
	}
	return nil
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// canonicalUUID reads a lower-case, canonical, non-nil UUID.
func canonicalUUID(raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	return id, err == nil && id != uuid.Nil && id.String() == raw
}

// ValidRequestID is a pending request's or a renewal's id: 22 base64url
// characters.
func ValidRequestID(id string) bool {
	return len(id) == 22 && !strings.ContainsFunc(id, func(c rune) bool {
		return (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_'
	})
}

// validBase64ID is n bytes in canonical unpadded base64url.
func validBase64ID(s string, n int) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(raw) == n && base64.RawURLEncoding.EncodeToString(raw) == s
}

func isLowerHex(s string) bool {
	return !strings.ContainsFunc(s, func(c rune) bool { return (c < '0' || c > '9') && (c < 'a' || c > 'f') })
}

// AIFeatureFits reports whether a message of this type takes a function
// (§18.3): audio for audio and voice notes, video for videos and round video
// notes that are not GIFs, image for images, stickers and GIFs, document for
// documents. What a document holds is the reader's to sniff.
func AIFeatureFits(feature, messageType string, isGIF bool) bool {
	switch feature {
	case AIAudio:
		return messageType == "audio" || messageType == "ptt"
	case AIVideo:
		return (messageType == "video" || messageType == "ptv") && !isGIF
	case AIImage:
		return messageType == "image" || messageType == "sticker" || messageType == "video" && isGIF
	case AIDocument:
		return messageType == "document"
	}
	return false
}
