package store_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// AI integrations on the ledger (docs/mcp-enclave.md §18): the
// authorization's row and its configuration, who may ask, the keychain, the
// results, the usage and the narrowing a person applies. Like every
// connection test these run as an ordinary role (NOSUPERUSER, NOBYPASSRLS),
// so a query that forgot its tenant transaction finds nothing and fails here.

// Example model ids: a model is the person's pick from their key's list, and
// no model name is a constant of the server; these only fill the fixtures.
const (
	geminiModel = "gemini-3.8-flash"
	claudeModel = "claude-sonnet-5-5"
	openaiModel = "gpt-5.4-mini"
)

type aiFixture struct {
	*contentFixture
	ai *store.AI
}

func newAIFixture(t *testing.T) *aiFixture {
	t.Helper()
	f := &aiFixture{contentFixture: newContentFixture(t)}
	f.ai = store.NewAI(f.pool)
	return f
}

// requestID is a pending request's id: 16 random bytes in base64url.
func requestID(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(randomBytes(t, 16))
}

// keychainItem stores a keychain item of a person's for a provider.
func (f *aiFixture) keychainItem(ctx context.Context, t *testing.T, user uuid.UUID, provider string) uuid.UUID {
	t.Helper()
	item, err := f.ai.AddKeychainItem(ctx, f.tenant, user, store.AIKeychainItem{
		ID: uuid.New(), Provider: provider, Label: provider + " key", Suffix: "a1B2",
		Envelope: append([]byte("WKC1"), randomBytes(t, 60)...),
	})
	if err != nil {
		t.Fatal(err)
	}
	return item.ID
}

// aiKeys are a person's keychain items for Google and Anthropic, the two
// providers the default configuration uses.
func (f *aiFixture) aiKeys(ctx context.Context, t *testing.T, user uuid.UUID) map[string]uuid.UUID {
	t.Helper()
	return map[string]uuid.UUID{"google": f.keychainItem(ctx, t, user, "google"), "anthropic": f.keychainItem(ctx, t, user, "anthropic")}
}

// aiConfigFor builds the ai_config the console sends with a consent: Gemini
// for audio and a Claude model for documents, on every number of the
// consent, requesters "self", and mutate's changes.
func aiConfigFor(t *testing.T, c contentConsent, keys map[string]uuid.UUID, mutate func(map[string]any)) []byte {
	t.Helper()
	epochs, ns, features, tags := map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}
	for _, d := range c.devices {
		epochs[d.String()] = 1
		ns[d.String()] = uuid.NewString()
		features[d.String()] = map[string]any{
			"audio":    map[string]any{"mode": "request", "lang": "pt-BR", "requesters": "self"},
			"document": map[string]any{"mode": "request", "requesters": "self"},
		}
		tags[d.String()] = base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))
	}
	keyMirror := map[string]any{}
	for provider, id := range keys {
		keyMirror[provider] = map[string]any{"keychain_id": id.String(), "sha256": hex.EncodeToString(randomBytes(t, 32)), "label": provider + " key", "suffix": "a1B2"}
	}
	cfg := map[string]any{
		"version": 1, "request": c.in.RequestID, "kid": c.in.ReaderKID, "service_user_id": c.service.String(),
		"epochs": epochs, "ns": ns, "keys": keyMirror,
		"functions": map[string]any{
			"audio":    map[string]any{"provider": "google", "model": geminiModel},
			"document": map[string]any{"provider": "anthropic", "model": claudeModel},
		},
		"features": features,
		"budget": map[string]any{"monthly_usd_cents": 1000, "request_items_per_day": 100, "rates": map[string]any{
			"google:" + geminiModel:    map[string]any{"in": 30, "out": 250, "sec": 0},
			"anthropic:" + claudeModel: map[string]any{"in": 300, "out": 1500, "sec": 0},
		}},
		"expires_at": c.in.ExpiresAt.UTC().Format(time.RFC3339), "key_mode": "ephemeral", "cfg_tags": tags,
	}
	if mutate != nil {
		mutate(cfg)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// prepareAI is what the console builds before an AI consent: a content
// consent's service account and key, as an AI row, with its configuration.
func (f *aiFixture) prepareAI(ctx context.Context, t *testing.T, actor uuid.UUID, keys map[string]uuid.UUID, mutate func(map[string]any), opts ...consentOption) contentConsent {
	t.Helper()
	c := f.prepareContent(ctx, t, actor, opts...)
	c.in.Kind, c.in.ClientName, c.in.RedirectHost = store.KindAI, store.AIClientName, store.AIRedirectHost
	c.in.RequestID = requestID(t)
	c.in.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	cfg, err := store.ParseAIConfig(aiConfigFor(t, c, keys, mutate))
	if err != nil {
		t.Fatal(err)
	}
	c.in.AIConfig = &cfg
	return c
}

// consentAI records and activates an AI authorization of actor's.
func (f *aiFixture) consentAI(ctx context.Context, t *testing.T, actor uuid.UUID, keys map[string]uuid.UUID, mutate func(map[string]any), opts ...consentOption) (store.MCPConnection, contentConsent) {
	t.Helper()
	c := f.prepareAI(ctx, t, actor, keys, mutate, opts...)
	conn, err := f.conns.Create(ctx, f.tenant, actor, c.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn, c
}

// member adds a person to the workspace with a role.
func (f *aiFixture) member(t *testing.T, role string) uuid.UUID {
	t.Helper()
	id, _ := transferOwner(t, f.archive, role)
	return id
}

// message archives one message of a type on a number, with an attachment
// for anything but text, and returns its uid.
func (f *aiFixture) message(ctx context.Context, t *testing.T, device uuid.UUID, kind domain.Type, gif bool) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	in := store.InsertMessage{
		UID: uid, TenantID: f.tenant, DeviceID: device, WAID: "wa-" + uid.String(), ChatKey: "5511911111111@s.whatsapp.net",
		Kind: domain.KindMessage, Type: kind, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1},
	}
	if kind != domain.TypeText {
		in.Media = &store.InsertMedia{MediaType: string(kind), IsGIF: gif, FileEncSHA256: randomBytes(t, 32)}
	}
	if _, err := store.NewMessages(f.pool).Insert(ctx, in); err != nil {
		t.Fatal(err)
	}
	return uid
}

// sealedAt is a record of the derived format at an epoch, n bytes of
// ciphertext long.
func sealedAt(t *testing.T, epoch, n int) []byte {
	t.Helper()
	out := append([]byte("WDRV"), 1, 0, 0)
	binary.BigEndian.PutUint16(out[5:7], uint16(epoch))
	return append(out, randomBytes(t, 12+n+16)...)
}

func (f *aiFixture) derived(t *testing.T, uid, device uuid.UUID, feature string) store.AIDerived {
	t.Helper()
	return store.AIDerived{MessageUID: uid, Feature: feature, DeviceID: device, Epoch: 1, Sealed: sealedAt(t, 1, 200), DedupeTag: randomBytes(t, 32)}
}

// keyID is the id of an issued key.
func (f *aiFixture) keyID(ctx context.Context, t *testing.T, key string) uuid.UUID {
	t.Helper()
	k, err := f.keys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	return k.ID
}

// allowAI is a policy with AI allowed and nothing off.
var allowAI = store.AIPolicy{Allowed: true}

// ---------------------------------------------------------------------------

func TestParseAIConfigShape(t *testing.T) {
	c := contentConsent{service: uuid.New(), devices: []uuid.UUID{uuid.New()}}
	c.in.RequestID, c.in.ReaderKID, c.in.ExpiresAt = requestID(t), "0123456789abcdef", time.Now().Add(24*time.Hour)
	keys := map[string]uuid.UUID{"google": uuid.New(), "anthropic": uuid.New()}
	if _, err := store.ParseAIConfig(aiConfigFor(t, c, keys, nil)); err != nil {
		t.Fatalf("the console's configuration was refused: %v", err)
	}
	device := c.devices[0].String()
	for name, mutate := range map[string]func(map[string]any){
		"unknown field": func(m map[string]any) { m["auto"] = nil },
		"version 2":     func(m map[string]any) { m["version"] = 2 },
		"no version":    func(m map[string]any) { delete(m, "version") },
		"request of a wrong shape": func(m map[string]any) {
			m["request"] = "not a request"
		},
		"kid upper case":         func(m map[string]any) { m["kid"] = "0123456789ABCDEF" },
		"key mode persisted":     func(m map[string]any) { m["key_mode"] = "persisted" },
		"service upper case":     func(m map[string]any) { m["service_user_id"] = strings.ToUpper(c.service.String()) },
		"expiry not a timestamp": func(m map[string]any) { m["expires_at"] = "tomorrow" },
		"no numbers":             func(m map[string]any) { m["epochs"] = map[string]any{} },
		"epoch zero":             func(m map[string]any) { m["epochs"] = map[string]any{device: 0} },
		"epoch a fraction":       func(m map[string]any) { m["epochs"] = map[string]any{device: 1.5} },
		"ns for another number": func(m map[string]any) {
			m["ns"] = map[string]any{uuid.NewString(): uuid.NewString()}
		},
		"a tag not canonical": func(m map[string]any) {
			m["cfg_tags"] = map[string]any{device: strings.Repeat("A", 42) + "B"}
		},
		"a tag too short": func(m map[string]any) {
			m["cfg_tags"] = map[string]any{device: "AAAA"}
		},
		"no functions": func(m map[string]any) { m["functions"] = map[string]any{} },
		"anthropic for audio": func(m map[string]any) {
			m["functions"].(map[string]any)["audio"] = map[string]any{"provider": "anthropic", "model": claudeModel}
		},
		"openai for video": func(m map[string]any) {
			m["functions"].(map[string]any)["video"] = map[string]any{"provider": "openai", "model": openaiModel}
		},
		"a function that is not one": func(m map[string]any) {
			m["functions"].(map[string]any)["translate"] = map[string]any{"provider": "google", "model": geminiModel}
		},
		"a model with a colon on google": func(m map[string]any) {
			m["functions"].(map[string]any)["audio"] = map[string]any{"provider": "google", "model": "gemini:flash"}
		},
		"a model in upper case": func(m map[string]any) {
			m["functions"].(map[string]any)["audio"] = map[string]any{"provider": "google", "model": "Gemini"}
		},
		"a key for a provider no function uses": func(m map[string]any) {
			m["keys"].(map[string]any)["openai"] = m["keys"].(map[string]any)["google"]
		},
		"a provider without its key": func(m map[string]any) { delete(m["keys"].(map[string]any), "google") },
		"a key's hash in upper case": func(m map[string]any) {
			m["keys"].(map[string]any)["google"].(map[string]any)["sha256"] = strings.Repeat("A", 64)
		},
		"a suffix of five": func(m map[string]any) {
			m["keys"].(map[string]any)["google"].(map[string]any)["suffix"] = "a1B2c"
		},
		"a label of 61": func(m map[string]any) {
			m["keys"].(map[string]any)["google"].(map[string]any)["label"] = strings.Repeat("x", 61)
		},
		"mode auto": func(m map[string]any) {
			m["features"].(map[string]any)[device].(map[string]any)["audio"] = map[string]any{"mode": "auto", "requesters": "self"}
		},
		"a number's function the configuration lacks": func(m map[string]any) {
			m["features"].(map[string]any)[device].(map[string]any)["image"] = map[string]any{"mode": "request", "requesters": "self"}
		},
		"requesters everyone": func(m map[string]any) {
			m["features"].(map[string]any)[device].(map[string]any)["audio"] = map[string]any{"mode": "request", "requesters": "everyone"}
		},
		"lang not a tag": func(m map[string]any) {
			m["features"].(map[string]any)[device].(map[string]any)["audio"] = map[string]any{"mode": "request", "requesters": "self", "lang": "Portuguese"}
		},
		"lang null": func(m map[string]any) {
			m["features"].(map[string]any)[device].(map[string]any)["audio"] = map[string]any{"mode": "request", "requesters": "self", "lang": nil}
		},
		"budget over the ceiling": func(m map[string]any) {
			m["budget"].(map[string]any)["monthly_usd_cents"] = 100_001
		},
		"items over the ceiling": func(m map[string]any) {
			m["budget"].(map[string]any)["request_items_per_day"] = 1001
		},
		"a rate for no pair": func(m map[string]any) {
			m["budget"].(map[string]any)["rates"].(map[string]any)["openai:"+openaiModel] = map[string]any{"in": 1, "out": 1, "sec": 1}
		},
		"a pair without its rate": func(m map[string]any) {
			delete(m["budget"].(map[string]any)["rates"].(map[string]any), "google:"+geminiModel)
		},
		"a negative rate": func(m map[string]any) {
			m["budget"].(map[string]any)["rates"].(map[string]any)["google:"+geminiModel] = map[string]any{"in": -1, "out": 1, "sec": 0}
		},
		"a rate over the ceiling": func(m map[string]any) {
			m["budget"].(map[string]any)["rates"].(map[string]any)["google:"+geminiModel] = map[string]any{"in": 100_000_001, "out": 1, "sec": 0}
		},
		"a rate without sec": func(m map[string]any) {
			m["budget"].(map[string]any)["rates"].(map[string]any)["google:"+geminiModel] = map[string]any{"in": 1, "out": 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.ParseAIConfig(aiConfigFor(t, c, keys, mutate)); !errors.Is(err, store.ErrAIConfig) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	for name, raw := range map[string]string{
		"not an object": `[]`, "two objects": `{}{}`, "empty": ``, "over 32 KiB": `{"version":1,"x":"` + strings.Repeat("a", 32<<10) + `"}`,
	} {
		if _, err := store.ParseAIConfig([]byte(raw)); !errors.Is(err, store.ErrAIConfig) {
			t.Fatalf("%s: accepted: %v", name, err)
		}
	}
	// Twenty-six numbers are one too many.
	many := c
	many.devices = nil
	for range store.AIDevicesMax + 1 {
		many.devices = append(many.devices, uuid.New())
	}
	if _, err := store.ParseAIConfig(aiConfigFor(t, many, keys, nil)); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("26 numbers accepted: %v", err)
	}
}

// OffFunctions is the union a status answer calls off, sorted.
func TestAIConfigOffFunctions(t *testing.T) {
	c := contentConsent{service: uuid.New(), devices: []uuid.UUID{uuid.New()}}
	c.in.RequestID, c.in.ReaderKID, c.in.ExpiresAt = requestID(t), "0123456789abcdef", time.Now().Add(24*time.Hour)
	cfg, err := store.ParseAIConfig(aiConfigFor(t, c, map[string]uuid.UUID{"google": uuid.New(), "anthropic": uuid.New()}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.OffFunctions(nil, nil, nil); len(got) != 0 {
		t.Fatalf("nothing off = %v", got)
	}
	if got := cfg.OffFunctions([]string{"video"}, []string{"anthropic"}, []string{"image", "video"}); strings.Join(got, ",") != "video,image,document" {
		t.Fatalf("off = %v", got)
	}
	if !cfg.FunctionsOff(nil, []string{"google"}) || !cfg.FunctionsOff([]string{"document"}, nil) || cfg.FunctionsOff([]string{"video"}, []string{"openai"}) {
		t.Fatal("FunctionsOff does not follow the configuration")
	}
}

// Which message types take which function (§18.3).
func TestAIFeatureFits(t *testing.T) {
	for _, tc := range []struct {
		feature, kind string
		gif, want     bool
	}{
		{"audio", "audio", false, true}, {"audio", "ptt", false, true}, {"audio", "video", false, false},
		{"video", "video", false, true}, {"video", "ptv", false, true}, {"video", "video", true, false},
		{"image", "image", false, true}, {"image", "sticker", false, true}, {"image", "video", true, true}, {"image", "video", false, false},
		{"document", "document", false, true}, {"document", "image", false, false}, {"audio", "text", false, false}, {"transcript", "ptt", false, false},
	} {
		if got := store.AIFeatureFits(tc.feature, tc.kind, tc.gif); got != tc.want {
			t.Errorf("%s on %s (gif %v) = %v", tc.feature, tc.kind, tc.gif, got)
		}
	}
}

// An AI authorization is a service-account row of its own: the consent's
// invariants hold as for content, plus its own, and it is neither counted
// in the cap of five nor listed with the assistants.
func TestCreateAIConnectionInvariants(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	keys := f.aiKeys(ctx, t, f.owner)

	conn, c := f.consentAI(ctx, t, f.owner, keys, nil)
	if conn.Kind != store.KindAI || conn.ClientName != store.AIClientName || conn.RedirectHost != store.AIRedirectHost ||
		conn.ServiceUserID == nil || *conn.ServiceUserID != c.service || conn.ConsentVersion != 1 || conn.Media || conn.SendMode != "" {
		t.Fatalf("connection = %+v", conn)
	}
	var stored []byte
	if err := f.pool.QueryRow(ctx, `SELECT ai_config::text FROM mcp_connections WHERE id=$1`, conn.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if again, err := store.ParseAIConfig(stored); err != nil || again.Request != c.in.RequestID {
		t.Fatalf("stored ai_config = %s %v", stored, err)
	}
	// Not an assistant's: left out of the listing.
	if listed, err := f.conns.List(ctx, f.tenant); err != nil || len(listed) != 0 {
		t.Fatalf("listed = %+v %v", listed, err)
	}

	refuse := func(t *testing.T, c contentConsent, want error) {
		t.Helper()
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, want) {
			t.Fatalf("err = %v, want %v", err, want)
		}
	}
	t.Run("no configuration", func(t *testing.T) {
		c := f.prepareAI(ctx, t, f.owner, keys, nil)
		c.in.AIConfig = nil
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	t.Run("a content consent with a configuration", func(t *testing.T) {
		c := f.prepareAI(ctx, t, f.owner, keys, nil)
		c.in.Kind, c.in.ClientName, c.in.RedirectHost = store.KindContent, "Claude", "claude.ai"
		refuse(t, c, store.ErrMCPKeyUnsuitable)
	})
	for name, mutate := range map[string]func(*store.CreateMCPConnection){
		"media":             func(in *store.CreateMCPConnection) { in.Media = true },
		"sending":           func(in *store.CreateMCPConnection) { in.SendMode = store.SendModeDraft },
		"consent version 2": func(in *store.CreateMCPConnection) { in.ConsentVersion = 2 },
		"an assistant name": func(in *store.CreateMCPConnection) { in.ClientName = "Claude" },
		"an assistant host": func(in *store.CreateMCPConnection) { in.RedirectHost = "claude.ai" },
		"the hosted reader": func(in *store.CreateMCPConnection) { in.Reader = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.prepareAI(ctx, t, f.owner, keys, nil)
			mutate(&c.in)
			refuse(t, c, store.ErrMCPKeyUnsuitable)
		})
	}
	for name, mutate := range map[string]func(*contentConsent){
		"another request":         func(c *contentConsent) { c.in.RequestID = requestID(t) },
		"another kid":             func(c *contentConsent) { c.in.ReaderKID = "fedcba9876543210" },
		"another expiry":          func(c *contentConsent) { c.in.ExpiresAt = c.in.ExpiresAt.Add(time.Hour) },
		"another service account": func(c *contentConsent) { c.in.AIConfig.ServiceUserID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.prepareAI(ctx, t, f.owner, keys, nil)
			mutate(&c)
			refuse(t, c, store.ErrAIConfig)
		})
	}
	t.Run("a number the key does not have", func(t *testing.T) {
		dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "second", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		c := f.prepareAI(ctx, t, f.owner, keys, func(m map[string]any) {
			other := dev.ID
			for _, field := range []string{"epochs", "ns", "features", "cfg_tags"} {
				byDevice := m[field].(map[string]any)
				for k, v := range byDevice {
					delete(byDevice, k)
					byDevice[other] = v
				}
			}
		})
		refuse(t, c, store.ErrAIConfig)
	})
	t.Run("another person's key", func(t *testing.T) {
		admin := f.member(t, "admin")
		theirs := f.aiKeys(ctx, t, admin)
		refuse(t, f.prepareAI(ctx, t, f.owner, theirs, nil), store.ErrAIConfig)
	})
	t.Run("a key of another provider", func(t *testing.T) {
		swapped := map[string]uuid.UUID{"google": keys["anthropic"], "anthropic": keys["google"]}
		refuse(t, f.prepareAI(ctx, t, f.owner, swapped, nil), store.ErrAIConfig)
	})
	t.Run("a deleted key", func(t *testing.T) {
		gone := map[string]uuid.UUID{"google": f.keychainItem(ctx, t, f.owner, "google"), "anthropic": keys["anthropic"]}
		if _, err := f.ai.DeleteKeychainItem(ctx, f.tenant, f.owner, gone["google"]); err != nil {
			t.Fatal(err)
		}
		refuse(t, f.prepareAI(ctx, t, f.owner, gone, nil), store.ErrAIConfig)
	})
	t.Run("a member", func(t *testing.T) {
		// In B1 only an owner or an admin makes one.
		member := f.member(t, "member")
		c := f.prepareAI(ctx, t, f.owner, keys, nil)
		if _, err := f.conns.Create(ctx, f.tenant, member, c.in); !errors.Is(err, store.ErrMembershipForbidden) {
			t.Fatalf("a member made an authorization: %v", err)
		}
	})

	// The cap of five does not count AI authorizations, and does not stop
	// one either.
	for range 5 {
		f.consentContent(ctx, t, f.owner)
	}
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, f.prepareContent(ctx, t, f.owner).in); !errors.Is(err, store.ErrTooManyMCPConnections) {
		t.Fatalf("a sixth assistant: %v", err)
	}
	f.consentAI(ctx, t, f.owner, keys, nil)
	if listed, err := f.conns.List(ctx, f.tenant); err != nil || len(listed) != 5 {
		t.Fatalf("listed = %d %v", len(listed), err)
	}
	if all, err := f.conns.AIAuthorizations(ctx, f.tenant, f.owner, true); err != nil || len(all) != 2 {
		t.Fatalf("authorizations = %d %v", len(all), err)
	}
}

// The migration's CHECKs are the backstop behind Create's: an AI row is
// never media, never sends, is the console's and carries its
// configuration; no other row carries AI columns.
func TestAIConnectionChecks(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	keys := f.aiKeys(ctx, t, f.owner)
	conn, _ := f.consentAI(ctx, t, f.owner, keys, nil)
	content, _ := f.consentContent(ctx, t, f.owner)
	for name, q := range map[string]string{
		"media on an AI row":             `UPDATE mcp_connections SET media=true WHERE id=$1`,
		"sending on an AI row":           `UPDATE mcp_connections SET send_mode='draft' WHERE id=$1`,
		"an AI row without its config":   `UPDATE mcp_connections SET ai_config=NULL WHERE id=$1`,
		"an AI row of another version":   `UPDATE mcp_connections SET consent_version=2 WHERE id=$1`,
		"an AI row for an assistant":     `UPDATE mcp_connections SET redirect_host='claude.ai' WHERE id=$1`,
		"an AI row without an account":   `UPDATE mcp_connections SET service_user_id=NULL WHERE id=$1`,
		"a function that is not one off": `UPDATE mcp_connections SET ai_off='{translate}' WHERE id=$1`,
		"a cap of zero":                  `UPDATE mcp_connections SET ai_cap_cents=0 WHERE id=$1`,
		"a cap over the ceiling":         `UPDATE mcp_connections SET ai_cap_cents=100001 WHERE id=$1`,
		"a kind that is not one":         `UPDATE mcp_connections SET kind='assistant' WHERE id=$1`,
	} {
		if _, err := f.pool.Exec(ctx, q, conn.ID); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
	for name, q := range map[string]string{
		"a config on a content row": `UPDATE mcp_connections SET ai_config='{}' WHERE id=$1`,
		"a pause on a content row":  `UPDATE mcp_connections SET ai_paused_at=now() WHERE id=$1`,
		"off on a content row":      `UPDATE mcp_connections SET ai_off='{audio}' WHERE id=$1`,
		"a cap on a content row":    `UPDATE mcp_connections SET ai_cap_cents=10 WHERE id=$1`,
		"alerts on a content row":   `UPDATE mcp_connections SET ai_alerts='{"x":1}' WHERE id=$1`,
	} {
		if _, err := f.pool.Exec(ctx, q, content.ID); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET revoke_reason='ai_key_deleted' WHERE id=$1`, content.ID); err != nil {
		t.Fatalf("the new reason was refused: %v", err)
	}
}

// An ai_config at AI_DEVICES_MAX, with the four functions and the longest
// language, labels and model ids, fits its column; the numbers are then
// exactly the key's.
func TestAIConfigAtDevicesMax(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	devices := []uuid.UUID{f.device}
	for i := 1; i < store.AIDevicesMax; i++ {
		dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), fmt.Sprintf("number %d", i), wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		device := uuid.MustParse(dev.ID)
		f.archiveKey(ctx, t, device, 1)
		devices = append(devices, device)
	}
	keys := map[string]uuid.UUID{"google": f.keychainItem(ctx, t, f.owner, "google"), "anthropic": f.keychainItem(ctx, t, f.owner, "anthropic"),
		"openai": f.keychainItem(ctx, t, f.owner, "openai")}
	// The longest of everything: four functions on three providers with
	// 64-character models, 60-character labels, the longest language on
	// every function of every number, the largest epochs and rates.
	model := func(c string) string { return c + strings.Repeat("x", 63) }
	longest := func(m map[string]any) {
		functions := map[string]any{
			"audio":    map[string]any{"provider": "openai", "model": model("a")},
			"video":    map[string]any{"provider": "google", "model": model("b")},
			"image":    map[string]any{"provider": "anthropic", "model": model("c")},
			"document": map[string]any{"provider": "google", "model": model("d")},
		}
		m["functions"] = functions
		rates := map[string]any{}
		for _, fn := range functions {
			fn := fn.(map[string]any)
			rates[fn["provider"].(string)+":"+fn["model"].(string)] = map[string]any{"in": 100_000_000, "out": 100_000_000, "sec": 100_000_000}
		}
		m["budget"].(map[string]any)["rates"] = rates
		m["budget"].(map[string]any)["monthly_usd_cents"] = 100_000
		for _, k := range m["keys"].(map[string]any) {
			k.(map[string]any)["label"] = strings.Repeat("ç", 60)
		}
		for d := range m["features"].(map[string]any) {
			byFeature := map[string]any{}
			for _, feature := range store.AIFeatures {
				byFeature[feature] = map[string]any{"mode": "request", "lang": "abc-abcdefgh-abcdefgh-abcdefgh", "requesters": "readers"}
			}
			m["features"].(map[string]any)[d] = byFeature
			m["epochs"].(map[string]any)[d] = 65535
		}
	}
	c := f.prepareAI(ctx, t, f.owner, keys, longest, withDevices(devices...))
	if len(c.in.AIConfig.Raw) < 14_000 || len(c.in.AIConfig.Raw) > 32<<10 {
		t.Fatalf("the longest configuration is %d bytes", len(c.in.AIConfig.Raw))
	}
	// The epochs say 65535 while the grants are at 1: this server keeps the
	// mirror as sent, and the enclave's tags decide.
	conn, err := f.conns.Create(ctx, f.tenant, f.owner, c.in)
	if err != nil {
		t.Fatalf("the longest configuration was refused: %v", err)
	}
	var size int
	if err := f.pool.QueryRow(ctx, `SELECT octet_length(ai_config::text) FROM mcp_connections WHERE id=$1`, conn.ID).Scan(&size); err != nil || size > 32768 {
		t.Fatalf("stored %d bytes %v", size, err)
	}
	// Fewer numbers than the key's is refused.
	short := f.prepareAI(ctx, t, f.owner, keys, func(m map[string]any) {
		longest(m)
		for _, field := range []string{"epochs", "ns", "features", "cfg_tags"} {
			delete(m[field].(map[string]any), devices[0].String())
		}
	}, withDevices(devices...))
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, short.in); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("a configuration short of the key's numbers: %v", err)
	}
}

// An AI row's standing is decided as a content connection's, with the AI
// test in place of the content one, and carries its narrowing.
func TestAIStatus(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	keys := f.aiKeys(ctx, t, f.owner)
	conn, c := f.consentAI(ctx, t, f.owner, keys, nil)
	yes := func(uuid.UUID) bool { return true }
	no := func(uuid.UUID) bool { return false }

	a, err := f.conns.StatusFor(ctx, "enclave", conn.ID, store.StatusAllowed{Content: no, AI: yes})
	if err != nil || a.Status != "active" || a.Kind != store.KindAI || a.AIConfig == nil || a.AIConfig.Request != c.in.RequestID ||
		a.AIPaused || a.AICapCents != nil || len(a.AIOff) != 0 || a.Media {
		t.Fatalf("answer = %+v %v", a, err)
	}
	// AI not allowed: reseal, computed and never written.
	for name, allowed := range map[string]store.StatusAllowed{
		"AI off, content on": {Content: yes, AI: no}, "neither": {}, "AI nil": {Content: yes},
	} {
		if a, err := f.conns.StatusFor(ctx, "enclave", conn.ID, allowed); err != nil || a.Status != "reseal" {
			t.Fatalf("%s: %+v %v", name, a, err)
		}
	}
	if got := f.aiRow(ctx, t, conn.ID); got.Status != "active" {
		t.Fatalf("the computed reseal was written: %+v", got)
	}
	// Status (the content-only form) never lets an AI row serve.
	if a, err := f.conns.Status(ctx, "enclave", conn.ID, yes); err != nil || a.Status != "reseal" {
		t.Fatalf("Status = %+v %v", a, err)
	}
	// The narrowing is answered.
	paused, cap := true, 500
	if _, err := f.conns.SetAIControls(ctx, f.tenant, f.owner, conn.ID, store.AIControls{Paused: &paused, Off: &[]string{"document"}, CapSet: true, Cap: &cap}); err != nil {
		t.Fatal(err)
	}
	if a, err := f.conns.StatusFor(ctx, "enclave", conn.ID, store.StatusAllowed{AI: yes}); err != nil || !a.AIPaused || a.AICapCents == nil ||
		*a.AICapCents != 500 || strings.Join(a.AIOff, ",") != "document" {
		t.Fatalf("narrowed = %+v %v", a, err)
	}
	// Access lost ends it, with the cascade.
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE prefix=$1`, c.prefix)
		return err
	})
	if a, err := f.conns.StatusFor(ctx, "enclave", conn.ID, store.StatusAllowed{AI: yes}); err != nil || a.Status != "revoked" {
		t.Fatalf("access lost = %+v %v", a, err)
	}
	if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
		t.Fatalf("the service account kept %+v", tr)
	}
	// Past its deadline it expires.
	other, _ := f.consentAI(ctx, t, f.owner, keys, nil)
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET expires_at=now()-interval '1 second' WHERE id=$1`, other.ID); err != nil {
		t.Fatal(err)
	}
	if a, err := f.conns.StatusFor(ctx, "enclave", other.ID, store.StatusAllowed{AI: yes}); err != nil || a.Status != "expired" {
		t.Fatalf("expired = %+v %v", a, err)
	}
}

// aiRow reads an authorization as the console lists it.
func (f *aiFixture) aiRow(ctx context.Context, t *testing.T, id string) store.AIAuthorization {
	t.Helper()
	all, err := f.conns.AIAuthorizations(ctx, f.tenant, f.owner, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("authorization %s not listed", id)
	return store.AIAuthorization{}
}

// /v1/media's lookup: an AI row's key is found as the row's, with whether
// it is active and paused.
func TestAIConnectionByAPIKey(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	conn, c := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, f.keyID(ctx, t, c.key))
	if err != nil || got.ConnectionID != conn.ID || got.Kind != store.KindAI || !got.Active || !got.Live || got.Paused || got.Media {
		t.Fatalf("active = %+v %v", got, err)
	}
	paused := true
	if _, err := f.conns.SetAIControls(ctx, f.tenant, f.owner, conn.ID, store.AIControls{Paused: &paused}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, f.keyID(ctx, t, c.key)); err != nil || !got.Paused {
		t.Fatalf("paused = %+v %v", got, err)
	}
	if err := f.conns.Reseal(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.conns.ContentConnectionByAPIKey(ctx, f.tenant, f.keyID(ctx, t, c.key)); err != nil || got.Active || !got.Live {
		t.Fatalf("resealed = %+v %v", got, err)
	}
}

// Who may ask (§18.10): the requester's own first, newest first; then
// another's that lets readers ask, oldest first, for a person who reads the
// number; the requester's own in reseal only when nothing active is
// admitted; never another's in reseal.
func TestPickAIAuthorization(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	admin := f.member(t, "admin")
	f.ownerReads(ctx, t, admin, f.device)
	reader := f.member(t, "member")
	f.ownerReads(ctx, t, reader, f.device)
	outsider := f.member(t, "member")
	ownerKeys, adminKeys := f.aiKeys(ctx, t, f.owner), f.aiKeys(ctx, t, admin)
	requesters := func(who string) func(map[string]any) {
		return func(m map[string]any) {
			for _, byFeature := range m["features"].(map[string]any) {
				for _, feature := range byFeature.(map[string]any) {
					feature.(map[string]any)["requesters"] = who
				}
			}
		}
	}
	pick := func(requester uuid.UUID, feature, origin string, policy store.AIPolicy) (store.AIPick, error) {
		return f.conns.PickAIAuthorization(ctx, f.tenant, requester, f.device, feature, origin, policy)
	}
	want := func(t *testing.T, got store.AIPick, err error, id, state string) {
		t.Helper()
		if err != nil || got.AuthorizationID != id || got.State != state {
			t.Fatalf("pick = %+v %v, want %s %s", got, err, id, state)
		}
	}
	none := func(t *testing.T, got store.AIPick, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrAINotEnabled) {
			t.Fatalf("pick = %+v %v, want none", got, err)
		}
	}

	// Nothing yet.
	got, err := pick(f.owner, "audio", "console", allowAI)
	none(t, got, err)

	adminReaders, _ := f.consentAI(ctx, t, admin, adminKeys, requesters("readers"))
	time.Sleep(5 * time.Millisecond)
	ownerOld, _ := f.consentAI(ctx, t, f.owner, ownerKeys, nil)
	time.Sleep(5 * time.Millisecond)
	ownerNew, _ := f.consentAI(ctx, t, f.owner, ownerKeys, nil)
	time.Sleep(5 * time.Millisecond)
	adminSelf, _ := f.consentAI(ctx, t, admin, adminKeys, nil)

	// Own first, the newest.
	got, err = pick(f.owner, "audio", "console", allowAI)
	want(t, got, err, ownerNew.ID, "active")
	got, err = pick(admin, "audio", "connector", allowAI)
	want(t, got, err, adminSelf.ID, "active")
	// Another reader of the number gets the one that lets readers ask; a
	// person who does not read the number gets nothing.
	got, err = pick(reader, "audio", "console", allowAI)
	want(t, got, err, adminReaders.ID, "active")
	got, err = pick(reader, "audio", "connector", allowAI)
	want(t, got, err, adminReaders.ID, "active")
	got, err = pick(outsider, "audio", "console", allowAI)
	none(t, got, err)
	// A function nobody configured, or one switched off, gets nothing.
	got, err = pick(f.owner, "video", "console", allowAI)
	none(t, got, err)
	got, err = pick(f.owner, "audio", "console", store.AIPolicy{Allowed: true, OffFeatures: []string{"audio"}})
	none(t, got, err)
	got, err = pick(f.owner, "audio", "console", store.AIPolicy{Allowed: true, OffProviders: []string{"google"}})
	none(t, got, err)
	got, err = pick(f.owner, "document", "console", store.AIPolicy{Allowed: true, OffProviders: []string{"google"}})
	want(t, got, err, ownerNew.ID, "active")
	got, err = pick(f.owner, "audio", "console", store.AIPolicy{})
	none(t, got, err)
	got, err = pick(f.owner, "audio", "auto", allowAI)
	none(t, got, err)

	// A paused row, and a row with the function off, are skipped.
	paused := true
	if _, err := f.conns.SetAIControls(ctx, f.tenant, f.owner, ownerNew.ID, store.AIControls{Paused: &paused}); err != nil {
		t.Fatal(err)
	}
	got, err = pick(f.owner, "audio", "console", allowAI)
	want(t, got, err, ownerOld.ID, "active")
	if _, err := f.conns.SetAIControls(ctx, f.tenant, f.owner, ownerOld.ID, store.AIControls{Off: &[]string{"audio"}}); err != nil {
		t.Fatal(err)
	}
	// Neither of the owner's own is left: another's that lets readers ask.
	got, err = pick(f.owner, "audio", "console", allowAI)
	want(t, got, err, adminReaders.ID, "active")

	// "console" requesters: the console only.
	consoleOnly, _ := f.consentAI(ctx, t, f.owner, ownerKeys, requesters("console"))
	got, err = pick(f.owner, "audio", "console", allowAI)
	want(t, got, err, consoleOnly.ID, "active")
	got, err = pick(f.owner, "audio", "connector", allowAI)
	want(t, got, err, adminReaders.ID, "active")

	// Reseal: the requester's own only when nothing active is admitted.
	if err := f.conns.Reseal(ctx, "enclave", consoleOnly.ID); err != nil {
		t.Fatal(err)
	}
	got, err = pick(f.owner, "audio", "console", allowAI)
	want(t, got, err, adminReaders.ID, "active")
	if err := f.conns.Reseal(ctx, "enclave", adminReaders.ID); err != nil {
		t.Fatal(err)
	}
	got, err = pick(f.owner, "audio", "console", allowAI)
	want(t, got, err, consoleOnly.ID, "reseal")
	// ... and only where it would otherwise be admitted: a console-only row
	// is not the connector's answer, and another person's reseal row is
	// never anyone else's.
	got, err = pick(f.owner, "audio", "connector", allowAI)
	none(t, got, err)
	got, err = pick(reader, "audio", "console", allowAI)
	none(t, got, err)
	got, err = pick(f.owner, "audio", "console", store.AIPolicy{})
	none(t, got, err)
	// An ended row is nobody's.
	if _, _, err := f.conns.RevokeAI(ctx, f.tenant, f.owner, consoleOnly.ID, false); err != nil {
		t.Fatal(err)
	}
	got, err = pick(f.owner, "audio", "console", allowAI)
	none(t, got, err)
	got, err = pick(admin, "audio", "console", allowAI)
	want(t, got, err, adminSelf.ID, "active")
}

// The keychain: a person's own items only, twenty at most, ids unique, and
// a deletion empties the envelope and ends every authorization that names
// the item, with its key and service account.
func TestAIKeychain(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	admin := f.member(t, "admin")
	envelope := append([]byte("WKC1"), randomBytes(t, 60)...)
	first, err := f.ai.AddKeychainItem(ctx, f.tenant, f.owner, store.AIKeychainItem{ID: uuid.New(), Provider: "openai", Label: "Wappie", Suffix: "x9Z!", Envelope: envelope})
	if err != nil || first.CreatedAt.IsZero() {
		t.Fatalf("add = %+v %v", first, err)
	}
	items, err := f.ai.Keychain(ctx, f.tenant, f.owner)
	if err != nil || len(items) != 1 || items[0].ID != first.ID || string(items[0].Envelope) != string(envelope) || items[0].Suffix != "x9Z!" {
		t.Fatalf("items = %+v %v", items, err)
	}
	if theirs, err := f.ai.Keychain(ctx, f.tenant, admin); err != nil || len(theirs) != 0 {
		t.Fatalf("another person's items = %+v %v", theirs, err)
	}
	if _, err := f.ai.AddKeychainItem(ctx, f.tenant, admin, store.AIKeychainItem{ID: first.ID, Provider: "openai", Label: "mine", Suffix: "abcd", Envelope: envelope}); !errors.Is(err, store.ErrAIKeychainExists) {
		t.Fatalf("a taken id = %v", err)
	}
	for _, bad := range []store.AIKeychainItem{
		{ID: uuid.New(), Provider: "mistral", Label: "x", Suffix: "abcd", Envelope: envelope},
		{ID: uuid.New(), Provider: "openai", Label: "", Suffix: "abcd", Envelope: envelope},
		{ID: uuid.New(), Provider: "openai", Label: "x", Suffix: "abc", Envelope: envelope},
		{ID: uuid.New(), Provider: "openai", Label: "x", Suffix: "abcd", Envelope: []byte("sk-plaintext-key-0123456789abcdef")},
		{ID: uuid.New(), Provider: "openai", Label: "x", Suffix: "abcd", Envelope: append([]byte("WKC1"), make([]byte, 4096)...)},
	} {
		if _, err := f.ai.AddKeychainItem(ctx, f.tenant, f.owner, bad); err == nil {
			t.Fatalf("stored %+v", bad)
		}
	}
	for i := 1; i < store.AIKeychainMax; i++ {
		f.keychainItem(ctx, t, f.owner, "google")
	}
	if _, err := f.ai.AddKeychainItem(ctx, f.tenant, f.owner, store.AIKeychainItem{ID: uuid.New(), Provider: "google", Label: "x", Suffix: "abcd", Envelope: envelope}); !errors.Is(err, store.ErrAIKeychainFull) {
		t.Fatalf("a twenty-first item = %v", err)
	}
	// Another person has room of their own.
	f.keychainItem(ctx, t, admin, "google")

	// Deleting: another person's is not found; the owner's ends what names it.
	if _, err := f.ai.DeleteKeychainItem(ctx, f.tenant, admin, first.ID); !errors.Is(err, store.ErrAINotFound) {
		t.Fatalf("another person deleted it: %v", err)
	}
	items, _ = f.ai.Keychain(ctx, f.tenant, f.owner)
	google := items[1].ID
	if ended, err := f.ai.DeleteKeychainItem(ctx, f.tenant, f.owner, items[2].ID); err != nil || len(ended) != 0 {
		t.Fatalf("an unused item = %v %v", ended, err)
	}
	anthropic := f.keychainItem(ctx, t, f.owner, "anthropic")
	uses, c := f.consentAI(ctx, t, f.owner, map[string]uuid.UUID{"google": google, "anthropic": anthropic}, nil)
	pending := f.prepareAI(ctx, t, f.owner, map[string]uuid.UUID{"google": google, "anthropic": anthropic}, nil)
	pendingConn, err := f.conns.Create(ctx, f.tenant, f.owner, pending.in)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := f.consentAI(ctx, t, f.owner, map[string]uuid.UUID{"google": items[3].ID, "anthropic": anthropic}, nil)
	ended, err := f.ai.DeleteKeychainItem(ctx, f.tenant, f.owner, google)
	if err != nil || len(ended) != 2 {
		t.Fatalf("ended = %+v %v", ended, err)
	}
	for _, e := range ended {
		if e.ID != uses.ID && e.ID != pendingConn.ID || e.Reader != "enclave" {
			t.Fatalf("ended %+v", e)
		}
	}
	for _, id := range []string{uses.ID, pendingConn.ID} {
		if got := f.aiRow(ctx, t, id); got.Status != "revoked" || got.RevokeReason != store.ReasonAIKeyDeleted {
			t.Fatalf("row %s = %s/%s", id, got.Status, got.RevokeReason)
		}
	}
	if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the authorization's key survived: %v", err)
	}
	if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
		t.Fatalf("the service account kept %+v", tr)
	}
	if got := f.aiRow(ctx, t, other.ID); got.Status != "active" {
		t.Fatalf("an authorization using another key ended: %+v", got)
	}
	var length int
	var deleted bool
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT length(envelope), deleted_at IS NOT NULL FROM ai_keychain WHERE id=$1`, google).Scan(&length, &deleted)
	})
	if length != 0 || !deleted {
		t.Fatalf("the deleted item kept %d bytes (deleted %v)", length, deleted)
	}
	if _, err := f.ai.DeleteKeychainItem(ctx, f.tenant, f.owner, google); !errors.Is(err, store.ErrAINotFound) {
		t.Fatalf("a second deletion = %v", err)
	}
	// A deleted item makes room.
	f.keychainItem(ctx, t, f.owner, "google")
}

// Results: only on a message of the number, of the function's type; one per
// message and function unless redone; refused while storage is paused;
// deleted by their authorization's creator or a manager.
func TestAIDerived(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	admin := f.member(t, "admin")
	member := f.member(t, "member")
	conn, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	voice := f.message(ctx, t, f.device, domain.TypePTT, false)
	gif := f.message(ctx, t, f.device, domain.TypeVideo, true)
	text := f.message(ctx, t, f.device, domain.TypeText, false)
	dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	second := uuid.MustParse(dev.ID)
	elsewhere := f.message(ctx, t, second, domain.TypePTT, false)

	rec := f.derived(t, voice, f.device, "audio")
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, rec, false); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]store.AIDerived{
		"a text":                  f.derived(t, text, f.device, "audio"),
		"a GIF as video":          f.derived(t, gif, f.device, "video"),
		"a voice note as a image": f.derived(t, voice, f.device, "image"),
		"another number's":        f.derived(t, elsewhere, f.device, "audio"),
		"a message that is not":   f.derived(t, uuid.New(), f.device, "audio"),
	} {
		if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, d, false); !errors.Is(err, store.ErrAIDerivedMismatch) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, f.derived(t, gif, f.device, "image"), false); err != nil {
		t.Fatalf("a GIF's description = %v", err)
	}
	for name, d := range map[string]store.AIDerived{
		"a wrong magic":        {MessageUID: voice, Feature: "audio", DeviceID: f.device, Epoch: 1, Sealed: append([]byte("WXYZ"), sealedAt(t, 1, 10)[4:]...), DedupeTag: randomBytes(t, 32)},
		"another epoch inside": {MessageUID: voice, Feature: "audio", DeviceID: f.device, Epoch: 2, Sealed: sealedAt(t, 1, 10), DedupeTag: randomBytes(t, 32)},
		"a short tag":          {MessageUID: voice, Feature: "audio", DeviceID: f.device, Epoch: 1, Sealed: sealedAt(t, 1, 10), DedupeTag: randomBytes(t, 31)},
		"too large":            {MessageUID: voice, Feature: "audio", DeviceID: f.device, Epoch: 1, Sealed: sealedAt(t, 1, store.AIDerivedSealedMax), DedupeTag: randomBytes(t, 32)},
	} {
		if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, d, true); err == nil {
			t.Fatalf("%s was stored", name)
		}
	}
	// One per message and function: a second without redo is refused, and
	// a redo replaces it.
	again := f.derived(t, voice, f.device, "audio")
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, again, false); !errors.Is(err, store.ErrAIDerivedExists) {
		t.Fatalf("a second record = %v", err)
	}
	items, err := f.ai.AIDerivedFor(ctx, f.tenant, f.device, []uuid.UUID{voice, gif, text})
	if err != nil || len(items) != 2 || string(items[slices.IndexFunc(items, func(d store.AIDerived) bool { return d.MessageUID == voice })].Sealed) != string(rec.Sealed) {
		t.Fatalf("items = %d %v", len(items), err)
	}
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, again, true); err != nil {
		t.Fatal(err)
	}
	items, _ = f.ai.AIDerivedFor(ctx, f.tenant, f.device, []uuid.UUID{voice})
	if len(items) != 1 || string(items[0].Sealed) != string(again.Sealed) || items[0].AuthorizationID == nil || items[0].AuthorizationID.String() != conn.ID {
		t.Fatalf("redone = %+v", items)
	}
	// Another number's lookup sees none of it.
	if items, err := f.ai.AIDerivedFor(ctx, f.tenant, second, []uuid.UUID{voice}); err != nil || len(items) != 0 {
		t.Fatalf("another number = %+v %v", items, err)
	}

	// The tags: only the pairs asked, of the function asked.
	byTag, err := f.ai.AIDerivedByTags(ctx, f.tenant, "audio", []store.AIDedupeTag{{DeviceID: f.device, Tag: again.DedupeTag}, {DeviceID: second, Tag: again.DedupeTag}})
	if err != nil || len(byTag) != 1 || byTag[0].MessageUID != voice {
		t.Fatalf("by tag = %+v %v", byTag, err)
	}
	for name, tags := range map[string][]store.AIDedupeTag{
		"the old tag":      {{DeviceID: f.device, Tag: rec.DedupeTag}},
		"another number":   {{DeviceID: second, Tag: again.DedupeTag}},
		"another function": nil,
	} {
		feature := "audio"
		if tags == nil {
			feature, tags = "video", []store.AIDedupeTag{{DeviceID: f.device, Tag: again.DedupeTag}}
		}
		if got, err := f.ai.AIDerivedByTags(ctx, f.tenant, feature, tags); err != nil || len(got) != 0 {
			t.Fatalf("%s = %+v %v", name, got, err)
		}
	}

	// Storage paused refuses a new one.
	pausedUID := f.message(ctx, t, f.device, domain.TypeAudio, false)
	if _, err := f.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at=now() WHERE id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, f.derived(t, pausedUID, f.device, "audio"), false); !errors.Is(err, store.ErrStoragePaused) {
		t.Fatalf("with storage paused = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at=NULL WHERE id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}

	// Deleting: a member who did not make it may not; its creator and an
	// admin may.
	if err := f.ai.DeleteAIDerived(ctx, f.tenant, member, voice, "audio"); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("a member deleted it: %v", err)
	}
	if err := f.ai.DeleteAIDerived(ctx, f.tenant, f.owner, voice, "audio"); err != nil {
		t.Fatal(err)
	}
	if err := f.ai.DeleteAIDerived(ctx, f.tenant, f.owner, voice, "audio"); !errors.Is(err, store.ErrAINotFound) {
		t.Fatalf("a second deletion = %v", err)
	}
	if err := f.ai.DeleteAIDerived(ctx, f.tenant, admin, gif, "image"); err != nil {
		t.Fatal(err)
	}
	// By authorization and by number.
	for _, uid := range []uuid.UUID{voice, gif} {
		feature := "audio"
		if uid == gif {
			feature = "image"
		}
		if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, f.derived(t, uid, f.device, feature), false); err != nil {
			t.Fatal(err)
		}
	}
	id := uuid.MustParse(conn.ID)
	if _, err := f.ai.DeleteAIDerivedOf(ctx, f.tenant, member, &id, nil); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("a member deleted an authorization's results: %v", err)
	}
	if _, err := f.ai.DeleteAIDerivedOf(ctx, f.tenant, f.owner, &f.device, nil); err == nil {
		t.Fatal("both named")
	}
	if n, err := f.ai.DeleteAIDerivedOf(ctx, f.tenant, f.owner, &id, nil); err != nil || n != 2 {
		t.Fatalf("by authorization = %d %v", n, err)
	}
	missing := uuid.New()
	if _, err := f.ai.DeleteAIDerivedOf(ctx, f.tenant, f.owner, &missing, nil); !errors.Is(err, store.ErrAINotFound) {
		t.Fatalf("an unknown authorization = %v", err)
	}
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, f.derived(t, voice, f.device, "audio"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ai.DeleteAIDerivedOf(ctx, f.tenant, member, nil, &f.device); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("a member deleted a number's results: %v", err)
	}
	if n, err := f.ai.DeleteAIDerivedOf(ctx, f.tenant, admin, nil, &f.device); err != nil || n != 1 {
		t.Fatalf("by number = %d %v", n, err)
	}

	// Revoking with delete_results takes them; without, they stay, and
	// once the authorization row is gone their authorization is nil and a
	// manager decides.
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, f.derived(t, voice, f.device, "audio"), false); err != nil {
		t.Fatal(err)
	}
	if _, deleted, err := f.conns.RevokeAI(ctx, f.tenant, f.owner, conn.ID, false); err != nil || deleted != 0 {
		t.Fatalf("revoke = %d %v", deleted, err)
	}
	if items, _ := f.ai.AIDerivedFor(ctx, f.tenant, f.device, []uuid.UUID{voice}); len(items) != 1 {
		t.Fatalf("the results went with the revocation: %+v", items)
	}
	if _, deleted, err := f.conns.RevokeAI(ctx, f.tenant, f.owner, conn.ID, true); err != nil || deleted != 1 {
		t.Fatalf("revoke deleting = %d %v", deleted, err)
	}
}

// Results count toward the quota, reconcile to the same total, are
// attributed to their number, and go with their message.
func TestAIDerivedStorage(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	storage := store.NewStorage(f.pool)
	if _, err := storage.Reconcile(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	conn, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	voice := f.message(ctx, t, f.device, domain.TypePTT, false)
	before, err := storage.UsageDetailed(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, store.AIDerived{MessageUID: voice, Feature: "audio", DeviceID: f.device, Epoch: 1,
		Sealed: sealedAt(t, 1, 10_000), DedupeTag: randomBytes(t, 32)}, false); err != nil {
		t.Fatal(err)
	}
	after, err := storage.UsageDetailed(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if grew := after.ArchiveBytes - before.ArchiveBytes; grew < 10_000 || grew > 11_000 {
		t.Fatalf("a 10 KB result grew the archive by %d", grew)
	}
	device := after.Breakdown.Devices[slices.IndexFunc(after.Breakdown.Devices, func(d store.DeviceStorageUsage) bool { return d.DeviceID == f.device.String() })]
	if device.ArchiveBytes != after.ArchiveBytes || after.Breakdown.Unassigned.ArchiveBytes != 0 {
		t.Fatalf("attribution = %+v", after.Breakdown)
	}
	reconciled, err := storage.Reconcile(ctx, f.tenant)
	if err != nil || reconciled.ArchiveBytes != after.ArchiveBytes {
		t.Fatalf("reconciled %d, counted %d %v", reconciled.ArchiveBytes, after.ArchiveBytes, err)
	}
	// Deleting the message deletes the result and gives its bytes back.
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM messages WHERE uid=$1`, voice)
		return err
	})
	if items, _ := f.ai.AIDerivedFor(ctx, f.tenant, f.device, []uuid.UUID{voice}); len(items) != 0 {
		t.Fatalf("the result outlived its message: %+v", items)
	}
	if got, err := storage.Usage(ctx, f.tenant); err != nil || got.ArchiveBytes >= before.ArchiveBytes {
		t.Fatalf("after the message went: %d, before %d %v", got.ArchiveBytes, before.ArchiveBytes, err)
	}
}

// A number moved to its owner's Personal takes its results, which no longer
// name an authorization of the old workspace; the totals of both stay the
// tables' own.
func TestAIDerivedMovesWithItsNumber(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	owner := f.owner
	var target uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, owner).Scan(&target); err != nil {
		t.Fatal(err)
	}
	conn, _ := f.consentAI(ctx, t, owner, f.aiKeys(ctx, t, owner), nil)
	voice := f.message(ctx, t, f.device, domain.TypePTT, false)
	if err := f.ai.PutAIDerived(ctx, f.tenant, conn.ID, f.derived(t, voice, f.device, "audio"), false); err != nil {
		t.Fatal(err)
	}
	if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, store.AIUsage{DeviceID: f.device, Feature: "audio", Provider: "google", Model: geminiModel,
		Origin: "console", RequesterID: owner, Items: 1}); err != nil {
		t.Fatal(err)
	}
	devices := store.NewDevices(f.pool)
	if err := devices.SetPaused(ctx, f.tenant.String(), f.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, f.tenant, owner, f.device, target); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.ai.AIDerivedFor(ctx, f.tenant, f.device, []uuid.UUID{voice}); len(items) != 0 {
		t.Fatalf("the source kept the result: %+v", items)
	}
	moved, err := f.ai.AIDerivedFor(ctx, target, f.device, []uuid.UUID{voice})
	if err != nil || len(moved) != 1 || moved[0].AuthorizationID != nil {
		t.Fatalf("moved = %+v %v", moved, err)
	}
	storage := store.NewStorage(f.pool)
	for _, tenant := range []uuid.UUID{f.tenant, target} {
		before, err := storage.UsageDetailed(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		after, err := storage.Reconcile(ctx, tenant)
		if err != nil || after.ArchiveBytes != before.ArchiveBytes {
			t.Fatalf("%s: reconciled %d, counted %d %v", tenant, after.ArchiveBytes, before.ArchiveBytes, err)
		}
	}
	// The usage stays with the workspace that wrote it.
	if got, err := f.ai.AIUsageMonth(ctx, f.tenant, owner, true, time.Now()); err != nil || len(got) != 1 {
		t.Fatalf("usage = %+v %v", got, err)
	}
}

// Usage: increments add up per day and key, the key is the one the
// configuration names as it records (kept for past rows through a renewal
// that rotates it), and the month's total and today's items come back.
func TestAIUsage(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	admin := f.member(t, "admin")
	f.ownerReads(ctx, t, admin, f.device)
	keys := f.aiKeys(ctx, t, f.owner)
	conn, c := f.consentAI(ctx, t, f.owner, keys, nil)
	theirs, _ := f.consentAI(ctx, t, admin, f.aiKeys(ctx, t, admin), nil)
	inc := store.AIUsage{DeviceID: f.device, Feature: "audio", Provider: "google", Model: geminiModel, Origin: "connector", RequesterID: f.owner,
		Items: 1, InputTokens: 1000, OutputTokens: 200, Seconds: 60, CostMicrocents: 80_000}
	for range 3 {
		if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, inc); err != nil {
			t.Fatal(err)
		}
	}
	// A reuse asked from the console is a row of its own.
	reused := inc
	reused.Origin, reused.Items, reused.Reused, reused.CostMicrocents, reused.InputTokens, reused.OutputTokens, reused.Seconds = "console", 0, 1, 0, 0, 0, 0
	if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, reused); err != nil {
		t.Fatal(err)
	}
	if err := f.ai.RecordAIUsage(ctx, f.tenant, theirs.ID, inc); err != nil {
		t.Fatal(err)
	}
	// A provider the authorization has no key for, and an origin of B2.
	openai := inc
	openai.Provider = "openai"
	if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, openai); !errors.Is(err, store.ErrAIUsageKey) {
		t.Fatalf("a provider without a key = %v", err)
	}
	auto := inc
	auto.Origin = "auto"
	if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, auto); err == nil {
		t.Fatal("an automatic job's usage was taken")
	}

	total, err := f.ai.AIMonthUsage(ctx, f.tenant, conn.ID, time.Now())
	if err != nil || total.CostMicrocents != 240_000 || total.ItemsToday != 3 {
		t.Fatalf("total = %+v %v", total, err)
	}
	if last, err := f.ai.AIMonthUsage(ctx, f.tenant, conn.ID, time.Now().AddDate(0, -1, 0)); err != nil || last.CostMicrocents != 0 || last.ItemsToday != 3 {
		t.Fatalf("last month = %+v %v", last, err)
	}
	// Yesterday's items are not today's.
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ai_usage_daily SET day = day - 1 WHERE authorization_id=$1`, conn.ID)
		return err
	})
	if total, err := f.ai.AIMonthUsage(ctx, f.tenant, conn.ID, time.Now().Add(-24*time.Hour)); err != nil || total.ItemsToday != 0 || total.CostMicrocents != 240_000 {
		t.Fatalf("after a day = %+v %v", total, err)
	}

	rows, err := f.ai.AIUsageMonth(ctx, f.tenant, f.owner, false, time.Now().Add(-24*time.Hour))
	if err != nil || len(rows) != 2 {
		t.Fatalf("own rows = %+v %v", rows, err)
	}
	for _, r := range rows {
		if r.AuthorizationID.String() != conn.ID || r.KeychainID != keys["google"] {
			t.Fatalf("row = %+v", r)
		}
	}
	if all, err := f.ai.AIUsageMonth(ctx, f.tenant, f.owner, true, time.Now().Add(-24*time.Hour)); err != nil || len(all) != 3 {
		t.Fatalf("all rows = %+v %v", all, err)
	}

	// A renewal rotating the Google key: the rows written before keep the
	// old key, and the next ones the new.
	rotated := map[string]uuid.UUID{"google": f.keychainItem(ctx, t, f.owner, "google"), "anthropic": keys["anthropic"]}
	f.renewAI(ctx, t, conn.ID, c, rotated, nil)
	if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, inc); err != nil {
		t.Fatal(err)
	}
	var byKey = map[uuid.UUID]int{}
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT keychain_id, sum(items) FROM ai_usage_daily WHERE authorization_id=$1 GROUP BY 1`, conn.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				return err
			}
			byKey[id] = n
		}
		return rows.Err()
	})
	if len(byKey) != 2 || byKey[keys["google"]] != 3 || byKey[rotated["google"]] != 1 {
		t.Fatalf("items by key = %v", byKey)
	}

	// Retention: 400 days after the day, and the keychain's deleted rows 30
	// days after their deletion.
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ai_usage_daily SET day = day - 400 WHERE authorization_id=$1 AND keychain_id=$2`, conn.ID, rotated["google"])
		return err
	})
	gone := f.keychainItem(ctx, t, f.owner, "openai")
	if _, err := f.ai.DeleteKeychainItem(ctx, f.tenant, f.owner, gone); err != nil {
		t.Fatal(err)
	}
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ai_keychain SET deleted_at = now() - interval '31 days' WHERE id=$1`, gone)
		return err
	})
	settled, err := store.SettleAI(ctx, f.pool)
	if err != nil || settled.UsageRows != 1 || settled.KeychainRows != 1 {
		t.Fatalf("settled = %+v %v", settled, err)
	}
}

// renewAI renews an AI authorization as the console and the enclave would,
// with new keys and mutate's changes to the configuration.
func (f *aiFixture) renewAI(ctx context.Context, t *testing.T, id string, old contentConsent, keys map[string]uuid.UUID, mutate func(map[string]any)) contentConsent {
	t.Helper()
	next := f.prepareContent(ctx, t, old.actor)
	next.in.RequestID = requestID(t)
	next.in.ReaderKID = "0f1e2d3c4b5a6978"
	next.in.ExpiresAt = old.in.ExpiresAt
	cfg, err := store.ParseAIConfig(aiConfigFor(t, next, keys, mutate))
	if err != nil {
		t.Fatal(err)
	}
	in := store.RenewMCPConnection{KeyPrefix: next.prefix, ServiceUserID: next.service, ReaderKID: next.in.ReaderKID,
		ReaderPublicKey: next.publicKey, AIConfig: &cfg}
	if _, err := f.conns.Renew(ctx, f.tenant, old.actor, id, in); err != nil {
		t.Fatal(err)
	}
	return next
}

// A renewal may rotate a key and change a model within its provider, with
// fresh tags, and clears the alerts; it may not change a provider, a
// number's functions, the budget's limits or the numbers.
func TestAIRenewal(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	keys := f.aiKeys(ctx, t, f.owner)
	conn, c := f.consentAI(ctx, t, f.owner, keys, nil)
	if err := f.conns.RecordAIAlert(ctx, "enclave", conn.ID, store.AIAlert{Code: "ai_quota", Provider: "google", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := f.aiRow(ctx, t, conn.ID); len(got.Alerts) != 1 || got.Alerts[0].Code != "ai_quota" || got.Alerts[0].Provider != "google" {
		t.Fatalf("alerts = %+v", got.Alerts)
	}

	try := func(keys map[string]uuid.UUID, mutate func(map[string]any)) error {
		next := f.prepareContent(ctx, t, f.owner)
		next.in.RequestID, next.in.ReaderKID, next.in.ExpiresAt = requestID(t), "0f1e2d3c4b5a6978", c.in.ExpiresAt
		cfg, err := store.ParseAIConfig(aiConfigFor(t, next, keys, mutate))
		if err != nil {
			return err
		}
		in := store.RenewMCPConnection{KeyPrefix: next.prefix, ServiceUserID: next.service, ReaderKID: next.in.ReaderKID, ReaderPublicKey: next.publicKey, AIConfig: &cfg}
		if err := f.conns.CheckRenewal(ctx, f.tenant, f.owner, conn.ID, in); err != nil {
			return err
		}
		_, err = f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, in)
		return err
	}
	for name, mutate := range map[string]func(map[string]any){
		"a function's provider changed": func(m map[string]any) {
			m["functions"].(map[string]any)["document"] = map[string]any{"provider": "google", "model": geminiModel}
			delete(m["keys"].(map[string]any), "anthropic")
			rates := m["budget"].(map[string]any)["rates"].(map[string]any)
			delete(rates, "anthropic:"+claudeModel)
		},
		"a function added": func(m map[string]any) {
			m["functions"].(map[string]any)["video"] = map[string]any{"provider": "google", "model": geminiModel}
		},
		"a number's requesters changed": func(m map[string]any) {
			for _, byFeature := range m["features"].(map[string]any) {
				byFeature.(map[string]any)["audio"].(map[string]any)["requesters"] = "readers"
			}
		},
		"a number's language changed": func(m map[string]any) {
			for _, byFeature := range m["features"].(map[string]any) {
				byFeature.(map[string]any)["audio"].(map[string]any)["lang"] = "en"
			}
		},
		"the monthly budget changed": func(m map[string]any) { m["budget"].(map[string]any)["monthly_usd_cents"] = 2000 },
		"the daily items changed":    func(m map[string]any) { m["budget"].(map[string]any)["request_items_per_day"] = 50 },
		"another expiry": func(m map[string]any) {
			m["expires_at"] = time.Now().Add(80 * 24 * time.Hour).UTC().Format(time.RFC3339)
		},
		"another service account": func(m map[string]any) { m["service_user_id"] = uuid.NewString() },
	} {
		if err := try(keys, mutate); !errors.Is(err, store.ErrAIConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A key of another person is refused too.
	admin := f.member(t, "admin")
	if err := try(map[string]uuid.UUID{"google": f.keychainItem(ctx, t, admin, "google"), "anthropic": keys["anthropic"]}, nil); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("another person's key: %v", err)
	}
	// Without a configuration, or a content connection with one.
	next := f.prepareContent(ctx, t, f.owner)
	plain := store.RenewMCPConnection{KeyPrefix: next.prefix, ServiceUserID: next.service, ReaderKID: "0f1e2d3c4b5a6978", ReaderPublicKey: next.publicKey}
	if _, err := f.conns.Renew(ctx, f.tenant, f.owner, conn.ID, plain); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("an AI renewal without ai_config: %v", err)
	}
	content, _ := f.consentContent(ctx, t, f.owner)
	withConfig := plain
	cfg := *c.in.AIConfig
	withConfig.AIConfig = &cfg
	if _, err := f.conns.Renew(ctx, f.tenant, f.owner, content.ID, withConfig); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("a content renewal with ai_config: %v", err)
	}
	// Nothing refused changed the row.
	if got := f.aiRow(ctx, t, conn.ID); len(got.Alerts) != 1 {
		t.Fatalf("a refused renewal cleared the alerts: %+v", got)
	}

	// Rotating a key and changing a model within the provider passes.
	rotated := map[string]uuid.UUID{"google": f.keychainItem(ctx, t, f.owner, "google"), "anthropic": keys["anthropic"]}
	newer := "gemini-4.0-pro"
	if err := try(rotated, func(m map[string]any) {
		m["functions"].(map[string]any)["audio"] = map[string]any{"provider": "google", "model": newer}
		rates := m["budget"].(map[string]any)["rates"].(map[string]any)
		delete(rates, "google:"+geminiModel)
		rates["google:"+newer] = map[string]any{"in": 125, "out": 1000, "sec": 0}
	}); err != nil {
		t.Fatalf("a rotation: %v", err)
	}
	got := f.aiRow(ctx, t, conn.ID)
	var stored map[string]any
	if err := json.Unmarshal(got.Config, &stored); err != nil {
		t.Fatal(err)
	}
	if got.Status != "active" || len(got.Alerts) != 0 ||
		stored["functions"].(map[string]any)["audio"].(map[string]any)["model"] != newer ||
		stored["keys"].(map[string]any)["google"].(map[string]any)["keychain_id"] != rotated["google"].String() {
		t.Fatalf("renewed = %+v %s", got, got.Config)
	}
	if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
		t.Fatalf("the old service account kept %+v", tr)
	}
	// Alerts are kept only on live AI rows of the reader.
	if err := f.conns.RecordAIAlert(ctx, "staging", conn.ID, store.AIAlert{Code: "ai_quota", At: time.Now()}); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("another reader's alert = %v", err)
	}
	if err := f.conns.RecordAIAlert(ctx, "enclave", content.ID, store.AIAlert{Code: "ai_quota", At: time.Now()}); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("a content row's alert = %v", err)
	}
	if err := f.conns.RecordAIAlert(ctx, "enclave", conn.ID, store.AIAlert{Code: "ai_bored", At: time.Now()}); err == nil {
		t.Fatal("an unknown alert was kept")
	}
}

// Pausing and narrowing are for the creator, an owner or an admin; taking
// a pause off and undoing a narrowing are the creator's.
func TestAIControls(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	admin := f.member(t, "admin")
	member := f.member(t, "member")
	conn, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	yes, no := true, false
	cap500, cap900, cap300 := 500, 900, 300
	set := func(actor uuid.UUID, in store.AIControls) (store.AIAuthorization, error) {
		return f.conns.SetAIControls(ctx, f.tenant, actor, conn.ID, in)
	}
	forbidden := func(t *testing.T, actor uuid.UUID, in store.AIControls) {
		t.Helper()
		if _, err := set(actor, in); !errors.Is(err, store.ErrMembershipForbidden) {
			t.Fatalf("%+v by %s = %v", in, actor, err)
		}
	}
	forbidden(t, member, store.AIControls{Paused: &yes})
	got, err := set(admin, store.AIControls{Paused: &yes, Off: &[]string{"document", "audio", "document"}, CapSet: true, Cap: &cap500})
	if err != nil || got.PausedAt == nil || strings.Join(got.Off, ",") != "audio,document" || got.CapCents == nil || *got.CapCents != 500 {
		t.Fatalf("narrowed by an admin = %+v %v", got, err)
	}
	// Narrowing further is still the admin's; widening is not.
	if got, err := set(admin, store.AIControls{CapSet: true, Cap: &cap300}); err != nil || *got.CapCents != 300 {
		t.Fatalf("lowered = %+v %v", got, err)
	}
	forbidden(t, admin, store.AIControls{Paused: &no})
	forbidden(t, admin, store.AIControls{Off: &[]string{"audio"}})
	forbidden(t, admin, store.AIControls{CapSet: true, Cap: &cap900})
	forbidden(t, admin, store.AIControls{CapSet: true})
	// Pausing what is paused, and switching off what is off, are not
	// widening.
	if _, err := set(admin, store.AIControls{Paused: &yes, Off: &[]string{"audio", "document", "video"}}); err != nil {
		t.Fatal(err)
	}
	// The creator undoes it all.
	got, err = set(f.owner, store.AIControls{Paused: &no, Off: &[]string{}, CapSet: true})
	if err != nil || got.PausedAt != nil || len(got.Off) != 0 || got.CapCents != nil {
		t.Fatalf("undone = %+v %v", got, err)
	}
	if _, err := set(f.owner, store.AIControls{Off: &[]string{"translate"}}); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("an unknown function = %v", err)
	}
	if _, err := set(f.owner, store.AIControls{CapSet: true, Cap: new(int)}); !errors.Is(err, store.ErrAIConfig) {
		t.Fatalf("a cap of zero = %v", err)
	}
	// Another workspace's id, and an ended one.
	if _, err := f.conns.SetAIControls(ctx, f.tenant, f.owner, uuid.NewString(), store.AIControls{Paused: &yes}); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("an unknown id = %v", err)
	}
	if _, _, err := f.conns.RevokeAI(ctx, f.tenant, member, conn.ID, false); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("a member revoked it: %v", err)
	}
	if reader, _, err := f.conns.RevokeAI(ctx, f.tenant, admin, conn.ID, false); err != nil || reader != "enclave" {
		t.Fatalf("an admin's revocation = %q %v", reader, err)
	}
	if _, err := set(f.owner, store.AIControls{Paused: &yes}); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("an ended authorization = %v", err)
	}
	got = f.aiRow(ctx, t, conn.ID)
	if got.Status != "revoked" || got.RevokeReason != store.ReasonConsole {
		t.Fatalf("revoked = %+v", got)
	}
	// Listing: a member sees their own only.
	if own, err := f.conns.AIAuthorizations(ctx, f.tenant, member, false); err != nil || len(own) != 0 {
		t.Fatalf("a member's list = %+v %v", own, err)
	}
	// The creator revokes their own even as a member.
	f.ownerReads(ctx, t, admin, f.device)
	theirs, _ := f.consentAI(ctx, t, admin, f.aiKeys(ctx, t, admin), nil)
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET role='member' WHERE tenant_id=$1 AND user_id=$2`, f.tenant, admin)
		return err
	})
	if _, err := f.conns.SetAIControls(ctx, f.tenant, admin, theirs.ID, store.AIControls{Paused: &yes}); err != nil {
		t.Fatalf("the creator's pause = %v", err)
	}
	if _, _, err := f.conns.RevokeAI(ctx, f.tenant, admin, theirs.ID, false); err != nil {
		t.Fatalf("the creator's revocation = %v", err)
	}
}

// An AI authorization ends as a content connection does when its creator
// leaves the workspace.
func TestAIConnectionEndsWithItsCreator(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	admin := f.member(t, "admin")
	f.ownerReads(ctx, t, admin, f.device)
	conn, c := f.consentAI(ctx, t, admin, f.aiKeys(ctx, t, admin), nil)
	if err := f.users.RemoveMember(ctx, f.tenant, f.owner, admin); err != nil {
		t.Fatal(err)
	}
	if got := f.aiRow(ctx, t, conn.ID); got.Status != "revoked" || got.RevokeReason != store.ReasonMemberRemoved {
		t.Fatalf("row = %+v", got)
	}
	if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
		t.Fatalf("the service account kept %+v", tr)
	}
}
