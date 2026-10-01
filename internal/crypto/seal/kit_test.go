package seal_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"testing/cryptotest"

	"github.com/google/uuid"
	kit "github.com/thehappieco/kit/seal"
	kitvectors "github.com/thehappieco/kit/vectors"

	"whatserver2/internal/crypto/seal"
)

// The shared kit's vectors, run through this package rather than the kit's
// own API. The kit proves its envelope reproduces what this package sealed
// before the move; these prove the names the server still calls bind Wappie's
// profile (the magic, the label, the kind names, the rows) and pass their
// arguments in the right order, over every kind, epoch and refusal the
// vectors hold. The files come from the kit version go.mod requires.

type kitVectorFile struct {
	Format      string `json:"format"`
	GeneratedBy struct {
		Toolchain string `json:"toolchain"`
	} `json:"generated_by"`
	Keys map[string]struct {
		PrivateKey string `json:"private_key_b64"`
		PublicKey  string `json:"public_key_b64"`
	} `json:"keys"`
	Cases []struct {
		ID    string          `json:"id"`
		Op    string          `json:"op"`
		Langs []string        `json:"langs"`
		In    json.RawMessage `json:"in"`
		Out   json.RawMessage `json:"out"`
		Error string          `json:"error"`
	} `json:"cases"`
}

func loadKitVectors(t *testing.T, path string) kitVectorFile {
	t.Helper()
	raw, err := fs.ReadFile(kitvectors.FS, path)
	if err != nil {
		t.Fatal(err)
	}
	var f kitVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if f.Format != "thehappieco-kit-vectors/1" || len(f.Cases) == 0 {
		t.Fatalf("%s: format %q with %d cases", path, f.Format, len(f.Cases))
	}
	return f
}

// kitErrorCode names an error the way the vectors do.
func kitErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, seal.ErrShort):
		return "short"
	case errors.Is(err, seal.ErrMagic):
		return "magic"
	case errors.Is(err, seal.ErrVersion):
		return "version"
	case errors.Is(err, seal.ErrSuite):
		return "suite"
	case errors.Is(err, seal.ErrMode):
		return "mode"
	case errors.Is(err, seal.ErrAuthentication):
		return "authentication"
	case errors.Is(err, kit.ErrKeyMismatch):
		return "key_mismatch"
	case errors.Is(err, kit.ErrInvalidKey):
		return "invalid_key"
	}
	return "unclassified: " + err.Error()
}

type kitSealIn struct {
	Key        string `json:"key"`
	Kind       int    `json:"kind"`
	Tenant     string `json:"tenant"`
	Device     string `json:"device"`
	Row        string `json:"row"`
	User       string `json:"user"`
	Epoch      uint16 `json:"epoch"`
	ID         uint32 `json:"id"`
	Plaintext  string `json:"plaintext_b64"`
	Envelope   string `json:"envelope_b64"`
	Sealed     string `json:"sealed_b64"`
	Seed       uint64 `json:"seed"`
	ContentKey struct {
		Tenant string `json:"tenant"`
		Device string `json:"device"`
		ID     uint32 `json:"id"`
		Sealed string `json:"sealed_b64"`
	} `json:"content_key"`
	Connection  string            `json:"connection"`
	Draft       string            `json:"draft"`
	Reply       *string           `json:"reply"`
	ChatKey     string            `json:"chat_key"`
	StoreTenant string            `json:"store_tenant"`
	Steps       []json.RawMessage `json:"steps"`
}

type kitSealOut struct {
	Name       string `json:"name"`
	Row        string `json:"row"`
	Envelope   string `json:"envelope_b64"`
	Plaintext  string `json:"plaintext_b64"`
	Sealed     string `json:"sealed_b64"`
	Epoch      uint16 `json:"epoch"`
	ID         uint32 `json:"id"`
	PrivateKey string `json:"private_key_b64"`
	PublicKey  string `json:"public_key_b64"`
}

// notWrapped are the kit's own derivations this package does not expose: the
// AAD, the HPKE info and the bare row. The kit's tests run them; every
// envelope below depends on them, so a wrong one fails here too.
var notWrapped = map[string]bool{"seal.info": true, "seal.aad": true, "seal.row": true}

func TestKitSealVectors(t *testing.T) {
	for _, path := range []string{"wappie/golden/seal-go.json", "wappie/golden/seal-ts.json"} {
		f := loadKitVectors(t, path)
		pub := map[string]seal.PublicKey{}
		priv := map[string]seal.PrivateKey{}
		for name, k := range f.Keys {
			p, err := seal.ParsePrivateKey(kitB64(t, k.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			if pub[name], err = seal.ParsePublicKey(kitB64(t, k.PublicKey)); err != nil {
				t.Fatal(err)
			}
			priv[name] = p
		}
		// Seeded seals replay only on the toolchain that recorded them: Go
		// does not promise to draw randomness the same way across releases.
		replays := runtime.Version() == f.GeneratedBy.Toolchain
		t.Run(path, func(t *testing.T) {
			ran := 0
			for _, c := range f.Cases {
				if notWrapped[c.Op] || len(c.Langs) > 0 && !slices.Contains(c.Langs, "go") {
					continue
				}
				ran++
				t.Run(c.ID, func(t *testing.T) {
					var in kitSealIn
					var out kitSealOut
					kitDecode(t, c.In, &in)
					if c.Error == "" {
						kitDecode(t, c.Out, &out)
					}
					runKitSealCase(t, c.Op, c.Error, in, out, c.Out, pub, priv, replays)
				})
			}
			if ran == 0 {
				t.Fatal("no case ran")
			}
		})
	}
}

func runKitSealCase(t *testing.T, op, wantErr string, in kitSealIn, out kitSealOut, rawOut json.RawMessage,
	pub map[string]seal.PublicKey, priv map[string]seal.PrivateKey, replays bool) {
	u := func(s string) uuid.UUID { return uuid.MustParse(s) }
	b := func(s string) []byte { return kitB64(t, s) }
	kind := seal.Kind(in.Kind)
	check := func(err error) {
		t.Helper()
		if got := kitErrorCode(err); got != wantErr {
			t.Errorf("error %q, want %q", got, wantErr)
		}
	}
	switch op {
	case "seal.generate_key_pair":
		if !replays {
			t.Skip("the key pair replays only on the toolchain that recorded it")
		}
		cryptotest.SetGlobalRandom(t, in.Seed)
		p, k, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := k.Bytes()
		if !bytes.Equal(raw, b(out.PrivateKey)) || !bytes.Equal(p.Bytes(), b(out.PublicKey)) {
			t.Error("the replayed key pair differs")
		}
	case "seal.kind_name":
		if got := kind.String(); got != out.Name {
			t.Errorf("name %q, want %q", got, out.Name)
		}
	case "seal.content_key_row":
		if got := seal.ContentKeyRow(u(in.Tenant), u(in.Device), in.ID).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "seal.grant_row":
		if got := seal.GrantRow(u(in.Tenant), u(in.Device), u(in.User), in.Epoch).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "wappie.draft_row":
		var reply *uuid.UUID
		if in.Reply != nil {
			r := u(*in.Reply)
			reply = &r
		}
		if got := seal.DraftRow(u(in.Tenant), u(in.Device), u(in.Connection), u(in.Draft), reply, in.ChatKey).String(); got != out.Row {
			t.Errorf("row %s, want %s", got, out.Row)
		}
	case "seal.seal_direct":
		if wantErr != "" {
			_, err := seal.SealDirect(pub[in.Key], kind, u(in.Tenant), u(in.Row), in.Epoch, b(in.Plaintext))
			check(err)
			return
		}
		got, err := seal.OpenDirect(priv[in.Key], kind, u(in.Tenant), u(in.Row), b(out.Envelope))
		if err != nil || !bytes.Equal(got, b(in.Plaintext)) {
			t.Fatalf("the recorded envelope does not open: %v", err)
		}
		if in.Seed == 0 || !replays {
			return // sealed by TypeScript, or recorded on another toolchain
		}
		cryptotest.SetGlobalRandom(t, in.Seed)
		env, err := seal.SealDirect(pub[in.Key], kind, u(in.Tenant), u(in.Row), in.Epoch, b(in.Plaintext))
		if err != nil || !bytes.Equal(env, b(out.Envelope)) {
			t.Errorf("the replayed envelope differs: %v", err)
		}
	case "seal.open_direct":
		got, err := seal.OpenDirect(priv[in.Key], kind, u(in.Tenant), u(in.Row), b(in.Envelope))
		if wantErr != "" {
			check(err)
		} else if err != nil || !bytes.Equal(got, b(out.Plaintext)) {
			t.Errorf("opened to %x, %v", got, err)
		}
	case "seal.new_content_key":
		ck, err := seal.OpenContentKey(priv[in.Key], u(in.Tenant), u(in.Device), in.ID, b(out.Sealed))
		if err != nil || ck.ID != in.ID || ck.Epoch != in.Epoch {
			t.Fatalf("the recorded content key does not open as %d/%d: %v", in.ID, in.Epoch, err)
		}
		if !replays {
			return
		}
		cryptotest.SetGlobalRandom(t, in.Seed)
		fresh, err := seal.NewContentKey(pub[in.Key], u(in.Tenant), u(in.Device), in.Epoch, in.ID)
		if err != nil || !bytes.Equal(fresh.Sealed, b(out.Sealed)) {
			t.Errorf("the replayed content key differs: %v", err)
		}
	case "seal.open_content_key":
		ck, err := seal.OpenContentKey(priv[in.Key], u(in.Tenant), u(in.Device), in.ID, b(in.Sealed))
		if wantErr != "" {
			check(err)
		} else if err != nil || ck.Epoch != out.Epoch {
			t.Errorf("content key: %v", err)
		}
	case "seal.seal_batch", "seal.open_batch":
		ck, err := seal.OpenContentKey(priv[in.Key], u(in.ContentKey.Tenant), u(in.ContentKey.Device), in.ContentKey.ID, b(in.ContentKey.Sealed))
		if err != nil {
			t.Fatal(err)
		}
		if op == "seal.open_batch" {
			got, err := ck.Open(kind, u(in.Tenant), u(in.Row), b(in.Envelope))
			if wantErr != "" {
				check(err)
			} else if err != nil || !bytes.Equal(got, b(out.Plaintext)) {
				t.Errorf("opened to %x, %v", got, err)
			}
			return
		}
		got, err := ck.Open(kind, u(in.Tenant), u(in.Row), b(out.Envelope))
		if err != nil || !bytes.Equal(got, b(in.Plaintext)) {
			t.Fatalf("the recorded envelope does not open: %v", err)
		}
		if !replays {
			return
		}
		cryptotest.SetGlobalRandom(t, in.Seed)
		env, err := ck.Seal(kind, u(in.Tenant), u(in.Row), b(in.Plaintext))
		if err != nil || !bytes.Equal(env, b(out.Envelope)) {
			t.Errorf("the replayed envelope differs: %v", err)
		}
	case "seal.content_key_id":
		id, epoch, err := seal.ContentKeyID(b(in.Envelope))
		if wantErr != "" {
			check(err)
		} else if err != nil || id != out.ID || epoch != out.Epoch {
			t.Errorf("id %d epoch %d: %v", id, epoch, err)
		}
	case "seal.sealer":
		runKitSealer(t, in, rawOut, pub[in.Key], priv[in.Key], replays)
	default:
		t.Errorf("op %q is not handled", op)
	}
}

type kitStore struct {
	next   uint32
	keys   map[uint32][]byte
	closed []uint32
}

func (m *kitStore) CreateContentKey(_ context.Context, _, _ uuid.UUID, _ uint16, fn func(uint32) ([]byte, error)) (uint32, error) {
	m.next++
	sealed, err := fn(m.next)
	if err != nil {
		m.next--
		return 0, err
	}
	m.keys[m.next] = sealed
	return m.next, nil
}

func (m *kitStore) CountSeal(context.Context, uuid.UUID, uuid.UUID, uint32, int) error { return nil }

func (m *kitStore) CloseContentKey(_ context.Context, _, _ uuid.UUID, id uint32) error {
	m.closed = append(m.closed, id)
	return nil
}

// runKitSealer opens everything a recorded Sealer produced and, on the
// recording toolchain, replays the sequence through NewSealerWithArchiveTenant:
// the store's tenant and the archive tenant are separate arguments, and
// swapping them would still seal, under the wrong namespace.
func runKitSealer(t *testing.T, in kitSealIn, rawOut json.RawMessage, pub seal.PublicKey, priv seal.PrivateKey, replays bool) {
	type value struct {
		Kind      int    `json:"kind"`
		Plaintext string `json:"plaintext_b64"`
		Envelope  string `json:"envelope_b64"`
	}
	type step struct {
		Action    string  `json:"action"`
		Kind      int     `json:"kind"`
		Row       string  `json:"row"`
		Plaintext string  `json:"plaintext_b64"`
		Values    []value `json:"values"`
		KeyID     uint32  `json:"key_id"`
		Envelope  string  `json:"envelope_b64"`
		Envelopes []value `json:"envelopes"`
	}
	var out struct {
		Steps       []step `json:"steps"`
		ContentKeys []struct {
			ID     uint32 `json:"id"`
			Sealed string `json:"sealed_b64"`
		} `json:"content_keys"`
		Closed []uint32 `json:"closed"`
	}
	kitDecode(t, rawOut, &out)
	steps := make([]step, len(in.Steps))
	for i, raw := range in.Steps {
		kitDecode(t, raw, &steps[i])
	}
	namespace, device := uuid.MustParse(in.Tenant), uuid.MustParse(in.Device)
	stored := map[uint32][]byte{}
	for _, k := range out.ContentKeys {
		stored[k.ID] = kitB64(t, k.Sealed)
	}
	open := func(keyID uint32, kind int, row, envelope string) []byte {
		ck, err := seal.OpenContentKey(priv, namespace, device, keyID, stored[keyID])
		if err != nil {
			t.Fatal(err)
		}
		pt, err := ck.Open(seal.Kind(kind), namespace, uuid.MustParse(row), kitB64(t, envelope))
		if err != nil {
			t.Fatal(err)
		}
		return pt
	}
	for i, s := range steps {
		switch s.Action {
		case "seal":
			if got := open(out.Steps[i].KeyID, s.Kind, s.Row, out.Steps[i].Envelope); !bytes.Equal(got, kitB64(t, s.Plaintext)) {
				t.Errorf("step %d opened to %q", i, got)
			}
		case "seal_all":
			for j, v := range s.Values {
				if got := open(out.Steps[i].KeyID, v.Kind, s.Row, out.Steps[i].Envelopes[j].Envelope); !bytes.Equal(got, kitB64(t, v.Plaintext)) {
					t.Errorf("step %d value %d opened to %q", i, j, got)
				}
			}
		}
	}
	if !replays {
		return
	}
	cryptotest.SetGlobalRandom(t, in.Seed)
	store := &kitStore{keys: map[uint32][]byte{}}
	s, err := seal.NewSealerWithArchiveTenant(uuid.MustParse(in.StoreTenant), namespace, device, pub, in.Epoch, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, st := range steps {
		want := out.Steps[i]
		switch st.Action {
		case "seal":
			env, err := s.Seal(ctx, seal.Kind(st.Kind), uuid.MustParse(st.Row), kitB64(t, st.Plaintext))
			if err != nil || !bytes.Equal(env, kitB64(t, want.Envelope)) || s.CurrentKeyID() != want.KeyID {
				t.Errorf("step %d: the replayed envelope differs: %v", i, err)
			}
		case "seal_all":
			values := map[seal.Kind][]byte{}
			for _, v := range st.Values {
				values[seal.Kind(v.Kind)] = kitB64(t, v.Plaintext)
			}
			sealed, keyID, err := s.SealAll(ctx, uuid.MustParse(st.Row), values)
			if err != nil || keyID != want.KeyID {
				t.Fatalf("step %d: %v", i, err)
			}
			for _, v := range want.Envelopes {
				if !bytes.Equal(sealed[seal.Kind(v.Kind)], kitB64(t, v.Envelope)) {
					t.Errorf("step %d: the replayed %s differs", i, seal.Kind(v.Kind))
				}
			}
		case "rotate":
			if err := s.Rotate(ctx); err != nil || s.CurrentKeyID() != want.KeyID {
				t.Errorf("step %d: rotate: %v", i, err)
			}
		}
	}
	for _, k := range out.ContentKeys {
		if !bytes.Equal(store.keys[k.ID], kitB64(t, k.Sealed)) {
			t.Errorf("content key %d differs", k.ID)
		}
	}
	if len(store.keys) != len(out.ContentKeys) || len(store.closed) != len(out.Closed) {
		t.Errorf("stored %d keys and closed %v", len(store.keys), store.closed)
	}
}

// TestFixturesMatchTheKit holds Wappie's own fixtures to the copies the kit
// took of them, and the TypeScript client's copies of the kit's vectors to
// the kit version Go imports. A fixture regenerated here (go test -update
// rewrites both seal files with fresh keys) fails this rather than drifting
// silently from the vectors the kit proves itself against.
func TestFixturesMatchTheKit(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	same := func(local, inKit string) {
		t.Helper()
		got, err := os.ReadFile(filepath.Join(root, local))
		if err != nil {
			t.Fatal(err)
		}
		want, err := fs.ReadFile(kitvectors.FS, inKit)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the kit's %s", local, inKit)
		}
	}
	for local, inKit := range map[string]string{
		"internal/crypto/seal/testdata/vectors.json":       "wappie/legacy/seal-vectors.json",
		"internal/crypto/seal/testdata/draft-vectors.json": "wappie/legacy/draft-vectors.json",
		"internal/wsapi/testdata/frames.json":              "wappie/legacy/frames.json",
		"packages/client/testdata/browser-grant.json":      "wappie/legacy/browser-grant.json",
		"packages/client/testdata/node-draft.json":         "wappie/legacy/node-draft.json",
		"packages/client/testdata/node-derived.json":       "wappie/legacy/node-derived.json",
	} {
		same(local, inKit)
	}
	copies, err := filepath.Glob(filepath.Join(root, "packages/client/test/kit/*.json"))
	if err != nil || len(copies) == 0 {
		t.Fatalf("no copies of the kit's vectors in packages/client/test/kit: %v", err)
	}
	for _, path := range copies {
		name := filepath.Base(path)
		same(filepath.Join("packages/client/test/kit", name), "wappie/golden/"+name)
	}
}

func kitB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func kitDecode(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}
