package seal_test

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

// The web client opens the archive in the browser, which means a second
// implementation of this format written in another language. A reimplementation
// that drops the AAD binding, or gets the HPKE labels subtly wrong, still opens
// every value it seals itself — the bug only appears against blobs this package
// produced, which is exactly when it is too late.
//
// So the format is pinned as data. Go writes the file, Go re-reads it, and the
// TypeScript suite in web/ reads the same file. A change to the wire format
// fails here first and has to be regenerated deliberately:
//
//	go test ./internal/crypto/seal -run Vectors -update
//
// The private key below is fixture material, generated for this file and used
// for nothing else. It is checked in on purpose: without it the vectors cannot
// be opened, which is the whole point of having them.
var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

type vectors struct {
	Note   string `json:"note"`
	Tenant string `json:"tenant"`
	// Device, because the archive key is per device: the content key's row
	// identity is derived from it, so a reader that ignored it would fail
	// authentication on every value with the correct key in hand.
	Device     string `json:"device"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`

	ContentKey struct {
		ID     uint32 `json:"id"`
		Epoch  uint16 `json:"epoch"`
		Sealed string `json:"sealed"`
	} `json:"content_key"`

	Batch  []vector `json:"batch"`
	Direct []vector `json:"direct"`

	// Grant is a device's archive key sealed to one account, with everything
	// the row derivation needs. A browser reimplements that derivation, and
	// getting it wrong fails authentication with the right key in hand.
	Grant struct {
		User   string `json:"user"`
		Epoch  uint16 `json:"epoch"`
		Sealed string `json:"sealed"`
		// DeviceKey is what opening it must produce: the archive private key
		// of the device named at the top of this file.
		DeviceKey string `json:"device_key"`
	} `json:"grant"`

	Negatives []negative `json:"negatives"`
}

// vector is one value that must open, and what it must open to.
type vector struct {
	Kind      byte   `json:"kind"`
	KindName  string `json:"kind_name"`
	Row       string `json:"row"`
	Sealed    string `json:"sealed"`
	Plaintext string `json:"plaintext"`
	Note      string `json:"note,omitempty"`
}

// negative is a value that must NOT open. Each one is a real attack the
// binding exists to stop, and an implementation missing that binding opens it
// happily.
type negative struct {
	Why    string `json:"why"`
	Mode   string `json:"mode"` // batch or direct
	Kind   byte   `json:"kind"`
	Row    string `json:"row"`
	Sealed string `json:"sealed"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding fixture bytes: %v", err)
	}
	return b
}

func TestVectors(t *testing.T) {
	if *update {
		writeVectors(t)
	}

	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("reading the vectors: %v (run with -update to create them)", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing the vectors: %v", err)
	}

	tenant := uuid.MustParse(v.Tenant)
	device := uuid.MustParse(v.Device)
	priv, err := seal.ParsePrivateKey(unb64(t, v.PrivateKey))
	if err != nil {
		t.Fatalf("parsing the fixture private key: %v", err)
	}

	ck, err := seal.OpenContentKey(priv, tenant, device, v.ContentKey.ID, unb64(t, v.ContentKey.Sealed))
	if err != nil {
		t.Fatalf("opening the content key: %v", err)
	}

	for _, want := range v.Batch {
		t.Run("batch/"+want.KindName, func(t *testing.T) {
			got, err := ck.Open(seal.Kind(want.Kind), tenant, uuid.MustParse(want.Row),
				unb64(t, want.Sealed))
			if err != nil {
				t.Fatalf("opening %s: %v", want.KindName, err)
			}
			if string(got) != string(unb64(t, want.Plaintext)) {
				t.Fatalf("%s opened to %q, want %q", want.KindName, got, unb64(t, want.Plaintext))
			}
		})
	}

	for _, want := range v.Direct {
		t.Run("direct/"+want.KindName, func(t *testing.T) {
			got, err := seal.OpenDirect(priv, seal.Kind(want.Kind), tenant,
				uuid.MustParse(want.Row), unb64(t, want.Sealed))
			if err != nil {
				t.Fatalf("opening %s: %v", want.KindName, err)
			}
			if string(got) != string(unb64(t, want.Plaintext)) {
				t.Fatalf("%s opened to %q, want %q", want.KindName, got, unb64(t, want.Plaintext))
			}
		})
	}

	t.Run("grant", func(t *testing.T) {
		user := uuid.MustParse(v.Grant.User)
		got, err := seal.OpenDirect(priv, seal.KindDeviceGrant, tenant,
			seal.GrantRow(tenant, device, user, v.Grant.Epoch), unb64(t, v.Grant.Sealed))
		if err != nil {
			t.Fatalf("the grant did not open: %v", err)
		}
		if string(got) != string(unb64(t, v.Grant.DeviceKey)) {
			t.Fatal("the grant opened to something other than the device key")
		}

		// And not for somebody else. A grant issued to one account must not be
		// usable as another's, which is what binding the user into the row buys.
		if _, err := seal.OpenDirect(priv, seal.KindDeviceGrant, tenant,
			seal.GrantRow(tenant, device, uuid.New(), v.Grant.Epoch),
			unb64(t, v.Grant.Sealed)); err == nil {
			t.Fatal("a grant opened while claiming to belong to another account")
		}
	})

	for _, bad := range v.Negatives {
		t.Run("refuses/"+bad.Why, func(t *testing.T) {
			var err error
			switch bad.Mode {
			case "direct":
				_, err = seal.OpenDirect(priv, seal.Kind(bad.Kind), tenant,
					uuid.MustParse(bad.Row), unb64(t, bad.Sealed))
			default:
				_, err = ck.Open(seal.Kind(bad.Kind), tenant, uuid.MustParse(bad.Row),
					unb64(t, bad.Sealed))
			}
			if err == nil {
				t.Fatalf("%s: opened, and it must not", bad.Why)
			}
		})
	}
}

// writeVectors regenerates the fixture. Separate from the assertions above so
// that running the suite normally can never overwrite what it is checking.
func writeVectors(t *testing.T) {
	t.Helper()

	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.New()
	device := uuid.New()

	const epoch = 1
	const keyID = 7
	ck, err := seal.NewContentKey(pub, tenant, device, epoch, keyID)
	if err != nil {
		t.Fatal(err)
	}

	v := vectors{
		Note: "Generated by go test ./internal/crypto/seal -run Vectors -update. " +
			"The private key is fixture material and protects nothing.",
		Tenant:     tenant.String(),
		Device:     device.String(),
		PrivateKey: b64(privBytes),
		PublicKey:  b64(pub.Bytes()),
	}
	v.ContentKey.ID, v.ContentKey.Epoch, v.ContentKey.Sealed = keyID, epoch, b64(ck.Sealed)

	// One value per kind a reader actually meets, with a plaintext that would
	// survive a round trip through a naive implementation: multi-byte UTF-8,
	// an emoji, JSON, and raw bytes that are not text at all.
	type sample struct {
		kind  seal.Kind
		name  string
		value []byte
		note  string
	}
	samples := []sample{
		{seal.KindBody, "body", []byte("olá, tudo bem? — acentuação e emoji 🇧🇷👋"),
			"a message body, deliberately not ASCII"},
		{seal.KindPayload, "payload",
			[]byte(`{"location":{"lat":-23.5505,"lon":-46.6333,"name":"São Paulo"}}`),
			"structured content, parsed with domain.ParsePayload"},
		{seal.KindMediaKey, "media_key", mediaKeyFixture(), "the 32 bytes that decrypt an attachment"},
		{seal.KindThumbnail, "thumbnail", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46},
			"binary, and not valid UTF-8"},
		{seal.KindContactName, "contact_name", []byte("Grupo da Serra"), ""},
		{seal.KindPushName, "push_name", []byte("Felipe"), ""},
		{seal.KindFullName, "full_name", []byte("Felipe Restum"), ""},
		{seal.KindBusinessName, "business_name", []byte("Padaria do Zé Ltda"), ""},
		{seal.KindAvatar, "avatar", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			"a profile picture, sealed by this server rather than stored as received"},
	}

	rows := make([]uuid.UUID, len(samples))
	for i, s := range samples {
		rows[i] = uuid.New()
		sealed, err := ck.Seal(s.kind, tenant, rows[i], s.value)
		if err != nil {
			t.Fatal(err)
		}
		v.Batch = append(v.Batch, vector{
			Kind: byte(s.kind), KindName: s.name, Row: rows[i].String(),
			Sealed: b64(sealed), Plaintext: b64(s.value), Note: s.note,
		})
	}

	// Direct mode carries the low-volume payloads. The real one is a key grant:
	// this device's archive private key, sealed to one account's public key.
	//
	// The fixture key stands in for both here — it is the account key opening a
	// grant addressed to it — which is enough to pin the row derivation, and
	// the row derivation is the part a second implementation gets wrong.
	user := uuid.New()
	deviceKey := make([]byte, seal.KeyLen)
	for i := range deviceKey {
		deviceKey[i] = byte(0xA0 + i)
	}
	grant, err := seal.SealDirect(pub, seal.KindDeviceGrant, tenant,
		seal.GrantRow(tenant, device, user, epoch), epoch, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	v.Grant.User, v.Grant.Epoch = user.String(), epoch
	v.Grant.Sealed, v.Grant.DeviceKey = b64(grant), b64(deviceKey)

	v.Direct = append(v.Direct, vector{
		Kind: byte(seal.KindDeviceGrant), KindName: "device_grant",
		Row:    seal.GrantRow(tenant, device, user, epoch).String(),
		Sealed: b64(grant), Plaintext: b64(deviceKey),
		Note: "direct mode: one asymmetric operation, used only for low-volume values",
	})

	// The negatives. Each is an attacker with write access to Postgres moving
	// a blob somewhere it does not belong.
	body := v.Batch[0]
	v.Negatives = []negative{
		{
			Why:  "row_moved",
			Mode: "batch", Kind: byte(seal.KindBody),
			Row: uuid.New().String(), Sealed: body.Sealed,
		},
		{
			Why:  "kind_swapped",
			Mode: "batch", Kind: byte(seal.KindThumbnail),
			Row: body.Row, Sealed: body.Sealed,
		},
		{
			Why:  "header_bit_flipped",
			Mode: "batch", Kind: byte(seal.KindBody),
			Row: body.Row, Sealed: b64(flipEpoch(unb64(t, body.Sealed))),
		},
		{
			Why:  "ciphertext_bit_flipped",
			Mode: "batch", Kind: byte(seal.KindBody),
			Row: body.Row, Sealed: b64(flipLast(unb64(t, body.Sealed))),
		},
		{
			Why:  "direct_row_moved",
			Mode: "direct", Kind: byte(seal.KindDeviceGrant),
			Row: uuid.New().String(), Sealed: b64(grant),
		},
	}

	if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", vectorsPath)
}

// mediaKeyFixture is a fixed 32 bytes standing in for a WhatsApp mediaKey.
func mediaKeyFixture() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

// flipEpoch alters the epoch in the clear header. The AAD covers the header, so
// an implementation that authenticates the payload but not the prefix accepts
// this — which is the bug the header was folded into the AAD to prevent.
func flipEpoch(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[6] ^= 0x01
	return out
}

func flipLast(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 0x01
	return out
}
