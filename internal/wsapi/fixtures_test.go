package wsapi

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

// Frames as a browser meets them, sealed for real.
//
// internal/crypto/seal/testdata/vectors.json proves the TypeScript can open
// what Go sealed. It cannot prove the client asks for the *right* row and the
// right kind: a message body is bound to the message uid, a chat name to the
// chat uid, a contact name to the contact uid, and a file name — confusingly —
// under the contact-name kind. Get any of those wrong and every value comes
// back as tampered, with the correct key in hand and nothing to point at.
//
// So the bindings are pinned as data too, in the shape the wire actually
// carries: whole frames, marshalled by the same structs the server sends.
//
//	go test ./internal/wsapi -run Fixtures -update
var updateFixtures = flag.Bool("update", false, "regenerate testdata/frames.json")

const framesPath = "testdata/frames.json"

type frames struct {
	Note       string `json:"note"`
	Tenant     string `json:"tenant"`
	Device     string `json:"device"`
	PrivateKey string `json:"private_key"`

	ContentKey struct {
		ID     uint32 `json:"id"`
		Sealed []byte `json:"sealed"`
	} `json:"content_key"`

	Message  SealedMessage  `json:"message"`
	Expected expectedValues `json:"expected"`

	Chat        ChatSummary    `json:"chat"`
	ChatName    string         `json:"chat_name"`
	Contact     ContactSummary `json:"contact"`
	ContactName struct {
		Push     string `json:"push"`
		Full     string `json:"full"`
		Business string `json:"business"`
	} `json:"contact_names"`
	Avatar      Avatar `json:"avatar"`
	AvatarBytes []byte `json:"avatar_bytes"`

	// Relocated is the same message with its body swapped for one sealed
	// against a different row. Opening it must fail.
	Relocated SealedMessage `json:"relocated"`
}

type expectedValues struct {
	Body      string `json:"body"`
	Payload   string `json:"payload"`
	MediaKey  []byte `json:"media_key"`
	Thumbnail []byte `json:"thumbnail"`
	FileName  string `json:"file_name"`
}

func TestFixtures(t *testing.T) {
	if *updateFixtures {
		writeFrames(t)
	}

	raw, err := os.ReadFile(framesPath)
	if err != nil {
		t.Fatalf("reading the frames: %v (run with -update to create them)", err)
	}
	var f frames
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing the frames: %v", err)
	}

	tenant := uuid.MustParse(f.Tenant)
	device := uuid.MustParse(f.Device)
	privBytes, err := base64.StdEncoding.DecodeString(f.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := seal.ParsePrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := seal.OpenContentKey(priv, tenant, device, f.ContentKey.ID, f.ContentKey.Sealed)
	if err != nil {
		t.Fatal(err)
	}

	// The same bindings the TypeScript opener uses, asserted here so a change
	// on either side fails on both.
	msgUID := uuid.MustParse(f.Message.UID)
	check := func(name string, kind seal.Kind, row uuid.UUID, sealed []byte, want string) {
		t.Helper()
		got, err := ck.Open(kind, tenant, row, sealed)
		if err != nil {
			t.Fatalf("%s did not open: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s opened to %q, want %q", name, got, want)
		}
	}

	check("body", seal.KindBody, msgUID, f.Message.BodySealed, f.Expected.Body)
	check("payload", seal.KindPayload, msgUID, f.Message.PayloadSealed, f.Expected.Payload)
	check("media key", seal.KindMediaKey, msgUID, f.Message.Media.MediaKeySealed,
		string(f.Expected.MediaKey))
	check("thumbnail", seal.KindThumbnail, msgUID, f.Message.Media.ThumbSealed,
		string(f.Expected.Thumbnail))
	// Under the contact-name kind, which reads oddly and is the format.
	check("file name", seal.KindContactName, msgUID, f.Message.Media.FileNameSealed,
		f.Expected.FileName)

	check("chat name", seal.KindContactName, uuid.MustParse(f.Chat.UID), f.Chat.NameSealed,
		f.ChatName)
	contactUID := uuid.MustParse(f.Contact.UID)
	check("push name", seal.KindPushName, contactUID, f.Contact.PushNameSealed, f.ContactName.Push)
	check("full name", seal.KindFullName, contactUID, f.Contact.FullNameSealed, f.ContactName.Full)
	check("business name", seal.KindBusinessName, contactUID, f.Contact.BusinessNameSealed,
		f.ContactName.Business)
	check("avatar", seal.KindAvatar, uuid.MustParse(f.Avatar.UID), f.Avatar.Sealed,
		string(f.AvatarBytes))

	if _, err := ck.Open(seal.KindBody, tenant, uuid.MustParse(f.Relocated.UID),
		f.Relocated.BodySealed); err == nil {
		t.Fatal("a body sealed for another row opened, and it must not")
	}
}

func writeFrames(t *testing.T) {
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

	const keyID = 3
	ck, err := seal.NewContentKey(pub, tenant, device, 1, keyID)
	if err != nil {
		t.Fatal(err)
	}
	sealValue := func(kind seal.Kind, row uuid.UUID, value []byte) []byte {
		t.Helper()
		out, err := ck.Seal(kind, tenant, row, value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	msgUID := uuid.New()
	chatUID := uuid.New()
	contactUID := uuid.New()
	at := time.Date(2026, 3, 14, 15, 9, 26, 0, time.UTC)

	body := "olha a foto do contrato — não repassa 🙏"
	payload := `{"mentions":["5511999999999@s.whatsapp.net"]}`
	mediaKey := make([]byte, 32)
	for i := range mediaKey {
		mediaKey[i] = byte(200 - i)
	}
	thumbnail := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	fileName := "acordo-divórcio.pdf"
	avatarBytes := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	f := frames{
		Note: "Generated by go test ./internal/wsapi -run Fixtures -update. " +
			"Whole frames, sealed as the ingest pipeline seals them, so a client " +
			"that asks for the wrong row or the wrong kind fails here.",
		Tenant:     tenant.String(),
		Device:     device.String(),
		PrivateKey: base64.StdEncoding.EncodeToString(privBytes),
	}
	f.ContentKey.ID, f.ContentKey.Sealed = keyID, ck.Sealed

	f.Message = SealedMessage{
		UID:      msgUID.String(),
		Seq:      4711,
		DeviceID: device.String(),
		WAID:     "3EB0A1B2C3D4E5F60718",
		ChatKey:  "5511996514211@s.whatsapp.net",
		TS:       &at,
		Kind:     "message",
		Type:     "document",
		Source:   "live",

		ContentKeyID:  keyID,
		BodySealed:    sealValue(seal.KindBody, msgUID, []byte(body)),
		PayloadSealed: sealValue(seal.KindPayload, msgUID, []byte(payload)),
		Media: &SealedMedia{
			MediaType:      "document",
			MimeType:       "application/pdf",
			FileLength:     177018,
			DownloadStatus: "done",
			MediaKeySealed: sealValue(seal.KindMediaKey, msgUID, mediaKey),
			ThumbSealed:    sealValue(seal.KindThumbnail, msgUID, thumbnail),
			FileNameSealed: sealValue(seal.KindContactName, msgUID, []byte(fileName)),
		},
	}
	f.Expected = expectedValues{
		Body: body, Payload: payload, MediaKey: mediaKey,
		Thumbnail: thumbnail, FileName: fileName,
	}

	f.ChatName = "Serra — obras"
	f.Chat = ChatSummary{
		UID:        chatUID.String(),
		ChatKey:    "120363000000000000@g.us",
		IsGroup:    true,
		LastSeq:    4711,
		LastTS:     &at,
		NameKeyID:  keyID,
		NameSealed: sealValue(seal.KindContactName, chatUID, []byte(f.ChatName)),
	}

	f.ContactName.Push, f.ContactName.Full, f.ContactName.Business = "Fê", "Felipe Restum", "Padaria do Zé"
	f.Contact = ContactSummary{
		UID:                contactUID.String(),
		ContactKey:         "5511996514211@s.whatsapp.net",
		ContactLID:         "224437861388494@lid",
		ContactPN:          "5511996514211@s.whatsapp.net",
		ContentKeyID:       keyID,
		PushNameSealed:     sealValue(seal.KindPushName, contactUID, []byte(f.ContactName.Push)),
		FullNameSealed:     sealValue(seal.KindFullName, contactUID, []byte(f.ContactName.Full)),
		BusinessNameSealed: sealValue(seal.KindBusinessName, contactUID, []byte(f.ContactName.Business)),
		HasAvatar:          true,
		AvatarKeyID:        keyID,
	}

	f.AvatarBytes = avatarBytes
	f.Avatar = Avatar{
		ContactKey: f.Contact.ContactKey,
		UID:        contactUID.String(),
		KeyID:      keyID,
		Sealed:     sealValue(seal.KindAvatar, contactUID, avatarBytes),
	}

	// The relocation: a body sealed against one message, presented as another.
	// This is what an attacker with write access to Postgres does, and what the
	// AAD binding exists to refuse.
	otherUID := uuid.New()
	f.Relocated = f.Message
	f.Relocated.UID = otherUID.String()

	if err := os.MkdirAll(filepath.Dir(framesPath), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(framesPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", framesPath)
}
