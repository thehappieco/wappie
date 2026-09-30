package seal_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

// An assistant's draft (docs/mcp-enclave.md §17.6) is sealed in the attested
// reader, in Node, to a number's archive key, stored by this server in the
// ledger, and opened in the person's browser with the row rebuilt from the
// ledger's fields. Three implementations meet on one derivation, DraftRow, and
// one of them must never open a draft moved to another chat, reply,
// connection or draft id. Two files pin that:
//
//   - testdata/draft-vectors.json: Go derives the rows and seals a draft;
//     packages/client/test/draft.spec.ts derives the same rows and opens it,
//     and refuses the negatives. Regenerate deliberately:
//     go test ./internal/crypto/seal -run DraftVectors -update
//   - packages/client/testdata/node-draft.json: the client seals a draft in
//     Node, as the enclave does, and Go opens it here. Regenerate with
//     cd packages/client && WS_REGEN_VECTORS=1 npm test
//
// The private key is fixture material and protects nothing.

const draftVectorsPath = "testdata/draft-vectors.json"

type draftVectors struct {
	Note       string      `json:"note"`
	Tenant     string      `json:"tenant"`
	PrivateKey string      `json:"private_key"`
	PublicKey  string      `json:"public_key"`
	Rows       []draftRow  `json:"rows"`
	Draft      sealedDraft `json:"draft"`
	// Negatives are the draft above, presented with one routing field
	// changed. Each must fail to open.
	Negatives []draftNegative `json:"negatives"`
}

// draftRow is one DraftRow input and what it derives.
type draftRow struct {
	Device     string  `json:"device"`
	Connection string  `json:"connection"`
	Draft      string  `json:"draft"`
	Reply      *string `json:"reply"`
	ChatKey    string  `json:"chat_key"`
	Row        string  `json:"row"`
	Note       string  `json:"note,omitempty"`
}

type sealedDraft struct {
	draftRow
	Epoch     uint16 `json:"epoch"`
	Plaintext string `json:"plaintext"`
	Sealed    string `json:"sealed"`
}

type draftNegative struct {
	Why string `json:"why"`
	// Kind is the kind it is opened as: mcp_draft unless the negative is
	// about the kind.
	Kind byte `json:"kind"`
	draftRow
}

func optionalUUID(s *string) *uuid.UUID {
	if s == nil {
		return nil
	}
	id := uuid.MustParse(*s)
	return &id
}

func (r draftRow) derive(tenant uuid.UUID) uuid.UUID {
	return seal.DraftRow(tenant, uuid.MustParse(r.Device), uuid.MustParse(r.Connection), uuid.MustParse(r.Draft), optionalUUID(r.Reply), r.ChatKey)
}

func TestDraftKind(t *testing.T) {
	if seal.KindMcpDraft != 0x0E || seal.KindMcpDraft.String() != "mcp_draft" {
		t.Fatalf("KindMcpDraft = %#x %q", byte(seal.KindMcpDraft), seal.KindMcpDraft)
	}
	// 0x0F is reserved (§18.8): it has no name yet.
	if got := seal.Kind(0x0F).String(); got != "kind(0xf)" {
		t.Fatalf("0x0f = %q", got)
	}
}

func TestDraftVectors(t *testing.T) {
	if *update {
		writeDraftVectors(t)
	}
	raw, err := os.ReadFile(draftVectorsPath)
	if err != nil {
		t.Fatalf("reading the draft vectors: %v (run with -run DraftVectors -update to create them)", err)
	}
	var v draftVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(v.Tenant)
	for _, r := range v.Rows {
		if got := r.derive(tenant).String(); got != r.Row {
			t.Errorf("DraftRow(%s) = %s, want %s", r.Note, got, r.Row)
		}
	}
	priv, err := seal.ParsePrivateKey(unb64(t, v.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	d := v.Draft
	if got := d.derive(tenant).String(); got != d.Row {
		t.Fatalf("the draft's row = %s, want %s", got, d.Row)
	}
	opened, err := seal.OpenDirect(priv, seal.KindMcpDraft, tenant, d.derive(tenant), unb64(t, d.Sealed))
	if err != nil {
		t.Fatalf("opening the draft: %v", err)
	}
	if string(opened) != d.Plaintext {
		t.Fatalf("the draft opened to %q", opened)
	}
	for _, bad := range v.Negatives {
		t.Run("refuses/"+bad.Why, func(t *testing.T) {
			if _, err := seal.OpenDirect(priv, seal.Kind(bad.Kind), tenant, bad.derive(tenant), unb64(t, d.Sealed)); err == nil {
				t.Fatalf("%s: the draft opened, and it must not", bad.Why)
			}
		})
	}
}

// nodeDraft is packages/client/testdata/node-draft.json: a draft sealed in
// Node by the client's sealDirect, the function the enclave seals with.
type nodeDraft struct {
	Tenant       string  `json:"tenant"`
	Device       string  `json:"device"`
	Connection   string  `json:"connection"`
	Draft        string  `json:"draft"`
	ReplyToUID   *string `json:"reply_to_uid"`
	ChatKey      string  `json:"chat_key"`
	Epoch        uint16  `json:"epoch"`
	PrivateKey   string  `json:"archive_private_key"`
	DraftRowText string  `json:"draft_row"`
	Plaintext    string  `json:"plaintext"`
	Sealed       string  `json:"sealed"`
}

func TestANodeSealedDraftOpensInGo(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/client/testdata/node-draft.json")
	if err != nil {
		t.Fatalf("reading the Node vector: %v\nIt is generated by the client suite: cd packages/client && npm test", err)
	}
	var n nodeDraft
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	tenant, device, connection, draft := uuid.MustParse(n.Tenant), uuid.MustParse(n.Device), uuid.MustParse(n.Connection), uuid.MustParse(n.Draft)
	reply := optionalUUID(n.ReplyToUID)
	row := seal.DraftRow(tenant, device, connection, draft, reply, n.ChatKey)
	if row.String() != n.DraftRowText {
		t.Fatalf("draft row = %s, Node derived %s", row, n.DraftRowText)
	}
	priv, err := seal.ParsePrivateKey(unb64(t, n.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.OpenDirect(priv, seal.KindMcpDraft, tenant, row, unb64(t, n.Sealed))
	if err != nil {
		t.Fatalf("opening a draft Node sealed: %v", err)
	}
	if string(opened) != n.Plaintext {
		t.Fatalf("the draft opened to %q", opened)
	}
	// And under every other routing, nothing: the console rebuilds the row
	// from the ledger, and a ledger that moved the draft must not open it.
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000cc")
	for why, moved := range map[string]uuid.UUID{
		"another chat":       seal.DraftRow(tenant, device, connection, draft, reply, n.ChatKey+"0"),
		"another reply":      seal.DraftRow(tenant, device, connection, draft, &other, n.ChatKey),
		"no reply":           seal.DraftRow(tenant, device, connection, draft, nil, n.ChatKey),
		"another connection": seal.DraftRow(tenant, device, other, draft, reply, n.ChatKey),
		"another draft":      seal.DraftRow(tenant, device, connection, other, reply, n.ChatKey),
		"another number":     seal.DraftRow(tenant, other, connection, draft, reply, n.ChatKey),
	} {
		if _, err := seal.OpenDirect(priv, seal.KindMcpDraft, tenant, moved, unb64(t, n.Sealed)); err == nil {
			t.Errorf("%s: a Node-sealed draft opened", why)
		}
	}
	if _, err := seal.OpenDirect(priv, seal.KindBody, tenant, row, unb64(t, n.Sealed)); err == nil {
		t.Error("a draft opened as a message body")
	}
}

// writeDraftVectors regenerates testdata/draft-vectors.json.
func writeDraftVectors(t *testing.T) {
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
	device, connection := uuid.New(), uuid.New()
	reply := uuid.New().String()
	row := func(draft string, reply *string, chat, note string) draftRow {
		r := draftRow{Device: device.String(), Connection: connection.String(), Draft: draft, Reply: reply, ChatKey: chat, Note: note}
		r.Row = r.derive(tenant).String()
		return r
	}
	v := draftVectors{
		Note: "Generated by go test ./internal/crypto/seal -run DraftVectors -update and read by packages/client/test/draft.spec.ts. " +
			"The private key is fixture material and protects nothing.",
		Tenant: tenant.String(), PrivateKey: b64(privBytes), PublicKey: b64(pub.Bytes()),
		Rows: []draftRow{
			row(uuid.NewString(), nil, "5511999990000@s.whatsapp.net", "a direct chat, no reply: sixteen zero bytes in its place"),
			row(uuid.NewString(), &reply, "5511999990000@s.whatsapp.net", "the same chat, replying"),
			row(uuid.NewString(), nil, "120363041234567890@g.us", "a group"),
			row(uuid.NewString(), nil, "240392312345678@lid", "a chat by LID"),
			row(uuid.NewString(), nil, "ação@s.whatsapp.net", "a chat key with non-ASCII bytes, hashed as UTF-8"),
		},
	}

	d := sealedDraft{draftRow: row(uuid.NewString(), &reply, "5511999990000@s.whatsapp.net", "the sealed draft"), Epoch: 3}
	plain, err := json.Marshal(struct {
		V          int       `json:"v"`
		Connection string    `json:"connection_id"`
		Device     string    `json:"device_id"`
		ChatKey    string    `json:"chat_key"`
		Reply      *string   `json:"reply_to_uid"`
		Text       string    `json:"text"`
		CreatedAt  string    `json:"created_at"`
		CrossChat  []chatRef `json:"cross_chat"`
	}{1, d.Connection, d.Device, d.ChatKey, d.Reply, "Oi! Confirmo amanhã às 10h — até lá 👋", "2026-10-01T09:30:15.123Z",
		[]chatRef{{Device: d.Device, ChatKey: "5511888880000@s.whatsapp.net"}}})
	if err != nil {
		t.Fatal(err)
	}
	d.Plaintext = string(plain)
	sealed, err := seal.SealDirect(pub, seal.KindMcpDraft, tenant, d.derive(tenant), d.Epoch, plain)
	if err != nil {
		t.Fatal(err)
	}
	d.Sealed = b64(sealed)
	v.Draft = d

	other := uuid.New().String()
	moved := func(why string, kind seal.Kind, change func(*draftRow)) draftNegative {
		r := d.draftRow
		change(&r)
		r.Note, r.Row = "", r.derive(tenant).String()
		return draftNegative{Why: why, Kind: byte(kind), draftRow: r}
	}
	v.Negatives = []draftNegative{
		moved("another_chat", seal.KindMcpDraft, func(r *draftRow) { r.ChatKey = "5511888880000@s.whatsapp.net" }),
		moved("another_reply", seal.KindMcpDraft, func(r *draftRow) { r.Reply = &other }),
		moved("no_reply", seal.KindMcpDraft, func(r *draftRow) { r.Reply = nil }),
		moved("another_connection", seal.KindMcpDraft, func(r *draftRow) { r.Connection = other }),
		moved("another_draft", seal.KindMcpDraft, func(r *draftRow) { r.Draft = other }),
		moved("another_number", seal.KindMcpDraft, func(r *draftRow) { r.Device = other }),
		moved("kind_swapped", seal.KindBody, func(*draftRow) {}),
	}

	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(draftVectorsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(draftVectorsPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", draftVectorsPath)
}

// chatRef is one entry of a draft's cross_chat.
type chatRef struct {
	Device  string `json:"device_id"`
	ChatKey string `json:"chat_key"`
}
