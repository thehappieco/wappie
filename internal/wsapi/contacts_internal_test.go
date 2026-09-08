package wsapi

import "testing"

// TestContactKeysNormalisesDeviceSuffixes is the bug this frame exists to avoid
// re-creating.
//
// A sender key on a message can carry a device suffix — 123:12@lid — and the
// contacts table is keyed without one, because a contact is a person and not
// one of their phones. Asking with the suffix finds no row, so the client would
// be told "nobody knows who that is" about a contact whose name is sitting in
// the table, and would go on drawing a LID at the reader. The same mistake was
// found once already in the LID map, where a missing ToNonAD produced a lookup
// matching no contact and no chat.
func TestContactKeysNormalisesDeviceSuffixes(t *testing.T) {
	got := contactKeys([]string{
		"123456789012345:12@lid",
		"123456789012345@lid", // the same person, already bare
		"5511999999999:3@s.whatsapp.net",
		"not a jid",
		"",
	})
	want := []string{"123456789012345@lid", "5511999999999@s.whatsapp.net"}
	if len(got) != len(want) {
		t.Fatalf("contactKeys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("contactKeys[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestContactKeysIsBounded stops a redraw becoming a database sweep.
//
// A client asks about what it is drawing, and a client with a bug asks about
// everything it holds. Dropping the tail rather than refusing keeps the common
// case working: the next draw asks about what is still unresolved.
func TestContactKeysIsBounded(t *testing.T) {
	in := make([]string, 0, resolveLimit*2)
	for i := 0; i < resolveLimit*2; i++ {
		in = append(in, string(rune('a'+i%26))+"000000000000@lid")
	}
	if got := len(contactKeys(in)); got > resolveLimit {
		t.Fatalf("contactKeys returned %d keys, want at most %d", got, resolveLimit)
	}
}

// TestContactKeysRefusesJunk guards a path that writes to the database.
//
// types.ParseJID accepts a bare string and hands back a user on the default
// server, so "hello" parses as "hello@s.whatsapp.net" with no error at all.
// These keys reach EnsureIdentity, which creates a contacts row — so without a
// stricter gate here, a client could name its own rows into existence, and the
// only symptom would be a table slowly filling with strings nobody sent a
// message to.
func TestContactKeysRefusesJunk(t *testing.T) {
	for _, raw := range []string{
		"hello", "", "   ", "@", "@lid",
		"5511999999999@example.com",
		"12345@newsletter",
	} {
		if got := contactKeys([]string{raw}); len(got) != 0 {
			t.Errorf("contactKeys(%q) = %v, want nothing accepted", raw, got)
		}
	}
}
