package label

import "testing"

func TestHintFromPN(t *testing.T) {
	for _, tc := range []struct{ pn, want string }{
		{"5511912345678@s.whatsapp.net", "…5678"},
		{"5511912345678:12@s.whatsapp.net", "…5678"},
		{"5511912345678", "…5678"},
		{"123@s.whatsapp.net", ""},
		{"", ""},
	} {
		got := HintFromPN(tc.pn)
		if (got == nil) != (tc.want == "") || got != nil && *got != tc.want {
			t.Errorf("HintFromPN(%q) = %v, want %q", tc.pn, got, tc.want)
		}
	}
}
