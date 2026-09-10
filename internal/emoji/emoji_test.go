package emoji

import (
	"encoding/json"
	"testing"
)

func TestWholeEmoji(t *testing.T) {
	for raw, want := range map[string]string{
		"": "", "👍": "👍", "❤": "❤️", "❤️": "❤️", "👩🏽‍💻": "👩🏽‍💻", "👨‍👩‍👧‍👦": "👨‍👩‍👧‍👦",
		"🇪🇪": "🇪🇪", "1️⃣": "1️⃣", "1⃣": "1️⃣", "🏳️‍🌈": "🏳️‍🌈", "🐦‍🔥": "🐦‍🔥", "🫩": "🫩",
	} {
		if got, ok := Normalize(raw); !ok || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
}

func TestRejectsTextAndMultipleEmoji(t *testing.T) {
	for _, value := range []string{"hello", "a", "1", "#", " ", "👍👍", "🇪🇪🇧🇷", "👍hello", "a\uFE0F", "\u200D", "👍\u200D👍", "\uFE0F", "🏻", "🦰", "🇪", "👍\n", "😀\uFE0F\uFE0F"} {
		if got, ok := Normalize(value); ok {
			t.Errorf("accepted %q as %q", value, got)
		}
	}
}

func TestSharedCatalogueAliasesStayComplete(t *testing.T) {
	var data struct {
		Groups []struct {
			Emojis [][]string `json:"emojis"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(catalogue, &data); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, group := range data.Groups {
		for _, variants := range group.Emojis {
			count++
			for _, value := range variants {
				if got, ok := Normalize(value); !ok || got != variants[0] {
					t.Fatalf("invalid catalogue entry %q", value)
				}
			}
		}
	}
	if count != 3944 {
		t.Fatalf("catalogue lost sequences: %d", count)
	}
}
