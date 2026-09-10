package wsapi_test

import (
	"strings"
	"testing"

	"whatserver2/internal/wsapi"
)

func TestReactionEmojiPreflight(t *testing.T) {
	conn, _ := handshake(t)
	for _, value := range []string{"text", "👍👍", " ", "🏻", "a\uFE0F"} {
		send(t, conn, wsapi.TypeReact, wsapi.ReactRequest{DeviceID: "018f3a2b-9999-7000-8000-00000000dead", Chat: "5511999999999@s.whatsapp.net", TargetID: "MSG1", Emoji: value})
		e := errorOf(t, read(t, conn))
		if e.Code != wsapi.ErrCodeBadRequest || !strings.Contains(e.Message, "emoji") {
			t.Fatalf("%q: %s %s", value, e.Code, e.Message)
		}
	}
	for _, value := range []string{"", "👩🏽‍💻", "👨‍👩‍👧‍👦", "🇪🇪", "❤"} {
		send(t, conn, wsapi.TypeReact, wsapi.ReactRequest{DeviceID: "018f3a2b-9999-7000-8000-00000000dead", Chat: "5511999999999@s.whatsapp.net", TargetID: "MSG1", Emoji: value})
		e := errorOf(t, read(t, conn))
		if strings.Contains(e.Message, "complete emoji") {
			t.Fatalf("valid emoji %q refused: %s", value, e.Message)
		}
	}
}
