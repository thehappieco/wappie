package send_test

import (
	"errors"
	"testing"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/send"
)

func TestRoundVideoRejectsUnsupportedMetadata(t *testing.T) {
	for _, scenario := range []string{"long", "caption", "gif", "not video"} {
		t.Run(scenario, func(t *testing.T) {
			a := upload()
			a.Type, a.MimeType, a.Seconds = domain.TypePTV, "video/mp4", 60
			switch scenario {
			case "long":
				a.Seconds = 61
			case "caption":
				a.Caption = "this would disappear"
			case "gif":
				a.IsGIF = true
			case "not video":
				a.MimeType = "image/jpeg"
			}
			if _, err := send.Media(dmChat, a, send.Options{}); !errors.Is(err, send.ErrInvalidVideo) {
				t.Fatalf("invalid round video accepted or misclassified: %v", err)
			}
		})
	}
}

func TestVideoPreservesActualResolutionAndForwardingChoice(t *testing.T) {
	for _, forwarded := range []bool{false, true} {
		a := upload()
		a.Type, a.MimeType, a.Seconds = domain.TypeVideo, "video/mp4; codecs=avc1", 120
		a.Width, a.Height, a.Caption = 1920, 1080, "HD source"
		msg, err := send.Media(dmChat, a, send.Options{Forwarded: forwarded, ForwardingScore: 8})
		if err != nil {
			t.Fatal(err)
		}
		video := msg.GetVideoMessage()
		if video.GetWidth() != 1920 || video.GetHeight() != 1080 || video.GetSeconds() != 120 || video.GetCaption() != a.Caption {
			t.Fatal("normal video metadata changed, or round-video duration limit affected it")
		}
		if video.GetContextInfo().GetIsForwarded() != forwarded {
			t.Fatal("forwarding choice was not respected")
		}
		if !forwarded && video.GetContextInfo().GetForwardingScore() != 0 {
			t.Fatal("disabled forwarding leaked a many-times score")
		}
	}
}

func TestRoundVideoSixtySecondsAndLegacyUnknownDuration(t *testing.T) {
	for _, duration := range []uint32{0, 60} {
		a := upload()
		a.Type, a.MimeType, a.Seconds = domain.TypePTV, "video/mp4", duration
		msg, err := send.Media(dmChat, a, send.Options{})
		if err != nil || msg.GetPtvMessage() == nil {
			t.Fatalf("valid round video refused: %v", err)
		}
	}
}
