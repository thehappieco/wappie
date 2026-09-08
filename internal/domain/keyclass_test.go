package domain_test

import (
	"testing"

	"whatserver2/internal/domain"
)

// Which keys an attachment's bytes are sealed under.
//
// The reason this is worth a test of its own: the class is chosen when the
// bytes are uploaded and the type is named again when the message is sent, and
// nothing else links the two calls. Every pair that shares a class here is a
// pair the caller may swap freely; every pair that does not is one where a swap
// produces an attachment that opens for nobody, with a 200 at every step.

func TestSeveralTypesShareOneSetOfKeys(t *testing.T) {
	// WhatsApp's scheme, not an approximation made here: a sticker rides on
	// the image keys, a round video note on video, a voice note on audio.
	same := [][2]domain.Type{
		{domain.TypeImage, domain.TypeSticker},
		{domain.TypeVideo, domain.TypePTV},
		{domain.TypeAudio, domain.TypePTT},
	}
	for _, pair := range same {
		if domain.KeyClass(pair[0]) != domain.KeyClass(pair[1]) {
			t.Errorf("%s and %s should share a key class, got %q and %q",
				pair[0], pair[1], domain.KeyClass(pair[0]), domain.KeyClass(pair[1]))
		}
	}
}

func TestAPhotographAndAFileDoNotShareKeys(t *testing.T) {
	// The one pair a person thinks of as the same file — "enviar a foto como
	// arquivo" — and the one where the crypto actually differs.
	if domain.KeyClass(domain.TypeImage) == domain.KeyClass(domain.TypeDocument) {
		t.Fatal("image and document must not share a key class; sending one as the " +
			"other would seal the bytes under a label the recipient does not derive")
	}
}

func TestEveryAttachmentTypeHasAClass(t *testing.T) {
	for _, kind := range []domain.Type{
		domain.TypeImage, domain.TypeVideo, domain.TypePTV,
		domain.TypeAudio, domain.TypePTT, domain.TypeDocument, domain.TypeSticker,
	} {
		if domain.KeyClass(kind) == "" {
			t.Errorf("%s is an attachment and has no key class", kind)
		}
	}
}

func TestSomethingThatIsNotAnAttachmentHasNoClass(t *testing.T) {
	// Empty rather than a guess. The upload endpoint refuses on this, and the
	// send comparison skips rather than accidentally matching two unrelated
	// types that both came back empty.
	for _, kind := range []domain.Type{
		domain.TypeText, domain.TypeLocation, domain.TypePoll, domain.TypeUnsupported, "",
	} {
		if got := domain.KeyClass(kind); got != "" {
			t.Errorf("KeyClass(%q) = %q, want empty", kind, got)
		}
	}
}
