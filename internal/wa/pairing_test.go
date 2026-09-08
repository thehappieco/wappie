package wa_test

import (
	"strings"
	"testing"

	"whatserver2/internal/wa"
)

// The phone number and display name rules are enforced by WhatsApp's servers,
// which answer a malformed request with an opaque 400. Checking locally turns
// that into a message that says what is actually wrong — and it costs a pairing
// attempt to find out the hard way, because the 160-second window has already
// started by the time the request goes out.
func TestPairOptionsValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		opts    wa.PairOptions
		wantErr string
	}{
		"no method": {
			wa.PairOptions{}, "method is required",
		},
		"unknown method": {
			wa.PairOptions{Method: "sms"}, "unknown pairing method",
		},
		"code without a number": {
			wa.PairOptions{Method: wa.PairByCode}, "needs a phone number",
		},
		"number too short": {
			wa.PairOptions{Method: wa.PairByCode, Phone: "551199"}, "too short",
		},
		"national format with a leading zero": {
			wa.PairOptions{Method: wa.PairByCode, Phone: "011999999999"}, "country code",
		},
		"display name is not free text": {
			wa.PairOptions{Method: wa.PairByQR, DisplayName: "meu servidor"}, "Browser (OS)",
		},
		"display name missing the OS": {
			wa.PairOptions{Method: wa.PairByQR, DisplayName: "Chrome"}, "Browser (OS)",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.opts.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %+v", tc.opts)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestPairOptionsAcceptsGoodInput(t *testing.T) {
	// Punctuation is stripped rather than rejected: people paste numbers the
	// way they are written down.
	opts := wa.PairOptions{Method: wa.PairByCode, Phone: "+55 (11) 99999-9999"}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if opts.Phone != "5511999999999" {
		t.Errorf("Phone = %q, want the digits only", opts.Phone)
	}
	// A default display name is supplied, and it satisfies the same rule the
	// server applies.
	if opts.DisplayName == "" {
		t.Fatal("Validate should default the display name")
	}
	if err := (&wa.PairOptions{Method: wa.PairByQR, DisplayName: opts.DisplayName}).Validate(); err != nil {
		t.Errorf("the default display name does not pass its own validation: %v", err)
	}
}

func TestPairOptionsAcceptsQRWithoutAPhone(t *testing.T) {
	opts := wa.PairOptions{Method: wa.PairByQR}
	if err := opts.Validate(); err != nil {
		t.Fatalf("QR pairing needs no phone number: %v", err)
	}
}

// The window is fixed by the protocol, not by us. Raising it would not buy more
// time; it would just mean the session outlives the socket.
func TestPairWindowMatchesTheProtocol(t *testing.T) {
	if wa.PairWindow.Seconds() != 160 {
		t.Errorf("PairWindow = %v; the login socket closes at 160s regardless", wa.PairWindow)
	}
}
