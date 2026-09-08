package media_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"whatserver2/internal/media"
	"whatserver2/internal/store"
)

// The URL of an attachment is chosen by whoever sent the message. What this
// server does with it is the difference between an archive and a proxy.

func TestOnlyWhatsAppHostsAreFetched(t *testing.T) {
	o := media.WhatsAppOrigins()
	allowed := []string{
		"https://mmg.whatsapp.net/v/t62.7118-24/abc?ccb=11-4",
		"https://media-gru2-1.cdn.whatsapp.net/v/t62.7118-24/abc",
		"https://pps.whatsapp.net/v/t61.24694-24/abc",
		"https://MMG.WHATSAPP.NET:443/v/x",
	}
	for _, u := range allowed {
		if err := o.Check(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	refused := map[string]string{
		"http://mmg.whatsapp.net/v/x":              "plaintext",
		"https://169.254.169.254/latest/meta-data": "host",
		"https://10.0.0.5/admin":                   "host",
		"https://localhost/":                       "host",
		"https://evil.example/whatsapp.net":        "host",
		"https://whatsapp.net.evil.example/":       "host",
		"https://mmg.whatsapp.net:8443/v/x":        "port",
		"https://user:pw@mmg.whatsapp.net/v/x":     "credentials",
		"ftp://mmg.whatsapp.net/v/x":               "scheme",
		"":                                         "scheme",
	}
	for u, reason := range refused {
		err := o.Check(u)
		if !errors.Is(err, media.ErrOrigin) {
			t.Errorf("%q accepted, want a refusal about %s", u, reason)
			continue
		}
		if !strings.Contains(err.Error(), reason) {
			t.Errorf("%q refused for the wrong reason: %v (want %s)", u, err, reason)
		}
	}
}

func TestALiteralPrivateAddressIsRefusedEvenWhenAnyHostIsAllowed(t *testing.T) {
	o := media.Origins{} // any host, but public addresses only
	for _, u := range []string{
		"https://169.254.169.254/latest/meta-data",
		"https://10.0.0.5/admin",
		"https://[::1]/",
		"https://127.0.0.1/",
		"https://100.64.0.1/",
	} {
		err := o.Check(u)
		if !errors.Is(err, media.ErrOrigin) || !strings.Contains(err.Error(), "public address") {
			t.Errorf("%s: err = %v, want a refusal about a public address", u, err)
		}
	}
}

func TestTheFetcherRefusesAMetadataURLWithoutDialing(t *testing.T) {
	f := media.NewFetcher(1<<20, t.TempDir())
	_, _, err := f.Fetch(context.Background(), store.Pending{
		URL: "http://169.254.169.254/latest/meta-data/iam/",
	})
	if !errors.Is(err, media.ErrOrigin) {
		t.Fatalf("err = %v, want ErrOrigin", err)
	}
}

func TestARedirectOffTheAllowedHostsIsRefused(t *testing.T) {
	// Two local servers: the first is allowed and bounces to the second,
	// which is not. A CDN-looking URL that redirects elsewhere is the same
	// forgery with one more hop.
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the redirect target was fetched")
		_, _ = w.Write([]byte("secret"))
	}))
	t.Cleanup(elsewhere.Close)
	elsewhereURL := strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)

	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhereURL+"/blob", http.StatusFound)
	}))
	t.Cleanup(cdn.Close)

	origins := media.Origins{
		Hosts: []string{"127.0.0.1"}, AllowPlaintext: true,
		AllowAnyPort: true, AllowPrivateAddresses: true,
	}
	f := media.NewFetcherFrom(origins, 1<<20, t.TempDir())
	_, _, err := f.Fetch(context.Background(), store.Pending{URL: cdn.URL + "/blob"})
	if !errors.Is(err, media.ErrOrigin) {
		t.Fatalf("err = %v, want ErrOrigin from the redirect check", err)
	}
}

func TestANameResolvingToAPrivateAddressIsRefused(t *testing.T) {
	// "localhost" is on the allowed list here, so the URL check passes; the
	// dialer is what has to catch it, because that is where a DNS answer
	// pointing at an internal address would otherwise be honoured.
	origins := media.Origins{Hosts: []string{"localhost"}, AllowPlaintext: true, AllowAnyPort: true}
	f := media.NewFetcherFrom(origins, 1<<20, t.TempDir())
	_, _, err := f.Fetch(context.Background(), store.Pending{URL: "http://localhost:1/blob"})
	if !errors.Is(err, media.ErrOrigin) {
		t.Fatalf("err = %v, want ErrOrigin from the dialer", err)
	}
}
