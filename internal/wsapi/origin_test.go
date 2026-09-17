package wsapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"whatserver2/internal/browserorigin"
)

func TestExplicitForeignBrowserOriginUpgrade(t *testing.T) {
	policy, _ := browserorigin.Parse("https://app.example.com", false)
	s := httptest.NewServer(NewServer(Config{BrowserOrigins: policy}))
	defer s.Close()
	for _, tt := range []struct {
		origin  string
		allowed bool
	}{{"https://app.example.com", true}, {"https://app.example.com.evil.test", false}, {"null", false}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		//nolint:bodyclose // coder/websocket.Dial owns and closes the response body.
		c, resp, err := websocket.Dial(ctx, strings.Replace(s.URL, "http:", "ws:", 1), &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{tt.origin}}})
		if tt.allowed {
			if err != nil {
				t.Errorf("allowed upgrade: %v", err)
			} else {
				_ = c.CloseNow()
			}
		} else if err == nil || resp == nil || resp.StatusCode != 403 {
			t.Errorf("untrusted origin %s accepted: %v", tt.origin, err)
		}
		cancel()
	}
}
