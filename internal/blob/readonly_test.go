package blob

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"whatserver2/internal/config"
)

// A bucket that records each request's method and answers a bucket check
// with "absent" or "present", and anything else with an empty 200.
func recordingBucket(t *testing.T, present bool) (*Store, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodHead || r.URL.Query().Has("location") {
			if !present {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>no</Message></Error>`)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s, err := New(config.Storage{Configured: true, Endpoint: srv.URL, Region: "us-east-1", Bucket: "media", AccessKey: "a", SecretKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return s, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

// A read-only store, a maintenance start's, writes no object: Put and
// Delete are refused before the bucket is asked, and a missing bucket is
// an error rather than one it creates. The store it was made from still
// writes, and an unconfigured store stays unconfigured.
func TestReadOnlyWritesNothing(t *testing.T) {
	ctx := context.Background()
	s, asked := recordingBucket(t, false)
	ro := s.ReadOnly()
	if err := ro.Put(ctx, "k", strings.NewReader("x"), 1); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("put: %v", err)
	}
	if err := ro.Delete(ctx, "k"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("delete: %v", err)
	}
	if got := asked(); len(got) != 0 {
		t.Fatalf("the refused writes asked the bucket: %q", got)
	}
	if err := ro.EnsureBucket(ctx, "us-east-1"); err == nil || !strings.Contains(err.Error(), "does not create it") {
		t.Fatalf("a missing bucket: %v", err)
	}
	for _, req := range asked() {
		if strings.HasPrefix(req, http.MethodPut) {
			t.Fatalf("the read-only check created the bucket: %q", asked())
		}
	}

	if err := s.Put(ctx, "k", strings.NewReader("x"), 1); err != nil {
		t.Fatalf("the writable store's put: %v", err)
	}
	if !strings.HasPrefix(asked()[len(asked())-1], http.MethodPut) {
		t.Fatalf("the writable store did not put: %q", asked())
	}

	var none *Store
	if none.ReadOnly() != nil || none.ReadOnly().Configured() {
		t.Fatal("an unconfigured store became configured")
	}
}
