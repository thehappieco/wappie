package blob

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"whatserver2/internal/config"
)

// A bucket that answers every request with 503, counting them.
func downBucket(t *testing.T) (*Store, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>ServiceUnavailable</Code><Message>down</Message></Error>`)
	}))
	t.Cleanup(srv.Close)
	s, err := New(config.Storage{Configured: true, Endpoint: srv.URL, Region: "us-east-1", Bucket: "media", AccessKey: "a", SecretKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return s, &hits
}

// Delete asks a bucket that is down once (decision 0038's plan, section 7):
// the janitor's bound and the next orphan pass are its retries, so the
// workspace's row it holds waits for one request, not for minio-go's ten
// with their backoff. Every other call keeps minio-go's retries.
func TestDeleteAsksOnce(t *testing.T) {
	s, hits := downBucket(t)
	start := time.Now()
	if err := s.Delete(context.Background(), "k"); err == nil {
		t.Fatal("a delete from a bucket that is down succeeded")
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("the delete asked the bucket %d times", n)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the delete took %s", took)
	}

	hits.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, _, err := s.Exists(ctx, "k"); err == nil {
		t.Fatal("a stat of a bucket that is down succeeded")
	}
	if n := hits.Load(); n < 2 {
		t.Fatalf("a stat asked the bucket %d times: it lost minio-go's retries", n)
	}
}
