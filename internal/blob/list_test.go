package blob

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"whatserver2/internal/config"
)

// listingBucket answers ListObjectsV2 from keys, two keys a page, and
// records every request's method, so a test can hold List to reading.
func listingBucket(t *testing.T, keys []string) (*Store, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		q := r.URL.Query()
		if r.Method != http.MethodGet || q.Get("list-type") != "2" {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		var page []string
		for _, k := range keys {
			if strings.HasPrefix(k, q.Get("prefix")) && k > q.Get("continuation-token") && k > q.Get("start-after") {
				page = append(page, k)
			}
		}
		truncated := len(page) > 2
		if truncated {
			page = page[:2]
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>media</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>%t</IsTruncated>`,
			q.Get("prefix"), len(page), truncated)
		if truncated {
			fmt.Fprintf(w, `<NextContinuationToken>%s</NextContinuationToken>`, page[len(page)-1])
		}
		for _, k := range page {
			fmt.Fprintf(w, `<Contents><Key>%s</Key><Size>%d</Size><ETag>"e"</ETag><LastModified>2026-11-27T00:00:00.000Z</LastModified><StorageClass>STANDARD</StorageClass></Contents>`, k, len(k))
		}
		fmt.Fprint(w, `</ListBucketResult>`)
	}))
	t.Cleanup(srv.Close)
	s, err := New(config.Storage{Configured: true, Endpoint: srv.URL, Region: "us-east-1", Bucket: "media", AccessKey: "a", SecretKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return s, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(methods)
	}
}

// List streams every object under a prefix, across pages, in key order,
// with its size, and only ever reads the bucket.
func TestListStreamsEveryPageAndOnlyReads(t *testing.T) {
	keys := []string{"a/1", "a/2", "a/3", "a/4", "a/5", "b/1"}
	s, methods := listingBucket(t, keys)
	var got []ObjectInfo
	if err := s.List(context.Background(), "a/", "", func(o ObjectInfo) error {
		got = append(got, o)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []ObjectInfo{{"a/1", 3}, {"a/2", 3}, {"a/3", 3}, {"a/4", 3}, {"a/5", 3}}
	if !slices.Equal(got, want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	// A listing resumed after a key starts at the next one.
	got = nil
	if err := s.List(context.Background(), "a/", "a/3", func(o ObjectInfo) error {
		got = append(got, o)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := want[3:]; !slices.Equal(got, want) {
		t.Fatalf("resumed after a/3: %v, want %v", got, want)
	}
	for _, m := range methods() {
		if m != http.MethodGet {
			t.Fatalf("the listing sent a %s", m)
		}
	}

	stop := errors.New("stop")
	n := 0
	if err := s.List(context.Background(), "", "", func(ObjectInfo) error {
		n++
		return stop
	}); !errors.Is(err, stop) || n != 1 {
		t.Fatalf("an error from fn gave %v after %d objects", err, n)
	}

	var nilStore *Store
	if err := nilStore.List(context.Background(), "", "", func(ObjectInfo) error { return nil }); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("an unconfigured store listed: %v", err)
	}
}
