package datacheck

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/blob"
)

// flakyBucket fails its listing once after two keys and each object's
// first read, as a bucket behind a restarting MinIO would.
type flakyBucket struct {
	keys       []string
	listFailed bool
	reads      map[string]int
	lists      []string
}

var errFlaky = errors.New("connection reset")

func (b *flakyBucket) List(ctx context.Context, prefix, after string, fn func(blob.ObjectInfo) error) error {
	b.lists = append(b.lists, after)
	n := 0
	for _, k := range b.keys {
		if !strings.HasPrefix(k, prefix) || k <= after {
			continue
		}
		if n == 2 && !b.listFailed {
			b.listFailed = true
			return errFlaky
		}
		n++
		if err := fn(blob.ObjectInfo{Key: k, Size: int64(len(k))}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (b *flakyBucket) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	b.reads[key]++
	if key == "gone" {
		return nil, 0, blob.ErrNotFound
	}
	if b.reads[key] == 1 {
		return nil, 0, errFlaky
	}
	return io.NopCloser(bytes.NewReader([]byte(key))), int64(len(key)), nil
}

// A failed listing resumes after the last key it gave, and a failed read
// is read again, so one transient error does not end the run; a missing
// object and an error of the caller's are not retried.
func TestTheBucketIsRetried(t *testing.T) {
	saved := retryPauses
	retryPauses = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryPauses = saved })
	ctx := context.Background()

	b := &flakyBucket{keys: []string{"a", "b", "c", "d"}, reads: map[string]int{}}
	var seen []string
	if err := listResuming(ctx, b, "", func(o blob.ObjectInfo) error {
		if _, _, err := hashObject(ctx, b, o.Key); err != nil {
			return err
		}
		seen = append(seen, o.Key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seen, b.keys) || !slices.Equal(b.lists, []string{"", "b"}) {
		t.Fatalf("listed %v in listings after %q", seen, b.lists)
	}
	for _, k := range b.keys {
		if b.reads[k] != 2 {
			t.Fatalf("%s read %d times", k, b.reads[k])
		}
	}

	if _, _, err := hashObject(ctx, b, "gone"); !errors.Is(err, blob.ErrNotFound) || b.reads["gone"] != 1 {
		t.Fatalf("a missing object: %v after %d reads", err, b.reads["gone"])
	}
	stop := errors.New("stop")
	b = &flakyBucket{keys: []string{"a", "b", "c"}, reads: map[string]int{}, listFailed: true}
	if err := listResuming(ctx, b, "", func(blob.ObjectInfo) error { return stop }); !errors.Is(err, stop) || len(b.lists) != 1 {
		t.Fatalf("the caller's error: %v after %d listings", err, len(b.lists))
	}
	// A listing that keeps failing ends after the last pause.
	always := &failingList{}
	if err := listResuming(ctx, always, "", func(blob.ObjectInfo) error { return nil }); !errors.Is(err, errFlaky) || always.n != len(retryPauses)+1 {
		t.Fatalf("a listing that never works: %v after %d tries", err, always.n)
	}
}

type failingList struct{ n int }

func (f *failingList) List(context.Context, string, string, func(blob.ObjectInfo) error) error {
	f.n++
	return errFlaky
}

func (f *failingList) Get(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, errFlaky
}
