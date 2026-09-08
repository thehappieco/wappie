package blob

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/minio/minio-go/v7"
)

// Two failures that used to read the same at boot, and have different fixes.
// A store that is down wants starting; a store that said no wants the
// configuration looked at. Telling somebody to check their credentials
// because Docker had not come up is the mistake these tests keep out.

func TestAConnectionRefusedIsUnreachable(t *testing.T) {
	// The shape net/http hands back when nothing is listening: a url.Error
	// around a net.OpError around the syscall.
	err := &url.Error{Op: "Head", URL: "http://localhost:9000/whatserver2-media/",
		Err: &net.OpError{Op: "dial", Net: "tcp",
			Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}}

	got := classify(err)
	if !errors.Is(got, ErrUnreachable) {
		t.Fatalf("classified as %v; a refused connection is a store that is down", got)
	}
	if errors.Is(got, ErrRefused) {
		t.Fatal("also reads as refused credentials, which sends somebody to check a key that is fine")
	}
}

func TestANameThatDoesNotResolveIsUnreachable(t *testing.T) {
	got := classify(&url.Error{Op: "Head", URL: "http://minio:9000/",
		Err: &net.DNSError{Err: "no such host", Name: "minio"}})
	if !errors.Is(got, ErrUnreachable) {
		t.Fatalf("classified as %v", got)
	}
}

func TestATimeoutIsUnreachable(t *testing.T) {
	if got := classify(context.DeadlineExceeded); !errors.Is(got, ErrUnreachable) {
		t.Fatalf("classified as %v", got)
	}
}

func TestABadKeyIsRefused(t *testing.T) {
	for _, code := range []string{"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch"} {
		got := classify(minio.ErrorResponse{Code: code, Message: "no"})
		if !errors.Is(got, ErrRefused) {
			t.Errorf("%s classified as %v; the store answered and said no", code, got)
		}
		if errors.Is(got, ErrUnreachable) {
			t.Errorf("%s also reads as unreachable; the fix for that is to start a store that is up", code)
		}
	}
}

func TestAnUnrelatedStoreErrorPassesThrough(t *testing.T) {
	// Not every S3 error is one of the two. A bucket that already belongs to
	// somebody else is neither down nor a bad key, and dressing it as either
	// would point the operator at the wrong thing.
	in := minio.ErrorResponse{Code: "BucketAlreadyOwnedByYou"}
	got := classify(in)
	if errors.Is(got, ErrRefused) || errors.Is(got, ErrUnreachable) {
		t.Fatalf("classified as %v, want it untouched", got)
	}
}
