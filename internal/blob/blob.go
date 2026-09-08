// Package blob stores the bytes that are too big for a database row.
//
// Everything written here is already encrypted, and not by this process.
// WhatsApp's CDN serves an attachment as AES-256-CBC ciphertext under a
// 32-byte media key, and that is exactly what gets stored — byte for byte, with
// its trailing HMAC intact. The key is sealed into the message row and never
// reaches the object store, so a compromised bucket, a public one, or a copied
// backup yields noise.
//
// That is a stronger property than it sounds, and it is the reason nothing here
// takes a decryption path. The v1 server stored the blob encrypted and then
// wrote the media key in the clear in the column beside it.
package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"whatserver2/internal/config"
)

// ErrNotConfigured reports a store that was never wired.
//
// Returned rather than panicking because a deployment with no object storage is
// legal: the server runs, media stays queued, and the log says so. Failing at
// boot would stop a text-only deployment from starting at all.
var ErrNotConfigured = errors.New("blob: object storage is not configured")

// ErrNotFound reports an object that is not in the bucket.
var ErrNotFound = errors.New("blob: no such object")

// ErrUnreachable reports that the object store did not answer at all: nothing
// listening at the endpoint, a name that does not resolve, a connection that
// timed out. It is the error of a service that is down, not of a setting that
// is wrong — and the two used to read identically at boot, which sent somebody
// checking their credentials every time Docker had not come up with the machine.
var ErrUnreachable = errors.New("blob: object storage is not reachable")

// ErrRefused reports that the store answered and said no: the access key is
// unknown, the secret does not match, or the account may not see this bucket.
// A boot-time mistake, and it should read like one.
var ErrRefused = errors.New("blob: object storage refused the credentials")

// Store is object storage.
type Store struct {
	client *minio.Client
	bucket string
}

// New builds a store from configuration. A store that is not configured is
// returned as nil, which every method below tolerates.
func New(cfg config.Storage) (*Store, error) {
	if !cfg.Configured {
		return nil, nil
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		// Real AWS. The region belongs in the host name rather than only in
		// the signature, or every request pays a redirect.
		endpoint = fmt.Sprintf("s3.%s.amazonaws.com", cfg.Region)
	}
	// A configured endpoint is commonly pasted with its scheme. Accepting that
	// and deriving UseSSL from it is friendlier than rejecting a URL that is
	// obviously what was meant.
	secure := cfg.UseSSL
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" && u.Scheme != "" {
		secure = u.Scheme == "https"
		endpoint = u.Host
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("blob: connect to %s: %w", endpoint, err)
	}
	return &Store{client: client, bucket: cfg.Bucket}, nil
}

// Configured reports whether this store can be used.
func (s *Store) Configured() bool { return s != nil && s.client != nil }

// EnsureBucket creates the bucket when it does not exist.
//
// Called at boot so a fresh MinIO in docker-compose works without a manual
// step, and so a wrong bucket name or a bad key fails immediately with a clear
// message rather than on the first attachment hours later.
func (s *Store) EnsureBucket(ctx context.Context, region string) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("blob: check bucket %s: %w", s.bucket, classify(err))
	}
	if exists {
		return nil
	}
	if err := s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{Region: region}); err != nil {
		return fmt.Errorf("blob: create bucket %s: %w", s.bucket, err)
	}
	return nil
}

// classify wraps a failure to reach the store with the sentinel that says
// which kind it was, so a caller can tell an operator what to do about it.
//
// Two kinds, because they have two remedies. A refusal is answered by the
// store and carries an S3 error code; the fix is in the configuration. An
// unreachable store never answers, and the fix is to start it — or to boot
// without it. Anything else is passed through as it came.
func classify(err error) error {
	if resp := minio.ToErrorResponse(err); resp.Code != "" {
		switch resp.Code {
		case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch",
			"AuthorizationHeaderMalformed", "InvalidToken":
			return fmt.Errorf("%w (%s): %w", ErrRefused, resp.Code, err)
		}
		return err
	}
	var netErr net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &dnsErr),
		errors.As(err, &netErr):
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return err
}

// Put streams size bytes from r into the object store.
//
// No content type is set, deliberately. The bytes are ciphertext; labelling
// them image/jpeg would be both false and a hint about what they hold, and it
// would let a misconfigured public bucket serve them to a browser as media.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("blob: put %s: %w", key, err)
	}
	return nil
}

// Get opens an object for reading. The caller closes it.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if !s.Configured() {
		return nil, 0, ErrNotConfigured
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("blob: get %s: %w", key, err)
	}
	// GetObject is lazy: it reports a missing object on the first read, not
	// here. Stat forces the error out now, so a caller does not start
	// streaming a response and discover the failure halfway through the body.
	info, err := obj.Stat()
	if err != nil {
		//nolint:errcheck // closing after a failed stat; the error is the stat's
		_ = obj.Close()
		if isNotFound(err) {
			return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return nil, 0, fmt.Errorf("blob: stat %s: %w", key, err)
	}
	return obj, info.Size, nil
}

// Exists reports whether an object is already stored.
//
// The download path checks this before fetching: attachments are
// content-addressed by the hash of their ciphertext, so the same forwarded
// image arriving in twenty chats is one object.
func (s *Store) Exists(ctx context.Context, key string) (bool, int64, error) {
	if !s.Configured() {
		return false, 0, ErrNotConfigured
	}
	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("blob: stat %s: %w", key, err)
	}
	return true, info.Size, nil
}

// Delete removes an object.
func (s *Store) Delete(ctx context.Context, key string) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("blob: delete %s: %w", key, err)
	}
	return nil
}

func isNotFound(err error) bool {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		return resp.Code == "NoSuchKey" || resp.StatusCode == 404
	}
	return strings.Contains(err.Error(), "does not exist")
}
