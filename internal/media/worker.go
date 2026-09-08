package media

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// ObjectStore is the part of object storage this package needs.
//
// An interface rather than the concrete store so the worker can be tested
// against a real fetch and a real database without an S3 anywhere: the useful
// thing to prove is what happens to a claim when a download fails, not that
// minio-go can sign a request.
type ObjectStore interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	Configured() bool
}

// TenantLister names the tenants whose queues to drain.
//
// Injected rather than queried here because row level security scopes every
// media query to one tenant, so the worker has to be told which ones exist.
// That is the isolation working as intended: there is no cross-tenant read,
// not even for a background job.
type TenantLister func(ctx context.Context) ([]uuid.UUID, error)

// Config wires a worker.
type Config struct {
	Media   *store.Media
	Blob    ObjectStore
	Fetcher *Fetcher
	Tenants TenantLister
	Metrics *obs.Metrics
	Log     *slog.Logger

	// Interval is the idle poll. Arrivals nudge the worker directly, so this
	// only has to catch what a nudge missed: rows left by a previous process,
	// and retries whose backoff has expired.
	Interval time.Duration
	// Batch is how many attachments one tenant yields per pass.
	Batch int
	// Concurrency is how many downloads run at once.
	Concurrency int
	// StuckAfter is how long a claim may be held before the sweeper assumes
	// the worker holding it died.
	StuckAfter time.Duration
}

// Worker downloads queued attachments.
type Worker struct {
	cfg   Config
	log   *slog.Logger
	nudge chan struct{}
}

// New builds a worker. A nil blob store is legal and means media is disabled:
// the rows stay queued and are picked up whenever storage is configured, rather
// than being lost.
func New(cfg Config) (*Worker, error) {
	switch {
	case cfg.Media == nil:
		return nil, errors.New("media: a media store is required")
	case cfg.Tenants == nil:
		return nil, errors.New("media: a tenant lister is required")
	case cfg.Fetcher == nil:
		return nil, errors.New("media: a fetcher is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 20
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.StuckAfter <= 0 {
		cfg.StuckAfter = 15 * time.Minute
	}
	return &Worker{cfg: cfg, log: cfg.Log, nudge: make(chan struct{}, 1)}, nil
}

// Enqueue records that an attachment is waiting. It satisfies ingest.MediaQueue.
//
// The database is the queue, not this channel. A row in 'pending' is the whole
// of the work item, so a restart loses nothing and a nudge that is dropped
// because one is already pending costs a wait until the next poll rather than
// an attachment. An in-memory queue would have had to be rebuilt on every boot
// and would have lost work on every crash.
func (w *Worker) Enqueue(_ context.Context, _, _ uuid.UUID) error {
	select {
	case w.nudge <- struct{}{}:
	default:
	}
	return nil
}

// Run drains the queues until the context ends.
func (w *Worker) Run(ctx context.Context) {
	if w.cfg.Blob == nil || !w.cfg.Blob.Configured() {
		w.log.Warn("object storage is not configured; attachments will stay queued " +
			"until it is. Nothing is lost: the queue is the database")
		return
	}
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		w.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-w.nudge:
		}
	}
}

// pass drains every tenant once.
func (w *Worker) pass(ctx context.Context) {
	tenants, err := w.cfg.Tenants(ctx)
	if err != nil {
		w.log.Error("could not list tenants for the media queue", "error", err)
		return
	}
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return
		}
		if n, err := w.cfg.Media.Sweep(ctx, tenant, w.cfg.StuckAfter); err != nil {
			w.log.Error("could not sweep stuck downloads", "tenant", tenant, "error", err)
		} else if n > 0 {
			w.log.Warn("returned stuck downloads to the queue", "tenant", tenant, "count", n)
		}
		w.drain(ctx, tenant)
	}
}

// drain claims and downloads until a tenant has nothing due.
func (w *Worker) drain(ctx context.Context, tenant uuid.UUID) {
	for {
		pending, err := w.cfg.Media.Claim(ctx, tenant, w.cfg.Batch)
		if err != nil {
			w.log.Error("could not claim attachments", "tenant", tenant, "error", err)
			return
		}
		if len(pending) == 0 {
			return
		}

		sem := make(chan struct{}, w.cfg.Concurrency)
		var wg sync.WaitGroup
		for _, p := range pending {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				w.one(ctx, p)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return
		}
	}
}

// one downloads a single attachment.
func (w *Worker) one(ctx context.Context, p store.Pending) {
	key := ObjectKey(p.TenantID, p.FileEncSHA256)

	// The same image forwarded into twenty chats is twenty rows and one
	// object. Checking the database first rather than the bucket keeps this to
	// an indexed local lookup in the common case.
	if existing, size, ok, err := w.cfg.Media.AdoptExisting(ctx, p.TenantID, p.FileEncSHA256); err == nil && ok {
		if err := w.cfg.Media.MarkDone(ctx, p.TenantID, p.MessageUID, existing, size); err != nil {
			w.log.Error("could not record a deduplicated attachment", "error", err)
			return
		}
		w.count("deduplicated")
		return
	}

	file, size, err := w.cfg.Fetcher.Fetch(ctx, p)
	if err != nil {
		w.fail(ctx, p, err)
		return
	}
	defer func() {
		name := file.Name()
		//nolint:errcheck // the ciphertext is uploaded; this temp file is spent
		_ = file.Close()
		//nolint:errcheck // best effort: a leftover temp file is swept by the OS
		_ = os.Remove(name)
	}()

	if err := w.cfg.Blob.Put(ctx, key, file, size); err != nil {
		w.log.Error("could not store an attachment",
			"message", p.MessageUID, "error", err)
		w.fail(ctx, p, err)
		return
	}
	if err := w.cfg.Media.MarkDone(ctx, p.TenantID, p.MessageUID, key, size); err != nil {
		// The bytes are stored and the row still says downloading. The sweeper
		// returns it to the queue, and the next attempt finds the object
		// already there — which is why the object key is derived from the
		// content rather than being random.
		w.log.Error("stored an attachment but could not record it",
			"message", p.MessageUID, "object", key, "error", err)
		return
	}
	w.count("stored")
	if w.cfg.Metrics != nil {
		w.cfg.Metrics.MediaBytes.Add(float64(size))
	}
}

// fail records a download failure and decides whether to try again.
func (w *Worker) fail(ctx context.Context, p store.Pending, cause error) {
	permanent := errors.Is(cause, ErrGone) || errors.Is(cause, ErrTooLarge)
	// Corrupt bytes are worth one more try — a truncated response is a
	// plausible transport failure — but not many. After a few the bytes on
	// the CDN are simply not what the sender published.
	if errors.Is(cause, ErrCorrupt) && p.Attempts >= 2 {
		permanent = true
	}
	if err := w.cfg.Media.MarkFailed(ctx, p.TenantID, p.MessageUID,
		cause.Error(), permanent, backoff(p.Attempts)); err != nil {
		w.log.Error("could not record a failed download", "error", err)
	}
	status := "failed"
	if permanent {
		status = "gone"
		w.log.Warn("an attachment will not be retried",
			"message", p.MessageUID, "reason", cause)
	}
	w.count(status)
}

func (w *Worker) count(status string) {
	if w.cfg.Metrics != nil {
		w.cfg.Metrics.MediaDownloads.WithLabelValues(status).Inc()
	}
}

// backoff spaces out retries. One minute, then doubling to about an hour.
func backoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 6 {
		attempts = 6
	}
	return time.Duration(1<<attempts) * time.Minute
}

// ObjectKey is where an attachment's ciphertext lives.
//
// Content-addressed by the hash of the ciphertext, so the same file arriving
// twice is stored once — and prefixed by tenant, so it is stored once *per
// tenant*. Sharing one object between tenants would save space and would mean
// one tenant's deletion could empty another's attachment, and that the presence
// of a key would answer "does anyone else here have this exact file".
//
// The two-character shard keeps listings usable in buckets that page them.
func ObjectKey(tenant uuid.UUID, encSHA []byte) string {
	h := hex.EncodeToString(encSHA)
	if len(h) < 2 {
		// A row with no published hash cannot be content-addressed. It also
		// cannot be verified, so the fetcher will not have got here.
		return fmt.Sprintf("%s/unhashed/%s", tenant, h)
	}
	return fmt.Sprintf("%s/%s/%s", tenant, h[:2], h)
}
