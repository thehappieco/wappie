package membership

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/thcseal"

	"whatserver2/internal/config"
)

// SealContext is the encryption context of both envelopes (DB17): the key
// policy of Wappie's KMS key allows GenerateDataKey and Decrypt under this
// context only. The ref is the secret's source, the constant platform, for
// both files: a ref per file would make the promote a reseal rather than a
// rename, and the root step would then have to open the secret to do it.
var SealContext = kms.Context{Service: "wappie", Env: "prod", Purpose: "contract-secret", Ref: "platform"}

// OpenWrapper opens Wappie's KMS key: awskms.New in production, which
// checks the pinned ARN with DescribeKey first. cmd/whatserverd passes it,
// so this package never compiles the AWS SDK.
type OpenWrapper func(ctx context.Context, region, keyARN string) (kms.Wrapper, error)

// The load's steps, as the log and the published load name a failure.
const (
	StepKMS     = "kms"     // the key: DescribeKey, or KMS refusing a Decrypt
	StepOpen    = "open"    // a file, or an envelope that does not open
	StepCheck   = "check"   // the secrets are not a valid pair (contract.CheckSecrets)
	StepMissing = "missing" // no secret is installed yet: not a failure of the loader
	stepNone    = "none"
)

// How long the lazy load waits between tries: every 30 s for ten
// minutes, then every five. Tests shorten them.
var (
	loadRetry     = 30 * time.Second
	loadRetryLate = 5 * time.Minute
	loadRetryFor  = 10 * time.Minute
	loadTimeout   = 30 * time.Second
)

// Loaded is what the server holds, as it publishes it after every load and
// reload, successful or not: the installer waits for it before it calls a
// step done. Fingerprints of the envelopes say nothing about the secret.
type Loaded struct {
	PID      int
	LoadedAt time.Time
	// Reloads counts the reloads asked for (SIGHUP) since the process
	// started, whatever became of them.
	Reloads int
	// Current and Other are the fingerprints of the envelopes in use
	// (Fingerprint), "none", or "plaintext" for a development file. A
	// reload that fails keeps the ones before it.
	Current, Other string
	// Error is the step the last load failed at, or "none".
	Error string
}

// String is the published file: one key=value per line.
func (l Loaded) String() string {
	return fmt.Sprintf("pid=%d\nloaded_at=%s\nreloads=%d\ncurrent=%s\nother=%s\nerror=%s\n",
		l.PID, l.LoadedAt.UTC().Format(time.RFC3339), l.Reloads, l.Current, l.Other, l.Error)
}

// Secrets loads the contract's secret into a Client, lazily, and again on
// every SIGHUP. Until a load succeeds the contract is unavailable and
// fail-static (README 7.2): nothing here ever stops the process.
type Secrets struct {
	// Config names the files, the key and where to publish (LoadedFile;
	// empty publishes nothing, as contract check, which is not the server,
	// does).
	Config config.Contract
	// Client takes the secrets once they load.
	Client *Client
	// OpenWrapper opens the KMS key, for sealed files.
	OpenWrapper OpenWrapper
	// Class names a failed load's error in the log by one closed word
	// (ErrorClass when nil; cmd/whatserverd's knows awskms's errors too).
	// The log never takes the error's text: a KMS refusal's names the
	// instance role's ARN, the account and the key (DB22).
	Class func(error) string
	Log   *slog.Logger
	// Now is the clock of loaded_at (time.Now when nil).
	Now func() time.Time

	mu      sync.Mutex
	wrapper kms.Wrapper
	reloads int
	held    [2]string // the fingerprints in use
	last    Loaded
	missing bool // the last load found no current file
}

// Load tries once, as the server's first load does.
func (s *Secrets) Load(ctx context.Context) error { return s.load(ctx, false) }

// Reload loads both files again, as a SIGHUP asks. A reload that fails
// keeps the client before it, and says so at ERROR.
func (s *Secrets) Reload(ctx context.Context) error { return s.load(ctx, true) }

// Last is what the last load published.
func (s *Secrets) Last() Loaded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// State is the secret's word on the start line: loaded, missing (no
// current file yet) or pending (a file, not loaded yet or not loadable).
func (s *Secrets) State() string {
	if s.Client.Loaded() {
		return "loaded"
	}
	if _, err := os.Lstat(s.Config.SecretFile); errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	return "pending"
}

// Run is the lazy load: it tries at once, then every 30 s, then every five
// minutes, until a load succeeds or ctx ends. It never stops the process;
// a SIGHUP's Reload may load the secrets in between, and Run then ends.
func (s *Secrets) Run(ctx context.Context) {
	start := time.Now()
	for !s.Client.Loaded() {
		if s.Load(ctx) == nil {
			return
		}
		wait := loadRetry
		if time.Since(start) > loadRetryFor {
			wait = loadRetryLate
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Watch reloads on every signal hup delivers, until ctx ends. The caller
// registers SIGHUP (signal.Notify) before anything else in the process, so
// a SIGHUP never takes Go's default, which is to exit.
func (s *Secrets) Watch(ctx context.Context, hup <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if err := s.Reload(ctx); err != nil {
				// Reload logged and published it; what was loaded before
				// stays in use.
				continue
			}
		}
	}
}

func (s *Secrets) load(ctx context.Context, reload bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reload {
		s.reloads++
	}
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()

	step, err := s.open(ctx)
	out := Loaded{PID: os.Getpid(), LoadedAt: s.clock(), Reloads: s.reloads, Current: s.held[0], Other: s.held[1], Error: stepNone}
	if out.Current == "" {
		out.Current, out.Other = "none", "none"
	}
	if err != nil {
		out.Error = step
	}
	s.last = out
	s.publish(out)
	if s.Log == nil {
		return err
	}
	switch {
	case err == nil:
		s.missing = false
		s.Log.Info("contract: secrets loaded", "current", out.Current, "other", out.Other, "reloads", out.Reloads)
	case step == StepMissing && !reload:
		// Expected between the settings and the owner's install: said once,
		// not alarmed on.
		if !s.missing {
			s.Log.Info("contract: no secret is installed yet; the contract stays unavailable until one is")
		}
		s.missing = true
	case reload && s.Client.Loaded():
		s.Log.Error("contract: secrets reload failed; the secrets loaded before stay in use",
			"step", step, "class", s.class(err), "reloads", out.Reloads)
	default:
		s.Log.Error("contract: secrets not loaded; the contract is unavailable",
			"step", step, "class", s.class(err), "reloads", out.Reloads)
	}
	return err
}

func (s *Secrets) class(err error) string {
	if s.Class != nil {
		return s.Class(err)
	}
	return ErrorClass(err)
}

// ErrorClass names a failed load's error by one closed word, for a log line
// (DB22: codes, never text): the envelope's fault (malformed, decrypt,
// provider_mismatch, too_large, unwrap, context), the secret's
// (secret_shape), a file's (not_found, permission), KMS's own error code
// (AccessDeniedException, KMSInvalidStateException, ...), timeout,
// unreachable, or other. The text, which may name ARNs and the account, is
// the owner's to read at the prompt (contract check, contract-secret).
func ErrorClass(err error) string {
	// An AWS API error carries its code; the SDK is never imported here.
	var api interface{ ErrorCode() string }
	var ne net.Error
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, thcseal.ErrMalformed):
		return "malformed"
	case errors.Is(err, thcseal.ErrDecrypt):
		return "decrypt"
	case errors.Is(err, thcseal.ErrProviderMismatch):
		return "provider_mismatch"
	case errors.Is(err, thcseal.ErrTooLarge):
		return "too_large"
	case errors.Is(err, kms.ErrUnwrap):
		return "unwrap"
	case errors.Is(err, kms.ErrInvalidContext):
		return "context"
	case errors.Is(err, kc.ErrSecret):
		return "secret_shape"
	case errors.Is(err, fs.ErrNotExist):
		return "not_found"
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	case errors.As(err, &api) && errorCode(api.ErrorCode()):
		return api.ErrorCode()
	case errors.As(err, &ne):
		return "unreachable"
	}
	return "other"
}

// errorCode reports a word fit for a log line: an API error's code, never
// a message.
func errorCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, r := range code {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// open reads, opens and checks both files and hands them to the client.
// It returns the step that failed. No error it returns holds a value of
// the secret: the kit's never echo one, and neither do these.
func (s *Secrets) open(ctx context.Context) (string, error) {
	current, err := os.ReadFile(s.Config.SecretFile)
	if errors.Is(err, fs.ErrNotExist) {
		return StepMissing, errors.New("membership: no current secret file")
	}
	if err != nil {
		return StepOpen, fmt.Errorf("membership: read the current secret: %w", err)
	}
	var other []byte
	if s.Config.SecretOtherFile != "" {
		other, err = os.ReadFile(s.Config.SecretOtherFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			other = nil // no rotation under way
		case err != nil:
			return StepOpen, fmt.Errorf("membership: read the other secret: %w", err)
		}
	}
	held := [2]string{Fingerprint(current), "none"}
	if other != nil {
		held[1] = Fingerprint(other)
	}
	var cur, oth string
	if s.Config.Sealed() {
		if s.wrapper == nil {
			if s.OpenWrapper == nil {
				return StepKMS, errors.New("membership: no KMS wrapper")
			}
			w, err := s.OpenWrapper(ctx, s.Config.KMSRegion, s.Config.KMSKeyARN)
			if err != nil {
				return StepKMS, err
			}
			s.wrapper = w
		}
		if cur, err = s.unseal(ctx, current); err != nil {
			return openStep(err), fmt.Errorf("membership: the current secret: %w", err)
		}
		if other != nil {
			if oth, err = s.unseal(ctx, other); err != nil {
				return openStep(err), fmt.Errorf("membership: the other secret: %w", err)
			}
		}
	} else {
		// Development only (Load refuses a contract without a key in
		// prod): the 43 characters as platformd export-contract-secret
		// writes them, one line.
		cur, held[0] = string(bytes.TrimSuffix(current, []byte("\n"))), "plaintext"
		if other != nil {
			oth, held[1] = string(bytes.TrimSuffix(other, []byte("\n"))), "plaintext"
		}
	}
	if err := s.Client.Use(cur, oth); err != nil {
		return StepCheck, err
	}
	s.held = held
	return "", nil
}

// unseal opens one envelope under SealContext.
func (s *Secrets) unseal(ctx context.Context, envelope []byte) (string, error) {
	plain, err := thcseal.Open(ctx, s.wrapper, SealContext, envelope)
	if err != nil {
		return "", err
	}
	out := string(plain)
	clear(plain)
	return out, nil
}

// openStep sorts a failed open: an envelope that is not one, or does not
// open, is the file's fault; anything else (KMS unreachable, access denied)
// the key's.
func openStep(err error) string {
	if errors.Is(err, thcseal.ErrMalformed) || errors.Is(err, thcseal.ErrDecrypt) ||
		errors.Is(err, thcseal.ErrProviderMismatch) || errors.Is(err, thcseal.ErrTooLarge) {
		return StepOpen
	}
	return StepKMS
}

// publish writes the load where the installer and contract status read it,
// through a temporary file and a rename, 0640 in its directory's group.
func (s *Secrets) publish(l Loaded) {
	path := s.Config.LoadedFile
	if path == "" {
		return
	}
	dir := SealDir(filepath.Dir(path))
	if err := dir.WriteFile(filepath.Base(path), []byte(l.String())); err != nil && s.Log != nil {
		s.Log.Error("contract: could not publish the loaded secrets; the installer will not see this load",
			"path", path, "error", err)
	}
}

func (s *Secrets) clock() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
