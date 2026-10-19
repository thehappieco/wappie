package membership

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/thcseal"

	"whatserver2/internal/config"
	"whatserver2/internal/membership/membershiptest"
)

const testARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func seal(ctx context.Context, t *testing.T, key *membershiptest.KMS, secret string) []byte {
	t.Helper()
	env, err := thcseal.Seal(ctx, key, SealContext, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func decodeSecret(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// readLoaded parses the published load.
func readLoaded(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("the published load's mode: %v %v", fi.Mode(), err)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			t.Fatalf("line %q", sc.Text())
		}
		out[k] = v
	}
	return out
}

// loaderFixture is a sealed directory, a key, a client and its loader.
type loaderFixture struct {
	dir     string
	key     *membershiptest.KMS
	cfg     config.Contract
	client  *Client
	secrets *Secrets
	logs    *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newLoader(t *testing.T, httpc *http.Client) *loaderFixture {
	t.Helper()
	dir := t.TempDir()
	f := &loaderFixture{dir: dir, key: membershiptest.NewKMS(t), logs: &syncBuffer{}}
	f.cfg = config.Contract{
		Socket: "/run/platform/contract.sock", KMSKeyARN: testARN, KMSRegion: "eu-west-1",
		SecretFile: filepath.Join(dir, SecretFileName), SecretOtherFile: filepath.Join(dir, SecretOtherFileName),
		LoadedFile: filepath.Join(dir, "contract-secrets.loaded"),
	}
	if httpc == nil {
		httpc = &http.Client{}
	}
	f.client = NewClient(httpc, Base, nil)
	f.secrets = &Secrets{Config: f.cfg, Client: f.client, OpenWrapper: f.key.Open,
		Log: slog.New(slog.NewTextHandler(f.logs, nil))}
	return f
}

func (f *loaderFixture) write(ctx context.Context, t *testing.T, path, secret string) string {
	t.Helper()
	return Fingerprint(writeSecret(ctx, t, f.key, true, path, secret))
}

// wantLoaded checks the published load against what the test expects.
func (f *loaderFixture) wantLoaded(t *testing.T, reloads int, current, other, step string) {
	t.Helper()
	got := readLoaded(t, f.cfg.LoadedFile)
	want := map[string]string{"pid": strconv.Itoa(os.Getpid()), "reloads": strconv.Itoa(reloads), "current": current, "other": other, "error": step}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("published %s=%q, want %q (%v)", k, got[k], v, got)
		}
	}
	if _, err := time.Parse(time.RFC3339, got["loaded_at"]); err != nil {
		t.Errorf("loaded_at %q", got["loaded_at"])
	}
}

// TestSealContext: the context both envelopes are sealed under is the one
// the key policy allows (15.3, DB17), written out here rather than read
// from the constant the code seals with.
func TestSealContext(t *testing.T) {
	if SealContext != (kms.Context{Service: "wappie", Env: "prod", Purpose: "contract-secret", Ref: "platform"}) {
		t.Fatalf("%+v", SealContext)
	}
}

// TestSecretLoader is TB7 of release B's plan.
func TestSecretLoader(t *testing.T) {
	ctx := context.Background()
	a, b := membershiptest.Secret(t), membershiptest.Secret(t)

	t.Run("open, check, and the order of Accept", func(t *testing.T) {
		f := newLoader(t, nil)
		if f.secrets.State() != "missing" {
			t.Fatalf("state %s", f.secrets.State())
		}
		// Nothing installed yet: missing, said once at INFO, never ERROR.
		if err := f.secrets.Load(ctx); err == nil || f.secrets.Last().Error != "missing" {
			t.Fatalf("%v %+v", err, f.secrets.Last())
		}
		f.wantLoaded(t, 0, "none", "none", "missing")
		fpA := f.write(ctx, t, f.cfg.SecretFile, a)
		if f.secrets.State() != "pending" {
			t.Fatalf("state %s", f.secrets.State())
		}
		if err := f.secrets.Load(ctx); err != nil {
			t.Fatal(err)
		}
		k := f.client.kit.Load()
		if k.Secret != a || len(k.Accept) != 1 || k.Accept[0] != a || k.App != App || f.client.Rotating() {
			t.Fatal("the current secret alone")
		}
		f.wantLoaded(t, 0, fpA, "none", "none")
		fpB := f.write(ctx, t, f.cfg.SecretOtherFile, b)
		if err := f.secrets.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		k = f.client.kit.Load()
		if k.Secret != a || len(k.Accept) != 2 || k.Accept[0] != a || k.Accept[1] != b || !f.client.Rotating() {
			t.Fatal("Accept is current, then other")
		}
		f.wantLoaded(t, 1, fpA, fpB, "none")
		if f.secrets.State() != "loaded" {
			t.Fatalf("state %s", f.secrets.State())
		}
		logs := f.logs.String()
		if strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "no secret is installed yet") ||
			!strings.Contains(logs, "current="+fpA) || strings.Contains(logs, a) || strings.Contains(logs, b) {
			t.Fatalf("logs: %s", logs)
		}
	})

	t.Run("an equal pair is refused, and the loaded one stays", func(t *testing.T) {
		f := newLoader(t, nil)
		fpA := f.write(ctx, t, f.cfg.SecretFile, a)
		if err := f.secrets.Load(ctx); err != nil {
			t.Fatal(err)
		}
		f.write(ctx, t, f.cfg.SecretOtherFile, a)
		if err := f.secrets.Reload(ctx); !errors.Is(err, kc.ErrSecret) {
			t.Fatalf("%v", err)
		}
		if k := f.client.kit.Load(); k.Secret != a || len(k.Accept) != 1 {
			t.Fatal("the failed reload changed the client")
		}
		f.wantLoaded(t, 1, fpA, "none", "check")
		if logs := f.logs.String(); !strings.Contains(logs, "reload failed") || strings.Contains(logs, a) {
			t.Fatalf("logs: %s", logs)
		}
	})

	t.Run("an unreadable other file fails the reload at open", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads every file")
		}
		f := newLoader(t, nil)
		fpA := f.write(ctx, t, f.cfg.SecretFile, a)
		if err := f.secrets.Load(ctx); err != nil {
			t.Fatal(err)
		}
		f.write(ctx, t, f.cfg.SecretOtherFile, b)
		if err := os.Chmod(f.cfg.SecretOtherFile, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.secrets.Reload(ctx); err == nil {
			t.Fatal("an unreadable file loaded")
		}
		f.wantLoaded(t, 1, fpA, "none", "open")
	})

	t.Run("an envelope of another key or context does not open", func(t *testing.T) {
		f := newLoader(t, nil)
		other := membershiptest.NewKMS(t)
		if err := os.WriteFile(f.cfg.SecretFile, seal(ctx, t, other, a), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := f.secrets.Load(ctx); !errors.Is(err, thcseal.ErrDecrypt) || f.secrets.Last().Error != "open" {
			t.Fatalf("%v %+v", err, f.secrets.Last())
		}
		// The same key, another ref: the key policy's context is one, and an
		// envelope sealed under any other never opens.
		otherRef := kms.Context{Service: "wappie", Env: "prod", Purpose: "contract-secret", Ref: "other"}
		env, err := thcseal.Seal(ctx, f.key, otherRef, []byte(a))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.cfg.SecretFile, env, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := f.secrets.Load(ctx); !errors.Is(err, thcseal.ErrDecrypt) || f.secrets.Last().Error != "open" {
			t.Fatalf("another context: %v %+v", err, f.secrets.Last())
		}
		if err := os.WriteFile(f.cfg.SecretFile, []byte(a+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := f.secrets.Load(ctx); !errors.Is(err, thcseal.ErrMalformed) || f.client.Loaded() {
			t.Fatalf("a plain-text file under a key: %v", err)
		}
	})

	t.Run("a KMS failure keeps the process up and the contract unavailable", func(t *testing.T) {
		f := newLoader(t, nil)
		f.write(ctx, t, f.cfg.SecretFile, a)
		f.key.SetDescribeFail(membershiptest.ErrUnreachable)
		defer restore(&loadRetry, 5*time.Millisecond)()
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { f.secrets.Run(runCtx); close(done) }()
		waitFor(t, func() bool { return f.secrets.Last().Error == "kms" })
		if _, err := f.client.Feed(ctx, 0, 0); !errors.Is(err, ErrNoSecret) || Classify(err) != Unavailable {
			t.Fatalf("%v", err)
		}
		f.wantLoaded(t, 0, "none", "none", "kms")
		// KMS reachable again, the next try loads, and Run ends.
		f.key.SetDescribeFail(nil)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not load once KMS answered")
		}
		cancel()
		if !f.client.Loaded() || f.secrets.Last().Error != "none" {
			t.Fatalf("%+v", f.secrets.Last())
		}
		// A Decrypt that KMS refuses is the key's step, not the file's.
		f.key.SetFail(membershiptest.ErrUnreachable)
		if err := f.secrets.Reload(ctx); err == nil || f.secrets.Last().Error != "kms" {
			t.Fatalf("%v %+v", err, f.secrets.Last())
		}
		if !strings.Contains(f.logs.String(), "level=ERROR") {
			t.Fatal("a KMS failure is said at ERROR")
		}
	})

	t.Run("a KMS refusal is logged by its class, never its text", func(t *testing.T) {
		f := newLoader(t, nil)
		f.write(ctx, t, f.cfg.SecretFile, a)
		denied := apiError{"AccessDeniedException"}
		f.key.SetDescribeFail(fmt.Errorf("awskms: describe key: %w", denied))
		if err := f.secrets.Load(ctx); err == nil || f.secrets.Last().Error != "kms" {
			t.Fatalf("%v %+v", err, f.secrets.Last())
		}
		f.key.SetDescribeFail(nil)
		if err := f.secrets.Load(ctx); err != nil {
			t.Fatal(err)
		}
		f.key.SetFail(fmt.Errorf("awskms: decrypt: %w", denied))
		if err := f.secrets.Reload(ctx); err == nil || f.secrets.Last().Error != "kms" {
			t.Fatalf("%v %+v", err, f.secrets.Last())
		}
		logs := f.logs.String()
		if strings.Count(logs, "class=AccessDeniedException") != 2 || strings.Contains(logs, "arn:") ||
			strings.Contains(logs, "111122223333") || strings.Contains(logs, "assumed-role") {
			t.Fatalf("logs: %s", logs)
		}
	})

	t.Run("a call in flight finishes on its client while SIGHUP swaps it", func(t *testing.T) {
		release := make(chan struct{})
		var mu sync.Mutex
		var signedWith []string
		// The platform answers with the secret that signed each request;
		// the first request waits for the swap.
		srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, err := kc.Scheme().Read(r.Header, time.Now())
			if err != nil {
				http.Error(w, "unsigned", http.StatusUnauthorized)
				return
			}
			secret := ""
			for _, s := range []string{a, b} {
				if kc.Scheme().SignedBy([]string{s}, got, kc.ToPlatform, App, r.Method, r.URL.RequestURI(), nil) {
					secret = s
				}
			}
			mu.Lock()
			first := len(signedWith) == 0
			signedWith = append(signedWith, secret)
			mu.Unlock()
			if first {
				<-release
			}
			body := []byte(`{"subscribed":false}`)
			kc.SignAnswer(w.Header(), secret, App, r.Method, r.URL.RequestURI(), got.Nonce, body, time.Now())
			_, _ = w.Write(body)
		})}
		dir := membershiptest.SocketDir(t)
		ln, err := net.Listen("unix", filepath.Join(dir, "contract.sock"))
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		d := &SocketDialer{Path: filepath.Join(dir, "contract.sock"), Owner: os.Getuid()}
		f := newLoader(t, HTTP(d.DialContext))
		f.write(ctx, t, f.cfg.SecretFile, a)
		if err := f.secrets.Load(ctx); err != nil {
			t.Fatal(err)
		}
		// A real SIGHUP, as the installer sends it: taken, never fatal.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		watchCtx, stopWatch := context.WithCancel(ctx)
		defer stopWatch()
		go f.secrets.Watch(watchCtx, hup)

		inFlight := make(chan error, 1)
		go func() { inFlight <- f.client.Unsubscribe(ctx, "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20") }()
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(signedWith) == 1 })
		// The rotation's end: b alone, a gone.
		fpB := f.write(ctx, t, f.cfg.SecretFile, b)
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return f.secrets.Last().Reloads == 1 })
		f.wantLoaded(t, 1, fpB, "none", "none")
		if k := f.client.kit.Load(); k.Secret != b || len(k.Accept) != 1 {
			t.Fatal("the reload did not swap the client")
		}
		close(release)
		// Signed with a and answered with a: it verifies only on the client
		// it started with, which accepts a.
		if err := <-inFlight; err != nil {
			t.Fatalf("the call in flight: %v", err)
		}
		if err := f.client.Unsubscribe(ctx, "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"); err != nil {
			t.Fatalf("a call after the swap: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(signedWith) != 2 || signedWith[0] != a || signedWith[1] != b {
			t.Fatal("the calls were not signed with the secrets they started with")
		}
	})

	t.Run("development: plain text, never in prod's shape", func(t *testing.T) {
		f := newLoader(t, nil)
		f.cfg.KMSKeyARN, f.cfg.KMSRegion = "", ""
		f.secrets.Config = f.cfg
		if err := os.WriteFile(f.cfg.SecretFile, []byte(a+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := f.secrets.Load(ctx); err != nil {
			t.Fatal(err)
		}
		// A plain-text file has no fingerprint to publish: it would be the
		// secret's.
		f.wantLoaded(t, 0, "plaintext", "none", "none")
		if f.key.Calls() != 0 {
			t.Fatal("KMS was called for a plain-text file")
		}
	})
}

// apiError is an AWS API error as the SDK gives one: a code, and a message
// that names the instance role, the account and the key.
type apiError struct{ code string }

func (e apiError) Error() string {
	return "operation error KMS: Decrypt, https response error StatusCode: 400, api error " + e.code +
		": User: arn:aws:sts::111122223333:assumed-role/thehappie-host/i-0123456789abcdef0 is not authorized to perform: kms:Decrypt on resource: " + testARN
}

func (e apiError) ErrorCode() string { return e.code }

func TestErrorClass(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{fmt.Errorf("membership: the current secret: %w", thcseal.ErrMalformed), "malformed"},
		{thcseal.ErrDecrypt, "decrypt"},
		{thcseal.ErrProviderMismatch, "provider_mismatch"},
		{thcseal.ErrTooLarge, "too_large"},
		{fmt.Errorf("thcseal: unwrap the data key: %w", kms.ErrUnwrap), "unwrap"},
		{kms.ErrInvalidContext, "context"},
		{fmt.Errorf("contract: %w", kc.ErrSecret), "secret_shape"},
		{&fs.PathError{Op: "open", Path: "/opt/wappie/sealed/x", Err: syscall.ENOENT}, "not_found"},
		{&fs.PathError{Op: "open", Path: "/opt/wappie/sealed/x", Err: syscall.EACCES}, "permission"},
		{fmt.Errorf("awskms: describe key: %w", context.DeadlineExceeded), "timeout"},
		{fmt.Errorf("awskms: describe key: %w", apiError{"AccessDeniedException"}), "AccessDeniedException"},
		{apiError{"not a code: arn:aws:kms"}, "other"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, "unreachable"},
		{errors.New("membership: no KMS wrapper"), "other"},
	} {
		if got := ErrorClass(tc.err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

// restore sets *v to x and returns what puts it back.
func restore[T any](v *T, x T) func() {
	old := *v
	*v = x
	return func() { *v = old }
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
