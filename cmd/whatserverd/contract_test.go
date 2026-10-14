package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/awskms"
	"github.com/thehappieco/kit/thcseal"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
)

// AWS's own documentation placeholders: no real account or key.
const (
	testKeyARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testRegion = "eu-west-1"
)

// secretWorld is a contract-secret command's world in a test: a sealed
// directory, a runtime.env holding other secrets beside the key, an
// in-memory KMS and what the command printed.
type secretWorld struct {
	dir      membership.SealDir
	envFile  string
	key      *membershiptest.KMS
	out, err bytes.Buffer
	opened   []string // the region and ARN each KMS open was given
	noCores  int
}

func newSecretWorld(t *testing.T) *secretWorld {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "sealed")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(root, "runtime.env")
	body := "WS_POSTGRES_DSN=postgres://wappie:hunter2@db/wappie\nWS_SMTP_PASSWORD=smtp-hunter2\n" +
		"WS_CONTRACT_KMS_KEY_ARN=" + testKeyARN + "\nWS_CONTRACT_KMS_REGION=" + testRegion + "\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return &secretWorld{dir: membership.SealDir(dir), envFile: env, key: membershiptest.NewKMS(t)}
}

// cmd is the command, with stdin and whether it is a terminal.
func (w *secretWorld) cmd(stdin string, tty bool) secretCommand {
	w.out.Reset()
	w.err.Reset()
	return secretCommand{
		stdin:    strings.NewReader(stdin),
		stdinTTY: func() bool { return tty },
		stdout:   &w.out,
		stderr:   &w.err,
		openWrapper: func(ctx context.Context, region, arn string) (kms.Wrapper, error) {
			w.opened = append(w.opened, region+" "+arn)
			return w.key.Open(ctx, region, arn)
		},
		exchange: testExchange,
		noCore:   func() error { w.noCores++; return nil },
	}
}

// testExchange is the real exchange on Linux; elsewhere, for the tests
// that play a rotation, the same swap in three renames (promote itself
// refuses there, which TestContractSecretCommands checks).
func testExchange(dir, a, b string) error {
	if runtime.GOOS == "linux" {
		return exchangeFiles(dir, a, b)
	}
	d := membership.SealDir(dir)
	tmp := d.Path("." + a + ".swap")
	if err := os.Rename(d.Path(a), tmp); err != nil {
		return err
	}
	if err := os.Rename(d.Path(b), d.Path(a)); err != nil {
		return err
	}
	return os.Rename(tmp, d.Path(b))
}

func (w *secretWorld) run(t *testing.T, stdin string, args ...string) error {
	t.Helper()
	return contractSecret(args, w.cmd(stdin, false))
}

func (w *secretWorld) seal(t *testing.T, slot, secret string) {
	t.Helper()
	if err := w.run(t, secret+"\n", "seal", "--slot", slot, "--dir", string(w.dir), "--env-file", w.envFile); err != nil {
		t.Fatalf("seal %s: %v (%s)", slot, err, w.err.String())
	}
}

func (w *secretWorld) open(t *testing.T, name string) string {
	t.Helper()
	env, err := os.ReadFile(w.dir.Path(name))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := thcseal.Open(context.Background(), w.key, membership.SealContext, env)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

func (w *secretWorld) state(t *testing.T) membership.SealState {
	t.Helper()
	s, err := w.dir.State()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (w *secretWorld) fingerprint(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(w.dir.Path(name))
	if errors.Is(err, os.ErrNotExist) {
		return "none"
	}
	if err != nil {
		t.Fatal(err)
	}
	return membership.Fingerprint(b)
}

// describeDenied is KMS's SDK refusing DescribeKey, for awskms.NewWithAPI.
type describeDenied struct{}

func (describeDenied) GenerateDataKey(context.Context, *kmssdk.GenerateDataKeyInput, ...func(*kmssdk.Options)) (*kmssdk.GenerateDataKeyOutput, error) {
	return nil, errors.New("not called")
}

func (describeDenied) Decrypt(context.Context, *kmssdk.DecryptInput, ...func(*kmssdk.Options)) (*kmssdk.DecryptOutput, error) {
	return nil, errors.New("not called")
}

func (describeDenied) DescribeKey(_ context.Context, in *kmssdk.DescribeKeyInput, _ ...func(*kmssdk.Options)) (*kmssdk.DescribeKeyOutput, error) {
	return nil, errors.New("AccessDeniedException: not authorized to perform kms:DescribeKey on " + aws.ToString(in.KeyId))
}

// TestContractSecretCommands is TB8 of release B's plan: the root half of
// the secret's life, step by step, out of turn, and never printing it.
func TestContractSecretCommands(t *testing.T) {
	a, b := membershiptest.Secret(t), membershiptest.Secret(t)
	noSecretIn := func(t *testing.T, w *secretWorld, secrets ...string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(w.out.String(), s) || strings.Contains(w.err.String(), s) {
				t.Fatalf("the output holds a secret: %q %q", w.out.String(), w.err.String())
			}
		}
	}

	t.Run("seal current", func(t *testing.T) {
		w := newSecretWorld(t)
		for _, k := range []string{"WS_POSTGRES_DSN", "WS_SMTP_PASSWORD", "WS_CONTRACT_KMS_KEY_ARN", "WS_CONTRACT_KMS_REGION"} {
			t.Setenv(k, "")
			if err := os.Unsetenv(k); err != nil {
				t.Fatal(err)
			}
		}
		// A terminal on stdin is refused, before anything is read or written.
		err := contractSecret([]string{"seal", "--slot", "current", "--dir", string(w.dir), "--env-file", w.envFile}, w.cmd(a, true))
		if err == nil || !strings.Contains(err.Error(), "terminal") || w.state(t) != membership.StateNone {
			t.Fatalf("a terminal: %v", err)
		}
		// Nothing on stdin is 4, apart from every other failure.
		var exit exitError
		err = w.run(t, "", "seal", "--slot", "current", "--dir", string(w.dir), "--env-file", w.envFile)
		if !errors.As(err, &exit) || exit.code != exitNoInput || w.state(t) != membership.StateNone {
			t.Fatalf("no input: %v", err)
		}
		for _, bad := range []string{"not-a-secret\n", a + "=\n", strings.Repeat("A", 65)} {
			err = w.run(t, bad, "seal", "--slot", "current", "--dir", string(w.dir), "--env-file", w.envFile)
			if err == nil || errors.As(err, &exit) || w.state(t) != membership.StateNone {
				t.Fatalf("%q: %v", bad, err)
			}
		}
		w.seal(t, "current", a)
		fi, err := os.Stat(w.dir.Path(membership.SecretFileName))
		if err != nil || fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode %v %v", fi.Mode(), err)
		}
		if w.open(t, membership.SecretFileName) != a || w.state(t) != membership.StateSteady {
			t.Fatal("the envelope does not open to the secret, or the state is not steady")
		}
		if got := w.out.String(); got != "sealed current "+w.fingerprint(t, membership.SecretFileName)+"\n" {
			t.Fatalf("printed %q", got)
		}
		noSecretIn(t, w, a)
		if left, _ := filepath.Glob(w.dir.Path(".*")); len(left) != 0 {
			t.Fatalf("temporary files left: %v", left)
		}
		// Of runtime.env, the key and its region alone, and the process's
		// environment gained nothing.
		if len(w.opened) != 1 || w.opened[0] != testRegion+" "+testKeyARN {
			t.Fatalf("opened %v", w.opened)
		}
		for _, k := range []string{"WS_POSTGRES_DSN", "WS_SMTP_PASSWORD", "WS_CONTRACT_KMS_KEY_ARN", "WS_CONTRACT_KMS_REGION"} {
			if _, set := os.LookupEnv(k); set {
				t.Errorf("the command set %s", k)
			}
		}
		if w.noCores == 0 {
			t.Fatal("core dumps were not turned off")
		}
		// A second install is refused: reinstall removes the files first.
		if err := w.run(t, b+"\n", "seal", "--slot", "current", "--dir", string(w.dir), "--env-file", w.envFile); err == nil {
			t.Fatal("a second current secret")
		}
		if w.open(t, membership.SecretFileName) != a {
			t.Fatal("the refused seal changed the file")
		}
	})

	t.Run("seal other, and every step out of turn", func(t *testing.T) {
		w := newSecretWorld(t)
		dir := string(w.dir)
		refused := func(why string, stdin string, args ...string) {
			t.Helper()
			before := w.state(t)
			if err := w.run(t, stdin, args...); err == nil {
				t.Fatalf("%s: accepted", why)
			}
			if w.state(t) != before {
				t.Fatalf("%s: the refusal changed the state", why)
			}
			noSecretIn(t, w, a, b)
		}
		refused("other before current", b+"\n", "seal", "--slot", "other", "--dir", dir, "--env-file", w.envFile)
		refused("promote with nothing", "", "promote", "--dir", dir)
		refused("drop with nothing", "", "drop", "--dir", dir)
		w.seal(t, "current", a)
		refused("an other equal to the current", a+"\n", "seal", "--slot", "other", "--dir", dir, "--env-file", w.envFile)
		refused("promote in steady", "", "promote", "--dir", dir)
		refused("unpromote in steady", "", "unpromote", "--dir", dir)
		refused("drop in steady", "", "drop", "--dir", dir)
		w.seal(t, "other", b)
		if w.state(t) != membership.StateNext || w.open(t, membership.SecretOtherFileName) != b || w.open(t, membership.SecretFileName) != a {
			t.Fatal("next")
		}
		refused("a second other", membershiptest.Secret(t)+"\n", "seal", "--slot", "other", "--dir", dir, "--env-file", w.envFile)
		refused("unpromote in next", "", "unpromote", "--dir", dir)
		if runtime.GOOS != "linux" {
			// The swap needs renameat2: elsewhere promote refuses, whole.
			err := contractSecret([]string{"promote", "--dir", dir}, func() secretCommand {
				c := w.cmd("", false)
				c.exchange = exchangeFiles
				return c
			}())
			if err == nil || !strings.Contains(err.Error(), "needs Linux") || w.state(t) != membership.StateNext {
				t.Fatalf("promote off Linux: %v", err)
			}
		}
		if err := w.run(t, "", "promote", "--dir", dir); err != nil {
			t.Fatal(err)
		}
		if w.state(t) != membership.StatePromoted || w.open(t, membership.SecretFileName) != b || w.open(t, membership.SecretOtherFileName) != a {
			t.Fatal("promoted")
		}
		if got := w.out.String(); got != "promote: current "+w.fingerprint(t, membership.SecretFileName)+" other "+w.fingerprint(t, membership.SecretOtherFileName)+"\n" {
			t.Fatalf("printed %q", got)
		}
		refused("promote twice", "", "promote", "--dir", dir)
		refused("seal other while promoted", membershiptest.Secret(t)+"\n", "seal", "--slot", "other", "--dir", dir, "--env-file", w.envFile)
		if err := w.run(t, "", "unpromote", "--dir", dir); err != nil {
			t.Fatal(err)
		}
		if w.state(t) != membership.StateNext || w.open(t, membership.SecretFileName) != a {
			t.Fatal("unpromoted")
		}
		if err := w.run(t, "", "promote", "--dir", dir); err != nil {
			t.Fatal(err)
		}
		if err := w.run(t, "", "drop", "--dir", dir); err != nil {
			t.Fatal(err)
		}
		if w.state(t) != membership.StateSteady || w.open(t, membership.SecretFileName) != b || w.fingerprint(t, membership.SecretOtherFileName) != "none" {
			t.Fatal("dropped")
		}
		// Files and state that disagree stop every step.
		if err := os.Remove(w.dir.Path(membership.SecretStateFileName)); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"seal", "--slot", "other", "--dir", dir, "--env-file", w.envFile},
			{"seal", "--slot", "current", "--dir", dir, "--env-file", w.envFile},
			{"promote", "--dir", dir}, {"unpromote", "--dir", dir}, {"drop", "--dir", dir},
		} {
			if err := w.run(t, membershiptest.Secret(t)+"\n", args...); !errors.Is(err, membership.ErrSealDisagree) {
				t.Fatalf("%v: %v", args, err)
			}
		}
	})

	t.Run("check-kms names the step that fails", func(t *testing.T) {
		w := newSecretWorld(t)
		if err := w.run(t, "", "seal", "--check-kms", "--env-file", w.envFile); err != nil || w.out.String() != "kms: ok\n" {
			t.Fatalf("%v %q", err, w.out.String())
		}
		// DescribeKey denied, through the kit's own awskms over a fake SDK.
		c := w.cmd("", false)
		c.openWrapper = func(ctx context.Context, _, arn string) (kms.Wrapper, error) {
			wr, err := awskms.NewWithAPI(ctx, describeDenied{}, arn)
			if err != nil {
				return nil, err
			}
			return wr, nil
		}
		if err := contractSecret([]string{"seal", "--check-kms", "--env-file", w.envFile}, c); err == nil || !strings.HasPrefix(err.Error(), "kms: describe") {
			t.Fatalf("describe: %v", err)
		}
		w.key.SetFail(membershiptest.ErrUnreachable)
		if err := w.run(t, "", "seal", "--check-kms", "--env-file", w.envFile); err == nil || !strings.HasPrefix(err.Error(), "kms: generate") {
			t.Fatalf("generate: %v", err)
		}
		if err := w.run(t, "", "seal", "--check-kms", "--env-file", w.envFile, "--dir", string(w.dir)); err == nil {
			t.Fatal("--check-kms took --dir")
		}
		// An env file without the key is refused.
		bare := filepath.Join(t.TempDir(), "runtime.env")
		if err := os.WriteFile(bare, []byte("WS_POSTGRES_DSN=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := w.run(t, "", "seal", "--check-kms", "--env-file", bare); err == nil || !strings.Contains(err.Error(), "WS_CONTRACT_KMS_KEY_ARN") {
			t.Fatalf("no key: %v", err)
		}
	})

	t.Run("capabilities", func(t *testing.T) {
		w := newSecretWorld(t)
		if err := w.run(t, "", "capabilities"); err != nil || w.out.String() != "sighup\n" {
			t.Fatalf("%v %q", err, w.out.String())
		}
		var usage usageError
		if err := w.run(t, "", "capabilities", "--all"); !errors.As(err, &usage) {
			t.Fatalf("%v", err)
		}
		if err := w.run(t, ""); !errors.As(err, &usage) {
			t.Fatalf("%v", err)
		}
		if err := w.run(t, "", "rotate"); !errors.As(err, &usage) {
			t.Fatalf("%v", err)
		}
	})
}

// rotation is README 7.3 played between the kit's fake platform, on a
// unix socket as in production, and Wappie's side: the root commands, the
// server's loader (reloaded as the installer's SIGHUP asks) and contract
// check's probes, each loading the files afresh as its own process would.
// The installer's rules (contract-secret.sh, which a later phase writes)
// are the functions below, so the probes are tested for what that script
// will act on.
type rotation struct {
	t        *testing.T
	w        *secretWorld
	platform *contracttest.Platform
	served   *membershiptest.Served
	sockDir  string
	server   *membership.Secrets
	client   *membership.Client
}

func newRotation(t *testing.T, current string) *rotation {
	t.Helper()
	old := socketOwner
	socketOwner = os.Getuid()
	t.Cleanup(func() { socketOwner = old })
	r := &rotation{t: t, w: newSecretWorld(t), sockDir: membershiptest.SocketDir(t)}
	r.platform = membershiptest.Platform(t, current, "")
	r.served = membershiptest.Serve(t, r.platform, r.sockDir)
	cfg := config.Contract{
		Socket:     r.served.Path,
		SecretFile: r.w.dir.Path(membership.SecretFileName), SecretOtherFile: r.w.dir.Path(membership.SecretOtherFileName),
		KMSKeyARN: testKeyARN, KMSRegion: testRegion,
		LoadedFile: filepath.Join(t.TempDir(), "contract-secrets.loaded"),
	}
	for k, v := range map[string]string{
		"WS_ENV": "dev", "WS_CONTRACT_SOCKET": cfg.Socket, "WS_CONTRACT_SECRET_FILE": cfg.SecretFile,
		"WS_CONTRACT_SECRET_OTHER_FILE": cfg.SecretOtherFile, "WS_CONTRACT_KMS_KEY_ARN": testKeyARN, "WS_CONTRACT_KMS_REGION": testRegion,
	} {
		t.Setenv(k, v)
	}
	r.client = newContractClient(cfg, nil)
	r.server = &membership.Secrets{Config: cfg, Client: r.client, OpenWrapper: r.w.key.Open}
	return r
}

// check is contract check with a flag, as its own process: its exit status.
func (r *rotation) check(flags ...string) int {
	r.t.Helper()
	var out bytes.Buffer
	err := contractCheck(flags, &out, r.w.key.Open)
	var exit exitError
	switch {
	case err == nil:
		if !strings.HasPrefix(out.String(), "signed answer: generation ") {
			r.t.Fatalf("check %v: %q", flags, out.String())
		}
		return 0
	case errors.As(err, &exit):
		return exit.code
	}
	return 1
}

// signal is the installer's SIGHUP and its wait: the server reloads and
// must hold what is on disk.
func (r *rotation) signal() {
	r.t.Helper()
	if err := r.server.Reload(context.Background()); err != nil {
		r.t.Fatalf("reload: %v", err)
	}
	l := r.server.Last()
	if l.Current != r.w.fingerprint(r.t, membership.SecretFileName) || l.Other != r.w.fingerprint(r.t, membership.SecretOtherFileName) {
		r.t.Fatalf("the server holds %s/%s, not the files", l.Current, l.Other)
	}
}

// feed is the server's own call after each step: none may fail.
func (r *rotation) feed(why string) {
	r.t.Helper()
	if _, err := r.client.Feed(context.Background(), 0, 0); err != nil {
		r.t.Fatalf("%s: the server's feed call failed: %v", why, err)
	}
}

func (r *rotation) install(secret string) {
	r.t.Helper()
	r.w.seal(r.t, "current", secret)
	r.signal()
	if code := r.check(); code != 0 {
		r.t.Fatalf("install: check %d", code)
	}
}

// next is README 7.3 step 2.
func (r *rotation) next(secret string) {
	r.t.Helper()
	r.w.seal(r.t, "other", secret)
	r.signal()
	if code := r.check("--other"); code != 0 {
		r.t.Fatalf("next: check --other %d", code)
	}
}

// promote is step 3.
func (r *rotation) promote() {
	r.t.Helper()
	if code := r.check("--other"); code != 0 {
		r.t.Fatalf("promote: check --other %d", code)
	}
	if err := r.w.run(r.t, "", "promote", "--dir", string(r.w.dir)); err != nil {
		r.t.Fatal(err)
	}
	r.signal()
	if code := r.check(); code != 0 {
		r.t.Fatalf("promote: check %d", code)
	}
}

// drop is step 5: refused unless the platform answers with the secret
// Wappie now signs with (its step 4). It returns the probe's status.
func (r *rotation) drop() int {
	r.t.Helper()
	code := r.check("--only-current")
	if code != 0 {
		return code
	}
	if err := r.w.run(r.t, "", "drop", "--dir", string(r.w.dir)); err != nil {
		r.t.Fatal(err)
	}
	r.signal()
	return 0
}

// cancel is the installer's cancel, from wherever the files stand: it
// returns the first probe's status, and changes nothing unless it is 0.
func (r *rotation) cancel() int {
	r.t.Helper()
	switch r.w.state(r.t) {
	case membership.StateNext:
		if code := r.check("--only-current"); code != 0 {
			return code
		}
	case membership.StatePromoted:
		if code := r.check("--only-other"); code != 0 {
			return code
		}
		if err := r.w.run(r.t, "", "unpromote", "--dir", string(r.w.dir)); err != nil {
			r.t.Fatal(err)
		}
		r.signal()
		if code := r.check("--only-current"); code != 0 {
			r.t.Fatalf("cancel: after unpromote, check --only-current %d", code)
		}
	default:
		return 0
	}
	if err := r.w.run(r.t, "", "drop", "--dir", string(r.w.dir)); err != nil {
		r.t.Fatal(err)
	}
	r.signal()
	if code := r.check("--only-current"); code != 0 {
		r.t.Fatalf("cancel: after drop, check --only-current %d", code)
	}
	return 0
}

// unchanged is the files' fingerprints and state, to compare across a
// refusal.
func (r *rotation) unchanged() func() {
	r.t.Helper()
	state := r.w.state(r.t)
	cur, oth := r.w.fingerprint(r.t, membership.SecretFileName), r.w.fingerprint(r.t, membership.SecretOtherFileName)
	return func() {
		r.t.Helper()
		if r.w.state(r.t) != state || r.w.fingerprint(r.t, membership.SecretFileName) != cur || r.w.fingerprint(r.t, membership.SecretOtherFileName) != oth {
			r.t.Fatal("a refused step changed the files")
		}
	}
}

func (r *rotation) setSecrets(current, other string) {
	r.t.Helper()
	if err := r.platform.SetSecrets("wappie", current, other); err != nil {
		r.t.Fatal(err)
	}
}

// TestRotationNeverFails is TB9 of release B's plan.
func TestRotationNeverFails(t *testing.T) {
	a, b := membershiptest.Secret(t), membershiptest.Secret(t)

	t.Run("the six steps, a call after each", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		r.feed("installed")
		r.setSecrets(a, b) // 1: secret-next
		r.feed("step 1")
		r.next(b) // 2
		r.feed("step 2")
		r.promote() // 3
		r.feed("step 3")
		r.setSecrets(b, a) // 4: secret-promote
		r.feed("step 4")
		if code := r.drop(); code != 0 { // 5
			t.Fatalf("drop after step 4: %d", code)
		}
		r.feed("step 5")
		r.setSecrets(b, "") // 6: secret-drop
		r.feed("step 6")
		if code := r.check(); code != 0 || r.w.state(t) != membership.StateSteady || r.w.open(t, membership.SecretFileName) != b {
			t.Fatalf("after the rotation: %d %s", code, r.w.state(t))
		}
	})

	t.Run("a drop before the platform's step 4 is refused", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		r.setSecrets(a, b)
		r.next(b)
		r.promote()
		same := r.unchanged()
		if code := r.drop(); code != membership.ProbeExcluded {
			t.Fatalf("drop before step 4: %d", code)
		}
		same()
		r.feed("after the refused drop")
	})

	t.Run("cancel after step 2, either order", func(t *testing.T) {
		for _, platformFirst := range []bool{true, false} {
			r := newRotation(t, a)
			r.install(a)
			r.setSecrets(a, b)
			r.next(b)
			if platformFirst {
				r.setSecrets(a, "") // secret-cancel
				r.feed("the platform cancelled")
			}
			if code := r.cancel(); code != 0 {
				t.Fatalf("cancel from next (platform first %v): %d", platformFirst, code)
			}
			r.feed("Wappie cancelled")
			if !platformFirst {
				r.setSecrets(a, "")
			}
			r.feed("both cancelled")
			if r.w.state(t) != membership.StateSteady || r.w.open(t, membership.SecretFileName) != a {
				t.Fatal("cancel from next keeps the old secret alone")
			}
		}
	})

	t.Run("cancel after Wappie's step 3, the platform's cancel after Wappie's", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		r.setSecrets(a, b)
		r.next(b)
		r.promote()
		if code := r.cancel(); code != 0 {
			t.Fatalf("cancel from promoted: %d", code)
		}
		r.feed("Wappie cancelled")
		r.setSecrets(a, "")
		r.feed("the platform cancelled")
		if r.w.state(t) != membership.StateSteady || r.w.open(t, membership.SecretFileName) != a {
			t.Fatal("cancel from promoted brings the old secret back alone")
		}
	})

	t.Run("cancel after Wappie's step 3, the platform's cancel first", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		r.setSecrets(a, b)
		r.next(b)
		r.promote()
		r.setSecrets(a, "") // the platform cancelled first: Wappie's next secret is refused
		if _, err := r.client.Feed(context.Background(), 0, 0); membership.Classify(err) != membership.Unverified {
			t.Fatalf("signing with the cancelled secret: %v", err)
		}
		if code := r.check("--only-other"); code != 0 {
			t.Fatalf("--only-other passes when the platform cancelled first: %d", code)
		}
		if code := r.cancel(); code != 0 {
			t.Fatalf("cancel as repair: %d", code)
		}
		r.feed("repaired")
	})

	t.Run("a cancel after the platform's step 4 is refused", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		r.setSecrets(a, b)
		r.next(b)
		r.promote()
		r.setSecrets(b, a) // secret-promote
		same := r.unchanged()
		if code := r.cancel(); code != membership.ProbeExcluded {
			t.Fatalf("cancel after step 4: %d", code)
		}
		same()
		r.feed("after the refused cancel")
	})

	t.Run("the platform promoting before Wappie's step 3", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		r.setSecrets(a, b)
		r.next(b)
		r.setSecrets(b, a) // promoted early
		r.feed("the platform promoted early")
		same := r.unchanged()
		if code := r.cancel(); code != membership.ProbeExcluded {
			t.Fatalf("cancel from next after an early promote: %d", code)
		}
		same()
		if r.w.fingerprint(t, membership.SecretOtherFileName) == "none" {
			t.Fatal("the next secret was dropped")
		}
	})

	t.Run("the socket absent during a cancel", func(t *testing.T) {
		for _, promoted := range []bool{false, true} {
			r := newRotation(t, a)
			r.install(a)
			r.setSecrets(a, b)
			r.next(b)
			if promoted {
				r.promote()
			}
			r.served.Stop()
			same := r.unchanged()
			if code := r.cancel(); code != membership.ProbeNoAnswer {
				t.Fatalf("cancel without the socket (promoted %v): %d", promoted, code)
			}
			same()
			// The socket back, the cancel goes.
			r.served = membershiptest.Serve(t, r.platform, r.sockDir)
			if code := r.cancel(); code != 0 {
				t.Fatalf("cancel with the socket back: %d", code)
			}
			r.feed("after the cancel")
		}
	})

	t.Run("the probes' exit statuses", func(t *testing.T) {
		r := newRotation(t, a)
		r.install(a)
		if code := r.check("--other"); code != membership.ProbeFailed {
			t.Fatalf("--other without an other secret: %d", code)
		}
		if code := r.check("--only-other"); code != membership.ProbeFailed {
			t.Fatalf("--only-other without an other secret: %d", code)
		}
		if code := r.check("--other", "--only-current"); code != membership.ProbeFailed {
			t.Fatalf("two flags: %d", code)
		}
		r.setSecrets(membershiptest.Secret(t), "") // the platform holds another secret
		if code := r.check(); code != membership.ProbeRejected {
			t.Fatalf("a secret the platform refuses: %d", code)
		}
		r.served.Stop()
		if code := r.check(); code != membership.ProbeNoAnswer {
			t.Fatalf("no socket: %d", code)
		}
		r.served = membershiptest.Serve(t, r.platform, r.sockDir)
		r.setSecrets(a, "")
		if code := r.check("--only-current"); code != 0 {
			t.Fatalf("--only-current, steady: %d", code)
		}
		// The platform not serving wappie: an unsigned 404.
		r.served.Stop()
		empty, err := contracttest.New(contracttest.Options{})
		if err != nil {
			t.Fatal(err)
		}
		r.served = membershiptest.Serve(t, empty, r.sockDir)
		if code := r.check(); code != membership.ProbeFailed {
			t.Fatalf("an unmapped app: %d", code)
		}
	})
}

// TestContractCheckNeedsATransport: without the settings, contract check
// refuses before it reads anything.
func TestContractCheckNeedsATransport(t *testing.T) {
	for _, k := range []string{"WS_CONTRACT_SOCKET", "WS_CONTRACT_ADDR", "WS_CONTRACT_SECRET_FILE", "WS_CONTRACT_SECRET_OTHER_FILE",
		"WS_CONTRACT_KMS_KEY_ARN", "WS_CONTRACT_KMS_REGION"} {
		t.Setenv(k, "")
	}
	t.Setenv("WS_ENV", "dev")
	var out bytes.Buffer
	if err := contractCheck(nil, &out, nil); err == nil || !strings.Contains(err.Error(), "no transport") {
		t.Fatalf("%v", err)
	}
	var usage usageError
	if err := contractCommand(nil, &out); !errors.As(err, &usage) {
		t.Fatalf("%v", err)
	}
	if err := contractCommand([]string{"status"}, &out); !errors.As(err, &usage) {
		t.Fatalf("%v", err)
	}
	if err := contractCheck([]string{"extra"}, &out, nil); !errors.As(err, &usage) {
		t.Fatalf("%v", err)
	}
}
