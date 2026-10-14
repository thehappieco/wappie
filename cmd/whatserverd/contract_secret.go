package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/thcseal"
	"golang.org/x/term"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
)

// whatserverd contract-secret is the root half of the secret's life
// (README 7.3; docs/contract.md, "The secret"), which commercial's
// contract-secret.sh runs at the owner's prompt on the host, never a kit.
// It opens no database and reads no .env: of runtime.env it takes the two
// KMS settings alone (config.ParseDotEnv), so the root process never holds
// the DSN, the SMTP password or any other secret in its environment. The
// secret itself arrives only on stdin, from platform-cli's pipe, and leaves
// only sealed: nothing prints it, logs it or writes it in the clear.
//
//	seal --slot current|other --dir D --env-file F   seal stdin into a slot
//	seal --check-kms --env-file F                    the key, end to end, in memory
//	promote --dir D                                  next -> promoted (Linux)
//	unpromote --dir D                                promoted -> next (Linux)
//	drop --dir D                                     next|promoted -> steady
//	capabilities                                     what this binary handles

// secretCommand is the command's world, so its tests can give it theirs.
type secretCommand struct {
	stdin io.Reader
	// stdinTTY reports whether stdin is a terminal: a secret is never
	// typed or pasted, only piped.
	stdinTTY    func() bool
	stdout      io.Writer
	stderr      io.Writer
	openWrapper membership.OpenWrapper
	// exchange swaps two files of a directory in one step
	// (renameat2(RENAME_EXCHANGE), Linux only).
	exchange func(dir, a, b string) error
	// noCore stops this process from ever dumping core: the secret is in
	// its memory.
	noCore func() error
}

func defaultSecretCommand() secretCommand {
	return secretCommand{
		stdin:       os.Stdin,
		stdinTTY:    func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }, //nolint:gosec // G115: a file descriptor fits an int
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		openWrapper: openKMS,
		exchange:    exchangeFiles,
		noCore: func() error {
			return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
		},
	}
}

// The exit status seal gives an empty stdin, apart from every other
// failure, so the installer can tell "platform-cli gave nothing" from a
// secret it refused.
const exitNoInput = 4

// maxSecretInput is the most seal reads: 43 characters and a newline, with
// room for nothing much else.
const maxSecretInput = 64

// kmsSettings are the only settings seal takes from the env file.
const (
	envKMSKeyARN = "WS_CONTRACT_KMS_KEY_ARN"
	envKMSRegion = "WS_CONTRACT_KMS_REGION"
)

func contractSecret(args []string, c secretCommand) error {
	if len(args) == 0 {
		return usageError{arg: "contract-secret"}
	}
	if args[0] == "capabilities" {
		if len(args) != 1 {
			return usageError{arg: "contract-secret " + strings.Join(args, " ")}
		}
		// The installer runs this on the running server's own binary before
		// it signals: a binary without the line exits on SIGHUP.
		//nolint:errcheck // writing to stdout; the installer reads it
		fmt.Fprintln(c.stdout, "sighup")
		return nil
	}
	switch args[0] {
	case "seal", "promote", "unpromote", "drop":
	default:
		return usageError{arg: "contract-secret " + strings.Join(args, " ")}
	}
	if err := c.noCore(); err != nil {
		return fmt.Errorf("contract-secret: core dumps could not be turned off: %w", err)
	}
	switch args[0] {
	case "seal":
		return c.seal(args[1:])
	case "promote":
		return c.swap(args[1:], "promote", membership.StateNext, membership.StatePromoted)
	case "unpromote":
		return c.swap(args[1:], "unpromote", membership.StatePromoted, membership.StateNext)
	case "drop":
		return c.drop(args[1:])
	}
	return usageError{arg: "contract-secret " + strings.Join(args, " ")}
}

func (c secretCommand) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("contract-secret "+name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

// sealDir opens --dir and reads where its files stand.
func sealDir(path string) (membership.SealDir, membership.SealState, error) {
	if path == "" {
		return "", "", errors.New("--dir is required")
	}
	dir := membership.SealDir(path)
	if err := dir.Check(); err != nil {
		return "", "", err
	}
	state, err := dir.State()
	return dir, state, err
}

func (c secretCommand) seal(args []string) error {
	fs := c.flags("seal")
	slot := fs.String("slot", "", "current (the first install) or other (a rotation's next secret)")
	dirPath := fs.String("dir", "", "the sealed directory, /opt/wappie/sealed")
	envFile := fs.String("env-file", "", "runtime.env, read for WS_CONTRACT_KMS_KEY_ARN and WS_CONTRACT_KMS_REGION only")
	checkKMS := fs.Bool("check-kms", false, "seal and open 32 random bytes in memory, under the real context: the key works")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract-secret seal " + strings.Join(fs.Args(), " ")}
	}
	region, keyARN, err := readKMSSettings(*envFile)
	if err != nil {
		return fmt.Errorf("contract-secret seal: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if *checkKMS {
		if *slot != "" || *dirPath != "" {
			return errors.New("contract-secret seal --check-kms takes --env-file only")
		}
		return c.checkKMS(ctx, region, keyARN)
	}

	// Out of turn is refused before the secret is read: the pipe's secret is
	// never taken into this process for a step that cannot happen.
	dir, state, err := sealDir(*dirPath)
	if err != nil {
		return fmt.Errorf("contract-secret seal: %w", err)
	}
	var name string
	var next membership.SealState
	switch *slot {
	case "current":
		if state != membership.StateNone {
			return errors.New("contract-secret seal: a current secret is installed already (reinstall removes it first)")
		}
		name, next = membership.SecretFileName, membership.StateSteady
	case "other":
		if state != membership.StateSteady {
			return fmt.Errorf("contract-secret seal: --slot other needs the state steady, not %q", stateWord(state))
		}
		name, next = membership.SecretOtherFileName, membership.StateNext
	default:
		return errors.New("contract-secret seal: --slot must be current or other")
	}
	if c.stdinTTY() {
		return errors.New("contract-secret seal: stdin is a terminal: the secret comes only through platform-cli's pipe, never typed or pasted")
	}
	raw, err := io.ReadAll(io.LimitReader(c.stdin, maxSecretInput+1))
	defer clear(raw)
	if err != nil {
		return fmt.Errorf("contract-secret seal: read stdin: %w", err)
	}
	if len(raw) == 0 {
		return exitError{code: exitNoInput, err: errors.New("contract-secret seal: no input")}
	}
	if len(raw) > maxSecretInput {
		return fmt.Errorf("contract-secret seal: more than %d bytes on stdin: not a contract secret", maxSecretInput)
	}
	secret := string(bytes.TrimSuffix(raw, []byte("\n")))
	// The shape first, before KMS is asked anything; ErrSecret's text
	// never echoes a value.
	if err := kc.CheckSecrets(secret, ""); err != nil {
		return fmt.Errorf("contract-secret seal: %w", err)
	}

	w, err := c.openWrapper(ctx, region, keyARN)
	if err != nil {
		return fmt.Errorf("contract-secret seal: kms: %w", err)
	}
	// The other secret must differ from the current one: open it to see.
	current, other := secret, ""
	if *slot == "other" {
		envelope, err := os.ReadFile(dir.Path(membership.SecretFileName))
		if err != nil {
			return fmt.Errorf("contract-secret seal: read the current secret: %w", err)
		}
		plain, err := thcseal.Open(ctx, w, membership.SealContext, envelope)
		if err != nil {
			return fmt.Errorf("contract-secret seal: open the current secret: %w", err)
		}
		current, other = string(plain), secret
		clear(plain)
	}
	if err := kc.CheckSecrets(current, other); err != nil {
		return fmt.Errorf("contract-secret seal: %w", err)
	}
	envelope, err := thcseal.Seal(ctx, w, membership.SealContext, []byte(secret))
	if err != nil {
		return fmt.Errorf("contract-secret seal: seal: %w", err)
	}
	back, err := thcseal.Open(ctx, w, membership.SealContext, envelope)
	if err != nil || string(back) != secret {
		return errors.New("contract-secret seal: the envelope does not open to the secret again; nothing written")
	}
	clear(back)
	if err := dir.WriteFile(name, envelope); err != nil {
		return fmt.Errorf("contract-secret seal: write %s: %w", name, err)
	}
	if err := dir.WriteState(next); err != nil {
		return fmt.Errorf("contract-secret seal: write the state: %w", err)
	}
	//nolint:errcheck // writing to stdout; the installer reads it
	fmt.Fprintf(c.stdout, "sealed %s %s\n", *slot, membership.Fingerprint(envelope))
	return nil
}

// checkKMS is seal --check-kms: the key, as wappie-api will use it, in
// memory. It names the step that failed: describe (the key or the role's
// DescribeKey), generate (GenerateDataKey under the context) or decrypt.
func (c secretCommand) checkKMS(ctx context.Context, region, keyARN string) error {
	w, err := c.openWrapper(ctx, region, keyARN)
	if err != nil {
		return fmt.Errorf("kms: describe: %w", err)
	}
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return err
	}
	envelope, err := thcseal.Seal(ctx, w, membership.SealContext, probe)
	if err != nil {
		return fmt.Errorf("kms: generate: %w", err)
	}
	back, err := thcseal.Open(ctx, w, membership.SealContext, envelope)
	if err != nil {
		return fmt.Errorf("kms: decrypt: %w", err)
	}
	if !bytes.Equal(back, probe) {
		return errors.New("kms: decrypt: the envelope opened to other bytes")
	}
	//nolint:errcheck // writing to stdout; the installer reads it
	fmt.Fprintln(c.stdout, "kms: ok")
	return nil
}

// readKMSSettings takes the key and its region from the env file, and
// nothing else of it.
func readKMSSettings(path string) (region, keyARN string, err error) {
	if path == "" {
		return "", "", errors.New("--env-file is required")
	}
	//nolint:gosec // G304: the installer names runtime.env
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only
	pairs, err := config.ParseDotEnv(f)
	if err != nil {
		return "", "", err
	}
	region, keyARN = strings.TrimSpace(pairs[envKMSRegion]), strings.TrimSpace(pairs[envKMSKeyARN])
	if region == "" || keyARN == "" {
		return "", "", fmt.Errorf("%s needs %s and %s", path, envKMSKeyARN, envKMSRegion)
	}
	return region, keyARN, nil
}

// swap is promote (next -> promoted) and unpromote (promoted -> next): the
// two files exchanged in one step, so a crash leaves both whole, then the
// state.
func (c secretCommand) swap(args []string, name string, from, to membership.SealState) error {
	fs := c.flags(name)
	dirPath := fs.String("dir", "", "the sealed directory, /opt/wappie/sealed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract-secret " + name + " " + strings.Join(fs.Args(), " ")}
	}
	dir, state, err := sealDir(*dirPath)
	if err != nil {
		return fmt.Errorf("contract-secret %s: %w", name, err)
	}
	if state != from {
		return fmt.Errorf("contract-secret %s: needs the state %s, not %q", name, from, stateWord(state))
	}
	if err := c.exchange(string(dir), membership.SecretFileName, membership.SecretOtherFileName); err != nil {
		return fmt.Errorf("contract-secret %s: %w", name, err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("contract-secret %s: %w", name, err)
	}
	if err := dir.WriteState(to); err != nil {
		return fmt.Errorf("contract-secret %s: write the state: %w", name, err)
	}
	return c.printFiles(dir, name)
}

// drop removes the other secret: the old one after the promote (README 7.3
// step 5), or the next one when a rotation is cancelled.
func (c secretCommand) drop(args []string) error {
	fs := c.flags("drop")
	dirPath := fs.String("dir", "", "the sealed directory, /opt/wappie/sealed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract-secret drop " + strings.Join(fs.Args(), " ")}
	}
	dir, state, err := sealDir(*dirPath)
	if err != nil {
		return fmt.Errorf("contract-secret drop: %w", err)
	}
	if state != membership.StateNext && state != membership.StatePromoted {
		return fmt.Errorf("contract-secret drop: needs the state next or promoted, not %q", stateWord(state))
	}
	if err := dir.Remove(membership.SecretOtherFileName); err != nil {
		return fmt.Errorf("contract-secret drop: %w", err)
	}
	if err := dir.WriteState(membership.StateSteady); err != nil {
		return fmt.Errorf("contract-secret drop: write the state: %w", err)
	}
	return c.printFiles(dir, "drop")
}

// printFiles prints the files' fingerprints after a step, as the server
// publishes them, so the installer can compare.
func (c secretCommand) printFiles(dir membership.SealDir, step string) error {
	fp := func(name string) string {
		b, err := os.ReadFile(dir.Path(name))
		if err != nil {
			return "none"
		}
		return membership.Fingerprint(b)
	}
	//nolint:errcheck // writing to stdout; the installer reads it
	fmt.Fprintf(c.stdout, "%s: current %s other %s\n", step, fp(membership.SecretFileName), fp(membership.SecretOtherFileName))
	return nil
}

func stateWord(s membership.SealState) string {
	if s == membership.StateNone {
		return "none"
	}
	return string(s)
}
