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
//	reset --dir D                                    any state -> none (reinstall)
//	capabilities                                     what this binary handles
//
// A crash between a step's file and its state leaves them disagreeing,
// which every command refuses, but for the step that stopped there: seal
// --slot other, promote, unpromote and drop finish what an earlier run of
// themselves left half done. Anything else that disagrees (an install a
// crash stopped, a hand in the directory) goes by reset, a reinstall's
// first half.

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
	case "seal", "promote", "unpromote", "drop", "reset":
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
		return c.swap(args[1:], "promote", membership.SwapPromoting, membership.StateNext, membership.StatePromoted)
	case "unpromote":
		return c.swap(args[1:], "unpromote", membership.SwapUnpromoting, membership.StatePromoted, membership.StateNext)
	case "drop":
		return c.drop(args[1:])
	case "reset":
		return c.reset(args[1:])
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
	dir, err := openSealDir(path)
	if err != nil {
		return "", "", err
	}
	state, err := dir.State()
	return dir, state, err
}

// openSealDir checks --dir, and reads nothing in it.
func openSealDir(path string) (membership.SealDir, error) {
	if path == "" {
		return "", errors.New("--dir is required")
	}
	dir := membership.SealDir(path)
	if err := dir.Check(); err != nil {
		return "", err
	}
	return dir, nil
}

// halfDone reads a directory that State refused for the one disagreement a
// crash leaves inside a step that changes a file and then the state: the
// files already as the step leaves them (current, other), and the state
// file still at one of the states the step starts from, which it returns.
func halfDone(dir membership.SealDir, before []membership.SealState, current, other bool) (membership.SealState, bool) {
	state, cur, oth, err := dir.Files()
	if err != nil || cur != current || oth != other {
		return "", false
	}
	for _, b := range before {
		if state == b {
			return state, true
		}
	}
	return "", false
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
	var name string
	var before, next membership.SealState
	switch *slot {
	case "current":
		name, before, next = membership.SecretFileName, membership.StateNone, membership.StateSteady
	case "other":
		name, before, next = membership.SecretOtherFileName, membership.StateSteady, membership.StateNext
	default:
		return errors.New("contract-secret seal: --slot must be current or other")
	}
	dir, state, err := sealDir(*dirPath)
	// An earlier seal of the other slot that wrote its file and stopped
	// before its state left the file unrecorded, and the server takes a file
	// only at its next load: this seal replaces it. (A current file without
	// a state is a reinstall's: reset, then seal.)
	replacing := false
	if errors.Is(err, membership.ErrSealDisagree) && *slot == "other" {
		state, replacing = halfDone(dir, []membership.SealState{before}, true, true)
		if replacing {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("contract-secret seal: %w", err)
	}
	switch {
	case state == before:
	case *slot == "current":
		return errors.New("contract-secret seal: a current secret is installed already (reinstall resets the directory first: contract-secret reset)")
	default:
		return fmt.Errorf("contract-secret seal: --slot other needs the state steady, not %q", stateWord(state))
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
	if replacing {
		//nolint:errcheck // a note for the owner; stdout keeps its one line
		fmt.Fprintf(c.stderr, "contract-secret seal: replaced the %s file an earlier seal wrote and did not record\n", *slot)
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
	pairs, err := config.ParseDotEnv(f, envKMSKeyARN, envKMSRegion)
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
// swap's intent first (its word and the fingerprint of the file it makes
// current), then the two files exchanged in one step, so a crash leaves
// both whole, then the state. A crash after the intent leaves it in the
// state file, and running the same swap again finishes it: the files'
// fingerprints say whether they were exchanged already. Without the
// intent, a run after a crash that came after the exchange would swap the
// files back and record the state the first run meant: current would hold
// the old secret, and every later step would carry the mismatch.
func (c secretCommand) swap(args []string, name, word string, from, to membership.SealState) error {
	fs := c.flags(name)
	dirPath := fs.String("dir", "", "the sealed directory, /opt/wappie/sealed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract-secret " + name + " " + strings.Join(fs.Args(), " ")}
	}
	dir, state, err := sealDir(*dirPath)
	makesCurrent, resuming := "", false
	if errors.Is(err, membership.ErrSealDisagree) {
		if makesCurrent, resuming = swapIntent(dir, word); resuming {
			state, err = from, nil
		}
	}
	if err != nil {
		return fmt.Errorf("contract-secret %s: %w", name, err)
	}
	if state != from {
		return fmt.Errorf("contract-secret %s: needs the state %s, not %q", name, from, stateWord(state))
	}
	current, err := fileFingerprint(dir, membership.SecretFileName)
	if err != nil {
		return fmt.Errorf("contract-secret %s: %w", name, err)
	}
	other, err := fileFingerprint(dir, membership.SecretOtherFileName)
	if err != nil {
		return fmt.Errorf("contract-secret %s: %w", name, err)
	}
	if current == other {
		return fmt.Errorf("contract-secret %s: %w: both files are one envelope", name, membership.ErrSealDisagree)
	}
	if !resuming {
		makesCurrent = other
		if err := dir.WriteState(membership.SwapIntent(word, makesCurrent)); err != nil {
			return fmt.Errorf("contract-secret %s: write the intent: %w", name, err)
		}
	}
	switch makesCurrent {
	case current:
		// An earlier run exchanged the files and stopped before the state.
	case other:
		if err := c.exchange(string(dir), membership.SecretFileName, membership.SecretOtherFileName); err != nil {
			// A refused exchange (not Linux, ...) changed nothing: the
			// state goes back to where it was, so nothing is half done.
			if now, ferr := fileFingerprint(dir, membership.SecretFileName); ferr == nil && now == current {
				if werr := dir.WriteState(from); werr != nil {
					err = errors.Join(err, werr)
				}
			}
			return fmt.Errorf("contract-secret %s: %w", name, err)
		}
		if err := dir.Sync(); err != nil {
			return fmt.Errorf("contract-secret %s: %w", name, err)
		}
	default:
		return fmt.Errorf("contract-secret %s: %w: the intent names %s, and the files are current=%s other=%s",
			name, membership.ErrSealDisagree, makesCurrent, current, other)
	}
	if err := dir.WriteState(to); err != nil {
		return fmt.Errorf("contract-secret %s: write the state: %w", name, err)
	}
	if resuming {
		//nolint:errcheck // a note for the owner; stdout keeps its one line
		fmt.Fprintf(c.stderr, "contract-secret %s: finished an earlier %s that stopped before it recorded its state\n", name, name)
	}
	return c.printFiles(dir, name)
}

// swapIntent reads a directory that State refused for the disagreement a
// crash leaves inside a swap: both files there, and the state file holding
// this swap's intent, whose fingerprint it returns.
func swapIntent(dir membership.SealDir, word string) (string, bool) {
	state, current, other, err := dir.Files()
	if err != nil || !current || !other {
		return "", false
	}
	w, makesCurrent, ok := state.Intent()
	if !ok || w != word {
		return "", false
	}
	return makesCurrent, true
}

// fileFingerprint is the fingerprint of an envelope in the directory.
func fileFingerprint(dir membership.SealDir, name string) (string, error) {
	b, err := os.ReadFile(dir.Path(name))
	if err != nil {
		return "", err
	}
	return membership.Fingerprint(b), nil
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
	// An earlier drop that removed the other file and stopped before its
	// state: finish it.
	finishing := false
	if errors.Is(err, membership.ErrSealDisagree) {
		state, finishing = halfDone(dir, []membership.SealState{membership.StateNext, membership.StatePromoted}, true, false)
		if finishing {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("contract-secret drop: %w", err)
	}
	if state != membership.StateNext && state != membership.StatePromoted {
		return fmt.Errorf("contract-secret drop: needs the state next or promoted, not %q", stateWord(state))
	}
	if !finishing {
		if err := dir.Remove(membership.SecretOtherFileName); err != nil {
			return fmt.Errorf("contract-secret drop: %w", err)
		}
	}
	if err := dir.WriteState(membership.StateSteady); err != nil {
		return fmt.Errorf("contract-secret drop: write the state: %w", err)
	}
	if finishing {
		//nolint:errcheck // a note for the owner; stdout keeps its one line
		fmt.Fprintln(c.stderr, "contract-secret drop: finished an earlier drop that removed the other file and did not record it")
	}
	return c.printFiles(dir, "drop")
}

// reset removes the secret's files from any state, disagreeing ones
// included: a reinstall's first half, then seal --slot current (after a
// platform restore, when Wappie holds a secret the platform no longer has).
func (c secretCommand) reset(args []string) error {
	fs := c.flags("reset")
	dirPath := fs.String("dir", "", "the sealed directory, /opt/wappie/sealed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract-secret reset " + strings.Join(fs.Args(), " ")}
	}
	dir, err := openSealDir(*dirPath)
	if err != nil {
		return fmt.Errorf("contract-secret reset: %w", err)
	}
	if err := dir.Reset(); err != nil {
		return fmt.Errorf("contract-secret reset: %w", err)
	}
	return c.printFiles(dir, "reset")
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
