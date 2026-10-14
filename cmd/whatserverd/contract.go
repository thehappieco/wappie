package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/thehappieco/kit/kms"
	"github.com/thehappieco/kit/kms/awskms"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
)

// The product contract's membership part (decision 0040; docs/contract.md),
// as this binary wires it: the transport to the platform's socket, the
// sealed secret loaded lazily and again on every SIGHUP, and the commands
// an operator and the installer run. This file is the only place the AWS
// SDK enters the server (kms/awskms): internal/membership takes the key as
// a function, so nothing that wappie-cloud imports compiles the SDK.

// socketOwner is the uid the contract socket and its directory must belong
// to: only root makes an entry under /run/platform (README 2). The tests
// serve a fake on a socket of their own.
var socketOwner = 0

// openKMS opens Wappie's key: awskms.New checks with DescribeKey that the
// pinned ARN is an enabled symmetric key for encryption, with the instance
// role's credentials only.
func openKMS(ctx context.Context, region, keyARN string) (kms.Wrapper, error) {
	w, err := awskms.New(ctx, region, keyARN)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// newContractClient is the client on the configured transport, with no
// secret yet.
func newContractClient(cfg config.Contract, log *slog.Logger) *membership.Client {
	if cfg.Socket != "" {
		d := &membership.SocketDialer{Path: cfg.Socket, Owner: socketOwner, Log: log}
		return membership.NewClient(membership.HTTP(d.DialContext), membership.Base, nil)
	}
	d := membership.TCPDialer{Addr: cfg.Addr}
	return membership.NewClient(membership.HTTP(d.DialContext), membership.Base, nil)
}

// startContract loads the contract's secret in the background when a
// transport is configured, and reloads it on every SIGHUP. Without one, a
// SIGHUP is said and ignored: serve takes SIGHUP in every configuration,
// since Go's default for it is to exit, which systemd counts as clean and
// would not restart (contract-secret capabilities says this binary takes
// it). Nothing here calls the platform; a load reaches only KMS.
func (a *app) startContract(ctx context.Context, hup <-chan os.Signal) {
	if !a.cfg.Contract.Configured() {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					a.log.Info("SIGHUP: nothing to reload, the contract has no transport configured")
				}
			}
		}()
		return
	}
	a.contract = newContractClient(a.cfg.Contract, a.log)
	a.secrets = &membership.Secrets{Config: a.cfg.Contract, Client: a.contract, OpenWrapper: openKMS, Log: a.log}
	go a.secrets.Watch(ctx, hup)
	go a.secrets.Run(ctx)
}

// contractCommand is whatserverd contract, as the service user runs it
// (systemd-run with the platform-contract group and runtime.env as its
// environment). check reads no .env and no database.
func contractCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError{arg: "contract"}
	}
	switch args[0] {
	case "check":
		return contractCheck(args[1:], stdout, openKMS)
	}
	return usageError{arg: "contract " + strings.Join(args, " ")}
}

// contractCheck is contract check [--other|--only-current|--only-other]:
// one signed feed request (GET /contract/v1/feed?after=0&wait=0, the check
// of the platform's hand-off), signed and accepted as the flag says. Its
// exit status is the installer's to act on: 0 a signed answer this check
// accepts, 3 an unsigned 401 (the platform refuses the request's secret),
// 4 an answer signed with the secret this check excludes, 5 no answer, 1
// anything else. It loads the secrets itself, as the service user, from the
// files the server reads; it publishes nothing, since it is not the server.
func contractCheck(args []string, stdout io.Writer, open membership.OpenWrapper) error {
	fs := flag.NewFlagSet("contract check", flag.ContinueOnError)
	other := fs.Bool("other", false, "sign with the other secret, accept either (before Wappie's promote)")
	onlyCurrent := fs.Bool("only-current", false, "sign with the current secret, accept only it (before a drop, or a cancel from next)")
	onlyOther := fs.Bool("only-other", false, "sign with the other secret, accept only it (before a cancel from promoted)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{arg: "contract check " + strings.Join(fs.Args(), " ")}
	}
	mode, n := membership.ProbeBoth, 0
	for _, f := range []struct {
		set  bool
		mode membership.ProbeMode
	}{{*other, membership.ProbeOther}, {*onlyCurrent, membership.ProbeOnlyCurrent}, {*onlyOther, membership.ProbeOnlyOther}} {
		if f.set {
			mode, n = f.mode, n+1
		}
	}
	if n > 1 {
		return errors.New("contract check: --other, --only-current and --only-other are exclusive")
	}
	cfg, _, err := config.LoadContract()
	if err != nil {
		return err
	}
	if !cfg.Configured() {
		return errors.New("contract check: no transport is configured (WS_CONTRACT_SOCKET)")
	}
	cfg.LoadedFile = ""
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	client := newContractClient(cfg, log)
	secrets := &membership.Secrets{Config: cfg, Client: client, OpenWrapper: open}
	ctx := context.Background()
	if err := secrets.Load(ctx); err != nil {
		return fmt.Errorf("contract check: the secrets did not load (step %s): %w", secrets.Last().Error, err)
	}
	res := client.Probe(ctx, mode)
	//nolint:errcheck // writing to stdout; the exit status carries the result
	fmt.Fprintln(stdout, res.Line)
	if res.Code != membership.ProbeVerified {
		return exitError{code: res.Code}
	}
	return nil
}
