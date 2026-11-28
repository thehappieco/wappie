package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"whatserver2/internal/blob"
	"whatserver2/internal/config"
	"whatserver2/internal/datacheck"
)

// datacheckUsage is the data check's command lines (docs/deployment.md).
const datacheckUsage = `whatserverd datacheck [-workspace ID] [-out FILE] [-objects [-sums FILE] [-sizes FILE] [-strict]] [-ledger FILE] [-token-stops FILE] [-require-files]
whatserverd datacheck compare [-expect equal|migration|seq-offset|key-change|lid-backfill] [-offset N] [-device ID]... [-allow PATTERN]... [-workspace-map OLD=NEW]... BEFORE AFTER`

// defaultTokenStops is where the cloud keeps the token stop record
// (commercial deploy/backup.sh): a path, not a credential.
const defaultTokenStops = "/var/lib/wappie/token-stops.jsonl" //nolint:gosec // G101: a file path

// exitDataDiffers is the data check's exit status for a difference a
// change did not declare (compare), or an object problem under -strict.
const exitDataDiffers = 3

// datacheckCommand is "whatserverd datacheck": the manifest of plan 0063-0066
// section 2.4, read in one READ ONLY REPEATABLE READ transaction that is
// never committed, and, with -objects, every object of the bucket read and
// hashed. It writes nothing to the database or the bucket, and never
// migrates: it records the schema it finds.
func datacheckCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "compare" {
		return datacheckCompare(args[1:], stdout)
	}
	fs := flag.NewFlagSet("datacheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	workspace := fs.String("workspace", "", "check one workspace (and its object prefix) only")
	out := fs.String("out", "", "write the manifest to FILE, which must not exist (default: stdout, the summary then on stderr)")
	objects := fs.Bool("objects", false, "also list, read and hash every object under the scope's prefix")
	sums := fs.String("sums", "", "with -objects: write \"<sha256>  <key>\" lines (sha256sum's format) to FILE, which must not exist")
	sizes := fs.String("sizes", "", "with -objects: write \"<size>  <key>\" lines to FILE, which must not exist")
	strict := fs.Bool("strict", false, "with -objects: exit 3 when the object check finds a problem")
	ledger := fs.String("ledger", "", "the deletion ledger to hash (default: WS_DELETION_LEDGER)")
	stops := fs.String("token-stops", defaultTokenStops, "the token stop record to hash")
	requireFiles := fs.Bool("require-files", false, "fail when the deletion ledger or the token stop record is absent")
	timeout := fs.Duration("statement-timeout", 30*time.Minute, "the bound on each query")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageError{arg: "datacheck " + strings.Join(args, " ")}
	}
	if !*objects && (*sums != "" || *sizes != "" || *strict) {
		return errors.New("datacheck: -sums, -sizes and -strict need -objects")
	}
	if err := config.LoadDotEnv(".env"); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *ledger == "" {
		*ledger = cfg.Deletion.Ledger
	}
	// A nil interface, not a nil *blob.Store, when there is no object check.
	var bucket datacheck.ObjectStore
	if *objects {
		s, err := blob.New(cfg.Storage)
		if err != nil {
			return err
		}
		if !s.Configured() {
			return errors.New("datacheck: -objects needs object storage (WS_S3_BUCKET, WS_S3_ACCESS_KEY, WS_S3_SECRET_KEY)")
		}
		bucket = s
	}
	// Created before anything is read, so a name already taken stops the
	// check at once, not after an hour of hashing.
	files := map[string]string{"manifest": *out, "sums": *sums, "sizes": *sizes}
	opened := map[string]*os.File{}
	keep := false
	defer func() {
		for _, f := range opened {
			_ = f.Close() //nolint:errcheck // synced before keep is set; a failed check removes it
			if !keep {
				_ = os.Remove(f.Name()) //nolint:errcheck // best effort: a half-written file must not look like a result
			}
		}
	}()
	for _, name := range []string{"manifest", "sums", "sizes"} {
		if files[name] == "" {
			continue
		}
		f, err := os.OpenFile(files[name], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("datacheck: %s: %w", name, err)
		}
		opened[name] = f
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	conn, err := openReadOnly(ctx, cfg.Postgres.DSN, *timeout)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx)) //nolint:errcheck // read only; nothing to flush
	var objectFiles datacheck.ObjectOutput
	if f := opened["sums"]; f != nil {
		objectFiles.Sums = f
	}
	if f := opened["sizes"]; f != nil {
		objectFiles.Sizes = f
	}
	m, err := runDatacheck(ctx, conn, bucket, datacheck.Options{Workspace: *workspace,
		Files: map[string]string{"deletion_ledger": *ledger, "token_stops": *stops}}, objectFiles)
	if err != nil {
		return err
	}
	// Before anything is kept: a run that must find both files and does
	// not leaves no manifest behind (plan 2.6 stops on a file not copied).
	if *requireFiles {
		for _, name := range []string{"deletion_ledger", "token_stops"} {
			if !m.Files[name].Present {
				return exitError{code: exitDataDiffers, err: fmt.Errorf("datacheck: the %s is absent", strings.ReplaceAll(name, "_", " "))}
			}
		}
	}
	j, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	j = append(j, '\n')
	summary := stdout
	if f := opened["manifest"]; f != nil {
		if _, err := f.Write(j); err != nil {
			return fmt.Errorf("datacheck: manifest: %w", err)
		}
	} else {
		if _, err := stdout.Write(j); err != nil {
			return err
		}
		summary = stderr
	}
	for name, f := range opened {
		if err := f.Sync(); err != nil {
			return fmt.Errorf("datacheck: %s: %w", name, err)
		}
	}
	keep = true
	if err := datacheck.WriteSummary(summary, m); err != nil {
		return err
	}
	if *strict && m.Objects.Problems() > 0 {
		return exitError{code: exitDataDiffers, err: fmt.Errorf("datacheck: the object check found %d problems", m.Objects.Problems())}
	}
	return nil
}

// openReadOnly opens the check's one connection, read-only from its first
// statement: every transaction on it defaults to READ ONLY, and the check's
// own is opened READ ONLY besides.
func openReadOnly(ctx context.Context, dsn string, timeout time.Duration) (*pgx.Conn, error) {
	pc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("datacheck: WS_POSTGRES_DSN: %w", err)
	}
	if pc.RuntimeParams == nil {
		pc.RuntimeParams = map[string]string{}
	}
	pc.RuntimeParams["application_name"] = "whatserver2/datacheck"
	pc.RuntimeParams["default_transaction_read_only"] = "on"
	pc.RuntimeParams["statement_timeout"] = strconv.FormatInt(timeout.Milliseconds(), 10)
	conn, err := pgx.ConnectConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("datacheck: connect: %w", err)
	}
	return conn, nil
}

// runDatacheck takes the manifest in one read-only transaction, which it
// always rolls back, and checks the objects in the same snapshot.
func runDatacheck(ctx context.Context, db datacheck.Beginner, bucket datacheck.ObjectStore, opts datacheck.Options,
	files datacheck.ObjectOutput) (*datacheck.Manifest, error) {
	tx, err := datacheck.Begin(ctx, db)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // read only: there is nothing to keep
	m, err := datacheck.Collect(ctx, tx, opts)
	if err != nil {
		return nil, err
	}
	if bucket == nil {
		return m, nil
	}
	var out datacheck.ObjectOutput
	var bufs []*bufio.Writer
	for _, w := range []struct {
		dst io.Writer
		set *io.Writer
	}{{files.Sums, &out.Sums}, {files.Sizes, &out.Sizes}} {
		if w.dst != nil {
			b := bufio.NewWriterSize(w.dst, 1<<16)
			bufs = append(bufs, b)
			*w.set = b
		}
	}
	if err := datacheck.CheckObjects(ctx, tx, bucket, m, out); err != nil {
		return nil, err
	}
	for _, b := range bufs {
		if err := b.Flush(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// datacheckCompare is "whatserverd datacheck compare": it prints every
// field that differs between two manifests, declared or not, and exits 3
// when any difference is not what the change declared (plan 2.5).
func datacheckCompare(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("datacheck compare", flag.ContinueOnError)
	expect := fs.String("expect", datacheck.ExpectEqual, "what the change declares: "+strings.Join(datacheck.Expects, ", "))
	offset := fs.Int64("offset", 0, "with -expect seq-offset: the seq offset of the renumbering")
	var allow patterns
	fs.Var(&allow, "allow", "a path pattern that may differ (\"*\" one segment, \"**\" any); repeatable")
	var wsMap pairs
	fs.Var(&wsMap, "workspace-map", "OLD=NEW: the first manifest's workspace OLD is the second's NEW; repeatable")
	var devices patterns
	fs.Var(&devices, "device", "a number (devices.id) the change moves or renumbers: compared under its id wherever it is, "+
		"and with seq-offset the only numbers renumbered (default: every number); repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageError{arg: "datacheck compare " + strings.Join(args, " ")}
	}
	read := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the manifests
		if err != nil {
			return nil, fmt.Errorf("datacheck compare: %w", err)
		}
		return b, nil
	}
	before, err := read(fs.Arg(0))
	if err != nil {
		return err
	}
	after, err := read(fs.Arg(1))
	if err != nil {
		return err
	}
	diffs, err := datacheck.Compare(before, after, datacheck.Expectations{Kind: *expect, Offset: *offset,
		Allow: allow, WorkspaceMap: wsMap, Devices: devices})
	if err != nil {
		return err
	}
	if err := datacheck.WriteReport(stdout, diffs); err != nil {
		return err
	}
	if n := datacheck.Unexpected(diffs); n > 0 {
		return exitError{code: exitDataDiffers, err: fmt.Errorf("datacheck compare: %d unexpected differences", n)}
	}
	return nil
}

// patterns is a repeatable flag of path patterns.
type patterns []string

func (p *patterns) String() string { return strings.Join(*p, ",") }

func (p *patterns) Set(s string) error {
	*p = append(*p, s)
	return nil
}

// pairs is a repeatable OLD=NEW flag.
type pairs map[string]string

func (p *pairs) String() string { return fmt.Sprint(map[string]string(*p)) }

func (p *pairs) Set(s string) error {
	from, to, ok := strings.Cut(s, "=")
	if !ok || from == "" || to == "" {
		return errors.New("want OLD=NEW")
	}
	if *p == nil {
		*p = pairs{}
	}
	(*p)[from] = to
	return nil
}
