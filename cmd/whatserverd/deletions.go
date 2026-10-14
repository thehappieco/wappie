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
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/blob"
	"whatserver2/internal/config"
	"whatserver2/internal/ledger"
	"whatserver2/internal/store"
)

// Deleted numbers and their ledger, from the command line (decision 0038's
// plan, sections 7 to 9). list-deleted, export-ledger and replay never
// migrate: they refuse a database whose schema is not exactly this
// binary's, so a dry run over a restored snapshot changes nothing, and the
// export before a rollback's down-step runs as the wappie user with
// wappie-api stopped.

// exportLedger appends a workspace's new deletion events to the ledger,
// best effort: a failure is logged, and the janitor's next pass exports
// again. Nothing is lost meanwhile: the events stay marked unexported.
func (a *app) exportLedger(ctx context.Context, tenant uuid.UUID) {
	if a.ledger == nil {
		return
	}
	if _, err := store.ExportLedger(ctx, a.pools.API, tenant, a.ledger); err != nil {
		a.log.Error("deletion ledger export failed", "path", a.ledger.Path, "tenant", tenant, "error", err)
	}
}

// checkDeletionLedger says once, at start and in prod, whether the server
// can write its deletion ledger, creating the file with mode 0600 when it
// is missing. It never stops the start.
func checkDeletionLedger(cfg config.Config, file *ledger.File, log *slog.Logger) {
	if !cfg.Env.IsProd() {
		return
	}
	if file == nil {
		log.Error("deletion ledger not writable", "path", "", "error", "WS_DELETION_LEDGER is empty")
		return
	}
	if err := file.CheckWritable(); err != nil {
		log.Error("deletion ledger not writable", "path", file.Path, "error", err)
		return
	}
	log.Info("deletion ledger writable", "path", file.Path)
}

// devicesCommand is "whatserverd devices list-deleted|purge-deleted".
func devicesCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("devices: list-deleted or purge-deleted")
	}
	switch args[0] {
	case "list-deleted":
		fs := flag.NewFlagSet("devices list-deleted", flag.ContinueOnError)
		tenant := fs.String("tenant", "", "one workspace (default: every one)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a, closeAll, err := setupCurrent(ctx)
		if err != nil {
			return err
		}
		defer closeAll()
		return listDeleted(ctx, a, *tenant, out)
	case "purge-deleted":
		fs := flag.NewFlagSet("devices purge-deleted", flag.ContinueOnError)
		tenant := fs.String("tenant", "", "one workspace (default: every one)")
		device := fs.String("device", "", "one deleted number")
		now := fs.Bool("now", false, "purge -device now, before its 30 days end (only with the owner's agreement)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		a, closeAll, err := setupCurrent(ctx)
		if err != nil {
			return err
		}
		defer closeAll()
		objects, err := blob.New(a.cfg.Storage)
		if err != nil {
			return err
		}
		return purgeDeleted(ctx, a, objects, *tenant, *device, *now, out)
	}
	return fmt.Errorf("devices: unknown command %q: list-deleted or purge-deleted", args[0])
}

// deletionsCommand is "whatserverd deletions export-ledger|replay".
func deletionsCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("deletions: export-ledger or replay")
	}
	switch args[0] {
	case "export-ledger":
		fs := flag.NewFlagSet("deletions export-ledger", flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		a, closeAll, err := setupCurrent(ctx)
		if err != nil {
			return err
		}
		defer closeAll()
		return exportAllLedger(ctx, a, out)
	case "replay":
		fs := flag.NewFlagSet("deletions replay", flag.ContinueOnError)
		path := fs.String("ledger", "", "the deletion ledger to replay (required): the host's own, else the newest off-host copy")
		snapshot := fs.String("snapshot-time", "", "the restored snapshot's stamp, YYYYMMDDTHHMMSSZ or RFC 3339 (required)")
		dryRun := fs.Bool("dry-run", false, "run every step and roll it back: say what would change, and what would refuse, and change nothing")
		addsNothing := fs.Bool("ledger-adds-nothing", false, "go on with a ledger that holds nothing newer than the snapshot")
		var leave ids
		fs.Var(&leave, "leave-excluded", "a number found in another workspace than its ledger says: exclude it where it is (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" || *snapshot == "" {
			fs.Usage()
			return errors.New("deletions replay: -ledger and -snapshot-time are required")
		}
		at, err := parseStamp(*snapshot)
		if err != nil {
			return fmt.Errorf("deletions replay: -snapshot-time: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		a, closeAll, err := setupCurrent(ctx)
		if err != nil {
			return err
		}
		defer closeAll()
		return replayLedger(ctx, a, *path, store.ReplayOptions{DryRun: *dryRun, SnapshotTime: at,
			LedgerAddsNothing: *addsNothing, LeaveExcluded: leave}, out)
	}
	return fmt.Errorf("deletions: unknown command %q: export-ledger or replay", args[0])
}

// printer writes a command's report and keeps its first error, which the
// command returns: a report that could not be written is a failure.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) say(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// ids is a repeatable flag of number ids.
type ids []uuid.UUID

func (v *ids) String() string { return fmt.Sprint([]uuid.UUID(*v)) }

func (v *ids) Set(s string) error {
	id, err := uuid.Parse(s)
	if err != nil {
		return err
	}
	*v = append(*v, id)
	return nil
}

// parseStamp reads a snapshot directory's name, or an RFC 3339 time.
func parseStamp(s string) (time.Time, error) {
	if t, err := time.Parse("20060102T150405Z", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func tenantsOf(ctx context.Context, a *app, only string) ([]uuid.UUID, error) {
	if only == "" {
		return a.listAllTenantIDs(ctx)
	}
	id, err := uuid.Parse(only)
	if err != nil {
		return nil, fmt.Errorf("%q is not a workspace id: %w", only, err)
	}
	return []uuid.UUID{id}, nil
}

// listDeleted prints every excluded number with its dates and state, and
// the ledger's: never a number's name or its phone.
func listDeleted(ctx context.Context, a *app, only string, out io.Writer) error {
	tenants, err := tenantsOf(ctx, a, only)
	if err != nil {
		return err
	}
	devices := store.NewDevices(a.pools.API)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	table := &printer{w: tw}
	table.say("WORKSPACE\tNUMBER\tDELETED\tPURGE AFTER\tSTATE\tSTATUS\tSESSION LEFT\n")
	n := 0
	for _, tenant := range tenants {
		listed, err := devices.ListAllDeleted(ctx, tenant)
		if err != nil {
			return fmt.Errorf("workspace %s: %w", tenant, err)
		}
		for _, d := range listed {
			state := "recoverable"
			switch {
			case d.PurgeStarted:
				state = "purging"
			case d.Due && d.DueFor > overdueAfter:
				state = "overdue by " + d.DueFor.Round(time.Minute).String()
			case d.Due:
				state = "due"
			}
			table.say("%s\t%s\t%s\t%s\t%s\t%s\t%v\n", tenant, d.DeviceID, d.DeletedAt.UTC().Format(time.RFC3339),
				d.PurgeAfter.UTC().Format(time.RFC3339), state, d.Status, d.Leftover)
			n++
		}
	}
	if table.err != nil {
		return table.err
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	p := &printer{w: out}
	p.say("%d deleted number(s)\n", n)
	if a.ledger == nil {
		p.say("deletion ledger: none configured (WS_DELETION_LEDGER)\n")
		return p.err
	}
	f, err := os.OpenFile(a.ledger.Path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		p.say("deletion ledger: %s is not writable by this user: %v\n", a.ledger.Path, err)
		return p.err
	}
	f.Close() //nolint:errcheck,gosec // only opened to see whether it could be
	p.say("deletion ledger: %s is writable\n", a.ledger.Path)
	return p.err
}

// purgeDeleted is the operator's purge: the due numbers of each workspace,
// as the janitor purges them, or one number, and with now before its date.
func purgeDeleted(ctx context.Context, a *app, objects objectStore, only, device string, now bool, out io.Writer) error {
	if now && device == "" {
		return errors.New("devices purge-deleted: -now needs -device: it purges one number before its date, never a workspace")
	}
	tenants, err := tenantsOf(ctx, a, only)
	if err != nil {
		return err
	}
	p := &printer{w: out}
	deletes := a.objectDeletes(objects, a.janitor.withDefaults().object)
	if deletes == nil {
		p.say("object storage is not configured: the numbers' objects are left to the orphan pass\n")
	}
	purge := func(tenant, id uuid.UUID) (store.PurgeResult, error) {
		res, err := store.PurgeDevice(ctx, a.pools.History, tenant, id, deletes, store.PurgeOptions{Now: now})
		if err == nil && res.Final {
			a.purged(ctx, tenant, id, res)
			p.say("purged %s in %s: %d batches, objects %d removed, %d failed, %d left for the orphan pass\n",
				id, tenant, res.Batches, res.ObjectsRemoved, res.ObjectsFailed, res.ObjectsSkipped)
		}
		return res, err
	}
	if device != "" {
		id, err := uuid.Parse(device)
		if err != nil {
			return fmt.Errorf("%q is not a number id: %w", device, err)
		}
		for _, tenant := range tenants {
			res, err := purge(tenant, id)
			switch {
			case errors.Is(err, store.ErrNotFound):
				continue
			case errors.Is(err, store.ErrNotDue):
				return fmt.Errorf("number %s is not due yet: pass -now to purge it before its date", id)
			case err != nil:
				return err
			case res.Busy:
				return fmt.Errorf("number %s is still held by a client or a logout; try again in a minute", id)
			}
			return p.err
		}
		return fmt.Errorf("no deleted number %s", id)
	}
	devices := store.NewDevices(a.pools.API)
	for _, tenant := range tenants {
		for {
			due, _, err := devices.DueDeletions(ctx, tenant, purgePerPass)
			if err != nil {
				return fmt.Errorf("workspace %s: %w", tenant, err)
			}
			progress := false
			for _, d := range due {
				res, err := purge(tenant, d.DeviceID)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("number %s: %w", d.DeviceID, err)
				}
				if res.Busy {
					p.say("number %s is still held by a client or a logout; skipped\n", d.DeviceID)
					continue
				}
				progress = true
			}
			if len(due) < purgePerPass || !progress {
				break
			}
		}
	}
	return p.err
}

// exportAllLedger exports every workspace's unexported events.
func exportAllLedger(ctx context.Context, a *app, out io.Writer) error {
	if a.ledger == nil {
		return errors.New("deletions export-ledger: WS_DELETION_LEDGER is empty")
	}
	tenants, err := a.listAllTenantIDs(ctx)
	if err != nil {
		return err
	}
	var failed []string
	total := 0
	for _, tenant := range tenants {
		n, err := store.ExportLedger(ctx, a.pools.API, tenant, a.ledger)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", tenant, err))
			continue
		}
		total += n
	}
	p := &printer{w: out}
	p.say("%d line(s) appended to %s\n", total, a.ledger.Path)
	if len(failed) > 0 {
		return fmt.Errorf("deletions export-ledger: %d workspace(s) not exported, their events stay unexported:\n%s", len(failed), strings.Join(failed, "\n"))
	}
	return p.err
}

// replayLedger replays a ledger file over the restored database.
func replayLedger(ctx context.Context, a *app, path string, opts store.ReplayOptions, out io.Writer) error {
	f, err := os.Open(path) //nolint:gosec // G304: the ledger the operator names
	if err != nil {
		return err
	}
	read, err := ledger.Read(f)
	f.Close() //nolint:errcheck,gosec // read-only handle
	if err != nil {
		return err
	}
	p := &printer{w: out}
	if read.TornTail {
		p.say("the ledger's last line was cut short by a crash; it was never exported, and is skipped\n")
	}
	if read.Duplicates > 0 {
		p.say("%d line(s) repeated an event and were folded into it\n", read.Duplicates)
	}
	report, err := store.ReplayLedger(ctx, a.pools.API, read.Lines, opts)
	p.say("%s", report.String())
	if opts.DryRun {
		p.say("dry run: nothing was changed\n")
	}
	switch {
	case errors.Is(err, store.ErrLedgerAddsNothing):
		return errors.New("deletions replay: the ledger holds nothing newer than the restored snapshot; " +
			"use the host's own ledger or the newest off-host copy, or pass -ledger-adds-nothing if this is that copy")
	case err != nil:
		return fmt.Errorf("deletions replay: %w; do not start wappie-api", err)
	}
	return p.err
}
