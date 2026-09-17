package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/google/uuid"
	"os"
	"time"
)

func (a *app) checkCapture(ctx context.Context, tenant string) error {
	if a.storage == nil {
		return nil
	}
	id, err := uuid.Parse(tenant)
	if err != nil {
		return err
	}
	return a.storage.Check(ctx, id)
}

func storageAdmin(args []string) error {
	fs := flag.NewFlagSet("storage", flag.ContinueOnError)
	tenantArg := fs.String("tenant", "", "workspace UUID (required)")
	limit := fs.Int64("limit-bytes", 0, "hosted storage capacity; no automatic purchase")
	unlimited := fs.Bool("unlimited", false, "remove installation quota")
	resume := fs.Bool("resume", false, "explicitly resume after freeing space or changing capacity")
	reconcile := fs.Bool("reconcile", false, "rebuild persisted archive measurement")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := uuid.Parse(*tenantArg)
	if err != nil {
		return errors.New("storage: valid -tenant required")
	}
	setLimit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "limit-bytes" {
			setLimit = true
		}
	})
	if setLimit && (*limit <= 0 || *unlimited) {
		return errors.New("storage: choose a positive -limit-bytes or -unlimited")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	a, closeAll, err := setup(ctx, false)
	if err != nil {
		return err
	}
	defer closeAll()
	if *reconcile {
		if _, err = a.storage.Reconcile(ctx, id); err != nil {
			return err
		}
	}
	if setLimit {
		err = a.storage.SetLimit(ctx, id, limit)
	} else if *unlimited {
		err = a.storage.SetLimit(ctx, id, nil)
	}
	if err != nil {
		return err
	}
	if *resume {
		if err = a.storage.Resume(ctx, id); err != nil {
			return err
		}
	}
	usage, err := a.storage.Usage(ctx, id)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(usage)
}
