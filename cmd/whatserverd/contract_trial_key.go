package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// whatserverd contract trial-key (E0 slice 19; docs/contract.md, "Trial
// codes"): K_app, the 32 bytes Wappie's trial codes are made under (the
// platform's spec, 15.10), sealed under Wappie's KMS key with the purpose
// trial-codes. init makes it and installs its envelope, once: it is never
// rotated, and a down-step keeps it. check --probe proves the owner's KMS
// step with a throwaway data key and never reads the envelope. suspend and
// resume switch the making of codes: suspended, no code is made anywhere,
// which is the first step of replacing an exposed key. No command opens
// the envelope: only wappie-api does. No output carries a byte of the key,
// of its envelope or a fingerprint of either.

// trialKeyConfig is how wappie-api opens K_app, from the contract's
// settings.
func trialKeyConfig(c config.Contract) membership.TrialKeyConfig {
	return membership.TrialKeyConfig{Open: openKMS, Region: c.KMSRegion, KeyARN: c.KMSKeyARN, Retired: c.TrialKeyRetiredSums()}
}

// contractTrialKeyCommand is contract trial-key init, check --probe, and
// suspend|resume [--platform-told].
func contractTrialKeyCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return usageError{arg: "contract trial-key"}
	}
	verb := args[0]
	fs := flag.NewFlagSet("contract trial-key "+verb, flag.ContinueOnError)
	told := fs.Bool("platform-told", false, "the platform's chat was told of this change")
	probe := false
	switch verb {
	case "init", "suspend", "resume":
	case "check":
		fs.BoolVar(&probe, "probe", false, "probe KMS under the trial-codes context with a throwaway data key")
	default:
		return usageError{arg: "contract trial-key " + strings.Join(args, " ")}
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (verb == "check" && !probe) {
		return usageError{arg: "contract trial-key " + strings.Join(args, " ")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if verb == "check" {
		// KMS only: no database, no envelope.
		cfg, _, err := config.LoadContract()
		if err != nil {
			return err
		}
		return trialKeyProbe(ctx, cfg, openKMS, out)
	}
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	c := store.NewContract(a.pools.API)
	if verb == "init" {
		return trialKeyInit(ctx, c, a.cfg.Contract, openKMS, out)
	}
	return trialKeyCodes(ctx, c, a.cfg.Contract, verb == "resume", *told, out)
}

// trialKeyInit makes K_app and installs its envelope, once: "trial key:
// created", or "trial key: present" and a refusal when one is installed
// (it is never rotated). It never opens the envelope again.
func trialKeyInit(ctx context.Context, c *store.Contract, cfg config.Contract, open membership.OpenWrapper, out io.Writer) error {
	w := &lines{w: out}
	st, err := c.TrialKeyState(ctx)
	if err != nil {
		return err
	}
	if st.Installed {
		w.f("trial key: present")
		return errors.Join(w.err, errors.New("contract trial-key init: a trial key is installed already, and it is never rotated "+
			"(spec 15.10); nothing changed"))
	}
	if cfg.KMSKeyARN == "" {
		return errors.New("contract trial-key init: the trial key is sealed under Wappie's KMS key: " +
			"set WS_CONTRACT_KMS_KEY_ARN and WS_CONTRACT_KMS_REGION; nothing changed")
	}
	wrapper, err := open(ctx, cfg.KMSRegion, cfg.KMSKeyARN)
	if err != nil {
		return fmt.Errorf("contract trial-key init: kms: describe: %s; nothing changed", membership.ErrorClass(err))
	}
	envelope, err := membership.SealTrialKey(ctx, wrapper, rand.Read)
	if err != nil {
		return fmt.Errorf("contract trial-key init: kms: generate: %s; nothing changed", membership.ErrorClass(err))
	}
	if err := c.InitTrialKey(ctx, envelope); errors.Is(err, store.ErrTrialKeyExists) {
		w.f("trial key: present")
		return errors.Join(w.err, errors.New("contract trial-key init: a trial key was installed meanwhile; nothing changed"))
	} else if err != nil {
		return err
	}
	slog.Info("contract: trial key created")
	w.f("trial key: created")
	w.f("wappie-api opens it within seconds; contract status says when")
	return w.err
}

// trialKeyProbe is check --probe: KMS under the trial-codes context, with
// a throwaway data key: "kms: ok", or the step that failed (describe,
// generate, decrypt) and its error's class.
func trialKeyProbe(ctx context.Context, cfg config.Contract, open membership.OpenWrapper, out io.Writer) error {
	if cfg.KMSKeyARN == "" {
		return errors.New("contract trial-key check: set WS_CONTRACT_KMS_KEY_ARN and WS_CONTRACT_KMS_REGION")
	}
	wrapper, err := open(ctx, cfg.KMSRegion, cfg.KMSKeyARN)
	if err != nil {
		return fmt.Errorf("kms: describe: %s", membership.ErrorClass(err))
	}
	if step, err := membership.ProbeTrialKey(ctx, wrapper); err != nil {
		return fmt.Errorf("kms: %s: %s", step, membership.ErrorClass(err))
	}
	w := &lines{w: out}
	w.f("kms: ok")
	return w.err
}

// trialKeyCodes switches the making of codes: suspend (the spec's 15.10
// exposure step 1: no code is made anywhere), or resume, refused while the
// installed envelope is on WS_TRIAL_KEY_RETIRED.
func trialKeyCodes(ctx context.Context, c *store.Contract, cfg config.Contract, resume, told bool, out io.Writer) error {
	codes := store.TrialCodesSuspended
	if resume {
		codes = store.TrialCodesOn
		st, err := c.TrialKeyState(ctx)
		if err != nil {
			return err
		}
		if st.Installed && retiredSum(cfg.TrialKeyRetiredSums(), st.StoredSHA256) {
			return errors.New("contract trial-key resume: the installed key is on WS_TRIAL_KEY_RETIRED and is never used again: " +
				"replace it first (docs/contract.md, \"Replacing an exposed key\"); nothing changed")
		}
	}
	changed, err := c.SetTrialCodes(ctx, codes)
	if err != nil {
		return err
	}
	w := &lines{w: out}
	if !changed {
		w.f("trial codes: already %s; nothing changed", codes)
		return w.err
	}
	slog.Info("contract: trial codes", "codes", codes, "platform_told", told)
	w.f("trial codes: %s", codes)
	switch {
	case !resume:
		w.f("no code is made from now on: links go as items with no code, link checks without codes")
	default:
		w.f("wappie-api makes codes again within seconds; its catch-up sends each number's codes once")
	}
	if !told {
		w.f("report it to the platform's chat")
	}
	return w.err
}

// retiredSum reports whether sum is on the retired list.
func retiredSum(retired []string, sum []byte) bool {
	return slices.Contains(retired, hex.EncodeToString(sum))
}

// trialKeyLines are slice 19's lines of contract status, read from what
// wappie-api recorded: the command never opens the key.
func trialKeyLines(w *lines, st store.TrialKeyState, cfg config.Contract, checks store.LinkCheckCounts) {
	switch {
	case !st.Installed:
		w.f("trial key: none (items have no code)")
	case retiredSum(cfg.TrialKeyRetiredSums(), st.StoredSHA256):
		w.f("trial key: retired (not used)")
	case st.OpenError != "" && st.OpenErrorAt != nil:
		w.f("trial key: does not open (%s) at %s", st.OpenError, stamp(*st.OpenErrorAt))
	case st.OpenedAt != nil && string(st.EnvelopeSHA256) == string(st.StoredSHA256):
		w.f("trial key: opened by wappie-api at %s", stamp(*st.OpenedAt))
	default:
		w.f("trial key: installed, not opened by wappie-api yet")
	}
	if st.Codes == store.TrialCodesOn {
		w.f("trial codes: on")
	} else {
		w.f("trial codes: suspended since %s", stamp(st.CodesAt))
	}
	w.f("link checks (24 h): %d answered, %d failed; would refuse: %d", checks.Answered, checks.Failed, checks.WouldRefuse)
}

// trialKeyFindings are --check's: a key that does not open, and a key row
// wappie-api has recorded no open of. A server with no key yet is not
// flagged.
func trialKeyFindings(st store.TrialKeyState) []string {
	if !st.Installed {
		return nil
	}
	var out []string
	if st.OpenError != "" {
		out = append(out, fmt.Sprintf("trial key does not open (%s)", st.OpenError))
	}
	if st.OpenedAt == nil || string(st.EnvelopeSHA256) != string(st.StoredSHA256) {
		out = append(out, "a key row exists but wappie-api has recorded no open of it")
	}
	return out
}
