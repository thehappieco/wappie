package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/config"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// whatserverd contract trial-key (E0 slice 19): init seals K_app under
// the purpose trial-codes and never opens it; check --probe never reads
// the envelope; suspend and resume; and contract status's lines and
// findings, read from what wappie-api recorded, never opening the key.

func trialKeyCfg() config.Contract {
	return config.Contract{KMSRegion: "eu-west-1", KMSKeyARN: "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"}
}

func TestTrialKeyInitSealsUnderTrialCodes(t *testing.T) {
	ctx := context.Background()
	c := store.NewContract(pgtest.Fresh(t, migrate.Run))
	k := membershiptest.NewKMS(t)
	var out bytes.Buffer
	if err := trialKeyInit(ctx, c, trialKeyCfg(), k.Open, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "trial key: created\n") {
		t.Fatalf("init said %q", out.String())
	}
	if k.Decrypts() != 0 || len(k.Purposes()) != 1 || k.Purposes()[0] != "trial-codes" {
		t.Fatalf("init's KMS calls: %v, %d decrypts", k.Purposes(), k.Decrypts())
	}
	envelope, _, ok, err := c.TrialKeyEnvelope(ctx)
	if err != nil || !ok || len(envelope) == 0 {
		t.Fatalf("the envelope: %v %v", ok, err)
	}
	out.Reset()
	err = trialKeyInit(ctx, c, trialKeyCfg(), k.Open, &out)
	if err == nil || !strings.Contains(err.Error(), "never rotated") || out.String() != "trial key: present\n" {
		t.Fatalf("a second init: %q %v", out.String(), err)
	}
	if again, _, _, _ := c.TrialKeyEnvelope(ctx); !bytes.Equal(again, envelope) || len(k.Purposes()) != 1 {
		t.Fatal("a second init changed the key or called KMS")
	}
	// Without Wappie's KMS key, init refuses and installs nothing.
	c2 := store.NewContract(pgtest.Fresh(t, migrate.Run))
	if err := trialKeyInit(ctx, c2, config.Contract{}, k.Open, &bytes.Buffer{}); err == nil {
		t.Fatal("init without a KMS key")
	}
}

// TestTrialKeyCheckProbeNeverReadsEnvelope: the probe takes no database:
// one throwaway data key, generated and decrypted under trial-codes; a KMS
// that refuses names its step.
func TestTrialKeyCheckProbeNeverReadsEnvelope(t *testing.T) {
	ctx := context.Background()
	k := membershiptest.NewKMS(t)
	var out bytes.Buffer
	if err := trialKeyProbe(ctx, trialKeyCfg(), k.Open, &out); err != nil || out.String() != "kms: ok\n" {
		t.Fatalf("the probe: %q %v", out.String(), err)
	}
	if !slices.Equal(k.Purposes(), []string{"trial-codes", "trial-codes"}) || k.Decrypts() != 1 {
		t.Fatalf("the probe's calls: %v, %d decrypts", k.Purposes(), k.Decrypts())
	}
	k.SetFail(membershiptest.ErrUnreachable)
	if err := trialKeyProbe(ctx, trialKeyCfg(), k.Open, &bytes.Buffer{}); err == nil || !strings.HasPrefix(err.Error(), "kms: generate: ") {
		t.Fatalf("a refusing KMS: %v", err)
	}
	k.SetFail(nil)
	k.SetDescribeFail(membershiptest.ErrUnreachable)
	if err := trialKeyProbe(ctx, trialKeyCfg(), k.Open, &bytes.Buffer{}); err == nil || !strings.HasPrefix(err.Error(), "kms: describe: ") {
		t.Fatalf("a key that does not describe: %v", err)
	}
}

// TestTrialKeySuspendResume: suspend and resume switch the codes, once;
// resume is refused while the installed envelope is retired.
func TestTrialKeySuspendResume(t *testing.T) {
	ctx := context.Background()
	c := store.NewContract(pgtest.Fresh(t, migrate.Run))
	k := membershiptest.NewKMS(t)
	if err := trialKeyInit(ctx, c, trialKeyCfg(), k.Open, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := trialKeyCodes(ctx, c, config.Contract{}, false, true, &out); err != nil || !strings.HasPrefix(out.String(), "trial codes: suspended\n") {
		t.Fatalf("suspend: %q %v", out.String(), err)
	}
	out.Reset()
	if err := trialKeyCodes(ctx, c, config.Contract{}, false, true, &out); err != nil || !strings.Contains(out.String(), "already suspended") {
		t.Fatalf("suspend again: %q %v", out.String(), err)
	}
	envelope, _, _, _ := c.TrialKeyEnvelope(ctx)
	sum := sha256.Sum256(envelope)
	retired := config.Contract{TrialKeyRetired: hex.EncodeToString(sum[:])}
	if err := trialKeyCodes(ctx, c, retired, true, true, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "WS_TRIAL_KEY_RETIRED") {
		t.Fatalf("resume of a retired key: %v", err)
	}
	out.Reset()
	if err := trialKeyCodes(ctx, c, config.Contract{}, true, false, &out); err != nil || !strings.Contains(out.String(), "trial codes: on") ||
		!strings.Contains(out.String(), "report it to the platform's chat") {
		t.Fatalf("resume: %q %v", out.String(), err)
	}
	if err := contractTrialKeyCommand([]string{"sideways"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
		t.Fatalf("sideways: %v", err)
	}
	if err := contractTrialKeyCommand([]string{"check"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
		t.Fatalf("check without --probe: %v", err)
	}
}

// TestContractStatusNeverOpensTrialKey: contract status's trial key lines
// and findings, from the state wappie-api recorded: none, installed and
// not opened, opened, not opening, retired, suspended; the link checks of
// the day; no byte of the key or of its envelope printed.
func TestContractStatusNeverOpensTrialKey(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	has := func(out, line string) bool { return strings.Contains(out, line) }
	out, findings, _ := statusRun(t, c, config.Contract{})
	if !has(out, "trial key: none (items have no code)\n") || !has(out, "trial codes: on\n") ||
		!has(out, "link checks (24 h): 0 answered, 0 failed; would refuse: 0\n") {
		t.Fatalf("with no key:\n%s", out)
	}
	for _, f := range findings {
		if strings.Contains(f, "trial key") || strings.Contains(f, "key row") {
			t.Fatalf("a server with no key flagged: %s", f)
		}
	}
	k := membershiptest.NewKMS(t)
	if err := trialKeyInit(ctx, c, trialKeyCfg(), k.Open, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	calls := k.Calls()
	out, findings, code := statusRun(t, c, config.Contract{})
	if !has(out, "trial key: installed, not opened by wappie-api yet\n") || code != 1 ||
		!slices.Contains(findings, "a key row exists but wappie-api has recorded no open of it") {
		t.Fatalf("not opened:\n%s", out)
	}
	envelope, _, _, _ := c.TrialKeyEnvelope(ctx)
	if err := c.TrialKeyOpened(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	if err := c.RecordLinkCheck(ctx, uuid.New(), store.LinkActLink, true, "new_links_off"); err != nil {
		t.Fatal(err)
	}
	out, findings, _ = statusRun(t, c, config.Contract{})
	if !has(out, "trial key: opened by wappie-api at ") || !has(out, "link checks (24 h): 1 answered, 0 failed; would refuse: 1\n") {
		t.Fatalf("opened:\n%s", out)
	}
	for _, f := range findings {
		if strings.Contains(f, "trial key") || strings.Contains(f, "key row") {
			t.Fatalf("an opened key flagged: %s", f)
		}
	}
	if err := c.TrialKeyOpenFailed(ctx, "decrypt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil {
		t.Fatal(err)
	}
	out, findings, _ = statusRun(t, c, config.Contract{})
	if !has(out, "trial key: does not open (decrypt) at ") || !has(out, "trial codes: suspended since ") ||
		!slices.Contains(findings, "trial key does not open (decrypt)") {
		t.Fatalf("not opening:\n%s", out)
	}
	sum := sha256.Sum256(envelope)
	out, _, _ = statusRun(t, c, config.Contract{TrialKeyRetired: hex.EncodeToString(sum[:])})
	if !has(out, "trial key: retired (not used)\n") {
		t.Fatalf("retired:\n%s", out)
	}
	if k.Calls() != calls {
		t.Fatal("contract status called KMS")
	}
	for _, s := range []string{hex.EncodeToString(envelope), base64.StdEncoding.EncodeToString(envelope), hex.EncodeToString(sum[:])} {
		if strings.Contains(out, s) {
			t.Fatal("contract status printed the envelope or its sum")
		}
	}
}
