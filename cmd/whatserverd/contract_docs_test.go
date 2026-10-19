package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/pg"
	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
)

// The contract's docs (docs/contract.md, docs/contract-events.md, the
// contract section of docs/deployment.md, and what the sign-in, workspace
// and device docs say of it) quote what an operator types, sets and greps
// for, and the codes a client gets: each must still be what the code says,
// as TestDeletionDocsMatchTheCode holds the deletion's.

// docText is a file with every run of white space one space, so a quote a
// Markdown line wraps still matches.
func docText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

// joinedLiterals undoes a Go string literal split by +, so a message the
// code wraps is matched whole.
var joinedLiterals = regexp.MustCompile(`"\s*\+\s*"`)

// contractCode is the non-test Go source the contract's docs quote, white
// space folded and split literals joined.
func contractCode(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, dir := range []string{".", "../../internal/membership", "../../internal/store", "../../internal/authapi",
		"../../internal/wsapi", "../../internal/mcpauth", "../../internal/config"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b.WriteString(docText(t, f))
			b.WriteByte(' ')
		}
	}
	return joinedLiterals.ReplaceAllString(b.String(), "")
}

func TestContractDocsMatchTheCode(t *testing.T) {
	code := contractCode(t)
	docs := map[string]string{}
	for _, name := range []string{"contract.md", "contract-events.md", "deployment.md", "platform-sign-in.md", "workspaces.md",
		"accounts-workspaces.md", "devices.md", "item-events.md", "device-personal-transfer.md"} {
		docs[name] = docText(t, "../../docs/"+name)
	}
	docs[".env.example"] = docText(t, "../../.env.example")
	says := func(doc, text string) {
		t.Helper()
		if !strings.Contains(docs[doc], text) {
			t.Errorf("docs/%s does not say %q", doc, text)
		}
	}
	codeSays := func(text string) {
		t.Helper()
		if !strings.Contains(code, text) {
			t.Errorf("the code no longer says %q", text)
		}
	}

	t.Run("log lines", func(t *testing.T) {
		// What each doc quotes of the code's log lines and messages.
		for doc, lines := range map[string][]string{
			"contract.md": {
				"contract: the socket failed its peer checks; no request goes to it for a minute",
				"contract: secrets loaded",
				"contract: secrets reload failed; the secrets loaded before stay in use",
				"contract: secrets not loaded; the contract is unavailable",
				"contract: no secret is installed yet; the contract stays unavailable until one is",
				"SIGHUP: nothing to reload, the contract has no transport configured",
				"contract: leading",
				"contract: no longer leading",
				"contract: held subs still have no document of this generation; their PUTs fail",
				"contract: no feed page for a long time",
				"contract: published_through ahead of the clock; the last trusted one is kept",
				"contract: a document cannot be stored",
				"contract: workspace kind changed",
				"contract: the platform's generation changed: every sub is subscribed again and the feed read from 0",
				"contract observe: matches",
				"contract observe: differences",
				"contract: sign-in would refuse",
				"freshness: would refuse",
				"freshness: stale at act",
				"transfer: would refuse",
				"contract: a workspace's snapshot is not sent: Wappie would not send it",
				"contract: a workspace's snapshot is parked",
				"contract: snapshot labels",
				"invite: this team's people join through The Happie Co; person invitations are paused here " +
					"until Wappie applies the platform's members (a service invitation still works: -role service)",
			},
			"contract-events.md": {
				"contract: an event's actor has no platform sub; it is sent with actor null",
				"contract: an event is not sent: Wappie would not send it",
				"contract: an event is parked: the platform refused it",
				"contract: a workspace's events are parked: the platform has not known it for a day",
				"contract: the platform refused a batch of events whole; sending them one by one",
				"contract: events parked for not_found are sent again",
				"contract: events never delivered in their 29 days are parked",
			},
			"item-events.md":              {"contract: events never delivered in their 29 days are parked"},
			"device-personal-transfer.md": {"transfer: would refuse"},
			"platform-sign-in.md": {
				"contract: sign-in would refuse",
				"refused a new account: its personal workspace's id is a workspace here already",
				"could not set up your workspace with The Happie Co; try again in a minute",
				"this account's workspace conflicts with one here; contact support",
			},
			"accounts-workspaces.md": {
				"people join this team through The Happie Co; person invitations are paused here until Wappie applies the platform's members",
			},
		} {
			for _, line := range lines {
				if !strings.Contains(code, `"`+line) && !strings.Contains(code, line+`"`) {
					t.Errorf("the code no longer says %q", line)
				}
				says(doc, line)
			}
		}
		// The start line, as a deploy checks it.
		codeSays(`"contract: mode=%s transport=%s secret=%s"`)
		says("contract.md", "contract: mode=off transport=none secret=missing")
		says("deployment.md", "contract: mode=off transport=none secret=missing")
	})

	t.Run("commands", func(t *testing.T) {
		usage := strings.Join(strings.Fields(commandList), " ")
		for _, c := range []struct{ doc, usage string }{
			{"whatserverd contract check [--other|--only-current|--only-other]", "contract check [--other|--only-current|--only-other]"},
			{"whatserverd contract status [--check]", "status [--check]"},
			{"whatserverd contract diff [--tenant T]", "diff [--tenant T]"},
			{"whatserverd contract mode off|observe", "mode off|observe"},
		} {
			says("contract.md", c.doc)
			says("deployment.md", c.doc)
			if !strings.Contains(usage, c.usage) {
				t.Errorf("whatserverd's usage does not show %q", c.usage)
			}
		}
		for _, name := range []string{`"other"`, `"only-current"`, `"only-other"`, `"check"`, `"tenant"`} {
			codeSays("(" + name)
		}
		if store.ContractOff != "off" || store.ContractObserve != "observe" {
			t.Errorf("the modes are %q and %q", store.ContractOff, store.ContractObserve)
		}
		if err := contractModeCommand([]string{"sideways"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
			t.Errorf("contract mode sideways: %v", err)
		}
		if !strings.Contains(usage, "contract-secret seal | promote | unpromote | drop | reset | capabilities") {
			t.Error("whatserverd's usage does not list contract-secret's subcommands")
		}

		// contract-secret, run: each documented subcommand is one it knows,
		// with the flags the docs give it.
		var out, stderr bytes.Buffer
		c := secretCommand{stdin: strings.NewReader(""), stdinTTY: func() bool { return false }, stdout: &out, stderr: &stderr,
			noCore: func() error { return nil }}
		if err := contractSecret([]string{"capabilities"}, c); err != nil || out.String() != "sighup\n" {
			t.Errorf("contract-secret capabilities: %q, %v", out.String(), err)
		}
		says("contract.md", "whatserverd contract-secret capabilities")
		says("contract.md", "prints `sighup`")
		says("deployment.md", "prints `sighup`")
		for _, sub := range []struct {
			name, doc string
			flags     []string
		}{
			{"seal", "whatserverd contract-secret seal --slot current|other --dir D --env-file F", []string{"-slot", "-dir", "-env-file", "-check-kms"}},
			{"seal", "whatserverd contract-secret seal --check-kms --env-file F", nil},
			{"promote", "whatserverd contract-secret promote --dir D", []string{"-dir"}},
			{"unpromote", "whatserverd contract-secret unpromote --dir D", []string{"-dir"}},
			{"drop", "whatserverd contract-secret drop --dir D", []string{"-dir"}},
			{"reset", "whatserverd contract-secret reset --dir D", []string{"-dir"}},
		} {
			says("contract.md", sub.doc)
			stderr.Reset()
			err := contractSecret([]string{sub.name, "-h"}, c)
			if err == nil || errors.As(err, new(usageError)) {
				t.Errorf("contract-secret %s -h: %v", sub.name, err)
			}
			for _, f := range sub.flags {
				if !strings.Contains(stderr.String(), "  "+f+" ") && !strings.Contains(stderr.String(), "  "+f+"\n") {
					t.Errorf("contract-secret %s has no flag %s:\n%s", sub.name, f, stderr.String())
				}
			}
		}
		if err := contractSecret([]string{"rotate"}, c); !errors.As(err, new(usageError)) {
			t.Errorf("contract-secret rotate: %v", err)
		}
		says("contract.md", fmt.Sprintf("An empty stdin exits `%d` (`contract-secret seal: no input`)", exitNoInput))
		codeSays(`"contract-secret seal: no input"`)
		codeSays(`"sealed %s %s\n"`)
		says("contract.md", "prints `sealed <slot> <fingerprint>`")
		codeSays(`"kms: ok"`)
		says("contract.md", "`kms: ok`")
		for _, step := range []string{"describe", "generate", "decrypt"} {
			codeSays(`"kms: ` + step + `: %w"`)
			says("contract.md", "`kms: "+step+"`")
		}
	})

	t.Run("contract check's exit codes", func(t *testing.T) {
		rows := tableRows(t, "../../docs/contract.md", "### Checking the secret: contract check")
		for _, c := range []struct {
			code   int
			phrase string
		}{
			{membership.ProbeVerified, "signed answer: generation"},
			{membership.ProbeVerified, "signed refusal: "},
			{membership.ProbeRejected, "unsigned 401: not the platform's secret"},
			{membership.ProbeExcluded, "which this check does not accept"},
			{membership.ProbeNoAnswer, "no answer from the platform"},
			{membership.ProbeNoAnswer, "the platform is busy"},
			{membership.ProbeFailed, "unsigned 404: the platform does not serve this caller: wappie is not mapped (PLATFORM_CONTRACT_APPS), or this process is not the wappie user"},
			{membership.ProbeFailed, "unsigned 401 stale_timestamp: this host's clock and the platform's differ by over a minute"},
		} {
			codeSays(c.phrase)
			row := strings.Join(rows[fmt.Sprintf("`%d`", c.code)], " | ")
			if !strings.Contains(row, c.phrase) {
				t.Errorf("docs/contract.md's row for exit %d does not say %q: %q", c.code, c.phrase, row)
			}
		}
		says("deployment.md", fmt.Sprintf("exits `%d` on a signed answer", membership.ProbeVerified))
		says("deployment.md", fmt.Sprintf("`%d` when the platform refuses the secret, `%d` on an answer signed with the secret it excludes, `%d` with no answer, `%d` otherwise",
			membership.ProbeRejected, membership.ProbeExcluded, membership.ProbeNoAnswer, membership.ProbeFailed))
		for _, flag := range []string{"--other", "--only-current", "--only-other"} {
			says("contract.md", "contract check "+flag)
		}
	})

	t.Run("settings", func(t *testing.T) {
		src := docText(t, "../../internal/config/contract.go")
		setting := regexp.MustCompile(`WS_CONTRACT_[A-Z_]*[A-Z]`)
		known := map[string]bool{}
		for _, m := range regexp.MustCompile(`"(WS_CONTRACT_[A-Z_]*[A-Z])"`).FindAllStringSubmatch(src, -1) {
			known[m[1]] = true
		}
		if len(known) < 8 {
			t.Fatalf("config/contract.go reads only %v", known)
		}
		for name := range known {
			for _, doc := range []string{"contract.md", "deployment.md", ".env.example"} {
				says(doc, name)
			}
		}
		for doc, text := range docs {
			for _, name := range setting.FindAllString(text, -1) {
				if !known[name] {
					t.Errorf("docs/%s names %s, which the configuration does not read", doc, name)
				}
			}
		}
		for _, doc := range []string{"contract.md", "deployment.md", ".env.example"} {
			says(doc, config.DefaultContractLoaded)
		}
	})

	t.Run("codes", func(t *testing.T) {
		for _, c := range []struct {
			status string
			number int
			code   string
			docs   []string
		}{
			{"StatusServiceUnavailable", 503, "platform_unavailable", []string{"platform-sign-in.md"}},
			{"StatusConflict", 409, "workspace_conflict", []string{"platform-sign-in.md"}},
			{"StatusForbidden", 403, "account_disabled", []string{"platform-sign-in.md"}},
			{"StatusConflict", 409, "invitations_paused", []string{"contract.md", "workspaces.md", "accounts-workspaces.md"}},
			{"StatusForbidden", 403, "owner_only", []string{"workspaces.md"}},
			{"StatusServiceUnavailable", 503, "workspace_busy", []string{"workspaces.md"}},
			{"StatusBadRequest", 400, "bad_request", []string{"workspaces.md"}},
			{"StatusTooManyRequests", 429, "rate_limited", []string{"workspaces.md"}},
		} {
			codeSays(fmt.Sprintf("http.%s, %q", c.status, c.code))
			for _, doc := range c.docs {
				says(doc, fmt.Sprintf("%d %s", c.number, c.code))
			}
		}
		codeSays(`http.StatusForbidden, stepup.Code`)
		if stepup.Code != "step_up_required" {
			t.Errorf("the step-up's code is %q", stepup.Code)
		}
		says("workspaces.md", "403 step_up_required")
		codeSays(`StatusConflict, struct`)
		codeSays(`Code: "last_reader_of_deleted"`)
		says("workspaces.md", "`409 last_reader_of_deleted`")
		codeSays(`http.StatusServiceUnavailable, "memberships_unconfirmed"`)
		codeSays(`"memberships_unconfirmed"`)
		says("contract.md", "`memberships_unconfirmed` (503 over HTTP, with `Retry-After: 60`")
		codeSays(`Set("Retry-After", "60")`)
		codeSays(`Set("Retry-After", "2")`)
		says("workspaces.md", "`503 workspace_busy` with `Retry-After: 2`")
		codeSays(`json:"strand_deleted"`)
		codeSays(`Get("strand_deleted")`)
		says("workspaces.md", "`\"strand_deleted\": true`")
		says("workspaces.md", "`?strand_deleted=true`")
		for _, kind := range []string{store.NoticeNumberStranded, store.NoticeNumberMovedOut} {
			says("devices.md", "`"+kind+"`")
		}
	})

	t.Run("findings", func(t *testing.T) {
		for _, f := range []string{
			"a contract ERROR in the last day: ",
			"the feed was last read ",
			"(the platform alerts after 10 minutes)",
			"published_through is ",
			"held subs not followed: their PUTs have failed since ",
			"has no snapshot accepted for over 60 minutes (the platform alerts after 90)",
			"is parked since ",
			": its snapshots are not sent",
			"events parked, the last at ",
			"'s events have had no verdict for over 60 minutes",
			"events pending for over 60 minutes, the oldest written at ",
			"the server's last secret load failed at step ",
			"a secret is installed but the server has published no load",
			"the server's published secrets cannot be read",
			"contract never observed but a secret is installed",
			"finding: ",
		} {
			codeSays(f)
			says("contract.md", strings.TrimSpace(f))
		}
		says("deployment.md", "contract never observed but a secret is installed")
		for _, class := range []string{store.ContractErrorFeedSilent, store.ContractErrorPublishedAhead, store.ContractErrorDocumentInvalid,
			store.ContractErrorKindChanged, store.ContractErrorRoundIncomplete, store.ContractErrorSnapshotParked,
			store.ContractErrorSnapshotInvalid, store.ContractErrorEventParked, store.ContractErrorEventsRefused, store.ContractErrorEventActor} {
			says("contract.md", "`"+class+"`")
		}
		says("contract-events.md", "`"+store.ContractErrorEventActor+"`")
		says("contract-events.md", "`"+store.ContractErrorEventParked+"`")
	})

	t.Run("words", func(t *testing.T) {
		for _, kind := range []string{store.DiffPersonalMismatch, store.DiffLocalOnly, store.DiffNoSub, store.DiffPlatformOnly, store.DiffRole,
			store.DiffAccountStatus, store.DiffMembershipStatus, store.DiffTeamClosed, store.DiffName, store.DiffSessionsWouldEnd,
			store.DiffCredentialsWouldStop, store.DiffUnnamedTenant} {
			says("contract.md", "| `"+kind+"` |")
		}
		for _, word := range []string{store.SnapshotActive, store.SnapshotSyncPaused, store.SnapshotDeleted, store.SnapshotByPerson,
			store.SnapshotNeedsReauth, store.SnapshotQuota, store.SnapshotError, store.PauseByPerson} {
			says("contract.md", "`"+word+"`")
		}
		for _, word := range []string{store.PauseByPerson, store.PauseForMove, store.PauseForDeletion} {
			says("devices.md", "`"+word+"`")
		}
		for _, ty := range []string{kc.EventDeleted, kc.EventRecovered, kc.EventSyncPaused, kc.EventPurged, kc.EventMovedOut, kc.EventStranded} {
			says("contract-events.md", "`"+ty+"`")
		}
		says("contract-events.md", "`to`: `"+kc.MovedToPersonal+"`")
		for _, code := range []string{store.EventParkedInvalid, store.EventParkedNotFound, store.EventParkedLocalInvalid,
			store.EventParkedConflict, store.EventParkedExpired} {
			says("contract-events.md", "`"+code+"`")
			says("item-events.md", "`"+code+"`")
		}
		for _, outcome := range []string{store.ContractEventAccepted, store.ContractEventDuplicate, "coalesced", "not_sent"} {
			says("contract-events.md", "`"+outcome+"`")
			says("item-events.md", "`"+outcome+"`")
		}
		ctx := membership.SealContext
		says("contract.md", fmt.Sprintf("`service=%s`, `env=%s`, `purpose=%s`, `ref=%s`", ctx.Service, ctx.Env, ctx.Purpose, ctx.Ref))
		for _, name := range []string{membership.SecretFileName, membership.SecretOtherFileName, membership.SecretStateFileName} {
			says("contract.md", "`"+name+"`")
		}
		for _, state := range []membership.SealState{membership.StateSteady, membership.StateNext, membership.StatePromoted} {
			says("contract.md", "`"+string(state)+"`")
		}
		for _, step := range []string{membership.StepKMS, membership.StepOpen, membership.StepCheck, membership.StepMissing} {
			says("contract.md", "`"+step+"`")
		}
		if membership.LockName != "contract" {
			t.Errorf("the leader's lock is %q", membership.LockName)
		}
		says("contract.md", "the advisory lock `"+membership.LockName+"`")
		for _, limit := range []string{
			fmt.Sprintf("At most %d items, %d people on an item", kc.MaxItems, kc.MaxPeople),
		} {
			says("contract.md", limit)
		}
		says("contract-events.md", fmt.Sprintf("at most %d events", kc.MaxEvents))
		says("contract-events.md", fmt.Sprintf("Above %d readers, `readers` is null", kc.MaxReaders))
	})

	t.Run("the 0051 down-step", func(t *testing.T) {
		sql := docText(t, "../../internal/migrate/sql/0051_contract_membership.sql")
		for _, msg := range []string{
			"the contract is on: run whatserverd contract mode off first",
			"a migration after 0051 is applied; run its down-step first",
		} {
			if !strings.Contains(sql, msg) {
				t.Errorf("0051's down-step no longer says %q", msg)
			}
			says("deployment.md", msg)
		}
		notice := "dropping % stranded rows, % owners'' notices, % unsent events, % home-taken security events"
		if !strings.Contains(sql, notice) {
			t.Errorf("0051's down-step no longer says %q", notice)
		}
		says("deployment.md", strings.ReplaceAll(strings.ReplaceAll(notice, "%", "N"), "''", "'"))
		says("deployment.md", "`migration51_sha256`")
		says("deployment.md", "`0051_contract_membership.sql`")
		if !strings.Contains(sql, "It runs first: 0051 down, then 0050 down") {
			t.Error("0051's header no longer says it comes down before 0050")
		}
		says("deployment.md", "It comes before 0050's down-step, whose guard refuses while 51 is applied")
	})

	t.Run("the event example", func(t *testing.T) {
		golden, err := os.ReadFile("../../internal/membership/testdata/events/deleted.json")
		if err != nil {
			t.Fatal(err)
		}
		doc, err := os.ReadFile("../../docs/contract-events.md")
		if err != nil {
			t.Fatal(err)
		}
		_, after, ok := strings.Cut(string(doc), "```json\n")
		block, _, closed := strings.Cut(after, "```")
		if !ok || !closed {
			t.Fatal("docs/contract-events.md has no JSON example")
		}
		if strings.TrimSpace(block) != strings.TrimSpace(string(golden)) {
			t.Errorf("docs/contract-events.md's example is not the renderer's golden deleted.json:\n%s", block)
		}
	})

	t.Run("timings", func(t *testing.T) {
		rows := tableRows(t, "../../docs/contract.md", "## Timings")
		for name, want := range map[string]string{
			"fresh":              spoken(store.FreshFor),
			"backup fresh":       spoken(store.BackupFreshFor),
			"clock skew":         spoken(store.ContractClockSkew),
			"orphan":             spoken(membership.OrphanAfter),
			"heartbeat":          spoken(pg.HoldHeartbeat),
			"long-poll":          spoken(time.Duration(kc.MaxWait) * time.Second),
			"snapshot not found": spoken(store.SnapshotNotFoundFor),
			"event not found":    spoken(store.ContractEventNotFoundFor),
			"event expiry":       spoken(store.ContractEventExpiry),
			"check feed":         spoken(checkFeedRead),
			"check snapshot":     spoken(checkSnapshot),
			"check published":    spoken(checkPublished),
			"check errors":       spoken(checkErrors),
			"check round":        spoken(checkRound),
			"check parked":       spoken(checkParked),
			"check events":       spoken(checkEvents),
		} {
			if got := rows[name]; len(got) == 0 || got[0] != want {
				t.Errorf("docs/contract.md's timing %q is %q, the code's is %q", name, got, want)
			}
		}
	})
}

// tableRows reads the tables under heading in a Markdown file, to the next
// heading: each row's first cell, its other cells. A row's first cell is
// unique there.
func tableRows(t *testing.T, path, heading string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(b), "\n"+heading+"\n")
	if !ok {
		t.Fatalf("%s has no %q", path, heading)
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "#") {
			break
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 || strings.HasPrefix(strings.TrimSpace(cells[1]), "---") {
			continue
		}
		key := strings.TrimSpace(cells[1])
		if _, twice := rows[key]; twice {
			t.Fatalf("%s's table under %q has %q twice", path, heading, key)
		}
		var rest []string
		for _, c := range cells[2 : len(cells)-1] {
			rest = append(rest, strings.TrimSpace(c))
		}
		rows[key] = rest
	}
	return rows
}

// spoken is a duration as the docs write it: "1 hour", "55 minutes",
// "29 days", "100 milliseconds".
func spoken(d time.Duration) string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	day := 24 * time.Hour
	switch {
	case d > day && d%day == 0:
		return unit(int64(d/day), "day")
	case d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute")
	case d%time.Second == 0:
		return unit(int64(d/time.Second), "second")
	}
	return unit(int64(d/time.Millisecond), "millisecond")
}

func TestSpoken(t *testing.T) {
	got := []string{spoken(time.Hour), spoken(55 * time.Minute), spoken(29 * 24 * time.Hour), spoken(24 * time.Hour),
		spoken(100 * time.Millisecond), spoken(time.Second), spoken(90 * time.Second)}
	want := []string{"1 hour", "55 minutes", "29 days", "24 hours", "100 milliseconds", "1 second", "90 seconds"}
	if !slices.Equal(got, want) {
		t.Errorf("spoken: %q", got)
	}
}
