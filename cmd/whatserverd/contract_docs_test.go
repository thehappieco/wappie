package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
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

// rawCode is a package's non-test Go source as written, for the patterns
// a line's layout matters to.
func rawCode(t *testing.T, dir string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // G304: the package's own sources
		if err != nil {
			t.Fatal(err)
		}
		b.Write(src)
		b.WriteByte('\n')
	}
	return b.String()
}

// funcBody is the body of the function name in src, to its closing brace
// at the start of a line.
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	_, body, ok := strings.Cut(src, "\nfunc "+name+"(")
	if !ok {
		t.Fatalf("no func %s", name)
	}
	body, _, _ = strings.Cut(body, "\n}\n")
	return body
}

// docSection is a doc's text under heading, to the next heading of its
// level or above, white space folded.
func docSection(t *testing.T, path, heading string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(b), "\n"+heading+"\n")
	if !ok {
		t.Fatalf("%s has no %q", path, heading)
	}
	level := heading[:strings.Index(heading, " ")+1]
	for _, l := range []string{"# ", "## ", "### "} {
		if section, _, _ = strings.Cut(section, "\n"+l); l == level {
			break
		}
	}
	return strings.Join(strings.Fields(section), " ")
}

// backticked is every `quoted` span of text, in order.
var backticked = regexp.MustCompile("`([^`]+)`")

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
		// A doc quotes a line whole, but these, which it quotes as the start
		// of every line that begins with them.
		prefixes := map[string]bool{"contract: workspace kind changed": true}
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
				"contract: the leader's lock is lost; stopping",
				"contract: could not publish the loaded secrets; the installer will not see this load",
				"contract: a feed document cannot be read; it is skipped",
				"contract: a new account's document names no personal workspace",
				"contract: held subs still have no document of this generation; their PUTs fail",
				"contract: no feed page for a long time",
				"contract: published_through ahead of the clock; the last trusted one is kept",
				"contract: a document cannot be stored",
				"contract: workspace kind changed",
				"contract: the platform's generation changed: every sub is subscribed again and the feed read from 0",
				"contract: following the token feed",
				"contract: no longer following the token feed",
				"contract: no token feed page for a long time",
				"contract: the token feed says the platform's generation changed: every sub is subscribed again and both feeds read from 0",
				"contract: the token feed was last read over an hour before this leader; token auth holds until it has caught up",
				"contract: a token page took over a second to commit",
				"contract: a token lookup got no answer",
				"contract: the token lookups answer again",
				"contract: the platform answered a token lookup with a record Wappie cannot use; it is asked again later",
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
			"deployment.md": {
				"token stop record writable",
				"token stop record not writable",
				"token stop record trim failed",
				"token stop record trimmed",
				"token stop record has unreadable lines",
				"no stop record (WS_TOKEN_STOP_RECORD is empty), so a restore of Wappie's database would lose it",
			},
		} {
			for _, line := range lines {
				quoted := `"` + line + `"`
				if prefixes[line] {
					quoted = `"` + line
				}
				if !strings.Contains(code, quoted) {
					t.Errorf("the code no longer says %q", line)
				}
				says(doc, line)
			}
		}
		// And the other way: every contract ERROR the code writes is in the
		// docs, so an operator grepping for the documented ones finds all.
		both := docs["contract.md"] + " " + docs["contract-events.md"]
		lines := regexp.MustCompile(`\.Error\("(contract[^"]*)"`).FindAllStringSubmatch(code, -1)
		if len(lines) < 20 {
			t.Fatalf("only %d contract ERROR lines in the code", len(lines))
		}
		for _, m := range lines {
			documented := strings.Contains(both, m[1])
			for p := range prefixes {
				documented = documented || strings.HasPrefix(m[1], p) && strings.Contains(both, p)
			}
			if !documented {
				t.Errorf("docs/contract.md and docs/contract-events.md do not say the ERROR %q", m[1])
			}
		}
		// And every contract line the docs quote is still the code's, so a
		// line the code no longer writes leaves the docs too.
		quoted := regexp.MustCompile(`"(contract: [^"]+)"`)
		for _, doc := range []string{"contract.md", "contract-events.md", "deployment.md"} {
			for _, m := range quoted.FindAllStringSubmatch(docs[doc], -1) {
				if !strings.Contains(code, m[1]) {
					t.Errorf("docs/%s quotes %q, which the code no longer says", doc, m[1])
				}
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
			{"whatserverd contract tokens on|off|status", "tokens on|off|status"},
			{"whatserverd tokens suspend [-note N] SELECTOR|TOKEN|-", "tokens suspend [-note N] SELECTOR|TOKEN|-"},
			{"whatserverd tokens suspend -replay F", "suspend -replay F"},
			{"whatserverd tokens lift SELECTOR|TOKEN|-", "lift SELECTOR|TOKEN|-"},
			{"whatserverd tokens list", "| list"},
		} {
			says("contract.md", c.doc)
			says("deployment.md", c.doc)
			if !strings.Contains(usage, c.usage) {
				t.Errorf("whatserverd's usage does not show %q", c.usage)
			}
		}
		// The flags, parsed by the commands themselves, which refuse before
		// they open anything: three flags that parse are exclusive, a
		// --tenant that parses is checked, and --check that parses leaves
		// the extra word.
		if err := contractCheck([]string{"--other", "--only-current", "--only-other"}, io.Discard, nil); err == nil ||
			err.Error() != "contract check: --other, --only-current and --only-other are exclusive" {
			t.Errorf("contract check --other --only-current --only-other: %v", err)
		}
		if err := contractDiffCommand([]string{"--tenant", "nope"}, io.Discard); err == nil || err.Error() != "contract diff: --tenant takes a workspace id" {
			t.Errorf("contract diff --tenant nope: %v", err)
		}
		if err := contractStatusCommand([]string{"--check", "extra"}, io.Discard); !errors.As(err, new(usageError)) {
			t.Errorf("contract status --check extra: %v", err)
		}
		if store.ContractOff != "off" || store.ContractObserve != "observe" {
			t.Errorf("the modes are %q and %q", store.ContractOff, store.ContractObserve)
		}
		if err := contractModeCommand([]string{"sideways"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
			t.Errorf("contract mode sideways: %v", err)
		}
		if err := contractTokensCommand([]string{"sideways"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
			t.Errorf("contract tokens sideways: %v", err)
		}
		if store.TokensOn != "on" || store.TokensOff != "off" {
			t.Errorf("the token modes are %q and %q", store.TokensOn, store.TokensOff)
		}
		// What -replay says it left, as the command's section and the
		// restore's runbook quote it.
		for _, left := range []struct{ code, runbook string }{
			{"lines left, no later than what the database holds or with nothing to lift", "those no later than what the database holds or with nothing to lift"},
			{"lines left, no later than the last stop retention let go", "those no later than the last stop retention let go"},
			{"lines over 365 days old left, their stops let go", "those over 365 days old"},
		} {
			codeSays(left.code)
			says("contract.md", left.code)
			says("deployment.md", left.runbook)
		}
		// A lift of a stop lifted already writes no line, as both docs
		// quote, so none says a line carries an earlier lift's time.
		lifted := "the operator's stop was lifted already; nothing changed or recorded"
		codeSays(lifted)
		says("contract.md", lifted)
		says("deployment.md", lifted)
		for name, text := range map[string]string{"contract.md": docs["contract.md"], "deployment.md": docs["deployment.md"], "the code": code} {
			if strings.Contains(text, "first lift's time") {
				t.Errorf("%s says a line carries the first lift's time", name)
			}
		}
		// tokens' flags, parsed before anything opens: each documented one
		// is the command's, and it has no other; a text that is no selector
		// or token is refused without being repeated.
		for _, c := range []struct {
			args  []string
			flags []string
		}{
			{[]string{"suspend", "-h"}, []string{"-note", "-replay"}},
			{[]string{"lift", "-h"}, nil},
		} {
			var stderr bytes.Buffer
			fs := tokensFlagOutput
			tokensFlagOutput = &stderr
			err := tokensCommand(c.args, strings.NewReader(""), io.Discard)
			tokensFlagOutput = fs
			if err == nil || errors.As(err, new(usageError)) {
				t.Errorf("tokens %v: %v", c.args, err)
			}
			var flags []string
			for l := range strings.Lines(stderr.String()) {
				if f, ok := strings.CutPrefix(l, "  -"); ok {
					flags = append(flags, "-"+strings.Fields(f)[0])
				}
			}
			if !slices.Equal(flags, c.flags) {
				t.Errorf("tokens %s's flags: %v, want %v:\n%s", c.args[0], flags, c.flags, stderr.String())
			}
		}
		const secretLike = "thc_0123456789abcdef.not-a-secret"
		if err := tokensCommand([]string{"suspend", secretLike}, strings.NewReader(""), io.Discard); err == nil ||
			strings.Contains(err.Error(), "not-a-secret") || !strings.Contains(err.Error(), "neither a token's selector") {
			t.Errorf("tokens suspend with a text that is no token: %v", err)
		}
		if err := tokensCommand([]string{"list", "extra"}, strings.NewReader(""), io.Discard); !errors.As(err, new(usageError)) {
			t.Errorf("tokens list extra: %v", err)
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
		// A whole name: WS_CONTRACT_SECRET_FILE is not WS_CONTRACT_SECRET.
		for name := range known {
			whole := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
			for _, doc := range []string{"contract.md", "deployment.md", ".env.example"} {
				if !whole.MatchString(docs[doc]) {
					t.Errorf("docs/%s does not name %s", doc, name)
				}
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
			says(doc, "WS_TOKEN_STOP_RECORD")
			says(doc, config.DefaultTokenStopRecord)
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
			"has no snapshot accepted for over %d minutes (the platform alerts after 90)",
			"is parked since ",
			": its snapshots are not sent",
			"events parked, the last at ",
			"'s events have had no verdict for over %d minutes",
			"events pending for over %d minutes, the oldest written at ",
			"the server's last secret load failed at step ",
			"the server holds current=",
			", the files are current=",
			"a secret is installed but the server has published no load",
			"the server's published secrets cannot be read",
			"contract never observed but a secret is installed",
			"the token feed was last read ",
			"the token feed's published_through is ",
			": tokens' send and manage are refused",
			"token auth holds: no token page with more false has committed since the token mode's switch at ",
			"the token acknowledgement has failed since ",
			"the token usage report has failed since ",
			" tokens unlisted by a reset's pass in the last day: refused here for good",
			" tokens' reading key changed: their new grants are refused",
			" tokens stopped here: a record of theirs could not be applied (apply_failed)",
			" ms to commit at ",
			" (over a second)",
			"finding: ",
		} {
			codeSays(f)
			if strings.Contains(f, "%d") {
				// The bound, as --check prints it: from its constant.
				bound := checkEvents
				if strings.Contains(f, "snapshot") {
					bound = checkSnapshot
				}
				f = fmt.Sprintf(f, int(bound/time.Minute))
			}
			says("contract.md", strings.TrimSpace(f))
		}
		says("deployment.md", "contract never observed but a secret is installed")
		for _, class := range []string{store.ContractErrorFeedSilent, store.ContractErrorPublishedAhead, store.ContractErrorDocumentInvalid,
			store.ContractErrorKindChanged, store.ContractErrorRoundIncomplete, store.ContractErrorSnapshotParked,
			store.ContractErrorSnapshotInvalid, store.ContractErrorEventParked, store.ContractErrorEventsRefused, store.ContractErrorEventActor,
			store.ContractErrorTokenFeedSilent, store.ContractErrorTokenLookupInvalid} {
			says("contract.md", "`"+class+"`")
		}
		says("contract-events.md", "`"+store.ContractErrorEventActor+"`")
		says("contract-events.md", "`"+store.ContractErrorEventParked+"`")
	})

	t.Run("the members list's override fields", func(t *testing.T) {
		// docs/workspaces.md names each field by the JSON name a console
		// reads, and names no other: the store's tags, both ways.
		section := docSection(t, "../../docs/workspaces.md", "### The strand override")
		tag := func(typ reflect.Type, field string) string {
			t.Helper()
			f, ok := typ.FieldByName(field)
			if !ok {
				t.Fatalf("%s has no field %s", typ, field)
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			return name
		}
		member := reflect.TypeFor[store.Member]()
		fields := map[string]bool{}
		for _, f := range []string{"LastKeyHolderOfDeleted", "LastKeyHolderOfDeletedAny", "StrandOverride"} {
			fields[tag(member, f)] = true
		}
		ref := reflect.TypeFor[store.DeletedNumberRef]()
		for i := range ref.NumField() {
			fields[tag(ref, ref.Field(i).Name)] = true
		}
		named := map[string]bool{}
		for _, m := range backticked.FindAllStringSubmatch(section, -1) {
			name, _, _ := strings.Cut(m[1], ": ")
			named[name] = true
			if strings.HasPrefix(name, "last_key_holder") || name == "strand_override" {
				if !fields[name] {
					t.Errorf("docs/workspaces.md's strand override names %q, which the members list does not send", name)
				}
			}
		}
		for name := range fields {
			if !named[name] {
				t.Errorf("docs/workspaces.md's strand override does not name the members list's %q", name)
			}
		}
	})

	t.Run("words", func(t *testing.T) {
		for _, kind := range []string{store.DiffPersonalMismatch, store.DiffLocalOnly, store.DiffNoSub, store.DiffPlatformOnly, store.DiffRole,
			store.DiffAccountStatus, store.DiffMembershipStatus, store.DiffTeamClosed, store.DiffName, store.DiffSessionsWouldEnd,
			store.DiffCredentialsWouldStop, store.DiffUnnamedTenant} {
			says("contract.md", "| `"+kind+"` |")
		}
		snapshots := docSection(t, "../../docs/contract.md", "## Access snapshots")
		for _, word := range []string{store.SnapshotActive, store.SnapshotSyncPaused, store.SnapshotDeleted, store.SnapshotByPerson,
			store.SnapshotNeedsReauth, store.SnapshotQuota, store.SnapshotError, store.PauseByPerson} {
			if !strings.Contains(snapshots, "`"+word+"`") {
				t.Errorf("docs/contract.md's Access snapshots do not say %q", word)
			}
		}

		// The acts, by the names the hooks log: each one the code gives a
		// hook is in the Act table, and each the table names is the code's.
		inTable := map[string]bool{}
		for key := range tableRows(t, "../../docs/contract.md", "## Freshness") {
			for _, m := range backticked.FindAllStringSubmatch(key, -1) {
				if !strings.HasPrefix(m[1], "Require") {
					inTable[m[1]] = true
					codeSays(`"` + m[1] + `"`)
				}
			}
		}
		for _, act := range gatedActs(t) {
			if !inTable[act] {
				t.Errorf("docs/contract.md's Act table does not name %q, which the code gives a hook", act)
			}
		}
		// The verdicts' reasons, which an operator greps the WARNs for: each
		// the code's, and the docs' two lists exactly those.
		for _, w := range []string{"no_sub", "unverified", "unavailable", "throttled", "not_stored", "no_confirmed_backup",
			"no_document", "not_a_member"} {
			codeSays(`"` + w + `"`)
		}
		for _, c := range []string{`"account_" + st.Status`, `"refused:" + RefusalCode(err)`, `"role_" + w.Role`, `fmt.Sprintf("owners_%d", n)`} {
			codeSays(c)
		}
		says("contract.md", "reason: `no_sub`, `account_"+kc.AccountDisabled+"`, `account_"+kc.AccountClosed+"`, `refused:<code>`, "+
			"`unverified`, `unavailable`, `throttled`, `not_stored`, or `no_confirmed_backup` with each holder's)")
		says("contract.md", `"transfer: would refuse" (`+"`no_document`, `not_a_member`, `role_<role>`, `owners_<n>`)")
		codeSays(`"contract: sign-in would refuse", "sub", sub, "reason", "stale"`)
		says("contract.md", "`account_"+kc.AccountDisabled+"`, `account_"+kc.AccountClosed+"` or `stale`), and the sign-in goes on")

		// A failed secret load's classes: every one the code gives is in the
		// docs' list, and the list holds no other but its example of KMS's
		// own codes.
		classes := map[string]bool{"AccessDeniedException": true}
		for _, src := range []string{funcBody(t, rawCode(t, "../../internal/membership"), "ErrorClass"),
			funcBody(t, rawCode(t, "."), "kmsErrorClass")} {
			for _, m := range regexp.MustCompile(`return "([a-z_]+)"`).FindAllStringSubmatch(src, -1) {
				if m[1] != "none" {
					classes[m[1]] = true
				}
			}
		}
		_, list, _ := strings.Cut(docs["contract.md"], "and a closed class (")
		list, _, _ = strings.Cut(list, "), never the error's text")
		listed := map[string]bool{}
		for _, m := range backticked.FindAllStringSubmatch(list, -1) {
			listed[m[1]] = true
			if !classes[m[1]] {
				t.Errorf("docs/contract.md lists the class %q, which the code never gives", m[1])
			}
		}
		for c := range classes {
			if !listed[c] {
				t.Errorf("docs/contract.md does not list the class %q", c)
			}
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
		says("contract.md", "(`"+membership.SwapPromoting+"` or `"+membership.SwapUnpromoting+"`, and the fingerprint of the file the swap makes current)")
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
		ours := map[string]string{
			"fresh":                 spoken(store.FreshFor),
			"backup fresh":          spoken(store.BackupFreshFor),
			"clock skew":            spoken(store.ContractClockSkew),
			"orphan":                spoken(membership.OrphanAfter),
			"heartbeat":             spoken(pg.HoldHeartbeat),
			"long-poll":             spoken(time.Duration(kc.MaxWait) * time.Second),
			"call timeout":          spoken(kc.CallTimeout),
			"feed grace":            spoken(kc.FeedGrace),
			"snapshot not found":    spoken(store.SnapshotNotFoundFor),
			"event not found":       spoken(store.ContractEventNotFoundFor),
			"event expiry":          spoken(store.ContractEventExpiry),
			"check feed":            spoken(checkFeedRead),
			"check snapshot":        spoken(checkSnapshot),
			"check published":       spoken(checkPublished),
			"check errors":          spoken(checkErrors),
			"check round":           spoken(checkRound),
			"check parked":          spoken(checkParked),
			"check events":          spoken(checkEvents),
			"check token feed":      spoken(checkTokenFeed),
			"check token published": spoken(checkTokenPublished),
			"check token held":      spoken(checkTokenHeld),
			"check acks":            spoken(checkAcks),
			"check usage":           spoken(checkUsage),
			"check token commit":    spoken(checkTokenCommit),
			"stop record lock":      spoken(tokenStopLockWait),
		}
		// The rows the membership package checks (TestContractTimingsMatchTheDocs,
		// which lists these as checked here), and wsapi's and mcpauth's.
		elsewhere := []string{"call bound", "mode cache", "pace", "sweep", "round", "leader retry", "peer checks",
			"feed backoff", "feed silent", "warn", "round failing", "debounce", "snapshot", "snapshot backoff", "labels",
			"event backoff", "event scan", "load retry", "load retry for", "load retry late", "hot path", "hot path bound",
			"token long-poll", "token backoff", "token stale start", "token commit", "judge", "ack spacing", "ack every", "ack backoff",
			"usage", "lookup", "lookup retry", "lookup backoff"}
		for name, want := range ours {
			if got := rows[name]; len(got) == 0 || got[0] != want {
				t.Errorf("docs/contract.md's timing %q is %q, the code's is %q", name, got, want)
			}
		}
		for name := range rows {
			if _, mine := ours[name]; name != "Timing" && !mine && !slices.Contains(elsewhere, name) {
				t.Errorf("docs/contract.md's timing %q is checked by no test", name)
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
var spoken = membershiptest.Spoken

func TestSpoken(t *testing.T) {
	got := []string{spoken(time.Hour), spoken(55 * time.Minute), spoken(29 * 24 * time.Hour), spoken(24 * time.Hour),
		spoken(100 * time.Millisecond), spoken(time.Second), spoken(90 * time.Second)}
	want := []string{"1 hour", "55 minutes", "29 days", "24 hours", "100 milliseconds", "1 second", "90 seconds"}
	if !slices.Equal(got, want) {
		t.Errorf("spoken: %q", got)
	}
}

// gatedActs are the acts the code gives the freshness hooks by name: the
// socket's frames (wsapi's fresh, widening and freshBackups), the act
// constants of mcpauth and authapi, and the mover's.
func gatedActs(t *testing.T) []string {
	t.Helper()
	ws := rawCode(t, "../../internal/wsapi")
	frames := map[string]string{}
	for _, m := range regexp.MustCompile(`\b(Type\w+)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(ws, -1) {
		frames[m[1]] = m[2]
	}
	var acts []string
	for _, m := range regexp.MustCompile(`s\.(?:fresh|widening|freshBackups)\(ctx, [\w.]+, (Type\w+)`).FindAllStringSubmatch(ws, -1) {
		act, ok := frames[m[1]]
		if !ok {
			t.Fatalf("wsapi gives a hook %s, which names no frame", m[1])
		}
		acts = append(acts, act)
	}
	for _, dir := range []string{"../../internal/mcpauth", "../../internal/authapi"} {
		for _, m := range regexp.MustCompile(`\bact[A-Z]\w*\s*=\s*"([^"]+)"`).FindAllStringSubmatch(rawCode(t, dir), -1) {
			acts = append(acts, m[1])
		}
	}
	acts = append(acts, membership.ActTransfer)
	if len(acts) < 18 {
		t.Fatalf("only %d gated acts found: %q", len(acts), acts)
	}
	return acts
}

// F5 and E4 of decision 0056's review: rolling back below 0052, or
// changing WS_TOKEN_STOP_RECORD, leaves the stop record with nothing that
// trims it, so both the down-step's header and docs/deployment.md say to
// trim it by hand or delete it once no re-upgrade will replay it; and the
// record's copy rules and a host's loss are said beside the ledger's.
func TestDocsSayRollingBackBelow0052(t *testing.T) {
	section := docSection(t, "../../docs/deployment.md", "### Rolling back below 0052")
	for _, s := range []string{
		"migration52_sha256",
		"An older binary knows nothing of the stop record (`WS_TOKEN_STOP_RECORD`), so nothing trims it any more.",
		"Trim it by hand, dropping each line whose `at` is over 365 days old, or delete it, and its copies, once no re-upgrade will replay it.",
	} {
		if !strings.Contains(section, s) {
			t.Errorf("docs/deployment.md's rolling back below 0052 does not say %q", s)
		}
	}
	deployment := docText(t, "../../docs/deployment.md")
	for _, s := range []string{
		"Change or blank `WS_TOKEN_STOP_RECORD` and nothing trims the old file any more",
		"It goes off host with every off-host copy of the database, and at least daily, as the ledger does.",
		"If the host is lost, a stop or lift made after the newest off-host copy of the record is lost with everything else made after it, and has to be made again",
		"A stop here is a stopgap: once the platform answers, have the token revoked in the console.",
		"Record a stop the file lacks by running `tokens suspend` again with the same `-note`",
	} {
		if !strings.Contains(deployment, s) {
			t.Errorf("docs/deployment.md does not say %q", s)
		}
	}
	sql, err := os.ReadFile("../../internal/migrate/sql/0052_contract_tokens.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Its comments as prose: no "--" between the words of two lines.
	header := strings.Join(strings.Fields(strings.ReplaceAll(string(sql), "\n--", "\n")), " ")
	for _, s := range []string{
		"Rolling back below 0052 leaves the stop record (WS_TOKEN_STOP_RECORD) with nothing that trims it",
		"or delete it once no re-upgrade will replay it",
		"when WS_TOKEN_STOP_RECORD is changed or blanked",
	} {
		if !strings.Contains(header, s) {
			t.Errorf("0052's header does not say %q", s)
		}
	}
}
