package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	kc "github.com/thehappieco/kit/contract"
)

// ProbeMode is which secret a probe signs with and which it accepts on the
// answer: the four checks of a rotation (README 7.3), each proving the one
// state the installer's next step needs.
type ProbeMode int

// The modes of contract check.
const (
	// ProbeBoth signs with the current secret and accepts either: the
	// check after an install, and after every step.
	ProbeBoth ProbeMode = iota
	// ProbeOther signs with the other secret and accepts either: the next
	// secret, before Wappie promotes it, is accepted on requests (the
	// platform's step 1).
	ProbeOther
	// ProbeOnlyCurrent signs with the current secret and accepts only it:
	// before a drop, that the platform answers with the secret Wappie now
	// signs with (its step 4); before a cancel from next, that it still
	// signs with the old one.
	ProbeOnlyCurrent
	// ProbeOnlyOther signs with the other secret and accepts only it:
	// before a cancel from promoted, that the platform still signs with the
	// old secret, which Wappie keeps as the other.
	ProbeOnlyOther
)

// A probe's exit codes, which the installer acts on (contract-secret.sh).
const (
	// ProbeVerified: an answer signed with a secret the probe accepts.
	ProbeVerified = 0
	// ProbeFailed: anything else (no such secret installed, an answer that
	// is not valid, a peer that failed its checks, an unsigned refusal
	// other than the secret's).
	ProbeFailed = 1
	// ProbeRejected: an unsigned 401, the platform refusing the request's
	// secret.
	ProbeRejected = 3
	// ProbeExcluded: an answer signed, but with the secret this probe
	// excludes.
	ProbeExcluded = 4
	// ProbeNoAnswer: no answer (no socket, a refused connection, a
	// timeout, an unsigned 429 or 503): try again, never proceed.
	ProbeNoAnswer = 5
)

// ProbeResult is what one probe found, as one line that holds no secret.
type ProbeResult struct {
	Code int
	Line string
}

// probeTarget is the check of platform-deploy ("Checking it"): a signed
// feed request that waits for nothing.
const probeTarget = "/contract/v1/feed?after=0&wait=0"

// Probe sends one signed feed request as mode says and sorts its answer by
// the secret that signed it. It signs and checks with the kit's own scheme
// and VerifyAnswer, as every call does; it does not go through the kit's
// Client, which would say only that an answer did not verify, and a
// rotation's checks need to know whether the excluded secret signed it.
func (c *Client) Probe(ctx context.Context, mode ProbeMode) ProbeResult {
	k := c.kit.Load()
	if k == nil {
		return ProbeResult{ProbeFailed, "no contract secret is loaded"}
	}
	current, other := k.Secret, ""
	if len(k.Accept) > 1 {
		other = k.Accept[1]
	}
	sign, accept := current, k.Accept
	var exclude []string
	var excluded string
	switch mode {
	case ProbeBoth:
	case ProbeOther:
		if other == "" {
			return ProbeResult{ProbeFailed, "no other secret is installed"}
		}
		sign = other
	case ProbeOnlyCurrent:
		accept = []string{current}
		if other != "" {
			exclude, excluded = []string{other}, "other"
		}
	case ProbeOnlyOther:
		if other == "" {
			return ProbeResult{ProbeFailed, "no other secret is installed"}
		}
		sign, accept, exclude, excluded = other, []string{other}, []string{current}, "current"
	default:
		return ProbeResult{ProbeFailed, "unknown probe"}
	}

	ctx, cancel := context.WithTimeout(ctx, kc.CallTimeout)
	defer cancel()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+probeTarget, http.NoBody)
	if err != nil {
		return ProbeResult{ProbeFailed, "the request could not be made"}
	}
	if err := kc.Scheme().Sign(req.Header, sign, kc.ToPlatform, App, http.MethodGet, probeTarget, nil, now()); err != nil {
		return ProbeResult{ProbeFailed, "the request could not be signed"}
	}
	nonce := req.Header.Get(kc.HeaderNonce)
	res, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrPeer) {
			reason := err.Error()
			if i := strings.Index(reason, ErrPeer.Error()); i >= 0 {
				reason = reason[i:]
			}
			return ProbeResult{ProbeFailed, reason}
		}
		return ProbeResult{ProbeNoAnswer, "no answer from the platform" + noAnswerCause(err)}
	}
	//nolint:errcheck // a failed close on an answer read whole tells us nothing
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, kc.MaxAnswer+1))
	if err != nil || len(body) > kc.MaxAnswer {
		return ProbeResult{ProbeNoAnswer, "no whole answer from the platform"}
	}
	at := now()
	verr := kc.VerifyAnswer(res.Header, accept, App, http.MethodGet, probeTarget, nonce, body, at)
	if verr == nil {
		return verified(body)
	}
	if exclude != nil && kc.VerifyAnswer(res.Header, exclude, App, http.MethodGet, probeTarget, nonce, body, at) == nil {
		return ProbeResult{ProbeExcluded, fmt.Sprintf("signed answer, but signed with the %s secret, which this check does not accept", excluded)}
	}
	if !errors.Is(verr, kc.ErrMissing) {
		return ProbeResult{ProbeFailed, fmt.Sprintf("an answer (%d) whose signature does not hold", res.StatusCode)}
	}
	// Unsigned, so its body is nobody's word: it only says which unsigned
	// refusal to report.
	var refusal kc.Error
	if json.Unmarshal(body, &refusal) != nil {
		refusal = kc.Error{}
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized && refusal.Code == kc.CodeStale:
		return ProbeResult{ProbeFailed, "unsigned 401 stale_timestamp: this host's clock and the platform's differ by over a minute"}
	case res.StatusCode == http.StatusUnauthorized:
		return ProbeResult{ProbeRejected, "unsigned 401: not the platform's secret"}
	case res.StatusCode == http.StatusTooManyRequests, res.StatusCode == http.StatusServiceUnavailable:
		return ProbeResult{ProbeNoAnswer, fmt.Sprintf("unsigned %d: the platform is busy", res.StatusCode)}
	case res.StatusCode == http.StatusNotFound:
		// README 4, step 1: an unmapped peer uid is a 404 too.
		return ProbeResult{ProbeFailed, "unsigned 404: the platform does not serve this caller: wappie is not mapped " +
			"(PLATFORM_CONTRACT_APPS), or this process is not the wappie user"}
	}
	return ProbeResult{ProbeFailed, fmt.Sprintf("unsigned %d", res.StatusCode)}
}

// noAnswerCause names why a request got no answer, as a class and never
// the address: the installer acts on the exit status (5, try again), and
// the owner reads the line, which tells a configuration fault that no retry
// fixes (the socket's group) from the platform restarting.
func noAnswerCause(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return ": permission denied on the socket (run as wappie with SupplementaryGroups=platform-contract)"
	case errors.Is(err, fs.ErrNotExist):
		return ": no socket at the configured path (the platform is down or restarting)"
	case errors.Is(err, syscall.ECONNREFUSED):
		return ": the connection was refused (the platform is down or restarting)"
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return ": timeout"
	}
	return ""
}

// verified reads a verified answer: a feed page, or a signed refusal, which
// proves the secret just as well.
func verified(body []byte) ProbeResult {
	var refusal kc.Error
	if json.Unmarshal(body, &refusal) == nil && refusal.Code != "" {
		return ProbeResult{ProbeVerified, "signed refusal: " + refusal.Code}
	}
	var f kc.Feed
	if err := json.Unmarshal(body, &f); err != nil {
		return ProbeResult{ProbeFailed, "a signed answer that is not a feed page"}
	}
	if err := f.Validate(App); err != nil {
		return ProbeResult{ProbeFailed, "a signed answer that is not a valid feed page"}
	}
	return ProbeResult{ProbeVerified, fmt.Sprintf("signed answer: generation %s confirmed %t head %d", f.Generation, f.GenerationConfirmed, f.Head)}
}
