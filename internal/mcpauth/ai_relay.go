package mcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"
)

// The AI calls of the signed relay (docs/mcp-enclave.md §18.11, Go → enclave):
// a pending AI request, its bundle, a job and a job's state. The bundle
// routes check every key and model with the providers before they answer,
// so this server waits for them longer than for anything else.

// aiBundleTimeout is how long an AI bundle, a consent's or a renewal's, may
// take: the enclave lists each key's models, every page, before it answers.
const aiBundleTimeout = 30 * time.Second

// AIJobError is the enclave refusing a job: its code, and for ai_busy when
// to come back.
type AIJobError struct {
	// Status is the enclave's answer: 409 or 429.
	Status int
	// Code is ai_paused, ai_budget_reached or ai_busy.
	Code string
	// RetryAfter is ai_busy's retry_after_s; zero otherwise.
	RetryAfter int
}

func (e *AIJobError) Error() string { return "mcpauth: the reader refused the AI job: " + e.Code }

// AIRequest asks the reader for a pending AI request over the browser's
// nonce: the prepared descriptor, attested like a prepare. The bytes come
// back as the reader sent them.
func (c *SignedRelay) AIRequest(ctx context.Context, nonce string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/ai/requests", prepareRequest{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusTooManyRequests:
		return nil, ErrTooManyPrepares
	case http.StatusBadRequest:
		return nil, &RefusalError{Code: readerCode(body)}
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%w: ai request answered 503 %s", ErrReaderUnavailable, readerCode(body))
	}
	return descriptorAnswer(status, body)
}

// AIBundle hands the reader an AI consent's sealed bundle, and waits for it
// to check the grants, the tags, the keys and the models and to activate the
// authorization.
func (c *SignedRelay) AIBundle(ctx context.Context, requestID string, in BundleRelay) error {
	ctx, cancel := context.WithTimeout(ctx, aiBundleTimeout)
	defer cancel()
	status, body, err := c.doWith(ctx, c.patient(), http.MethodPost, "/internal/ai/requests/"+url.PathEscape(requestID)+"/bundle", in)
	if err != nil {
		return err
	}
	return bundleAnswer(status, body)
}

// AIRenewalBundle is RenewalBundle for an AI authorization, with the same
// wait as an AI consent.
func (c *SignedRelay) AIRenewalBundle(ctx context.Context, connectionID, renewalID string, in BundleRelay) error {
	ctx, cancel := context.WithTimeout(ctx, aiBundleTimeout)
	defer cancel()
	status, body, err := c.doWith(ctx, c.patient(), http.MethodPost,
		"/internal/connections/"+url.PathEscape(connectionID)+"/renewal/"+url.PathEscape(renewalID)+"/bundle", in)
	if err != nil {
		return err
	}
	return bundleAnswer(status, body)
}

// AIJobRequest is a console's request for a function on a message, under
// the authorization this server picked for it.
type AIJobRequest struct {
	AuthorizationID string `json:"authorization_id"`
	DeviceID        string `json:"device_id"`
	UID             string `json:"uid"`
	Feature         string `json:"feature"`
	Origin          string `json:"origin"`
	RequesterID     string `json:"requester_id"`
	Redo            bool   `json:"redo"`
}

// AIJobStarted is the reader's answer to a job: its id, or that a result is
// stored already.
type AIJobStarted struct {
	Job    string `json:"job,omitempty"`
	Stored bool   `json:"stored,omitempty"`
}

// AIJob hands the reader a job. A refusal is an *AIJobError; a record the
// reader does not hold is ErrReaderNotFound.
func (c *SignedRelay) AIJob(ctx context.Context, in AIJobRequest) (AIJobStarted, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/ai/jobs", in)
	if err != nil {
		return AIJobStarted{}, err
	}
	switch status {
	case http.StatusAccepted, http.StatusOK:
		var out AIJobStarted
		if json.Unmarshal(body, &out) != nil || status == http.StatusAccepted && !ValidJobID(out.Job) || status == http.StatusOK && !out.Stored {
			return AIJobStarted{}, fmt.Errorf("%w: the job's answer is not the expected object", ErrReaderUnavailable)
		}
		return out, nil
	case http.StatusNotFound:
		return AIJobStarted{}, ErrReaderNotFound
	case http.StatusConflict, http.StatusTooManyRequests:
		var refusal struct {
			Code       string `json:"code"`
			RetryAfter int    `json:"retry_after_s"`
		}
		if json.Unmarshal(body, &refusal) != nil || refusal.Code == "" {
			refusal.Code = "unspecified"
		}
		return AIJobStarted{}, &AIJobError{Status: status, Code: refusal.Code, RetryAfter: refusal.RetryAfter}
	default:
		return AIJobStarted{}, fmt.Errorf("%w: ai job answered %d %s", ErrReaderUnavailable, status, readerCode(body))
	}
}

// AIJobState is a job's state as the reader keeps it.
type AIJobState struct {
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
}

// aiJobStates are the states a job is in.
var aiJobStates = []string{"queued", "running", "done", "failed"}

// AIJobStatus asks the reader for a job's state, for its requester. A job
// the reader does not know, or another requester's, is ErrReaderNotFound.
func (c *SignedRelay) AIJobStatus(ctx context.Context, job, requester string) (AIJobState, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/internal/ai/jobs/"+url.PathEscape(job)+"?requester_id="+url.QueryEscape(requester), nil)
	if err != nil {
		return AIJobState{}, err
	}
	switch status {
	case http.StatusOK:
		var out AIJobState
		if json.Unmarshal(body, &out) != nil || !slices.Contains(aiJobStates, out.State) || out.Code != "" && !codePattern.MatchString(out.Code) {
			return AIJobState{}, fmt.Errorf("%w: the job's state is not the expected object", ErrReaderUnavailable)
		}
		return out, nil
	case http.StatusNotFound:
		return AIJobState{}, ErrReaderNotFound
	default:
		return AIJobState{}, fmt.Errorf("%w: ai job state answered %d", ErrReaderUnavailable, status)
	}
}

// patient is the relay's client with the AI bundles' wait: the same
// transport, a longer deadline.
func (c *SignedRelay) patient() *http.Client {
	client := c.Client
	if client == nil {
		client = signedClient("", nil)
	}
	longer := *client
	longer.Timeout = aiBundleTimeout
	return &longer
}

// jobIDPattern is a job's id as the reader makes it: opaque, URL-safe and
// bounded.
var jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// ValidJobID reports whether a job id has the shape the reader gives one.
func ValidJobID(job string) bool { return jobIDPattern.MatchString(job) }

// codePattern is an error code's shape.
var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
