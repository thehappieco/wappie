package membership

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"
)

// The settings part's calls (the platform's spec, section 14; the kit's
// SPEC 11.19), on the client every other call uses: the sections and the
// person's document Wappie sends, the command feed it follows, and the
// results it posts. Each goes through call, so a signed replay or an
// unavailable is asked once more, signed afresh.

// PutSettings sends one section of one platform workspace
// (PUT /contract/v1/workspaces/{id}/settings/{section}).
func (c *Client) PutSettings(ctx context.Context, doc kc.SettingsDoc) error {
	return c.call(func(k *kc.Client) error { return k.PutSettings(ctx, doc) })
}

// PutPersonSettings sends one person's own settings
// (PUT /contract/v1/accounts/{sub}/settings).
func (c *Client) PutPersonSettings(ctx context.Context, doc kc.PersonSettingsDoc) error {
	return c.call(func(k *kc.Client) error { return k.PutPersonSettings(ctx, doc) })
}

// CommandPage is one signed command feed answer, and what checks its
// commands: the time the platform signed it (expiry is judged on it), and
// the secrets of the client that fetched it, so a reload between the fetch
// and the verification changes nothing.
type CommandPage struct {
	Feed     kc.CommandFeed
	SignedAt time.Time
	accept   []string
}

// Commands returns the commands after the cursor after, waiting up to wait
// seconds (GET /contract/v1/commands): a page the kit validated, its
// commands as they came. Each is verified on its own (VerifyCommand).
func (c *Client) Commands(ctx context.Context, after int64, wait int) (CommandPage, error) {
	var p CommandPage
	err := c.call(func(k *kc.Client) (err error) {
		p = CommandPage{accept: k.Accept}
		p.Feed, p.SignedAt, err = k.Commands(ctx, after, wait)
		return err
	})
	return p, err
}

// PostResults sends a batch of results and returns one answer per result,
// in order (POST /contract/v1/commands/results).
func (c *Client) PostResults(ctx context.Context, results []kc.CommandResult) ([]kc.CommandResultAnswer, error) {
	var a []kc.CommandResultAnswer
	err := c.call(func(k *kc.Client) (err error) {
		a, err = k.PostResults(ctx, results)
		return err
	})
	return a, err
}

// VerifyCommand checks the MAC of raw, a command of page, with the secrets
// of the client that fetched it (the current and, during a rotation, the
// other: the spec's 14.6), for Wappie's app only, and decodes it.
func (c *Client) VerifyCommand(page CommandPage, raw json.RawMessage) (kc.Command, error) {
	return kc.VerifyCommand(raw, App, page.accept)
}

// bodyKey is what tells two bodies of one command apart (the spec's 14.6):
// the sha256 of the JCS text of the body as received, decoded into generic
// JSON values, without generation, cseq, secret and mac, which the
// platform sets each time it serves it; of the raw bytes when the body is
// not one well-formed object JCS writes.
func bodyKey(raw []byte) []byte {
	if kc.DecodeStrict(raw, new(json.RawMessage)) == nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v map[string]any
		if dec.Decode(&v) == nil && v != nil {
			for _, member := range []string{"generation", "cseq", "secret", "mac"} {
				delete(v, member)
			}
			if canonical, err := jcs.Marshal(v); err == nil {
				sum := sha256.Sum256(canonical)
				return sum[:]
			}
		}
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}
