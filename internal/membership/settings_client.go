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
// the client that fetched it, whose secrets check them, so a reload
// between the fetch and the verification changes nothing. The client is
// held by pointer, never its secrets by value: a page printed shows an
// address (Client's own rule).
type CommandPage struct {
	Feed     kc.CommandFeed
	SignedAt time.Time
	kit      *kc.Client
}

// Commands returns the commands after the cursor after, waiting up to wait
// seconds (GET /contract/v1/commands): a page the kit validated, its
// commands as they came. Each is verified on its own (VerifyCommand).
func (c *Client) Commands(ctx context.Context, after int64, wait int) (CommandPage, error) {
	var p CommandPage
	err := c.call(func(k *kc.Client) (err error) {
		p = CommandPage{kit: k}
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
	if page.kit == nil {
		return kc.Command{}, kc.ErrCommandMAC
	}
	return kc.VerifyCommand(raw, App, page.kit.Accept)
}

// bodyKey is what tells two bodies of one command apart (the spec's 14.6):
// the sha256 of the JCS text of the body as received, decoded into generic
// JSON values, without generation, cseq, secret and mac, which the
// platform sets each time it serves it; of the raw bytes when the body is
// not one well-formed object JCS writes.
func bodyKey(raw []byte) []byte {
	if v, ok := genericObject(raw); ok {
		for _, member := range []string{"generation", "cseq", "secret", "mac"} {
			delete(v, member)
		}
		if canonical, err := jcs.Marshal(v); err == nil {
			sum := sha256.Sum256(canonical)
			return sum[:]
		}
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}

// genericObject is raw decoded into generic JSON values, its numbers as
// written, when it is one well-formed object (valid UTF-8, no escape of
// half a surrogate pair, no member twice anywhere).
func genericObject(raw []byte) (map[string]any, bool) {
	if kc.DecodeStrict(raw, new(json.RawMessage)) != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if dec.Decode(&v) != nil || v == nil {
		return nil, false
	}
	return v, true
}

// macCovers reports whether raw is a command the kit's MAC can cover: one
// well-formed object, its mac a string where it has one, and the rest a
// text JCS writes (no fraction, no integer past 2^53-1), as the kit's
// canonicalCommand asks before it checks the app and the MAC. A command
// the kit refuses as ErrInvalid that passes this, and names the app that
// verifies it, had its MAC hold: only its typed decode failed.
func macCovers(raw []byte) bool {
	v, ok := genericObject(raw)
	if !ok {
		return false
	}
	if mac, has := v["mac"]; has {
		if _, isString := mac.(string); !isString {
			return false
		}
		delete(v, "mac")
	}
	_, err := jcs.Marshal(v)
	return err == nil
}
