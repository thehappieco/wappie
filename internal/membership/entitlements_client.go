package membership

import (
	"context"
	"time"

	kc "github.com/thehappieco/kit/contract"
)

// The entitlements part's calls (the platform's spec, section 15; kit
// v0.12.0), on the client every other call uses, each through call, so a
// signed replay or an unavailable is asked once more, signed afresh. No
// error here carries a figure or a code of a report.

// Entitlements returns the entitlements documents after the cursor after,
// waiting up to wait seconds (GET /contract/v1/entitlements): a page the
// kit validated, each document as it came, judged alone by the follower
// (kc.EntitlementsFeedItem.Document).
func (c *Client) Entitlements(ctx context.Context, after int64, wait int) (kc.EntitlementsFeed, error) {
	var f kc.EntitlementsFeed
	err := c.call(func(k *kc.Client) (err error) {
		f, err = k.Entitlements(ctx, after, wait)
		return err
	})
	return f, err
}

// EntitlementsDoc returns the document of the workspace ws, computed now
// (GET /contract/v1/workspaces/{id}/entitlements), and the time the
// platform signed the answer, from which its freshness counts. The kit has
// refused a document that does not validate (kc.ErrUnverified) and one of
// another app or workspace (kc.ErrForeignDocument); its generation is the
// follower's to judge.
func (c *Client) EntitlementsDoc(ctx context.Context, ws string) (kc.EntitlementsDoc, time.Time, error) {
	var d kc.EntitlementsDoc
	var at time.Time
	err := c.call(func(k *kc.Client) (err error) {
		d, at, err = k.EntitlementsDoc(ctx, ws)
		return err
	})
	return d, at, err
}

// EntitlementsApplied acknowledges the entitlements feed
// (POST /contract/v1/entitlements/applied). Another generation, or a
// through past the feed's head, is a signed gone.
func (c *Client) EntitlementsApplied(ctx context.Context, ack kc.EntitlementsApplied) error {
	return c.call(func(k *kc.Client) error { return k.EntitlementsApplied(ctx, ack) })
}

// PutUsage sends a workspace's usage report
// (PUT /contract/v1/workspaces/{id}/usage), and whether the platform keeps
// it; both answers count as delivered. The kit refuses a report that fails
// ValidateAt on this clock before it sends anything.
func (c *Client) PutUsage(ctx context.Context, ws string, u kc.Usage) (bool, error) {
	var kept bool
	err := c.call(func(k *kc.Client) (err error) {
		kept, err = k.PutUsage(ctx, ws, u)
		return err
	})
	return kept, err
}

// LinkCheck asks the platform about a link in the workspace ws, with no side
// effect (POST /contract/v1/workspaces/{id}/link-check). Slice 19's; no
// error carries a code.
func (c *Client) LinkCheck(ctx context.Context, ws string, req kc.LinkCheck) (kc.LinkCheckAnswer, error) {
	var a kc.LinkCheckAnswer
	err := c.call(func(k *kc.Client) (err error) {
		a, err = k.LinkCheck(ctx, ws, req)
		return err
	})
	return a, err
}
