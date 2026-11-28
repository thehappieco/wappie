package membershiptest

import (
	"net/http/httptest"
	"testing"

	"github.com/thehappieco/kit/contract/contracttest"
)

// TestCallOfEntitlementsRoutes: the entitlements part's six routes are
// named as the kit's fake names them, so Refuse, RefuseAlways, Before and
// Count reach them (kit v0.12.0); before, three fell into the access
// snapshot's name and three into none.
func TestCallOfEntitlementsRoutes(t *testing.T) {
	const ws = "0190a5b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b"
	for _, c := range []struct {
		method, target string
		call, arg      string
	}{
		{"GET", "/contract/v1/entitlements?after=7&wait=25", contracttest.CallEntitlements, "7"},
		{"POST", "/contract/v1/entitlements/applied", contracttest.CallEntitlementsApplied, ""},
		{"GET", "/contract/v1/workspaces/" + ws + "/entitlements", contracttest.CallEntitlementsDoc, ws},
		{"PUT", "/contract/v1/workspaces/" + ws + "/usage", contracttest.CallUsage, ws},
		{"POST", "/contract/v1/workspaces/" + ws + "/link-check", contracttest.CallLinkCheck, ws},
		{"POST", "/contract/v1/trim/results", contracttest.CallTrimResults, ""},
		// The routes beside them keep their names.
		{"PUT", "/contract/v1/workspaces/" + ws + "/access", contracttest.CallAccess, ws},
		{"PUT", "/contract/v1/workspaces/" + ws + "/settings/numbers", contracttest.CallSettings, ws},
	} {
		call, arg := callOf(httptest.NewRequest(c.method, c.target, nil))
		if call != c.call || arg != c.arg {
			t.Errorf("%s %s: %q %q, want %q %q", c.method, c.target, call, arg, c.call, c.arg)
		}
	}
}
