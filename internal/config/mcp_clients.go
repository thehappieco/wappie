package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"whatserver2/internal/netguard"
)

// Any MCP client (docs/mcp-enclave.md §19.21): what this server accepts of a
// reader that admits any client. Every one of these can only refuse: the
// reader decides who is admitted and in which tier, and this server can turn
// a tier, or one tested client, off without a release.

// CIMD modes. In allowlist mode a version-2 descriptor of a client Wappie
// has not tested is refused, which is 0.5.0's rule; any admits it.
const (
	CIMDModeAllowlist = "allowlist"
	CIMDModeAny       = "any"
)

// defaultDCRHosts are the hosts of the pinned DCR redirects (§19.8): Claude's
// two callbacks and ChatGPT's.
const defaultDCRHosts = "claude.ai,claude.com,chatgpt.com"

// testedIDPattern is a tested client's id in the image's TESTED_CLIENTS.
var testedIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// loadClients reads WS_MCP_CIMD_MODE, WS_MCP_BLOCKED_CLIENTS,
// WS_MCP_DCR_HOSTS and WS_MCP_NOTICE_ORIGIN. Nothing is judged here; Validate
// reports what is wrong while the connector is on.
func loadClients(m *MCP) {
	m.CIMDMode = strings.ToLower(strings.TrimSpace(str("WS_MCP_CIMD_MODE", CIMDModeAllowlist)))
	m.BlockedClients, m.blockedErr = testedIDs(os.Getenv("WS_MCP_BLOCKED_CLIENTS"))
	m.DCRHosts, m.dcrHostErr = dcrHosts(str("WS_MCP_DCR_HOSTS", defaultDCRHosts))
	m.NoticeOrigin = strings.TrimSpace(os.Getenv("WS_MCP_NOTICE_ORIGIN"))
}

// testedIDs parses WS_MCP_BLOCKED_CLIENTS: tested ids, comma separated, once
// each and sorted. A word of the wrong shape is an error rather than
// ignored: a mistyped id would leave on the client it was meant to block.
func testedIDs(raw string) ([]string, error) {
	var out []string
	var errs []error
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		if !testedIDPattern.MatchString(part) {
			errs = append(errs, fmt.Errorf("WS_MCP_BLOCKED_CLIENTS: %q is not a tested client's id (^[a-z][a-z0-9_]{0,31}$)", part))
			continue
		}
		if !slices.Contains(out, part) {
			out = append(out, part)
		}
	}
	slices.Sort(out)
	return out, errors.Join(errs...)
}

// dcrHosts parses WS_MCP_DCR_HOSTS: hosts, comma separated, lower-cased and
// once each, every one a host a client may be identified by (§19.5 step 4).
func dcrHosts(raw string) ([]string, error) {
	var out []string
	var errs []error
	for _, part := range strings.Split(raw, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part == "" {
			continue
		}
		if _, reason := netguard.CheckHost(part); reason != "" {
			errs = append(errs, fmt.Errorf("WS_MCP_DCR_HOSTS: %q is not a client's host (%s)", part, reason))
			continue
		}
		if !slices.Contains(out, part) {
			out = append(out, part)
		}
	}
	return out, errors.Join(errs...)
}

// validateClients checks the any-client block.
func (m MCP) validateClients(prod bool) []error {
	var errs []error
	if m.CIMDMode != CIMDModeAllowlist && m.CIMDMode != CIMDModeAny {
		errs = append(errs, fmt.Errorf("WS_MCP_CIMD_MODE: %q is neither %s nor %s", m.CIMDMode, CIMDModeAllowlist, CIMDModeAny))
	}
	if m.blockedErr != nil {
		errs = append(errs, m.blockedErr)
	}
	if m.dcrHostErr != nil {
		errs = append(errs, m.dcrHostErr)
	}
	if len(m.DCRHosts) == 0 && m.dcrHostErr == nil {
		errs = append(errs, errors.New("WS_MCP_DCR_HOSTS must name at least one host"))
	}
	if m.NoticeOrigin != "" {
		if _, err := AccountBrowserOrigin(m.NoticeOrigin, !prod); err != nil {
			errs = append(errs, errors.New("WS_MCP_NOTICE_ORIGIN must be this server's public https origin, such as https://api.wappie.thehappie.co"))
		}
	}
	return errs
}

// UnknownAllowed reports whether a client Wappie has not tested, or a
// console token, may connect: WS_MCP_CIMD_MODE is any.
func (m MCP) UnknownAllowed() bool { return m.CIMDMode == CIMDModeAny }

// NoticeLinkOrigin is the origin a notice e-mail's revoke-only link is on,
// "" when none is configured (and no notice e-mail can go).
func (m MCP) NoticeLinkOrigin(prod bool) string {
	if m.NoticeOrigin == "" {
		return ""
	}
	u, err := AccountBrowserOrigin(m.NoticeOrigin, !prod)
	if err != nil {
		return ""
	}
	return u.String()
}

// clientsString renders the block for the startup line.
func (m MCP) clientsString() string {
	blocked := "none"
	if len(m.BlockedClients) > 0 {
		blocked = strings.Join(m.BlockedClients, ",")
	}
	notice := "unset"
	if m.NoticeOrigin != "" {
		notice = m.NoticeOrigin
	}
	return fmt.Sprintf(" cimd_mode=%s blocked_clients=%s dcr_hosts=%s notice_origin=%s",
		m.CIMDMode, blocked, strings.Join(m.DCRHosts, ","), notice)
}
