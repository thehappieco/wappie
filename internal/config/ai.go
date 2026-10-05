package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// AI integrations (docs/mcp-enclave.md §18): the attested reader sends a
// number's attachments to the AI providers a person chose, with their own
// API keys, and stores the transcripts, descriptions and summaries it gets
// back, sealed. This server never sees a key or a word of the content; what
// it configures is who may, and what is switched off.
//
// AI rides on the attachment path (§16): an authorization opens attachments
// as a media connection does, so turning attachments off in a hurry stops it
// too, and while they are off nothing of this block is inspected.

// AIProviders are the providers WS_AI_OFF_PROVIDERS may switch off, in the
// contract's order.
var AIProviders = []string{"anthropic", "openai", "google"}

// AIFeatures are the functions WS_AI_OFF_FEATURES may switch off: audio and
// voice notes, video, images (with stickers and GIFs) and documents.
var AIFeatures = []string{"audio", "video", "image", "document"}

// loadAI reads the WS_AI_* block into m. Nothing is judged here beyond
// parsing; validateAI says what is wrong, and only while the block is used.
func loadAI(m *MCP, errs *[]error) {
	m.AIEnabled = boolean("WS_AI_ENABLED", false, errs)
	m.AIOffProviders, m.aiOffProvidersErr = wordList("WS_AI_OFF_PROVIDERS", os.Getenv("WS_AI_OFF_PROVIDERS"), AIProviders, "an AI provider")
	m.AIOffFeatures, m.aiOffFeaturesErr = wordList("WS_AI_OFF_FEATURES", os.Getenv("WS_AI_OFF_FEATURES"), AIFeatures, "an AI function")
}

// wordList parses a comma-separated subset of words, in any case and order.
// It comes back lower-cased, once each and sorted. A word that is not in the
// set is an error rather than ignored: a mistyped provider would leave on
// what it was meant to switch off.
func wordList(name, raw string, words []string, what string) ([]string, error) {
	var out []string
	var errs []error
	for _, part := range strings.Split(raw, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part == "" {
			continue
		}
		if !slices.Contains(words, part) {
			errs = append(errs, fmt.Errorf("%s: %q is not %s (%s)", name, part, what, strings.Join(words, ", ")))
			continue
		}
		if !slices.Contains(out, part) {
			out = append(out, part)
		}
	}
	slices.Sort(out)
	return out, errors.Join(errs...)
}

// validateAI checks the AI switch. While content is off nothing of it is
// inspected, as for attachments, so content can be turned off in a hurry;
// while the switch itself is off, likewise. On, it needs attachments on, off
// lists of known words, and WS_AI_TENANTS gone.
func (m MCP) validateAI() []error {
	if !m.AIEnabled || !m.ContentEnabled {
		return nil
	}
	if !m.MediaEnabled {
		return []error{errors.New("WS_AI_ENABLED needs WS_MCP_MEDIA_ENABLED: AI integrations open attachments as a media connection does")}
	}
	var errs []error
	if m.retiredLists["WS_AI_TENANTS"] {
		errs = append(errs, retiredList("WS_AI_TENANTS"))
	}
	if m.aiOffProvidersErr != nil {
		errs = append(errs, m.aiOffProvidersErr)
	}
	if m.aiOffFeaturesErr != nil {
		errs = append(errs, m.aiOffFeaturesErr)
	}
	return errs
}

// AIAllowed reports whether the operator lets a workspace have AI
// integrations right now: attachments are allowed for it and the AI switch is
// on. Which providers and functions are off is AIOffProviders and
// AIOffFeatures, for every workspace.
func (m MCP) AIAllowed(tenant uuid.UUID) bool {
	return m.MediaAllowed(tenant) && m.AIEnabled
}

// aiString is the AI part of the startup line: the switch and, when any is
// off, what.
func (m MCP) aiString() string {
	out := fmt.Sprintf(" ai=%s", onOff(m.AIEnabled))
	if len(m.AIOffProviders) > 0 || len(m.AIOffFeatures) > 0 {
		out += fmt.Sprintf(" ai_off_providers=%s ai_off_features=%s", strings.Join(m.AIOffProviders, ","), strings.Join(m.AIOffFeatures, ","))
	}
	return out
}
