package wsapi

import "whatserver2/internal/domain"

// WithheldAttachments is why a row's sealed content is withheld: a platform
// token reads it while its workspace's attachments switch is off (the
// plan's 3.5). That content holds the attachment's media key, its CDN path
// and a legible thumbnail: with them a token could fetch and open the file
// from WhatsApp's CDN around the switch. A media row's caption goes with
// it; a text row's link preview stays the text's.
const WithheldAttachments = "attachments"

// WithholdAttachments clears the sealed content of a row whose clear type
// has an attachment (domain.Type.HasMedia): the body (its caption), the
// payload, and the attachment's sealed key, thumbnail and file name. The
// envelope's shape stays: the type, the MIME type, the sizes, the
// duration, the waveform and the download status.
func (m *SealedMessage) WithholdAttachments() {
	if !domain.Type(m.Type).HasMedia() {
		return
	}
	m.BodySealed, m.PayloadSealed, m.Withheld = nil, nil, WithheldAttachments
	if m.Media != nil {
		m.Media.MediaKeySealed, m.Media.ThumbSealed, m.Media.FileNameSealed = nil, nil, nil
	}
}

// WithholdAttachments clears the newest message's sealed body when it has
// an attachment.
func (c *ChatSummary) WithholdAttachments() {
	if domain.Type(c.LastType).HasMedia() {
		c.LastBodySealed, c.LastWithheld = nil, WithheldAttachments
	}
}

// WithholdAttachments withholds each chat's newest message.
func (c *Chats) WithholdAttachments() {
	for i := range c.Chats {
		c.Chats[i].WithholdAttachments()
	}
}

// WithholdAttachments withholds each message of the page.
func (p *Page) WithholdAttachments() {
	for i := range p.Messages {
		p.Messages[i].WithholdAttachments()
	}
}

// WithholdAttachments withholds every revision, the deletion and the
// reactions.
func (h *History) WithholdAttachments() {
	for i := range h.Versions {
		h.Versions[i].Message.WithholdAttachments()
	}
	if h.Deletion != nil {
		h.Deletion.Message.WithholdAttachments()
	}
	for i := range h.Reactions {
		h.Reactions[i].Message.WithholdAttachments()
	}
}
