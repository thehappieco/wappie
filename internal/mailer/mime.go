package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// A plain-text alternative keeps the action usable without HTML. The embedded
// PNG logo works without external image requests or recipient tracking.
func message(from, recipient string, model accountEmail) ([]byte, string, string, error) {
	if strings.ContainsAny(from+recipient+model.Subject, "\r\n") {
		return nil, "", "", errors.New("mailer: invalid header")
	}
	f, err := mail.ParseAddress(from)
	if err != nil {
		return nil, "", "", errors.New("mailer: invalid sender")
	}
	r, err := mail.ParseAddress(recipient)
	if err != nil {
		return nil, "", "", errors.New("mailer: invalid recipient")
	}
	plain, html, err := model.render()
	if err != nil {
		return nil, "", "", err
	}
	var body bytes.Buffer
	related := multipart.NewWriter(&body)
	alternative := multipart.NewWriter(io.Discard)
	root, err := related.CreatePart(textproto.MIMEHeader{"Content-Type": {mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": alternative.Boundary()})}})
	if err != nil {
		return nil, "", "", err
	}
	boundary := alternative.Boundary()
	alternative = multipart.NewWriter(root)
	if err := alternative.SetBoundary(boundary); err != nil {
		return nil, "", "", err
	}
	for _, part := range []struct{ kind, body string }{{"text/plain", plain}, {"text/html", html}} {
		out, err := alternative.CreatePart(textproto.MIMEHeader{"Content-Type": {part.kind + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		if err != nil {
			return nil, "", "", err
		}
		encoded := quotedprintable.NewWriter(out)
		if _, err := io.WriteString(encoded, part.body); err != nil {
			return nil, "", "", err
		}
		if err := encoded.Close(); err != nil {
			return nil, "", "", err
		}
	}
	if err := alternative.Close(); err != nil {
		return nil, "", "", err
	}
	logo, err := related.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"image/png"}, "Content-ID": {"<wappie-brand>"},
		"Content-Disposition": {"inline; filename=wappie.png"}, "Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, "", "", err
	}
	encodedLogo := base64.StdEncoding.EncodeToString(brandPNG)
	for len(encodedLogo) > 0 {
		n := min(76, len(encodedLogo))
		if _, err := io.WriteString(logo, encodedLogo[:n]+"\r\n"); err != nil {
			return nil, "", "", err
		}
		encodedLogo = encodedLogo[n:]
	}
	if err := related.Close(); err != nil {
		return nil, "", "", err
	}
	domain := strings.SplitN(f.Address, "@", 2)[1]
	// Identify transactional mail so auto-responders can avoid reply loops.
	// This header does not certify the sender or bypass spam filtering.
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: %s\r\n\r\n",
		f.String(), r.String(), mime.QEncoding.Encode("UTF-8", model.Subject), time.Now().UTC().Format(time.RFC1123Z), rand.Text(), domain,
		mime.FormatMediaType("multipart/related", map[string]string{"boundary": related.Boundary(), "type": "multipart/alternative"}))
	return append([]byte(headers), body.Bytes()...), f.Address, r.Address, nil
}
