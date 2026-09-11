package mailer

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/config"
)

func TestAccountLinksKeepSecretsOutOfRequests(t *testing.T) {
	link, err := accountLink("https://app.example.com", url.Values{"invite": {"a+b/c="}, "email": {"person+tag@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.RawQuery != "signup=1" || strings.Contains(u.RequestURI(), "invite") {
		t.Fatal("code leaked into server request")
	}
	values, err := url.ParseQuery(u.Fragment)
	if err != nil || values.Get("invite") != "a+b/c=" || values.Get("email") != "person+tag@example.com" {
		t.Fatal("fragment damaged")
	}
	if _, err := accountLink("http://remote.example.com", nil); err == nil {
		t.Fatal("accepted insecure origin")
	}
}

func TestMessageRejectsHeaderInjection(t *testing.T) {
	model, err := signupEmail("https://app.example.com", "b@example.com", "test-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := message("a@example.com", "b@example.com\r\nBcc: c@example.com", model); err == nil {
		t.Fatal("injection accepted")
	}
	model.Subject = "Confirmação"
	data, from, to, err := message("Wappie <a@example.com>", "b@example.com", model)
	if err != nil || from != "a@example.com" || to != "b@example.com" || !strings.Contains(string(data), "multipart/related") {
		t.Fatal("invalid MIME message")
	}
	model.Subject = "Invite\r\nBcc: c@example.com"
	if _, _, _, err := message("a@example.com", "b@example.com", model); err == nil {
		t.Fatal("subject injection accepted")
	}
}

func TestSenderNeverAuthenticatesWithoutTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint:errcheck // Test listener cleanup.
	commands := make(chan string, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			commands <- ""
			return
		}
		defer c.Close() //nolint:errcheck // Test connection cleanup.
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(c, "220 test ESMTP\r\n")
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		_, _ = io.WriteString(c, "250-test\r\n250 AUTH PLAIN\r\n")
		next, _ := r.ReadString('\n')
		commands <- line + next
	}()
	s := Sender{Config: config.SMTP{Address: listener.Addr().String(), TLSMode: "starttls", From: "a@example.com", Username: "secret-user", Password: "secret-password"}, AppURL: "https://app.example.com"}
	if err := s.SignupVerification(context.Background(), "b@example.com", "secret-token"); err == nil {
		t.Fatal("accepted cleartext connection")
	}
	if transcript := <-commands; strings.Contains(transcript, "AUTH") || strings.Contains(transcript, "MAIL") || strings.Contains(transcript, "secret") {
		t.Fatal("sent authentication or mail before TLS")
	}
}
