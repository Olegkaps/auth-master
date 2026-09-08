package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Sender struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	Timeout  time.Duration
}

func (s *Sender) Send(ctx context.Context, to []string, subject, body string) error {
	if len(to) == 0 {
		return errors.New("smtp has no recipients")
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		s.From, strings.Join(to, ","), subject, body))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return smtpStageError(ctx, "connect")
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return errors.New("smtp deadline failed")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	defer close(done)

	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return smtpStageError(ctx, "greeting")
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.Host}); err != nil {
			return smtpStageError(ctx, "starttls")
		}
	}
	if s.User != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return errors.New("smtp authentication unavailable")
		}
		if err := client.Auth(smtp.PlainAuth("", s.User, s.Password, s.Host)); err != nil {
			return smtpStageError(ctx, "authentication")
		}
	}
	if err := client.Mail(s.From); err != nil {
		return smtpStageError(ctx, "sender")
	}
	for _, recipient := range to {
		// The concrete recipient is intentionally omitted from every error.
		if err := client.Rcpt(recipient); err != nil {
			return smtpStageError(ctx, "recipient")
		}
	}
	w, err := client.Data()
	if err != nil {
		return smtpStageError(ctx, "data")
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return smtpStageError(ctx, "body")
	}
	if err := w.Close(); err != nil {
		return smtpStageError(ctx, "acceptance")
	}
	// DATA's final 250 response is the server's delivery acceptance. Do not
	// wait for QUIT afterward: a slow or broken shutdown reply must not turn an
	// accepted message into an apparent delivery failure.
	return nil
}

func smtpStageError(ctx context.Context, stage string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("smtp %s failed", stage)
}
