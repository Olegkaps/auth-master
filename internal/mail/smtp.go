package mail

import (
	"fmt"
	"net/smtp"
	"strings"
)

type Sender struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
}

func (s *Sender) Send(to []string, subject, body string) error {
	if len(to) == 0 {
		return fmt.Errorf("no recipients")
	}
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		s.From, strings.Join(to, ","), subject, body))
	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Password, s.Host)
	}
	return smtp.SendMail(addr, auth, s.From, to, msg)
}
