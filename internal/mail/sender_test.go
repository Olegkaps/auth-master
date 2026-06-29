package mail

import "testing"

func TestSender_noRecipients(t *testing.T) {
	s := &Sender{Host: "127.0.0.1", Port: 1, From: "a@b.c"}
	if err := s.Send(nil, "s", "b"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSender_unreachableSMTP(t *testing.T) {
	s := &Sender{Host: "127.0.0.1", Port: 1, From: "a@b.c"}
	err := s.Send([]string{"x@y.z"}, "sub", "body")
	if err == nil {
		t.Fatal("expected dial error")
	}
}
