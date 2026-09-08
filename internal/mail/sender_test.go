package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSender_noRecipients(t *testing.T) {
	s := &Sender{Host: "127.0.0.1", Port: 1, From: "a@b.c"}
	if err := s.Send(context.Background(), nil, "s", "b"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSenderTimesOutAndRedactsMessageDataWhenServerNeverGreets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	s := &Sender{Host: "127.0.0.1", Port: addr.Port, User: "secret-user", Password: "secret-password", From: "from@example.test", Timeout: 75 * time.Millisecond}
	started := time.Now()
	err = s.Send(context.Background(), []string{"recipient@example.test"}, "secret subject", "Code: 731905 secret body")
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(started) > time.Second {
		t.Fatalf("SMTP timeout was not bounded: %v", time.Since(started))
	}
	for _, secret := range []string{"recipient@example.test", "731905", "secret body", "secret-user", "secret-password"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("SMTP error leaked %q: %v", secret, err)
		}
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	default:
	}
}

func TestSenderCancellationUnblocksHungSMTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			time.Sleep(time.Second)
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	s := &Sender{Host: "127.0.0.1", Port: addr.Port, From: "from@example.test", Timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Send(ctx, []string{"recipient@example.test"}, "subject", "body") }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case sendErr := <-done:
		if sendErr == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("context cancellation did not unblock SMTP")
	}
}

func TestSenderReturnsSuccessImmediatelyAfterSMTPAcceptance(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	postAcceptanceCommand := make(chan string, 1)
	serverError := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, writeErr := fmt.Fprint(conn, "220 test ESMTP\r\n"); writeErr != nil {
			serverError <- writeErr
			return
		}
		for _, response := range []string{
			"250-test\r\n250 HELP\r\n",
			"250 sender ok\r\n",
			"250 recipient ok\r\n",
			"354 send data\r\n",
		} {
			if _, readErr := reader.ReadString('\n'); readErr != nil {
				serverError <- readErr
				return
			}
			if _, writeErr := fmt.Fprint(conn, response); writeErr != nil {
				serverError <- writeErr
				return
			}
		}
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverError <- readErr
				return
			}
			if line == ".\r\n" {
				break
			}
		}
		if _, writeErr := fmt.Fprint(conn, "250 accepted\r\n"); writeErr != nil {
			serverError <- writeErr
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		line, _ := reader.ReadString('\n')
		postAcceptanceCommand <- line
	}()

	addr := listener.Addr().(*net.TCPAddr)
	sender := &Sender{Host: "127.0.0.1", Port: addr.Port, From: "from@example.test", Timeout: 2 * time.Second}
	started := time.Now()
	if err := sender.Send(context.Background(), []string{"recipient@example.test"}, "subject", "body"); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("accepted SMTP message waited for shutdown: %v", elapsed)
	}
	select {
	case err := <-serverError:
		t.Fatal(err)
	case command := <-postAcceptanceCommand:
		if command != "" {
			t.Fatalf("unexpected command after delivery acceptance: %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP server did not observe connection shutdown")
	}
}

func TestSender_unreachableSMTP(t *testing.T) {
	s := &Sender{Host: "127.0.0.1", Port: 1, From: "a@b.c"}
	err := s.Send(context.Background(), []string{"x@y.z"}, "sub", "body")
	if err == nil {
		t.Fatal("expected dial error")
	}
}
