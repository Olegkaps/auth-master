package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/olegkapshai/auth-master/internal/config"
)

func TestBindListenersClosesHTTPWhenGRPCBindFails(t *testing.T) {
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	httpListener, grpcListener, err := bindListeners("127.0.0.1:0", blocked.Addr().String())
	if err == nil || httpListener != nil || grpcListener != nil {
		t.Fatalf("expected atomic bind failure, http=%v grpc=%v err=%v", httpListener, grpcListener, err)
	}
}

func TestLoadGRPCCredentials(t *testing.T) {
	credentials, err := loadGRPCCredentials(config.Config{})
	if err != nil || credentials != nil {
		t.Fatalf("plaintext configuration: credentials=%v err=%v", credentials, err)
	}

	directory := t.TempDir()
	certFile := filepath.Join(directory, "invalid-cert.pem")
	keyFile := filepath.Join(directory, "invalid-key.pem")
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err = loadGRPCCredentials(config.Config{GRPCTLSCertFile: certFile, GRPCTLSKeyFile: keyFile})
	if err == nil || credentials != nil {
		t.Fatalf("invalid certificate: credentials=%v err=%v", credentials, err)
	}
}
