package logging

import (
	"context"
	"log/slog"
	"testing"
)

func TestRequestIDContext(t *testing.T) {
	ctx := WithRequestID(context.Background(), "rid-1")
	if RequestIDFromContext(ctx) != "rid-1" {
		t.Fatal()
	}
	l := Logger(ctx, slog.Default())
	if l == nil {
		t.Fatal()
	}
}
