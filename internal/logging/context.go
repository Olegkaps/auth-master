package logging

import (
	"context"
	"log/slog"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	handlerKey
)

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

func WithHandler(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, handlerKey, name)
}

func HandlerFromContext(ctx context.Context) string {
	v, _ := ctx.Value(handlerKey).(string)
	return v
}

// Logger returns a slog.Logger with request_id and optional handler from context.
func Logger(ctx context.Context, base *slog.Logger) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}
	l := base
	if id := RequestIDFromContext(ctx); id != "" {
		l = l.With("request_id", id)
	}
	if h := HandlerFromContext(ctx); h != "" {
		l = l.With("handler", h)
	}
	return l
}
