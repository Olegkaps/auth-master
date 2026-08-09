package httptransport

import (
	"context"

	"github.com/google/uuid"
)

type ctxKey int

const (
	userIDKey ctxKey = iota + 1
	serviceActorKey
)

func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

func UserID(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(userIDKey).(uuid.UUID)
	return v, ok
}

func withActor(ctx context.Context, id uuid.UUID, service bool) context.Context {
	ctx = WithUserID(ctx, id)
	return context.WithValue(ctx, serviceActorKey, service)
}

func isServiceActor(ctx context.Context) bool {
	service, _ := ctx.Value(serviceActorKey).(bool)
	return service
}
