package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

type blockingPublicMailRepository struct {
	repository.Repository
	started chan string
	release chan struct{}
}

func (r *blockingPublicMailRepository) GetHumanUserByLoginOrEmail(ctx context.Context, identity string) (*domain.User, error) {
	select {
	case r.started <- identity:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-r.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestPublicMailStartsReturnBeforeIdentityLookupCompletes(t *testing.T) {
	for _, test := range []struct {
		name         string
		start        func(*Auth) error
		wantIdentity string
	}{
		{"magic link", func(a *Auth) error { return a.StartMagicLink(context.Background(), " MIXED@Example.Test ") }, "mixed@example.test"},
		{"password reset", func(a *Auth) error { return a.StartPasswordReset(context.Background(), " MIXED@Example.Test ") }, "mixed@example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &blockingPublicMailRepository{started: make(chan string, 1), release: make(chan struct{})}
			cfg := testConfig()
			cfg.PublicMailWorkers, cfg.PublicMailQueueSize = 1, 1
			cfg.PublicMailJobTimeout = time.Second
			auth, err := NewAuth(cfg, repo, &passwordResetMailer{}, nil)
			require.NoError(t, err)
			returned := make(chan error, 1)
			go func() { returned <- test.start(auth) }()
			select {
			case err := <-returned:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("public request waited for private lookup")
			}
			require.Equal(t, test.wantIdentity, <-repo.started)
			close(repo.release)
			require.NoError(t, auth.Shutdown(context.Background()))
		})
	}
}

func TestPublicMailQueueBackpressureDrainPanicAndSanitizedLogs(t *testing.T) {
	t.Run("full queue drops without exposing job data", func(t *testing.T) {
		var logs bytes.Buffer
		started := make(chan struct{})
		release := make(chan struct{})
		var processed atomic.Int32
		q, err := newPublicMailQueue(1, 1, time.Second, slog.New(slog.NewTextHandler(&logs, nil)), func(context.Context, publicMailJob) {
			if processed.Add(1) == 1 {
				close(started)
				<-release
			}
		})
		require.NoError(t, err)
		q.enqueue(publicMailJob{kind: publicMailMagicLink, identity: "first-secret@example.test"})
		<-started
		q.enqueue(publicMailJob{kind: publicMailMagicLink, identity: "queued-secret@example.test"})
		q.enqueue(publicMailJob{kind: publicMailMagicLink, identity: "dropped-secret@example.test"})
		close(release)
		require.NoError(t, q.Shutdown(context.Background()))
		require.Equal(t, int32(2), processed.Load())
		require.Contains(t, logs.String(), "class=queue_full")
		require.NotContains(t, logs.String(), "secret@example.test")
	})

	t.Run("panic does not kill worker", func(t *testing.T) {
		var calls atomic.Int32
		var logs bytes.Buffer
		q, err := newPublicMailQueue(1, 2, time.Second, slog.New(slog.NewTextHandler(&logs, nil)), func(context.Context, publicMailJob) {
			if calls.Add(1) == 1 {
				panic("private panic material")
			}
		})
		require.NoError(t, err)
		q.enqueue(publicMailJob{kind: publicMailPasswordReset})
		q.enqueue(publicMailJob{kind: publicMailPasswordReset})
		require.NoError(t, q.Shutdown(context.Background()))
		require.Equal(t, int32(2), calls.Load())
		require.Contains(t, logs.String(), "class=worker_panic")
		require.NotContains(t, logs.String(), "private panic material")
	})

	t.Run("deadline cancels active worker", func(t *testing.T) {
		started := make(chan struct{})
		canceled := make(chan struct{})
		q, err := newPublicMailQueue(1, 1, time.Hour, nil, func(ctx context.Context, _ publicMailJob) {
			close(started)
			<-ctx.Done()
			close(canceled)
		})
		require.NoError(t, err)
		q.enqueue(publicMailJob{kind: publicMailMagicLink})
		<-started
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.ErrorIs(t, q.Shutdown(ctx), context.Canceled)
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not cancel worker context")
		}
	})
}

func TestPublicMailQueueConcurrentEnqueueAndShutdownIsSafeAndIdempotent(t *testing.T) {
	q, err := newPublicMailQueue(2, 8, time.Second, nil, func(context.Context, publicMailJob) {})
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				q.enqueue(publicMailJob{kind: publicMailMagicLink, identity: strings.Repeat("x", j%3)})
			}
		}()
	}
	require.NoError(t, q.Shutdown(context.Background()))
	wg.Wait()
	require.NoError(t, q.Shutdown(context.Background()))
}

func TestPublicMailQueueRejectsInvalidConfiguration(t *testing.T) {
	processor := func(context.Context, publicMailJob) {}
	for _, test := range []struct {
		workers, capacity int
		timeout           time.Duration
		process           func(context.Context, publicMailJob)
	}{
		{0, 1, time.Second, processor},
		{1, 0, time.Second, processor},
		{1, 1, 0, processor},
		{1, 1, time.Second, nil},
	} {
		q, err := newPublicMailQueue(test.workers, test.capacity, test.timeout, nil, test.process)
		require.Error(t, err)
		require.Nil(t, q)
	}
	for _, value := range []int{-1, -2} {
		cfg := testConfig()
		cfg.PublicMailWorkers = value
		_, err := NewAuth(cfg, &blockingPublicMailRepository{}, &passwordResetMailer{}, nil)
		require.Error(t, err)
	}
}

func TestPublicMailEmptyIdentityRejectedBeforeEnqueue(t *testing.T) {
	auth, err := NewAuth(testConfig(), &blockingPublicMailRepository{}, &passwordResetMailer{}, nil)
	require.NoError(t, err)
	require.ErrorIs(t, auth.StartPasswordReset(context.Background(), " \t "), ErrInvalidArgument)
	require.ErrorIs(t, auth.StartMagicLink(context.Background(), " \t "), ErrInvalidArgument)
	require.NoError(t, auth.Shutdown(context.Background()))
}

func TestPublicMailIdentityBoundAppliesBeforeQueueAllocation(t *testing.T) {
	auth, err := NewAuth(testConfig(), &blockingPublicMailRepository{}, &passwordResetMailer{}, nil)
	require.NoError(t, err)
	oversized := strings.Repeat("x", MaxPublicIdentityBytes+1)
	for _, start := range []func(context.Context, string) error{auth.StartMagicLink, auth.StartPasswordReset} {
		require.ErrorIs(t, start(context.Background(), oversized), ErrInvalidArgument)
		require.Empty(t, auth.publicMail.jobs, "invalid identities must never occupy queue memory")
	}
	require.NoError(t, auth.Shutdown(context.Background()))
}
