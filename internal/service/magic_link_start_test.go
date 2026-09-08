package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

type magicLinkStartRepository struct {
	repository.Repository
	user            *domain.User
	lookupErr       error
	insertErr       error
	invalidateErrs  []error
	lookupCalls     int
	insertCalls     int
	invalidateCalls int
	invalidateErr   error
	hadDeadline     bool
}

func (r *magicLinkStartRepository) GetHumanUserByLoginOrEmail(context.Context, string) (*domain.User, error) {
	r.lookupCalls++
	return r.user, r.lookupErr
}

func (r *magicLinkStartRepository) InsertMagicLink(context.Context, []byte, uuid.UUID, time.Time) (uuid.UUID, error) {
	r.insertCalls++
	return uuid.MustParse("11111111-1111-4111-8111-111111111111"), r.insertErr
}

func (r *magicLinkStartRepository) InvalidateMagicLink(ctx context.Context, _ uuid.UUID) error {
	r.invalidateCalls++
	r.invalidateErr = ctx.Err()
	_, r.hadDeadline = ctx.Deadline()
	if r.invalidateCalls <= len(r.invalidateErrs) {
		return r.invalidateErrs[r.invalidateCalls-1]
	}
	return nil
}

func TestMagicLinkCleanupDetachesFromCanceledMailContext(t *testing.T) {
	email := "person@example.test"
	repo := &magicLinkStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Email: &email}}
	auth, err := NewAuth(testConfig(), repo, &magicLinkStartMailer{err: context.Canceled}, nil)
	require.NoError(t, err)
	auth.randomBytes = func(int) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil }

	mailCtx, cancel := context.WithCancel(context.Background())
	cancel()
	auth.processMagicLink(mailCtx, "person@example.test")

	require.Equal(t, 1, repo.invalidateCalls)
	require.NoError(t, repo.invalidateErr, "cleanup must not inherit the canceled SMTP context")
	require.True(t, repo.hadDeadline, "detached cleanup must remain independently bounded")
}

type magicLinkStartMailer struct {
	err   error
	calls int
}

func (m *magicLinkStartMailer) Send(context.Context, []string, string, string) error {
	m.calls++
	return m.err
}

func TestStartMagicLinkHidesEveryPostValidationOutcome(t *testing.T) {
	email := "known@example.test"
	bannedAt := time.Now()
	known := &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Login: "known", Email: &email}
	for _, test := range []struct {
		name            string
		repo            *magicLinkStartRepository
		mailer          *magicLinkStartMailer
		callback        string
		randomErr       error
		wantInserts     int
		wantInvalidates int
		wantOperation   string
	}{
		{name: "lookup failure", repo: &magicLinkStartRepository{lookupErr: errors.New("database secret")}, mailer: &magicLinkStartMailer{}, wantOperation: "identity_lookup"},
		{name: "unknown", repo: &magicLinkStartRepository{}, mailer: &magicLinkStartMailer{}, wantOperation: "identity_ineligible"},
		{name: "missing email", repo: &magicLinkStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman}}, mailer: &magicLinkStartMailer{}, wantOperation: "identity_ineligible"},
		{name: "banned", repo: &magicLinkStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Email: &email, BannedAt: &bannedAt}}, mailer: &magicLinkStartMailer{}, wantOperation: "identity_ineligible"},
		{name: "randomness failure", repo: &magicLinkStartRepository{user: known}, mailer: &magicLinkStartMailer{}, randomErr: errors.New("entropy secret"), wantOperation: "token_generation"},
		{name: "callback failure", repo: &magicLinkStartRepository{user: known}, mailer: &magicLinkStartMailer{}, callback: "://bad-secret", wantOperation: "callback_configuration"},
		{name: "insert failure", repo: &magicLinkStartRepository{user: known, insertErr: errors.New("database insert secret")}, mailer: &magicLinkStartMailer{}, wantInserts: 1, wantOperation: "token_persistence"},
		{name: "delivery failure", repo: &magicLinkStartRepository{user: known}, mailer: &magicLinkStartMailer{err: errors.New("smtp secret")}, wantInserts: 1, wantInvalidates: 1, wantOperation: "message_delivery"},
		{name: "cleanup retries", repo: &magicLinkStartRepository{user: known, invalidateErrs: []error{errors.New("one"), errors.New("two")}}, mailer: &magicLinkStartMailer{err: errors.New("smtp secret")}, wantInserts: 1, wantInvalidates: 3, wantOperation: "message_delivery"},
		{name: "success", repo: &magicLinkStartRepository{user: known}, mailer: &magicLinkStartMailer{}, wantInserts: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.MagicLinkCallbackURL = test.callback
			var logs bytes.Buffer
			auth, err := NewAuth(cfg, test.repo, test.mailer, slog.New(slog.NewTextHandler(&logs, nil)))
			require.NoError(t, err)
			auth.randomBytes = func(int) ([]byte, error) {
				if test.randomErr != nil {
					return nil, test.randomErr
				}
				return bytes.Repeat([]byte{0x2a}, 32), nil
			}
			auth.processMagicLink(context.Background(), "known@example.test")
			require.Equal(t, test.wantInserts, test.repo.insertCalls)
			require.Equal(t, test.wantInvalidates, test.repo.invalidateCalls)
			if test.wantOperation != "" {
				require.Contains(t, logs.String(), "operation="+test.wantOperation)
			}
			for _, secret := range []string{"Known@Example.Test", "known@example.test", "database secret", "entropy secret", "smtp secret", "://bad-secret"} {
				require.NotContains(t, logs.String(), secret)
			}
		})
	}
}

func TestStartMagicLinkRejectsEmptyInputBeforeLookup(t *testing.T) {
	repo := &magicLinkStartRepository{}
	auth, err := NewAuth(testConfig(), repo, &magicLinkStartMailer{}, nil)
	require.NoError(t, err)
	err = auth.StartMagicLink(context.Background(), " \t ")
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.Zero(t, repo.lookupCalls)
}

func TestStartMagicLinkLogsOnlySanitizedCleanupFailureClass(t *testing.T) {
	email := "person@example.test"
	repo := &magicLinkStartRepository{
		user:           &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Email: &email},
		invalidateErrs: []error{errors.New("cleanup-secret"), errors.New("cleanup-secret"), errors.New("cleanup-secret")},
	}
	var logs bytes.Buffer
	auth, err := NewAuth(testConfig(), repo, &magicLinkStartMailer{err: errors.New("delivery-secret")}, slog.New(slog.NewTextHandler(&logs, nil)))
	require.NoError(t, err)
	auth.randomBytes = func(int) ([]byte, error) { return bytes.Repeat([]byte{1}, 32), nil }
	auth.processMagicLink(context.Background(), "person")
	require.Contains(t, logs.String(), "operation=token_invalidation")
	require.Contains(t, logs.String(), "operation=message_delivery")
	require.False(t, strings.Contains(logs.String(), "secret"), logs.String())
}
