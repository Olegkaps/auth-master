package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

type passwordResetStartRepository struct {
	repository.Repository
	user                     *domain.User
	lookupErr                error
	reserveErr               error
	issued                   bool
	lookup                   string
	reserveCalls             int
	activationCalls          int
	successfulActivations    int
	rejectCanceledActivation bool
	activationErrors         []error
}

func (r *passwordResetStartRepository) GetHumanUserByLoginOrEmail(_ context.Context, identity string) (*domain.User, error) {
	r.lookup = identity
	return r.user, r.lookupErr
}

func (r *passwordResetStartRepository) ReservePasswordResetOTP(_ context.Context, _ uuid.UUID, _ []byte, _, _ time.Time, _ time.Duration) (uuid.UUID, bool, error) {
	r.reserveCalls++
	return uuid.New(), r.issued, r.reserveErr
}

func (r *passwordResetStartRepository) ActivatePasswordResetOTP(ctx context.Context, _, _ uuid.UUID, _ time.Time) (repository.PasswordResetActivation, error) {
	r.activationCalls++
	if r.rejectCanceledActivation && ctx.Err() != nil {
		return repository.PasswordResetSuperseded, ctx.Err()
	}
	if len(r.activationErrors) >= r.activationCalls && r.activationErrors[r.activationCalls-1] != nil {
		return repository.PasswordResetSuperseded, r.activationErrors[r.activationCalls-1]
	}
	r.successfulActivations++
	return repository.PasswordResetActivated, nil
}

type passwordResetMailer struct {
	err       error
	calls     int
	afterSend func()
}

func (m *passwordResetMailer) Send(context.Context, []string, string, string) error {
	m.calls++
	if m.afterSend != nil {
		m.afterSend()
	}
	return m.err
}

func TestStartPasswordResetKeepsIneligibleAndPersistenceOutcomesEnumerationSafe(t *testing.T) {
	email := "mixed@example.test"
	bannedAt := time.Now()
	for _, test := range []struct {
		name         string
		repo         *passwordResetStartRepository
		wantReserves int
	}{
		{name: "lookup failure", repo: &passwordResetStartRepository{lookupErr: errors.New("database unavailable")}},
		{name: "unknown", repo: &passwordResetStartRepository{}},
		{name: "service", repo: &passwordResetStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserService, Email: &email}}},
		{name: "missing email", repo: &passwordResetStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman}}},
		{name: "banned", repo: &passwordResetStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Email: &email, BannedAt: &bannedAt}}},
		{name: "reservation failure", repo: &passwordResetStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Email: &email}, reserveErr: errors.New("write failed")}, wantReserves: 1},
		{name: "throttled", repo: &passwordResetStartRepository{user: &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Email: &email}, issued: false}, wantReserves: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, err := NewAuth(testConfig(), test.repo, &mail.Sender{Host: "127.0.0.1", Port: 1, From: "test@example.test"}, nil)
			require.NoError(t, err)
			auth.processPasswordReset(context.Background(), "mixed@example.test")
			require.Equal(t, "mixed@example.test", test.repo.lookup)
			require.Equal(t, test.wantReserves, test.repo.reserveCalls)
		})
	}
}

func TestStartPasswordResetActivatesOnlyAfterMailAndRetriesTransientPersistence(t *testing.T) {
	email := "person@example.test"
	repo := &passwordResetStartRepository{
		user:             &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Login: "person", Email: &email},
		issued:           true,
		activationErrors: []error{errors.New("transient activation error"), nil},
	}
	mailer := &passwordResetMailer{}
	auth, err := NewAuth(testConfig(), repo, mailer, nil)
	require.NoError(t, err)
	auth.processPasswordReset(context.Background(), "person")
	require.Equal(t, 1, mailer.calls)
	require.Equal(t, 2, repo.activationCalls)

	repo.activationCalls = 0
	repo.activationErrors = nil
	mailer.err = errors.New("mail unavailable")
	auth.processPasswordReset(context.Background(), "person")
	require.Equal(t, 0, repo.activationCalls, "failed SMTP acceptance must leave the reservation pending")
}

func TestStartPasswordResetActivatesAfterSMTPSuccessCancelsMailJob(t *testing.T) {
	email := "deadline@example.test"
	repo := &passwordResetStartRepository{
		user:                     &domain.User{ID: uuid.New(), Kind: domain.UserHuman, Login: "deadline", Email: &email},
		issued:                   true,
		rejectCanceledActivation: true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mailer := &passwordResetMailer{afterSend: cancel}
	auth, err := NewAuth(testConfig(), repo, mailer, nil)
	require.NoError(t, err)

	auth.processPasswordReset(ctx, "deadline")

	require.Equal(t, 1, mailer.calls)
	require.Equal(t, 1, repo.activationCalls)
	require.Equal(t, 1, repo.successfulActivations,
		"SMTP acceptance at the job deadline must still make the delivered code usable")
}
