package service

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

type devFlagsRepository struct {
	repository.Repository
	user             *domain.User
	openCalls        int
	inviteLookups    int
	openLogin        string
	openEmail        string
	openPasswordHash string
	openCipher       []byte
	openNonce        []byte
	openID           uuid.UUID
	otp              *repository.OTPRow
	otpConsumes      int
	otpIncrements    int
	failedLogins     int
}

func (r *devFlagsRepository) RegisterHumanOpen(_ context.Context, login, email, passwordHash string, cipher, nonce []byte, _ int) (uuid.UUID, error) {
	r.openCalls++
	r.openLogin, r.openEmail, r.openPasswordHash = login, email, passwordHash
	r.openCipher, r.openNonce = cipher, nonce
	return r.openID, nil
}

func (r *devFlagsRepository) GetValidRegistrationInviteByTokenHash(context.Context, []byte) (*repository.RegistrationInvite, error) {
	r.inviteLookups++
	return nil, nil
}

func (r *devFlagsRepository) GetHumanUserByLoginOrEmail(context.Context, string) (*domain.User, error) {
	return r.user, nil
}

func (r *devFlagsRepository) CreateEmailOTP(_ context.Context, userID uuid.UUID, purpose domain.OTPPurpose, codeHash []byte, expiresAt time.Time, correlation *string) (uuid.UUID, error) {
	id := uuid.New()
	r.otp = &repository.OTPRow{ID: id, UserID: userID, Purpose: purpose, CodeHash: codeHash, ExpiresAt: expiresAt, Correlation: correlation}
	return id, nil
}

func (r *devFlagsRepository) GetOTPByCorrelation(context.Context, string) (*repository.OTPRow, error) {
	return r.otp, nil
}

func (r *devFlagsRepository) IncrementOTPAttempt(context.Context, uuid.UUID) error {
	r.otpIncrements++
	return nil
}

func (r *devFlagsRepository) ConsumeOTP(context.Context, uuid.UUID) error {
	r.otpConsumes++
	return nil
}

func (r *devFlagsRepository) InsertFailedLogin(context.Context, string, net.IP) error {
	r.failedLogins++
	return nil
}

func (r *devFlagsRepository) CountFailedLogins(context.Context, string, time.Time) (int64, error) {
	return int64(r.failedLogins), nil
}

type countingMailer struct{ calls int }

func (m *countingMailer) Send(context.Context, []string, string, string) error {
	m.calls++
	return nil
}

func TestOpenRegistrationDecisionAndPreparation(t *testing.T) {
	cfg := testConfig()
	repo := &devFlagsRepository{openID: uuid.New()}
	auth, err := NewAuth(cfg, repo, &countingMailer{}, nil)
	require.NoError(t, err)

	_, err = auth.Register(context.Background(), "", "Person", "PERSON@EXAMPLE.TEST", "Strong-Person1!")
	require.ErrorIs(t, err, ErrInvalidInvite)
	require.Zero(t, repo.openCalls)

	cfg.RegistrationOpen = true
	id, err := auth.Register(context.Background(), "", "  Person  ", "  PERSON@EXAMPLE.TEST ", "Strong-Person1!")
	require.NoError(t, err)
	require.Equal(t, repo.openID, id)
	require.Equal(t, "person", repo.openLogin)
	require.Equal(t, "person@example.test", repo.openEmail)
	valid, err := crypto.VerifyPassword("Strong-Person1!", repo.openPasswordHash)
	require.NoError(t, err)
	require.True(t, valid)
	require.NotEmpty(t, repo.openCipher)
	require.NotEmpty(t, repo.openNonce)
	_, err = auth.Register(context.Background(), "", "weak", "weak@example.test", "weak")
	require.ErrorIs(t, err, ErrPasswordPolicy)
	require.Equal(t, 1, repo.openCalls)

	_, err = auth.Register(context.Background(), "explicit-invalid", "other", "other@example.test", "Strong-Person2!")
	require.ErrorIs(t, err, ErrInvalidInvite)
	require.Equal(t, 1, repo.openCalls, "an explicit token must never fall back to open registration")
	require.Equal(t, 1, repo.inviteLookups)
}

func TestSkipLoginOTPIssuesOnlyEmptyCodeChallenge(t *testing.T) {
	password := "Strong-Login1!"
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)
	email := "person@example.test"
	repo := &devFlagsRepository{user: &domain.User{ID: uuid.New(), Login: "person", Email: &email, Kind: domain.UserHuman, PasswordHash: &hash}}
	mailer := &countingMailer{}
	cfg := testConfig()
	cfg.SkipLoginOTP = true
	auth, err := NewAuth(cfg, repo, mailer, nil)
	require.NoError(t, err)

	result, err := auth.LoginPassword(context.Background(), "person", password, nil)
	require.NoError(t, err)
	require.False(t, result.OTPRequired)
	require.NotEmpty(t, result.LoginChallenge)
	require.Equal(t, auth.IntegrationOTPHash(""), repo.otp.CodeHash)
	require.Zero(t, mailer.calls)
}

func TestNormalLoginChallengeCannotBeBypassedAfterFlagFlip(t *testing.T) {
	password := "Strong-Login2!"
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)
	email := "person@example.test"
	repo := &devFlagsRepository{user: &domain.User{ID: uuid.New(), Login: "person", Email: &email, Kind: domain.UserHuman, PasswordHash: &hash}}
	cfg := testConfig()
	auth, err := NewAuth(cfg, repo, &countingMailer{}, nil)
	require.NoError(t, err)
	result, err := auth.LoginPassword(context.Background(), "person", password, nil)
	require.NoError(t, err)
	require.True(t, result.OTPRequired)

	cfg.SkipLoginOTP = true
	_, _, err = auth.LoginVerifyOTP(context.Background(), result.LoginChallenge, "", "device", "test")
	require.ErrorIs(t, err, ErrOTPInvalid)
	require.Equal(t, 1, repo.otpIncrements)
	require.Equal(t, 1, repo.otpConsumes)
}

func TestSkipLoginOTPDoesNotBypassPasswordOrAccountEligibility(t *testing.T) {
	password := "Strong-Login3!"
	hash, err := crypto.HashPassword(password)
	require.NoError(t, err)
	email := "person@example.test"
	now := time.Now()

	tests := []struct {
		name     string
		user     *domain.User
		password string
		wantErr  error
	}{
		{
			name:     "wrong password",
			user:     &domain.User{ID: uuid.New(), Login: "person", Email: &email, Kind: domain.UserHuman, PasswordHash: &hash},
			password: "Wrong-Password3!",
			wantErr:  ErrInvalidCredentials,
		},
		{
			name:     "banned user",
			user:     &domain.User{ID: uuid.New(), Login: "person", Email: &email, Kind: domain.UserHuman, PasswordHash: &hash, BannedAt: &now},
			password: password,
			wantErr:  ErrBanned,
		},
		{
			name: "locked user",
			user: func() *domain.User {
				lockedUntil := now.Add(time.Hour)
				return &domain.User{ID: uuid.New(), Login: "person", Email: &email, Kind: domain.UserHuman, PasswordHash: &hash, LockedUntil: &lockedUntil}
			}(),
			password: password,
			wantErr:  ErrLocked,
		},
		{
			name:     "passwordless user",
			user:     &domain.User{ID: uuid.New(), Login: "person", Email: &email, Kind: domain.UserHuman},
			password: password,
			wantErr:  ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &devFlagsRepository{user: tt.user}
			mailer := &countingMailer{}
			cfg := testConfig()
			cfg.SkipLoginOTP = true
			auth, authErr := NewAuth(cfg, repo, mailer, nil)
			require.NoError(t, authErr)

			result, loginErr := auth.LoginPassword(context.Background(), "person", tt.password, nil)
			require.Nil(t, result)
			require.ErrorIs(t, loginErr, tt.wantErr)
			require.Nil(t, repo.otp, "ineligible password login must not create a bypass challenge")
			require.Zero(t, mailer.calls)
		})
	}
}
