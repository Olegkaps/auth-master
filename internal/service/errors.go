package service

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrLocked             = errors.New("account locked")
	ErrBanned             = errors.New("account banned")
	ErrStaleSigningKey    = errors.New("signing key stale")
	ErrWrongTokenType     = errors.New("wrong token type")
	ErrOTPInvalid         = errors.New("invalid or expired otp")
	ErrPasswordPolicy     = errors.New("password policy violation")
	ErrForbidden          = errors.New("forbidden")
	ErrNotFound           = errors.New("not found")
	ErrInvalidInvite      = errors.New("invalid or expired registration invite")
	ErrCannotBanSelf      = errors.New("cannot ban yourself")
	ErrCannotBanSuperuser = errors.New("cannot ban a superuser")
)
