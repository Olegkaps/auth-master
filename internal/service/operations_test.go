package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateServiceAccountCredentials(t *testing.T) {
	login, err := validateServiceAccountCredentials("  Storage-Provisioner  ", "Strong-Service1!")
	require.NoError(t, err)
	require.Equal(t, "storage-provisioner", login)

	tests := []struct {
		name   string
		login  string
		secret string
		want   error
	}{
		{name: "missing login", secret: "Strong-Service1!", want: ErrInvalidArgument},
		{name: "long login", login: strings.Repeat("a", maxServiceAccountLoginBytes+1), secret: "Strong-Service1!", want: ErrInvalidArgument},
		{name: "weak secret", login: "svc", secret: "weak", want: ErrPasswordPolicy},
		{name: "long secret", login: "svc", secret: strings.Repeat("A", maxServiceSecretBytes+1), want: ErrInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, validationErr := validateServiceAccountCredentials(test.login, test.secret)
			require.ErrorIs(t, validationErr, test.want)
			require.NotContains(t, validationErr.Error(), test.secret)
		})
	}
}
