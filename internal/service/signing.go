package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/repository"
)

// EnsureBootstrap creates the first signing key if the table is empty.
func (a *Auth) EnsureBootstrap(ctx context.Context) error {
	return a.ensureSigningBootstrap(ctx)
}

func (a *Auth) ensureSigningBootstrap(ctx context.Context) error {
	n, err := a.repo.CountSigningKeys(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	kid := uuid.New().String()
	secret, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	nonce, cipher, err := crypto.EncryptAESGCM(a.signingMaster, secret, []byte(kid))
	if err != nil {
		return err
	}
	return a.repo.InsertSigningKey(ctx, kid, cipher, nonce, false)
}

func (a *Auth) decryptSigningMaterial(m *repository.SigningKeyMaterial) ([]byte, error) {
	plain, err := crypto.DecryptAESGCM(a.signingMaster, m.Nonce, m.SecretCipher, []byte(m.Kid))
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (a *Auth) currentSigningSecret(ctx context.Context) (kid string, secret []byte, err error) {
	m, err := a.repo.GetCurrentSigningKeyMaterial(ctx)
	if err != nil {
		return "", nil, err
	}
	if m == nil {
		return "", nil, fmt.Errorf("no current signing key")
	}
	sec, err := a.decryptSigningMaterial(m)
	if err != nil {
		return "", nil, err
	}
	return m.Kid, sec, nil
}

func (a *Auth) secretForKID(ctx context.Context, kid string, now time.Time) (secret []byte, deprecatedAt *time.Time, stale bool, err error) {
	m, err := a.repo.GetSigningKeyMaterial(ctx, kid)
	if err != nil {
		return nil, nil, false, err
	}
	if m == nil {
		return nil, nil, false, fmt.Errorf("unknown signing key %q", kid)
	}
	sec, err := a.decryptSigningMaterial(m)
	if err != nil {
		return nil, nil, false, err
	}
	if m.DeprecatedAt != nil && !m.DeprecatedAt.IsZero() {
		if now.After(m.DeprecatedAt.Add(a.cfg.SigningGracePeriod)) {
			return sec, m.DeprecatedAt, true, nil
		}
	}
	return sec, m.DeprecatedAt, false, nil
}

func (a *Auth) RotateSigningKey(ctx context.Context) error {
	kid := uuid.New().String()
	secret, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	nonce, cipher, err := crypto.EncryptAESGCM(a.signingMaster, secret, []byte(kid))
	if err != nil {
		return err
	}
	return a.repo.DeprecateCurrentAndSet(ctx, kid, cipher, nonce)
}
