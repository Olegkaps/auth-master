package repository

import (
	"context"
	"net"
	"time"
)

func (s *Store) CountFailedLogins(ctx context.Context, loginNorm string, since time.Time) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&failedLoginModel{}).
		Where("login_norm = ? AND created_at >= ?", loginNorm, since).
		Count(&n).Error
	return n, err
}

func (s *Store) InsertFailedLogin(ctx context.Context, loginNorm string, ip net.IP) error {
	var ipArg any
	if ip != nil {
		ipArg = ip.String()
	}
	return s.db.WithContext(ctx).Exec(
		`INSERT INTO failed_login_attempts (login_norm, ip, created_at) VALUES (?, ?::inet, now())`,
		loginNorm, ipArg,
	).Error
}

func (s *Store) DeleteOldFailedLogins(ctx context.Context, before time.Time) error {
	return s.db.WithContext(ctx).Where("created_at < ?", before).Delete(&failedLoginModel{}).Error
}
