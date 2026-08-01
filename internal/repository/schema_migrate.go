package repository

import (
	"fmt"

	"gorm.io/gorm"
)

// MigrateDB creates PostgreSQL enum types, runs GORM AutoMigrate, then applies partial unique indexes and CHECK constraints.
func MigrateDB(db *gorm.DB) error {
	for _, q := range []string{
		`DO $$ BEGIN CREATE TYPE user_kind AS ENUM ('human', 'service'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN CREATE TYPE role_level AS ENUM ('member', 'role_admin'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN CREATE TYPE otp_purpose AS ENUM ('login', 'session_revoke', 'password_change', 'grpc_2fa', 'generic'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN CREATE TYPE role_request_status AS ENUM ('pending', 'approved', 'rejected'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
	} {
		if err := db.Exec(q).Error; err != nil {
			return fmt.Errorf("enum: %w", err)
		}
	}

	if err := db.AutoMigrate(
		&userModel{},
		&roleModel{},
		&roleMountModel{},
		&userRoleModel{},
		&signingKeyModel{},
		&refreshSessionModel{},
		&passwordHistoryModel{},
		&emailOTPModel{},
		&failedLoginModel{},
		&stepUp2FAModel{},
		&roleRequestModel{},
		&registrationInviteModel{},
		&magicLinkModel{},
	); err != nil {
		return fmt.Errorf("automigrate: %w", err)
	}

	for _, q := range []string{
		`INSERT INTO role_mounts (child_role_id, parent_role_id, created_at)
		 SELECT id, parent_id, NOW() FROM roles WHERE parent_id IS NOT NULL
		 ON CONFLICT (child_role_id, parent_role_id) DO NOTHING`,
		`CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_current ON signing_keys (is_current) WHERE is_current = true`,
		`CREATE UNIQUE INDEX IF NOT EXISTS role_requests_one_pending ON role_requests (target_user_id, role_id) WHERE status = 'pending'`,
	} {
		if err := db.Exec(q).Error; err != nil {
			return fmt.Errorf("index: %w", err)
		}
	}

	for _, q := range []string{
		`DO $$ BEGIN
			ALTER TABLE users ADD CONSTRAINT users_human_email CHECK (kind <> 'human' OR email IS NOT NULL);
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE users ADD CONSTRAINT users_service_secret CHECK (kind <> 'service' OR service_secret_hash IS NOT NULL);
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
	} {
		if err := db.Exec(q).Error; err != nil {
			return fmt.Errorf("constraint: %w", err)
		}
	}

	return nil
}
