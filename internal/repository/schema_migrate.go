package repository

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MigrateDB creates PostgreSQL enum types, runs GORM AutoMigrate, then applies partial unique indexes and CHECK constraints.
func MigrateDB(db *gorm.DB) error {
	for _, q := range []string{
		`CREATE EXTENSION IF NOT EXISTS pg_trgm`,
		`DO $$ BEGIN CREATE TYPE user_kind AS ENUM ('human', 'service'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN CREATE TYPE role_level AS ENUM ('direct_member', 'member', 'role_admin'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`ALTER TYPE role_level ADD VALUE IF NOT EXISTS 'direct_member'`,
		`DO $$ BEGIN CREATE TYPE otp_purpose AS ENUM ('login', 'session_revoke', 'password_change', 'password_reset', 'grpc_2fa', 'generic'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`ALTER TYPE otp_purpose ADD VALUE IF NOT EXISTS 'password_reset'`,
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
		&roleTagModel{},
		&userRoleModel{},
		&userRoleTagModel{},
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
	if err := migrateLegacyRoleNames(db); err != nil {
		return err
	}

	for _, q := range []string{
		`INSERT INTO role_mounts (child_role_id, parent_role_id, created_at)
		 SELECT id, parent_id, NOW() FROM roles WHERE parent_id IS NOT NULL
		 ON CONFLICT (child_role_id, parent_role_id) DO NOTHING`,
		`CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_current ON signing_keys (is_current) WHERE is_current = true`,
		`CREATE UNIQUE INDEX IF NOT EXISTS role_requests_one_pending ON role_requests (target_user_id, role_id) WHERE status = 'pending'`,
		`CREATE INDEX IF NOT EXISTS users_keyset_order ON users (LOWER(login), id)`,
		`CREATE INDEX IF NOT EXISTS roles_keyset_order ON roles (LOWER(name), id)`,
		`CREATE INDEX IF NOT EXISTS users_login_trgm ON users USING gin (LOWER(login) gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS users_email_trgm ON users USING gin (LOWER(COALESCE(email, '')) gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS roles_name_trgm ON roles USING gin (LOWER(name) gin_trgm_ops)`,
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
		`DO $$ BEGIN
			ALTER TABLE role_mounts ADD CONSTRAINT role_mounts_child_fk FOREIGN KEY (child_role_id) REFERENCES roles(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE role_mounts ADD CONSTRAINT role_mounts_parent_fk FOREIGN KEY (parent_role_id) REFERENCES roles(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE role_tags ADD CONSTRAINT role_tags_role_fk FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE user_roles ADD CONSTRAINT user_roles_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE user_roles ADD CONSTRAINT user_roles_role_fk FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE user_role_tags ADD CONSTRAINT user_role_tags_membership_fk FOREIGN KEY (user_role_id) REFERENCES user_roles(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE role_requests ADD CONSTRAINT role_requests_requester_fk FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE role_requests ADD CONSTRAINT role_requests_target_fk FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		`DO $$ BEGIN
			ALTER TABLE role_requests ADD CONSTRAINT role_requests_role_fk FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
	} {
		if err := db.Exec(q).Error; err != nil {
			return fmt.Errorf("constraint: %w", err)
		}
	}

	return nil
}

type legacyRoleName struct {
	ID   uuid.UUID
	Name string
}

// migrateLegacyRoleNames performs the authorization-key normalization while an
// exclusive table lock prevents concurrent role writes. Ambiguous legacy data
// is never merged or renamed: operators get every conflicting ID and original
// value, repair it explicitly, and rerun the idempotent migration.
func migrateLegacyRoleNames(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("LOCK TABLE roles IN ACCESS EXCLUSIVE MODE").Error; err != nil {
			return fmt.Errorf("role-name migration lock: %w", err)
		}
		var rows []legacyRoleName
		if err := tx.Raw("SELECT id, name FROM roles ORDER BY id").Scan(&rows).Error; err != nil {
			return fmt.Errorf("role-name migration scan: %w", err)
		}
		blanks := make([]legacyRoleName, 0)
		groups := make(map[string][]legacyRoleName)
		for _, row := range rows {
			normalized := strings.ToLower(strings.TrimSpace(row.Name))
			if normalized == "" {
				blanks = append(blanks, row)
				continue
			}
			groups[normalized] = append(groups[normalized], row)
		}
		collidingKeys := make([]string, 0)
		for key, group := range groups {
			if len(group) > 1 {
				collidingKeys = append(collidingKeys, key)
			}
		}
		sort.Strings(collidingKeys)
		if len(blanks) > 0 || len(collidingKeys) > 0 {
			parts := make([]string, 0, 2)
			if len(blanks) > 0 {
				values := make([]string, 0, len(blanks))
				for _, row := range blanks {
					values = append(values, fmt.Sprintf("id=%s name=%q", row.ID, row.Name))
				}
				parts = append(parts, "blank names ["+strings.Join(values, ", ")+"]")
			}
			if len(collidingKeys) > 0 {
				values := make([]string, 0, len(collidingKeys))
				for _, key := range collidingKeys {
					members := make([]string, 0, len(groups[key]))
					for _, row := range groups[key] {
						members = append(members, fmt.Sprintf("id=%s name=%q", row.ID, row.Name))
					}
					values = append(values, fmt.Sprintf("key=%q [%s]", key, strings.Join(members, ", ")))
				}
				parts = append(parts, "normalized collisions ["+strings.Join(values, "; ")+"]")
			}
			return fmt.Errorf("role-name migration blocked: %s; repair roles.name to nonblank case-insensitively unique values and rerun", strings.Join(parts, "; "))
		}
		if err := tx.Exec("UPDATE roles SET name = BTRIM(name) WHERE name <> BTRIM(name)").Error; err != nil {
			return fmt.Errorf("role-name migration trim: %w", err)
		}
		if err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS roles_name_ci_unique ON roles (LOWER(BTRIM(name)))").Error; err != nil {
			return fmt.Errorf("role-name migration unique index: %w", err)
		}
		if err := tx.Exec(`DO $$ BEGIN
			ALTER TABLE roles ADD CONSTRAINT roles_name_not_blank CHECK (BTRIM(name) <> '');
		EXCEPTION WHEN duplicate_object THEN NULL; END $$;`).Error; err != nil {
			return fmt.Errorf("role-name migration blank constraint: %w", err)
		}
		return nil
	})
}
