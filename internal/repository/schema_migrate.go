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
	if err := migrateUserIdentityKeys(db); err != nil {
		return err
	}
	// Deployments that predate token_version could already contain banned
	// users and credentials issued without the claim (which decodes as version
	// 0). Advance those subjects and revoke their live refresh sessions in one
	// atomic PostgreSQL statement. Active legacy users retain version 0
	// compatibility, while reruns leave both versions and revocation timestamps
	// untouched because migrated_users is then empty.
	if err := db.Exec(`
		WITH migrated_users AS (
			UPDATE users
			SET token_version = 1
			WHERE banned_at IS NOT NULL AND token_version = 0
			RETURNING id
		)
		UPDATE refresh_sessions AS rs
		SET revoked_at = CURRENT_TIMESTAMP
		FROM migrated_users AS u
		WHERE rs.user_id = u.id AND rs.revoked_at IS NULL`).Error; err != nil {
		return fmt.Errorf("token-version and refresh-session migration for banned legacy users: %w", err)
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
		`CREATE UNIQUE INDEX IF NOT EXISTS users_login_ci_unique ON users (LOWER(BTRIM(login)))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS users_email_ci_unique ON users (LOWER(BTRIM(email))) WHERE email IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS roles_keyset_order ON roles (LOWER(name), id)`,
		`CREATE INDEX IF NOT EXISTS users_login_trgm ON users USING gin (LOWER(login) gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS users_email_trgm ON users USING gin (LOWER(COALESCE(email, '')) gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS roles_name_trgm ON roles USING gin (LOWER(name) gin_trgm_ops)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS email_otp_one_active_password_reset
		 ON email_otp_challenges (user_id)
		 WHERE purpose = 'password_reset' AND delivery_state = 'active' AND consumed_at IS NULL`,
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
			ALTER TABLE email_otp_challenges ADD CONSTRAINT email_otp_delivery_state_check CHECK (delivery_state IN ('pending', 'active'));
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

type legacyUserIdentity struct {
	ID    uuid.UUID
	Kind  string
	Login string
	Email *string
}

// migrateUserIdentityKeys makes every interactive identity canonical and
// unambiguous before installing case-insensitive uniqueness enforcement. It
// intentionally fails closed and reports every collision instead of merging
// accounts based on guesses.
func migrateUserIdentityKeys(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var installed bool
		if err := tx.Raw(`SELECT to_regclass('user_identity_keys') IS NOT NULL
			AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'users_canonicalize_identity' AND NOT tgisinternal)
			AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'users_sync_human_identity_keys' AND NOT tgisinternal)`).Scan(&installed).Error; err != nil {
			return fmt.Errorf("inspect user identity migration: %w", err)
		}
		if installed {
			return nil
		}
		if err := tx.Exec("LOCK TABLE users IN ACCESS EXCLUSIVE MODE").Error; err != nil {
			return fmt.Errorf("user identity migration lock: %w", err)
		}
		var rows []legacyUserIdentity
		if err := tx.Raw("SELECT id, kind, login, email FROM users ORDER BY id").Scan(&rows).Error; err != nil {
			return fmt.Errorf("user identity migration scan: %w", err)
		}
		owners := make(map[string]map[uuid.UUID]struct{})
		blanks := make([]uuid.UUID, 0)
		blankHumanEmails := make([]uuid.UUID, 0)
		for _, row := range rows {
			login := strings.ToLower(strings.TrimSpace(row.Login))
			if login == "" {
				blanks = append(blanks, row.ID)
			} else {
				if owners["login:"+login] == nil {
					owners["login:"+login] = map[uuid.UUID]struct{}{}
				}
				owners["login:"+login][row.ID] = struct{}{}
				if row.Kind == "human" {
					if owners["human:"+login] == nil {
						owners["human:"+login] = map[uuid.UUID]struct{}{}
					}
					owners["human:"+login][row.ID] = struct{}{}
				}
			}
			if row.Kind == "human" && (row.Email == nil || strings.TrimSpace(*row.Email) == "") {
				blankHumanEmails = append(blankHumanEmails, row.ID)
			}
			if row.Email != nil && strings.TrimSpace(*row.Email) != "" {
				email := strings.ToLower(strings.TrimSpace(*row.Email))
				if owners["email:"+email] == nil {
					owners["email:"+email] = map[uuid.UUID]struct{}{}
				}
				owners["email:"+email][row.ID] = struct{}{}
				if row.Kind == "human" {
					if owners["human:"+email] == nil {
						owners["human:"+email] = map[uuid.UUID]struct{}{}
					}
					owners["human:"+email][row.ID] = struct{}{}
				}
			}
		}
		collisions := make([]string, 0)
		for key, ids := range owners {
			if len(ids) > 1 {
				values := make([]string, 0, len(ids))
				for id := range ids {
					values = append(values, id.String())
				}
				sort.Strings(values)
				collisions = append(collisions, fmt.Sprintf("%s=[%s]", key, strings.Join(values, ",")))
			}
		}
		sort.Strings(collisions)
		if len(blanks) > 0 || len(blankHumanEmails) > 0 || len(collisions) > 0 {
			return fmt.Errorf("user identity migration blocked: blank_logins=%v blank_human_emails=%v collisions=%v; repair users and rerun", blanks, blankHumanEmails, collisions)
		}
		if err := tx.Exec(`UPDATE users
			SET login = LOWER(BTRIM(login)),
				email = CASE WHEN email IS NULL THEN NULL ELSE LOWER(BTRIM(email)) END
			WHERE login IS DISTINCT FROM LOWER(BTRIM(login))
				OR email IS DISTINCT FROM CASE WHEN email IS NULL THEN NULL ELSE LOWER(BTRIM(email)) END`).Error; err != nil {
			return fmt.Errorf("user identity migration normalize: %w", err)
		}
		// A separate key table turns the human login-or-email namespace into one
		// atomic database invariant. Separate indexes cannot prevent user A's
		// login racing with user B's email.
		if err := tx.Exec(`CREATE TABLE IF NOT EXISTS user_identity_keys (
			normalized_identity text PRIMARY KEY,
			user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			UNIQUE (user_id, normalized_identity)
		)`).Error; err != nil {
			return fmt.Errorf("create user identity keys: %w", err)
		}
		if err := tx.Exec(`INSERT INTO user_identity_keys (normalized_identity, user_id)
			SELECT identity, id FROM (
				SELECT LOWER(BTRIM(login)) AS identity, id FROM users WHERE kind = 'human'
				UNION
				SELECT LOWER(BTRIM(email)) AS identity, id FROM users WHERE kind = 'human' AND email IS NOT NULL
			) identities
			WHERE NOT EXISTS (
				SELECT 1 FROM user_identity_keys existing
				WHERE existing.normalized_identity = identities.identity AND existing.user_id = identities.id
			)`).Error; err != nil {
			return fmt.Errorf("populate user identity keys: %w", err)
		}
		if err := tx.Exec(`CREATE OR REPLACE FUNCTION canonicalize_user_identity() RETURNS trigger AS $$
		BEGIN
			NEW.login := LOWER(BTRIM(NEW.login));
			IF NEW.email IS NOT NULL THEN NEW.email := LOWER(BTRIM(NEW.email)); END IF;
			IF NEW.login = '' THEN RAISE EXCEPTION 'blank login' USING ERRCODE = '23514'; END IF;
			IF NEW.kind = 'human' AND (NEW.email IS NULL OR NEW.email = '') THEN
				RAISE EXCEPTION 'blank human email' USING ERRCODE = '23514';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`).Error; err != nil {
			return fmt.Errorf("create identity canonicalization trigger function: %w", err)
		}
		if err := tx.Exec(`DROP TRIGGER IF EXISTS users_canonicalize_identity ON users;
			CREATE TRIGGER users_canonicalize_identity BEFORE INSERT OR UPDATE OF login, email, kind ON users
			FOR EACH ROW EXECUTE FUNCTION canonicalize_user_identity()`).Error; err != nil {
			return fmt.Errorf("install identity canonicalization trigger: %w", err)
		}
		if err := tx.Exec(`CREATE OR REPLACE FUNCTION sync_human_identity_keys() RETURNS trigger AS $$
		BEGIN
			IF TG_OP = 'DELETE' THEN
				DELETE FROM user_identity_keys WHERE user_id = OLD.id;
				RETURN OLD;
			END IF;
			DELETE FROM user_identity_keys WHERE user_id = NEW.id;
			IF NEW.kind = 'human' THEN
				INSERT INTO user_identity_keys (normalized_identity, user_id) VALUES (NEW.login, NEW.id);
				IF NEW.email IS NOT NULL AND NEW.email <> NEW.login THEN
					INSERT INTO user_identity_keys (normalized_identity, user_id) VALUES (NEW.email, NEW.id);
				END IF;
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`).Error; err != nil {
			return fmt.Errorf("create identity key trigger function: %w", err)
		}
		if err := tx.Exec(`DROP TRIGGER IF EXISTS users_sync_human_identity_keys ON users;
			CREATE TRIGGER users_sync_human_identity_keys AFTER INSERT OR UPDATE OF login, email, kind OR DELETE ON users
			FOR EACH ROW EXECUTE FUNCTION sync_human_identity_keys()`).Error; err != nil {
			return fmt.Errorf("install identity key trigger: %w", err)
		}
		return nil
	})
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
