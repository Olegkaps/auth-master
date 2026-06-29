package migrate

import (
	"context"
	"fmt"

	"github.com/olegkapshai/auth-master/internal/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open returns a GORM DB handle for PostgreSQL.
func Open(databaseURL string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
}

// Up runs schema migration (enums, AutoMigrate, indexes, constraints).
func Up(db *gorm.DB) error {
	if err := repository.MigrateDB(db); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// UpSQL opens DATABASE_URL and runs migrations (for one-off tools).
func UpSQL(ctx context.Context, databaseURL string) error {
	_ = ctx
	db, err := Open(databaseURL)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	return Up(db)
}
