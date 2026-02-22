package services

import (
	"context"
	"log"
	"time"

	"github.com/Olegkaps/auth-master/models"
	"gorm.io/gorm"
)

type CleanupService struct {
	DB        *gorm.DB
	Interval  time.Duration
	BatchSize int
}

func NewCleanupService(db *gorm.DB, interval time.Duration, batchSize int) *CleanupService {
	return &CleanupService{
		DB:        db,
		Interval:  interval,
		BatchSize: batchSize,
	}
}

func (s *CleanupService) Start(ctx context.Context) {
	log.Printf("Cleanup service started. Interval: %v, Batch size: %d", s.Interval, s.BatchSize)

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := s.deleteUsedTokens(ctx)
			if err != nil {
				log.Printf("Cleanup error: %v", err)
			}
		case <-ctx.Done():
			log.Println("Cleanup service stopped")
			return
		}
	}
}

func (s *CleanupService) deleteUsedTokens(ctx context.Context) error {
	var deletedCount int64

	for {
		result := s.DB.WithContext(ctx).
			Where("used = ? AND expires_at < ?", true, time.Now().Add(-7*24*time.Hour)). // to cfg
			Limit(s.BatchSize).
			Delete(&models.RefreshToken{})

		if result.Error != nil {
			return result.Error
		}

		deletedCount += result.RowsAffected

		if result.RowsAffected < int64(s.BatchSize) {
			break
		}

		// wait before next deletion
		time.Sleep(100 * time.Millisecond)
	}

	if deletedCount > 0 {
		log.Printf("Deleted %d used refresh tokens", deletedCount)
	} else {
		log.Println("No used refresh tokens to delete")
	}

	return nil
}
