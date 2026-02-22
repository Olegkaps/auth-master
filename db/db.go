package db

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Olegkaps/auth-master/models"
	"github.com/go-redis/redis/v8"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	dsn := os.Getenv("DB_DSN") // "host=localhost user=gorm password=gorm dbname=gorm port=5432 sslmode=disable TimeZone=UTC"
	if dsn == "" {
		return fmt.Errorf("DB_DSN not set")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	DB = db

	// Automigration
	err = DB.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.Role{}, &models.UserRole{}, &models.Service{})
	if err != nil {
		return err
	}

	log.Println("Database initialized")
	return nil
}

var RedisClient *redis.Client

func InitRedis() {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal("Cannot connect to Redis:", err)
	}

	RedisClient = client
}
