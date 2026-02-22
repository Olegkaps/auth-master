package config

import (
	"os"
	"strconv"
)

type Config struct {
	HTTPPort        string
	GRPCPort        string
	DBDSN           string
	RedisAddr       string
	JWTSecret       string
	OTPExpiration   int // secs
	RefreshTokenTTL int // days
	LogLevel        string
	OpenSearchURL   string
	GrafanaAPIKey   string
}

func LoadConfig() Config {
	return Config{
		HTTPPort:        os.Getenv("HTTP_PORT"),
		GRPCPort:        os.Getenv("GRPC_PORT"),
		DBDSN:           os.Getenv("DB_DSN"),
		RedisAddr:       os.Getenv("REDIS_ADDR"),
		JWTSecret:       os.Getenv("JWT_SECRET"),
		OTPExpiration:   getEnvInt("OTP_EXPIRATION", 300),
		RefreshTokenTTL: getEnvInt("REFRESH_TOKEN_TTL", 7),
		LogLevel:        os.Getenv("LOG_LEVEL"),
		OpenSearchURL:   os.Getenv("OPENSEARCH_URL"),
		GrafanaAPIKey:   os.Getenv("GRAFANA_API_KEY"),
	}
}

func getEnvInt(key string, defaultValue int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultValue
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultValue
	}
	return val
}

var Cfg Config = LoadConfig()
