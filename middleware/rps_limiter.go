package middleware

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/Olegkaps/auth-master/logging"
	"github.com/go-redis/redis/v8"
)

type RPSLimiter struct {
	redisClient *redis.Client
	limit       int
	period      time.Duration
	prefix      string
}

func NewRPSLimiter(redisClient *redis.Client, limit int, period time.Duration) *RPSLimiter {
	return &RPSLimiter{
		redisClient: redisClient,
		limit:       limit,
		period:      period,
		prefix:      "rps_limit:",
	}
}

func (l *RPSLimiter) LimitByDeviceID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentDeviceID := r.Header.Get("X-Device-ID")
		if currentDeviceID == "" {
			logging.Logger.Warn("No user_id in context, skipping RPS limit")
			http.Error(w, "Missing device id", http.StatusBadRequest)
			return
		}

		key := l.prefix + currentDeviceID

		count, err := l.redisClient.Incr(context.Background(), key).Result()
		if err != nil {
			logging.Logger.Error("Redis Incr error:", err)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		if count == 1 {
			ttl := l.period
			if err := l.redisClient.Expire(context.Background(), key, ttl).Err(); err != nil {
				logging.Logger.Error("Redis Expire error:", err)
				http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		if count > int64(l.limit) {
			w.Header().Set("Retry-After", strconv.Itoa(int(l.period.Seconds())))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
