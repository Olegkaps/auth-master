// http/server.go

package http

import (
	"log"
	"net/http"
	"time"

	"github.com/Olegkaps/auth-master/handlers"
	"github.com/Olegkaps/auth-master/middleware"

	"github.com/Olegkaps/auth-master/config"
	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/metrics"
	"github.com/gorilla/mux"
)

func StartHTTPServer(cfg config.Config) error {
	r := mux.NewRouter()

	rpsLimiter := middleware.NewRPSLimiter(
		db.RedisClient,
		10,
		1*time.Second,
	)

	r.Use(rpsLimiter.LimitByDeviceID)

	// public routes
	r.HandleFunc("/api/v1/auth/register", handlers.Register).Methods("POST")
	r.HandleFunc("/api/v1/auth/login", handlers.Login).Methods("POST")
	r.HandleFunc("/api/v1/auth/login/otp", handlers.LoginOTP).Methods("POST")
	r.HandleFunc("/api/v1/auth/otp/request", handlers.RequestOTP).Methods("POST")

	// private routes (requires JWT)
	auth := r.PathPrefix("/api/v1/auth").Subrouter()
	auth.Use(middleware.JWTMiddleware)

	auth.HandleFunc("/2fa/enable", handlers.Enable2FA).Methods("POST")
	auth.HandleFunc("/2fa/verify", handlers.Verify2FA).Methods("POST")
	auth.HandleFunc("/change-password", handlers.ChangePassword).Methods("PUT")
	auth.HandleFunc("/change-email", handlers.ChangeEmail).Methods("PUT")
	auth.HandleFunc("/refresh", handlers.RefreshToken).Methods("POST")
	auth.HandleFunc("/logout", handlers.Logout).Methods("POST")

	// Prometheus metrics
	r.Handle("/metrics", metrics.PrometheusHandler())

	log.Printf("HTTP server starting on :%s", cfg.HTTPPort)
	return http.ListenAndServe(":"+cfg.HTTPPort, r)
}
