package handlers

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/Olegkaps/auth-master/config"
	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/models"
)

func RequestOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// generate OTP
	otp := generateOTP(6)
	expiresAt := time.Now().Add(time.Duration(config.Cfg.OTPExpiration) * time.Second)

	// send to Redis: key=email, value=OTP+expires
	err := db.RedisClient.Set(context.Background(), req.Email, otp, time.Until(expiresAt)).Err()
	if err != nil {
		http.Error(w, "Failed to store OTP", http.StatusInternalServerError)
		return
	}

	sendOTPByEmail(req.Email, otp)

	w.WriteHeader(http.StatusOK)
}

func generateOTP(length int) string {
	digits := "0123456789"
	otp := make([]byte, length)
	for i := range otp {
		otp[i] = digits[rand.Intn(len(digits))]
	}
	return string(otp)
}

func sendOTPByEmail(email, otp string) {
	// TODO: intargation SMTP/SendGrid/Mailgun
	log.Printf("OTP %s sent to %s", otp, email)
}

func LoginOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// check OTP в Redis
	storedOTP, err := db.RedisClient.Get(context.Background(), req.Email).Result()
	if err != nil || storedOTP != req.OTP {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	// delete OTP from Redis
	db.RedisClient.Del(context.Background(), req.Email)

	// Get user
	var user models.User
	if err := db.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// generate JWT
	accessToken, refreshToken, err := authService.GenerateTokens(user.ID, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
