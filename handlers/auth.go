// handlers/auth.go

package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/models"
)

func Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := authService.Register(req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := authService.Login(req.Email, req.Password, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// search refresh‑token in BD
	var token models.RefreshToken
	if err := db.DB.Where("token_id = ? AND used = false AND expires_at > ?", req.RefreshToken, time.Now()).First(&token).Error; err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Generate new tokens
	accessToken, newRefreshToken, err := authService.GenerateTokens(token.UserID, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// mark old refresh‑token as used
	token.Used = true
	db.DB.Save(&token)

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// search refresh‑token in BD
	var token models.RefreshToken
	if err := db.DB.Where("token_id = ? AND used = false AND expires_at > ?", req.RefreshToken, time.Now()).First(&token).Error; err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// mark old refresh‑token as used
	token.Used = true
	db.DB.Save(&token)

	w.WriteHeader(http.StatusOK)
}
