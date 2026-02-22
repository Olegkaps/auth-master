package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/models"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func Enable2FA(w http.ResponseWriter, r *http.Request) {
	userID := getUserIDFromContext(r) // from JWT-claims

	var req struct {
		CurrentPassword string `json:"current_password"`
		Enable          bool   `json:"enable"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// check current password
	var user models.User
	if err := db.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// enable/disable 2FA
	user.TwoFAEnabled = req.Enable
	if req.Enable {
		// generate secret for TOTP
		secret, err := totp.Generate(
			totp.GenerateOpts{
				Issuer:      "YourApp",
				AccountName: user.Email,
			})
		if err != nil {
			http.Error(w, "Failed to generate 2FA secret", http.StatusInternalServerError)
			return
		}
		user.TwoFASecret = secret.Secret()
	} else {
		user.TwoFASecret = ""
	}

	db.DB.Save(&user)

	w.WriteHeader(http.StatusOK)
}

func Verify2FA(w http.ResponseWriter, r *http.Request) {
	userID := getUserIDFromContext(r)
	var req struct {
		OTP string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user models.User
	if err := db.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if !user.TwoFAEnabled {
		http.Error(w, "2FA is not enabled", http.StatusBadRequest)
		return
	}

	// Check TOTP
	valid := totp.Validate(req.OTP, user.TwoFASecret)
	if !valid {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}
