package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"log"

	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/logging"
	"github.com/Olegkaps/auth-master/models"
	"golang.org/x/crypto/bcrypt"
)

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := getUserIDFromContext(r)

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "Current password and new password are required", http.StatusBadRequest)
		return
	}

	var user models.User
	if err := db.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(req.CurrentPassword),
	); err != nil {

		if err == bcrypt.ErrMismatchedHashAndPassword {
			http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
		} else {
			log.Printf("BCrypt error for user %s: %v", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// check password
	// TODO: more checks
	if len(req.NewPassword) < 8 {
		http.Error(w, "New password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(req.NewPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		log.Printf("Failed to hash new password for user %s: %v", userID, err)
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = string(hash)
	user.UpdatedAt = time.Now()

	if err := db.DB.Save(&user).Error; err != nil {
		log.Printf("Failed to update password for user %s: %v", userID, err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	logging.Logger.Infof("Password changed for user %s", userID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password successfully updated",
	})
}
