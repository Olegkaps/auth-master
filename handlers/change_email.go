package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/models"
	"golang.org/x/crypto/bcrypt"
)

func ChangeEmail(w http.ResponseWriter, r *http.Request) {
	userID := getUserIDFromContext(r)
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewEmail        string `json:"new_email"`
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

	// check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		http.Error(w, "Incorrect current password", http.StatusUnauthorized)
		return
	}

	// Check that email is unique
	var count int64
	err := db.DB.Model(&models.User{}).Where("email = ?", req.NewEmail).Count(&count).Error
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	// renew email
	user.Email = req.NewEmail
	if err := db.DB.Save(&user).Error; err != nil {
		http.Error(w, "Failed to update email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
