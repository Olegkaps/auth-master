// middleware/jwt.go

package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/Olegkaps/auth-master/db"
	jwt_utils "github.com/Olegkaps/auth-master/jwt"
	"github.com/Olegkaps/auth-master/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt_utils.ValidateToken(tokenString)
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// get userID from JWT
		claims := token.Claims.(jwt.MapClaims)
		userIDStr, ok := claims["sub"].(string)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusUnauthorized)
			return
		}

		currentDeviceID := r.Header.Get("X-Device-ID")
		currentBrowser := r.Header.Get("User-Agent")

		// Check that token is linked to this device
		var tokenRecord models.RefreshToken
		err = db.DB.Where("user_id = ? AND device_id = ?", userID, currentDeviceID).
			Order("expires_at DESC").
			First(&tokenRecord).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "Token not associated with this device", http.StatusUnauthorized)
			} else {
				log.Printf("DB error: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		if !strings.Contains(tokenRecord.Browser, strings.Split(currentBrowser, " ")[0]) {
			log.Printf("Browser mismatch: expected %s, got %s", tokenRecord.Browser, currentBrowser)
		}

		// save userID and deviceID
		ctx := context.WithValue(r.Context(), "user_id", userID)
		ctx = context.WithValue(ctx, "device_id", currentDeviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
