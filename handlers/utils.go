package handlers

import (
	"net/http"

	"github.com/Olegkaps/auth-master/services"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var authService *services.AuthService

func SetAuthService(service *services.AuthService) {
	authService = service
}

func getUserIDFromContext(r *http.Request) uuid.UUID {
	ctx := r.Context()
	claims, ok := ctx.Value("jwt_claims").(jwt.MapClaims)
	if !ok {
		return uuid.Nil
	}

	userIDStr, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil
	}

	return userID
}
