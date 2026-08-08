package jwtutil

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
	TypeService = "service"
)

type Claims struct {
	Login        string `json:"login"`
	Typ          string `json:"typ"`
	Kid          string `json:"kid"`
	TokenVersion int64  `json:"token_version"`
	jwt.RegisteredClaims
}

func SignAccess(secret []byte, kid, userID, login, typ string, tokenVersion int64, ttl time.Duration) (string, error) {
	if typ != TypeAccess && typ != TypeService {
		return "", errors.New("invalid typ for access jwt")
	}
	now := time.Now()
	claims := Claims{
		Login:        login,
		Typ:          typ,
		Kid:          kid,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

// ParseUnverifiedClaims reads kid/login/typ/sub without signature check.
func ParseUnverifiedClaims(tokenString string) (*Claims, error) {
	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, err
	}
	c, ok := tok.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return c, nil
}

func ParseAndVerify(tokenString string, secret []byte) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	tok, err := parser.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}
