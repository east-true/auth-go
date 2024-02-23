package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/east-true/auth-go/jwt/claims"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthToken struct {
	Access  *claims.Claims `json:"access_token"`
	refresh *claims.Claims
}

func NewAuthToken(role string) *AuthToken {
	now := time.Now()
	idgen, _ := uuid.NewUUID()
	id := idgen.String()
	access := claims.New(id, role, now, 10*time.Minute)
	refresh := claims.New(id, role, now, 1*time.Hour)
	if err := refresh.Store(); err != nil {
		fmt.Println(err)
		return nil
	}

	return &AuthToken{
		Access:  access,
		refresh: refresh,
	}
}

func (auth *AuthToken) GetTokens() (string, string, error) {
	access, err := auth.Access.Token()
	if err != nil {
		return "", "", err
	}

	refresh, err := auth.refresh.Token()
	if err != nil {
		return access, "", err
	}

	return access, refresh, nil
}

func (auth *AuthToken) Refresh() (string, error) {
	if auth.refresh == nil {
		return "", errors.New("not issued refresh token")
	}

	if auth.refresh.Expired() {
		return "", jwt.ErrTokenExpired
	}

	auth.Access = claims.New(auth.refresh.Subject, auth.refresh.Role, time.Now(), 10*time.Minute)
	return auth.Access.Token()
}
