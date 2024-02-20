package claims

import (
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var secret []byte = []byte("secret")

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func New(id, sub, iss, role string) *Claims {
	return &Claims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 30)),
		},
	}
}

func (c *Claims) NewToken() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signedToken, err := token.SignedString(secret)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	return signedToken
}

func (c *Claims) Verify(token string) bool {
	jwtToken, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); ok {
			return []byte(secret), nil
		}

		exp, err := t.Claims.GetExpirationTime()
		if err != nil {
			return nil, jwt.ErrTokenInvalidClaims
		}

		if exp.After(time.Now()) {
			return nil, jwt.ErrTokenExpired
		}

		return nil, jwt.ErrInvalidKeyType
	})

	if err != nil {
		fmt.Println(err)
		return false
	}

	claims := jwtToken.Claims.(*Claims)
	c.Role = claims.Role
	c.RegisteredClaims = claims.RegisteredClaims
	return jwtToken.Valid
}
