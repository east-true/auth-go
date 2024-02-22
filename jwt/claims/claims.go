package claims

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var secret []byte

func init() {
	idgen, _ := uuid.NewRandom()
	id := idgen.String()
	secret = []byte(id)
}

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func New(uuid, role string, now time.Time, dur time.Duration) *Claims {
	return &Claims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(dur)),
		},
	}
}

func (c *Claims) Token() (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString(secret)
}

func (c *Claims) Verify(token string) bool {
	jwtToken, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); ok {
			return secret, nil
		}

		return nil, jwt.ErrInvalidKeyType
	})
	if err != nil {
		return false
	}

	return jwtToken.Valid
}

func (c *Claims) Expired() bool {
	return c.ExpiresAt.Time.Before(time.Now())
}

func (c *Claims) Store() error {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	conn := rdb.Conn()
	defer conn.Close()

	ctx := context.Background()
	token, err := c.Token()
	if err != nil {
		fmt.Println(err)
	}

	err = conn.Set(ctx, c.Subject, token, c.ExpiresAt.Sub(time.Now())).Err()
	if err != nil {
		return err
	}

	return nil
}
