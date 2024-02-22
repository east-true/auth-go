package claims_test

import (
	"testing"
	"time"

	. "github.com/east-true/auth-go/jwt/claims"
	"github.com/google/uuid"
)

var claims *Claims

func TestNew(t *testing.T) {
	idgen, _ := uuid.NewRandom()
	id := idgen.String()
	now := time.Now()
	dur := time.Duration(1 * time.Second)
	claims = New(id, "test", now, dur)
	if claims.Subject != id {
		t.Fail()
	}
}

func TestToken(t *testing.T) {
	token, err := claims.Token()
	if err != nil || token == "" {
		t.Fail()
	}
}

func TestVerify(t *testing.T) {
	token, err := claims.Token()
	if err != nil || token == "" {
		t.Fail()
	}

	if !claims.Verify(token) {
		t.Fail()
	}
}

func TestNotExpired(t *testing.T) {
	if claims.Expired() {
		t.Fail()
	}
}

func TestExpired(t *testing.T) {
	time.Sleep(3 * time.Second)
	if !claims.Expired() {
		t.Fail()
	}
}
