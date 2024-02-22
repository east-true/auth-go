package jwt

import (
	"net/http"
	"strings"

	"github.com/east-true/auth-go/jwt/claims"
	"github.com/gin-gonic/gin"
)

var AnonymousUrls map[string]bool = map[string]bool{
	"/api/login": true,
}

func JwtVerify(ctx *gin.Context) {
	if _, ok := AnonymousUrls[ctx.Request.RequestURI]; ok {
		ctx.Next()
	}

	auth := ctx.Request.Header.Get("authorization")
	if strings.HasPrefix(auth, "Bearer") {
		token := strings.Split(auth, " ")[1]
		claim := new(claims.Claims)
		if claim.Verify(token) {
			ctx.Set("claim", claim)
			return
		}
	}

	ctx.AbortWithStatus(http.StatusForbidden)
}
