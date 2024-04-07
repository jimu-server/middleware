package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/jimu-server/common/resp"
	"strings"
)

const Key = "Token"

func Authorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		respResult := resp.Error(resp.AuthorizationExpired, resp.Msg("身份验证失败"), resp.Code(resp.TokenErr))
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			// websocket 身份校验
			if tokenString = c.GetHeader("Sec-Websocket-Protocol"); tokenString == "" {
				c.AbortWithStatusJSON(500, resp.Error(resp.AuthorizationExpired, resp.Msg("身份验证失败")))
				return
			}
		}
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = tokenString[7:]
		}
		v, err := ParseToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(500, respResult)
			return
		}
		v.Value = tokenString
		c.Set(Key, v)
		c.Next()
	}
}
