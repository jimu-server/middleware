package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/jimu-server/common/resp"
	"slices"
	"strings"
)

// Key 从 gin.Context 中获取 Token 的key
const Key = "Token"

// Authorization 身份验证中间件
// 解析当前用户 id 和当前组织信息
// urls 配置在用户访问权限中需要过滤放行的 url 接口
func Authorization(urls ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		respResult := resp.Error(resp.AuthorizationExpired, resp.Msg("身份验证失败"), resp.Code(resp.TokenErr))
		tokenString := c.GetHeader("Authorization")
		orgId := c.GetHeader("Orgid")
		requestURI := c.Request.RequestURI
		if orgId == "" && !slices.Contains(urls, requestURI) {
			c.AbortWithStatusJSON(500, resp.Error(resp.AuthorizationExpired, resp.Msg("组织机构验证失败")))
		}
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
		v.OrgId = orgId
		c.Set(Key, v)
		c.Next()
	}
}
