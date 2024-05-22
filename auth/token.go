package auth

import "github.com/golang-jwt/jwt"

type Token struct {
	jwt.StandardClaims
	// 当前用户id
	Id string
	// token
	Value string
	// 当前用户所属机构id
	OrgId string
}
