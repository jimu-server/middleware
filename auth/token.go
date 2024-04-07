package auth

import "github.com/golang-jwt/jwt"

type Token struct {
	jwt.StandardClaims
	Id    string
	Value string
}
