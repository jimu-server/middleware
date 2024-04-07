package auth

import (
	"github.com/golang-jwt/jwt"
	"github.com/jimu-server/config"
	"github.com/jimu-server/model"
	"time"
)

func CreateToken(account model.User) (string, error) {
	s := time.Now().Format(time.DateTime)
	// 设置token10天过期
	parse, err := time.Parse(time.DateTime, time.Now().Add(time.Duration(10*24*60*60)*time.Second).Format(time.DateTime))
	if err != nil {
		return "", err
	}
	claims := jwt.NewWithClaims(jwt.SigningMethodHS512, Token{
		StandardClaims: jwt.StandardClaims{
			Issuer:    s,
			ExpiresAt: parse.Unix(),
		},
		Id: account.Id,
	})

	key := []byte(config.Evn.App.Key)
	tokenString := ""
	if tokenString, err = claims.SignedString(key); err != nil {
		return "", err
	}
	return tokenString, nil
}

func ParseToken(tokenString string) (*Token, error) {
	data := &Token{}
	_, err := jwt.ParseWithClaims(tokenString, data, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return []byte(config.Evn.App.Key), nil
		}
		return []byte(config.Evn.App.Key), nil
	})
	if err != nil {
		return nil, err
	}
	return data, err
}
