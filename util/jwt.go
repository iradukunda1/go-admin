package util

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const secretKey = "secret"

func GenerateJwt(issuer string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer: issuer,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // 1 day
	})
	return claims.SignedString([]byte(secretKey))
}

func ParseJwt(cookie string) (string, error) {
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return "", err
	}
	Claims := token.Claims.(*jwt.StandardClaims)

	return Claims.Issuer, nil
}
