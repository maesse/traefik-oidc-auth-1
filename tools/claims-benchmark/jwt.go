package claimbench

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	benchmarkIssuer   = "https://auth.example.test/application/o/traefik/"
	benchmarkAudience = "traefik"
)

var (
	benchmarkJWTOnce      sync.Once
	benchmarkJWTError     error
	benchmarkJWTString    string
	benchmarkJWTPublicKey *rsa.PublicKey
)

func prepareBenchmarkJWT() error {
	benchmarkJWTOnce.Do(func() {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			benchmarkJWTError = err
			return
		}

		claims := jwt.MapClaims{
			"iss":                benchmarkIssuer,
			"sub":                benchmarkClaims["sub"],
			"aud":                benchmarkAudience,
			"exp":                time.Now().Add(time.Hour).Unix(),
			"iat":                time.Now().Unix(),
			"email":              benchmarkClaims["email"],
			"email_verified":     benchmarkClaims["email_verified"],
			"preferred_username": benchmarkClaims["preferred_username"],
			"name":               benchmarkClaims["name"],
			"groups":             benchmarkClaims["groups"],
		}

		benchmarkJWTString, err = jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		if err != nil {
			benchmarkJWTError = err
			return
		}
		benchmarkJWTPublicKey = &privateKey.PublicKey
	})
	return benchmarkJWTError
}

func validateBenchmarkJWT() (map[string]interface{}, error) {
	if benchmarkJWTString == "" || benchmarkJWTPublicKey == nil {
		return nil, errors.New("benchmark JWT is not initialized")
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(benchmarkIssuer),
		jwt.WithAudience(benchmarkAudience),
	)
	_, err := parser.ParseWithClaims(benchmarkJWTString, claims, func(_ *jwt.Token) (interface{}, error) {
		return benchmarkJWTPublicKey, nil
	})
	return claims, err
}
