package token_manager

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

/*

Token Manager JWT

A helper so I don't bother ever again coding it again

*/

var JWT_SIGNING_METHOD = jwt.SigningMethodHS256

type TokenManager struct {
	secretKey []byte
}

func NewTokenManager(secretKey string) *TokenManager {
	return &TokenManager{secretKey: []byte(secretKey)}
}

func (tm *TokenManager) GenerateToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(JWT_SIGNING_METHOD, claims)
	return token.SignedString(tm.secretKey)
}

func (tm *TokenManager) MakeClaim(user_id int, minutes int64) jwt.MapClaims {
	timeout := time.Duration(minutes)
	claims := jwt.MapClaims{
		"user_id": user_id,
		"exp":     time.Now().Add(time.Minute * timeout).Unix(),
	}
	return claims
}

func (tm *TokenManager) VerifyToken(tokenString string) (jwt.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return tm.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("Token validation failed.")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Unable to parse Token Claims.")
	}

	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Now().After(expirationTime) {
		return nil, errors.New("Token has been expired.")
	}

	return claims, nil
}

func (tm *TokenManager) VerifyJWT(endpointHandler func(writer http.ResponseWriter, request *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header["Token"] != nil {
			tokenString := request.Header["Token"][0]
			verifiedClaims, err := tm.VerifyToken(tokenString)
			if err != nil {
				writer.WriteHeader(http.StatusUnauthorized)
				_, err := writer.Write([]byte("You're Unauthorized due to error parsing the JWT"))
				if err != nil {
					return
				}
			}

			if verifiedClaims != nil {
				endpointHandler(writer, request)
			} else {
				writer.WriteHeader(http.StatusUnauthorized)
				_, err := writer.Write([]byte("You're Unauthorized due to invalid token"))
				if err != nil {
					return
				}
			}

		} else {
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("You're Unauthorized due to No token in the header"))
			if err != nil {
				return
			}
		}
	})
}

func (tm *TokenManager) JWTHandler(next http.Handler) http.Handler {
	return tm.VerifyJWT(next.ServeHTTP)
}
