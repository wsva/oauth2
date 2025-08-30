package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	wl_net "github.com/wsva/lib_go/net"
	wl_uuid "github.com/wsva/lib_go/uuid"

	"github.com/golang-jwt/jwt/v5"
)

func NewClaims(sub, aud string) jwt.Claims {
	return &jwt.RegisteredClaims{
		Issuer:    "wsva_oauth2",
		Subject:   sub,
		Audience:  jwt.ClaimStrings{aud},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        wl_uuid.New(),
	}
}

func GenerateToken(key *rsa.PrivateKey, claims jwt.Claims) (string, string, error) {
	jwtToken := jwt.Token{
		Method: &jwt.SigningMethodRSA{Name: "RS256", Hash: crypto.SHA256},
		Header: map[string]any{
			"typ": "JWT",
			"alg": "RS256", // Auth.js needs RS256
		},
		Claims: claims,
	}

	access, err := jwtToken.SignedString(key)
	if err != nil {
		return "", "", err
	}

	refresh := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
	refresh = base64.URLEncoding.EncodeToString([]byte(refresh))
	refresh = strings.ToUpper(strings.TrimRight(refresh, "="))

	return access, refresh, nil
}

type AuthInfo struct {
	Authorized bool
	Name       string
	Email      string
	Token      *Token
}

func CheckAuthorization(r *http.Request, check_ip bool) *AuthInfo {
	tokenString, err := ParseTokenFromRequest(r)
	if err != nil {
		return &AuthInfo{Authorized: false}
	}
	dt, name, err := VerifyAccessToken(tokenString)
	if err != nil {
		return &AuthInfo{Authorized: false}
	}
	if check_ip && dt.IP != wl_net.GetIPFromRequest(r).String() {
		return &AuthInfo{Authorized: false}
	}
	return &AuthInfo{
		Authorized: true,
		Name:       name,
		Email:      dt.UserID,
		Token:      dt,
	}
}

func VerifyAccessToken(access_token string) (*Token, string, error) {
	token, err := jwt.Parse(access_token, func(t *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, "", err
	}
	if !token.Valid {
		return nil, "", errors.New("invalid token")
	}
	dt := &Token{AccessToken: access_token}
	return dt.DBQuery(dbConfig)
}

func SetCookieToken(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  time.Now().Add(7 * 24 * time.Hour), // longer expiration
	})
}

func DeleteCookieToken(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // this deletes the cookie
	})
}

func ParseTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("access_token")
	if err == nil {
		return cookie.Value, nil
	}
	token := r.Header.Get("Authorization")
	if len(token) > 6 && strings.ToUpper(token[0:7]) == "BEARER " {
		return token[7:], nil
	}
	return "", errors.New("no token found")
}
