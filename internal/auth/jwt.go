// Package auth provides JWT token handling, password hashing, middleware,
// and HTTP route handlers for the Aware Platform authentication system.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer    = "wareit.ai"
	algorithm = "HS256"
)

// JWTClaims represents the claims embedded in an Aware access token.
type JWTClaims struct {
	Email string `json:"email"`
	Tier  string `json:"tier"`
	jwt.RegisteredClaims
}

// TokenPair holds an access token and its expiration time.
type TokenPair struct {
	AccessToken string
	ExpiresAt   time.Time
}

// SignAccessToken creates a signed HS256 JWT for the given user.
// The token includes email and tier as custom claims, and sub/iss/iat/exp
// as registered claims. This matches the TypeScript implementation exactly.
func SignAccessToken(secret string, sub, email, tier string, ttl time.Duration) (*TokenPair, error) {
	now := time.Now()
	exp := now.Add(ttl)

	claims := JWTClaims{
		Email: email,
		Tier:  tier,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	return &TokenPair{
		AccessToken: signed,
		ExpiresAt:   exp,
	}, nil
}

// VerifyAccessToken parses and validates a JWT access token.
// Returns the claims if the token is valid, or an error if it is expired,
// malformed, or has an invalid signature.
func VerifyAccessToken(secret string, tokenStr string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithIssuer(issuer))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// GenerateOpaqueToken creates a cryptographically random 32-byte token,
// returned as a 64-character hex string. Used for refresh tokens and
// gateway tokens.
func GenerateOpaqueToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// SHA256Hash returns the hex-encoded SHA-256 digest of the input string.
// Used for storing refresh token hashes in the database.
func SHA256Hash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}
