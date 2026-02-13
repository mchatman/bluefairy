package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// contextKey is an unexported type used for context keys to prevent collisions.
type contextKey int

const claimsKey contextKey = iota

// Middleware returns an HTTP middleware that extracts and verifies a JWT
// from the Authorization header ("Bearer <token>") or the "aware_token" cookie.
// On success, the decoded JWTClaims are stored in the request context and
// retrievable via GetClaims.
func Middleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenStr string

			// Try Authorization header first
			if auth := r.Header.Get("Authorization"); auth != "" {
				if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					writeAuthError(w, http.StatusUnauthorized, "auth/malformed_header", "Expected 'Bearer <token>'")
					return
				}
				tokenStr = auth[7:] // len("Bearer ") == 7
			}

			// Fall back to cookie
			if tokenStr == "" {
				if c, err := r.Cookie("aware_token"); err == nil {
					tokenStr = c.Value
				}
			}

			if tokenStr == "" {
				writeAuthError(w, http.StatusUnauthorized, "auth/missing_token", "Authorization header or aware_token cookie required")
				return
			}

			claims, err := VerifyAccessToken(secret, tokenStr)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "auth/invalid_token", "Token is invalid or expired")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims retrieves the JWTClaims from the request context.
// Returns nil if the middleware has not run or if there are no claims.
func GetClaims(ctx context.Context) *JWTClaims {
	claims, _ := ctx.Value(claimsKey).(*JWTClaims)
	return claims
}

func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
