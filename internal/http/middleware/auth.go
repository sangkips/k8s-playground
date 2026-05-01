package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"sangkips/k8s-playground/internal/auth"
)

// Authenticate is a middleware that validates the Bearer JWT and stores
// the parsed claims in the request context. Returns 401 on failure.
func Authenticate(tokens *auth.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeUnauthorized(w, "missing or malformed Authorization header")
				return
			}

			tokenStr := strings.TrimPrefix(header, "Bearer ")
			claims, err := tokens.ValidateAccessToken(r.Context(), tokenStr)
			if err != nil {
				writeUnauthorized(w, "invalid or expired token")
				return
			}

			ctx := auth.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
