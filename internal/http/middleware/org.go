package middleware

import (
	"context"
	"net/http"
)

type orgContextKey string

const orgIDKey orgContextKey = "org_id"

// OrgID injects the {orgId} path value into the request context so handlers
// don't need to call r.PathValue repeatedly.
func OrgID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("orgId")
		ctx := context.WithValue(r.Context(), orgIDKey, orgID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OrgIDFromContext retrieves the org id stored by the OrgID middleware.
func OrgIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(orgIDKey).(string)
	return v
}
