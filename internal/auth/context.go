package auth

import "context"

type contextKey string

const ClaimsContextKey contextKey = "auth_claims"

// ContextWithClaims stores claims in the context.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ClaimsContextKey, c)
}

// ClaimsFromContext retrieves JWT claims from the context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return c, ok
}
