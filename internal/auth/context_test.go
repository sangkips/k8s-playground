package auth_test

import (
	"context"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"

	"github.com/golang-jwt/jwt/v5"
)

func TestContextWithClaims_RoundTrip(t *testing.T) {
	t.Parallel()

	want := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-abc",
			Subject:   "user-xyz",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		UserID: "user-xyz",
		Role:   "learner",
		Email:  "ada@example.com",
	}

	ctx := auth.ContextWithClaims(context.Background(), want)
	got, ok := auth.ClaimsFromContext(ctx)

	if !ok {
		t.Fatal("expected claims in context, got none")
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID: got %s, want %s", got.UserID, want.UserID)
	}
	if got.Email != want.Email {
		t.Errorf("Email: got %s, want %s", got.Email, want.Email)
	}
	if got.Role != want.Role {
		t.Errorf("Role: got %s, want %s", got.Role, want.Role)
	}
}

func TestClaimsFromContext_MissingReturnsNotOk(t *testing.T) {
	t.Parallel()

	_, ok := auth.ClaimsFromContext(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context, got true")
	}
}
