package auth_test

import (
	"context"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"

	"github.com/redis/go-redis/v9"
)

// newTestTokenService creates a TokenService backed by a real miniredis-free
// in-process Redis client. We use redis.NewClient pointed at a non-existent
// server and override only the denylist path via a mock — but for unit tests
// that don't exercise the denylist we can use a real local Redis or skip.
//
// To keep tests self-contained without requiring a running Redis, we use the
// go-redis ring client with a single shard that never connects; denylist
// checks are only exercised in tests that explicitly call DenyToken.
func newTestTokenService(t *testing.T) *auth.TokenService {
	t.Helper()
	// Use a real Redis client pointed at localhost. Tests that need the
	// denylist will fail gracefully if Redis is unavailable; pure JWT
	// tests don't touch Redis at all.
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	t.Cleanup(func() { _ = rdb.Close() })
	return auth.NewTokenService("test-secret-key-for-unit-tests", 15*time.Minute, 7*24*time.Hour, rdb)
}

func TestIssueAccessToken_ReturnsValidToken(t *testing.T) {
	t.Parallel()
	svc := newTestTokenService(t)

	tokenStr, jti, expiresAt, err := svc.IssueAccessToken("user-123", "ada@example.com", "learner")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}
	if jti == "" {
		t.Fatal("expected non-empty jti")
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("expected expiresAt to be in the future")
	}
}

func TestValidateAccessToken_ValidToken(t *testing.T) {
	t.Parallel()
	svc := newTestTokenService(t)

	tokenStr, _, _, err := svc.IssueAccessToken("user-123", "ada@example.com", "learner")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims, err := svc.ValidateAccessToken(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Errorf("expected UserID=user-123, got %s", claims.UserID)
	}
	if claims.Email != "ada@example.com" {
		t.Errorf("expected email=ada@example.com, got %s", claims.Email)
	}
	if claims.Role != "learner" {
		t.Errorf("expected role=learner, got %s", claims.Role)
	}
}

func TestValidateAccessToken_TamperedToken(t *testing.T) {
	t.Parallel()
	svc := newTestTokenService(t)

	tokenStr, _, _, _ := svc.IssueAccessToken("user-123", "ada@example.com", "learner")
	tampered := tokenStr + "x"

	_, err := svc.ValidateAccessToken(context.Background(), tampered)
	if err == nil {
		t.Fatal("expected error for tampered token, got nil")
	}
}

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	t.Parallel()

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()

	svcA := auth.NewTokenService("secret-A", 15*time.Minute, 7*24*time.Hour, rdb)
	svcB := auth.NewTokenService("secret-B", 15*time.Minute, 7*24*time.Hour, rdb)

	tokenStr, _, _, _ := svcA.IssueAccessToken("user-123", "ada@example.com", "learner")

	_, err := svcB.ValidateAccessToken(context.Background(), tokenStr)
	if err == nil {
		t.Fatal("expected error when validating with wrong secret, got nil")
	}
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	t.Parallel()

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()

	// TTL of -1 second means the token is already expired when issued.
	svc := auth.NewTokenService("test-secret", -time.Second, 7*24*time.Hour, rdb)

	tokenStr, _, _, _ := svc.IssueAccessToken("user-123", "ada@example.com", "learner")

	_, err := svc.ValidateAccessToken(context.Background(), tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestAccessTokenTTLSeconds(t *testing.T) {
	t.Parallel()
	svc := newTestTokenService(t)

	if got := svc.AccessTokenTTLSeconds(); got != 900 {
		t.Errorf("expected 900 seconds (15 min), got %d", got)
	}
}

func TestIssueRefreshToken_UniqueAndHashable(t *testing.T) {
	t.Parallel()

	raw1, hash1, err := auth.IssueRefreshToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw2, hash2, _ := auth.IssueRefreshToken()

	if raw1 == raw2 {
		t.Fatal("expected unique refresh tokens, got identical")
	}
	if hash1 == hash2 {
		t.Fatal("expected unique hashes, got identical")
	}

	// HashRefreshToken must be deterministic.
	if got := auth.HashRefreshToken(raw1); got != hash1 {
		t.Errorf("HashRefreshToken(%s) = %s, want %s", raw1, got, hash1)
	}
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
	t.Parallel()

	raw := "aaabbbccc000111"
	h1 := auth.HashRefreshToken(raw)
	h2 := auth.HashRefreshToken(raw)
	if h1 != h2 {
		t.Errorf("expected deterministic hash, got %s and %s", h1, h2)
	}
}
