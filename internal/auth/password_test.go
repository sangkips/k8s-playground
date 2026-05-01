package auth_test

import (
	"strings"
	"testing"

	"sangkips/k8s-playground/internal/auth"
)

func TestHashPassword_ProducesValidBcryptHash(t *testing.T) {
	t.Parallel()

	hash, err := auth.HashPassword("supersecretpassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Fatalf("expected bcrypt hash, got: %s", hash)
	}
}

func TestHashPassword_DifferentCallsProduceDifferentHashes(t *testing.T) {
	t.Parallel()

	h1, _ := auth.HashPassword("samepassword123")
	h2, _ := auth.HashPassword("samepassword123")
	if h1 == h2 {
		t.Fatal("expected different hashes due to random salt, got identical hashes")
	}
}

func TestCheckPassword_CorrectPassword(t *testing.T) {
	t.Parallel()

	hash, _ := auth.HashPassword("correcthorsebatterystaple")
	if err := auth.CheckPassword(hash, "correcthorsebatterystaple"); err != nil {
		t.Fatalf("expected nil error for correct password, got: %v", err)
	}
}

func TestCheckPassword_WrongPassword(t *testing.T) {
	t.Parallel()

	hash, _ := auth.HashPassword("correcthorsebatterystaple")
	if err := auth.CheckPassword(hash, "wrongpassword"); err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestCheckPassword_EmptyPassword(t *testing.T) {
	t.Parallel()

	hash, _ := auth.HashPassword("somepassword123")
	if err := auth.CheckPassword(hash, ""); err == nil {
		t.Fatal("expected error for empty password, got nil")
	}
}
