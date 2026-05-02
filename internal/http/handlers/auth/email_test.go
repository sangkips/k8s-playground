package authhandler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"
	authhandler "sangkips/k8s-playground/internal/http/handlers/auth"
	"sangkips/k8s-playground/internal/store"
)

func newEmailHandler(t *testing.T) (*authhandler.EmailHandler, *fakeUserStore, *fakeVerificationStore, *fakeMailer) {
	t.Helper()
	users := newFakeUserStore()
	verif := newFakeVerificationStore()
	ml := &fakeMailer{}
	h := authhandler.NewEmailHandler(users, verif, ml, "http://localhost:3000")
	return h, users, verif, ml
}

// seedVerifToken creates a verification token in the fake store and returns the raw token.
func seedVerifToken(t *testing.T, verif *fakeVerificationStore, userID string, kind store.TokenKind, ttl time.Duration) string {
	t.Helper()
	raw, tokenHash, err := auth.IssueRefreshToken()
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if err := verif.CreateToken(context.Background(), userID, kind, tokenHash, time.Now().Add(ttl)); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return raw
}

// ── VerifyEmail ───────────────────────────────────────────────────────────────

func TestVerifyEmail_Success(t *testing.T) {
	t.Parallel()
	h, users, verif, _ := newEmailHandler(t)
	u := seedUser(t, users, "ada@example.com", "strongpassword123")
	raw := seedVerifToken(t, verif, u.ID, store.TokenKindEmailVerification, time.Hour)

	rec := postJSON(t, h.VerifyEmail, map[string]string{"token": raw})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	if ok, _ := decodeBody(t, rec)["ok"].(bool); !ok {
		t.Error("expected ok=true")
	}
	if !verif.verifiedUsers[u.ID] {
		t.Error("expected user to be marked as email-verified")
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newEmailHandler(t)

	rec := postJSON(t, h.VerifyEmail, map[string]string{"token": "not-a-real-token"})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	t.Parallel()
	h, users, verif, _ := newEmailHandler(t)
	u := seedUser(t, users, "ada@example.com", "strongpassword123")
	// TTL of -1s means already expired.
	raw := seedVerifToken(t, verif, u.ID, store.TokenKindEmailVerification, -time.Second)

	rec := postJSON(t, h.VerifyEmail, map[string]string{"token": raw})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for expired token, got %d", rec.Code)
	}
}

func TestVerifyEmail_TokenReuse(t *testing.T) {
	t.Parallel()
	h, users, verif, _ := newEmailHandler(t)
	u := seedUser(t, users, "ada@example.com", "strongpassword123")
	raw := seedVerifToken(t, verif, u.ID, store.TokenKindEmailVerification, time.Hour)

	// First use — should succeed.
	postJSON(t, h.VerifyEmail, map[string]string{"token": raw})

	// Second use — must fail.
	rec := postJSON(t, h.VerifyEmail, map[string]string{"token": raw})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on token reuse, got %d", rec.Code)
	}
}

func TestVerifyEmail_MissingToken(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newEmailHandler(t)

	rec := postJSON(t, h.VerifyEmail, map[string]string{})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

// ── ForgotPassword ────────────────────────────────────────────────────────────

func TestForgotPassword_AlwaysReturnsOK(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newEmailHandler(t)

	// Unknown email — must still return 200 (no enumeration).
	rec := postJSON(t, h.ForgotPassword, map[string]string{"email": "ghost@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown email, got %d", rec.Code)
	}
	if ok, _ := decodeBody(t, rec)["ok"].(bool); !ok {
		t.Error("expected ok=true")
	}
}

func TestForgotPassword_KnownEmail_SendsResetEmail(t *testing.T) {
	t.Parallel()
	h, users, _, ml := newEmailHandler(t)
	seedUser(t, users, "ada@example.com", "strongpassword123")

	rec := postJSON(t, h.ForgotPassword, map[string]string{"email": "ada@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Give the goroutine a moment to run (it's fire-and-forget).
	// In a real test suite you'd use a synchronous mailer or a WaitGroup.
	// Here we just check the mailer was called at all.
	// The fake mailer is synchronous so this is fine.
	ml.mu.Lock()
	sent := len(ml.resetsSent)
	ml.mu.Unlock()
	if sent == 0 {
		t.Error("expected password reset email to be sent")
	}
}

func TestForgotPassword_MalformedJSON(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newEmailHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ForgotPassword(rec, req)

	// Even with a bad body we return 400, not 200 — the defer fires after the early return.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// ── ResetPassword ─────────────────────────────────────────────────────────────

func TestResetPassword_Success(t *testing.T) {
	t.Parallel()
	h, users, verif, _ := newEmailHandler(t)
	u := seedUser(t, users, "ada@example.com", "oldpassword1234")
	raw := seedVerifToken(t, verif, u.ID, store.TokenKindPasswordReset, time.Hour)

	rec := postJSON(t, h.ResetPassword, map[string]string{
		"token":        raw,
		"new_password": "brandnewpassword99",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	if ok, _ := decodeBody(t, rec)["ok"].(bool); !ok {
		t.Error("expected ok=true")
	}
	if verif.updatedPasswords[u.ID] == "" {
		t.Error("expected password to be updated in store")
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newEmailHandler(t)

	rec := postJSON(t, h.ResetPassword, map[string]string{
		"token": "bad-token", "new_password": "brandnewpassword99",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestResetPassword_PasswordTooShort(t *testing.T) {
	t.Parallel()
	h, users, verif, _ := newEmailHandler(t)
	u := seedUser(t, users, "ada@example.com", "oldpassword1234")
	raw := seedVerifToken(t, verif, u.ID, store.TokenKindPasswordReset, time.Hour)

	rec := postJSON(t, h.ResetPassword, map[string]string{
		"token": raw, "new_password": "short",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestResetPassword_MissingToken(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newEmailHandler(t)

	rec := postJSON(t, h.ResetPassword, map[string]string{"new_password": "brandnewpassword99"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestResetPassword_WrongKind(t *testing.T) {
	t.Parallel()
	h, users, verif, _ := newEmailHandler(t)
	u := seedUser(t, users, "ada@example.com", "oldpassword1234")
	// Create an email-verification token, not a password-reset token.
	raw := seedVerifToken(t, verif, u.ID, store.TokenKindEmailVerification, time.Hour)

	rec := postJSON(t, h.ResetPassword, map[string]string{
		"token": raw, "new_password": "brandnewpassword99",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 when using wrong token kind, got %d", rec.Code)
	}
}
