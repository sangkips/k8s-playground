package authhandler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"
	authhandler "sangkips/k8s-playground/internal/http/handlers/auth"
	"sangkips/k8s-playground/internal/store"

	"github.com/redis/go-redis/v9"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTokenService(t *testing.T) *auth.TokenService {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	t.Cleanup(func() { _ = rdb.Close() })
	return auth.NewTokenService("handler-test-secret", 15*time.Minute, 7*24*time.Hour, rdb)
}

func newHandler(t *testing.T) (*authhandler.Handler, *fakeUserStore, *fakeSessionStore, *auth.TokenService) {
	t.Helper()
	users := newFakeUserStore()
	sessions := newFakeSessionStore()
	tokens := newTokenService(t)
	return authhandler.NewHandler(users, sessions, tokens), users, sessions, tokens
}

func postJSON(t *testing.T, fn http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&m); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return m
}

// seedUser inserts a user directly into the fake store, bypassing HTTP.
func seedUser(t *testing.T, users *fakeUserStore, email, password string) store.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u, err := users.Create(context.Background(), email, hash, "Test User")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// ── Register ──────────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Register, map[string]string{
		"email":        "ada@example.com",
		"password":     "strongpassword123",
		"display_name": "Ada Lovelace",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)

	for _, key := range []string{"access_token", "refresh_token", "expires_in", "user"} {
		if _, ok := body[key]; !ok {
			t.Errorf("expected %q in response", key)
		}
	}

	user, _ := body["user"].(map[string]any)
	if user["email"] != "ada@example.com" {
		t.Errorf("user.email: got %v, want ada@example.com", user["email"])
	}
	if user["role"] != "learner" {
		t.Errorf("user.role: got %v, want learner", user["role"])
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	t.Parallel()
	h, users, _, _ := newHandler(t)
	seedUser(t, users, "ada@example.com", "strongpassword123")

	rec := postJSON(t, h.Register, map[string]string{
		"email":        "ada@example.com",
		"password":     "anotherpassword456",
		"display_name": "Ada Again",
	})

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Register, map[string]string{
		"email":        "not-an-email",
		"password":     "strongpassword123",
		"display_name": "Ada Lovelace",
	})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestRegister_PasswordTooShort(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Register, map[string]string{
		"email":        "ada@example.com",
		"password":     "tooshort",
		"display_name": "Ada Lovelace",
	})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestRegister_MissingDisplayName(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Register, map[string]string{
		"email":    "ada@example.com",
		"password": "strongpassword123",
	})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestRegister_MalformedJSON(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// ── Login ─────────────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	t.Parallel()
	h, users, _, _ := newHandler(t)
	seedUser(t, users, "ada@example.com", "correctpassword123")

	rec := postJSON(t, h.Login, map[string]string{
		"email":    "ada@example.com",
		"password": "correctpassword123",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	for _, key := range []string{"access_token", "refresh_token", "expires_in"} {
		if _, ok := body[key]; !ok {
			t.Errorf("expected %q in response", key)
		}
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	t.Parallel()
	h, users, _, _ := newHandler(t)
	seedUser(t, users, "ada@example.com", "correctpassword123")

	rec := postJSON(t, h.Login, map[string]string{
		"email":    "ada@example.com",
		"password": "wrongpassword",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Login, map[string]string{
		"email":    "nobody@example.com",
		"password": "somepassword123",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestLogin_EmailNormalized(t *testing.T) {
	t.Parallel()
	h, users, _, _ := newHandler(t)
	seedUser(t, users, "ada@example.com", "correctpassword123")

	// Mixed-case email should match the lowercase-stored record.
	rec := postJSON(t, h.Login, map[string]string{
		"email":    "ADA@EXAMPLE.COM",
		"password": "correctpassword123",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for case-insensitive email, got %d", rec.Code)
	}
}

func TestLogin_MalformedJSON(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// ── Refresh ───────────────────────────────────────────────────────────────────

func TestRefresh_Success(t *testing.T) {
	t.Parallel()
	h, users, _, _ := newHandler(t)
	seedUser(t, users, "ada@example.com", "correctpassword123")

	loginRec := postJSON(t, h.Login, map[string]string{
		"email":    "ada@example.com",
		"password": "correctpassword123",
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d — %s", loginRec.Code, loginRec.Body)
	}
	refreshToken, _ := decodeBody(t, loginRec)["refresh_token"].(string)

	rec := postJSON(t, h.Refresh, map[string]string{"refresh_token": refreshToken})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	for _, key := range []string{"access_token", "expires_in"} {
		if _, ok := body[key]; !ok {
			t.Errorf("expected %q in refresh response", key)
		}
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Refresh, map[string]string{"refresh_token": "totally-invalid-token"})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRefresh_MissingToken(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	rec := postJSON(t, h.Refresh, map[string]string{})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestRefresh_TokenRotation(t *testing.T) {
	t.Parallel()
	h, users, _, _ := newHandler(t)
	seedUser(t, users, "ada@example.com", "correctpassword123")

	loginRec := postJSON(t, h.Login, map[string]string{
		"email":    "ada@example.com",
		"password": "correctpassword123",
	})
	firstToken, _ := decodeBody(t, loginRec)["refresh_token"].(string)

	// First use — should succeed.
	postJSON(t, h.Refresh, map[string]string{"refresh_token": firstToken})

	// Second use of the same token — must be rejected.
	rec := postJSON(t, h.Refresh, map[string]string{"refresh_token": firstToken})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on reuse of rotated token, got %d", rec.Code)
	}
}

// ── Logout ────────────────────────────────────────────────────────────────────

func TestLogout_WithoutToken_Returns401(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	// No claims in context — middleware not applied — must return 401.
	h.Logout(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestLogout_WithValidToken_ReturnsOK(t *testing.T) {
	t.Parallel()

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available, skipping logout denylist test")
	}

	users := newFakeUserStore()
	sessions := newFakeSessionStore()
	tokens := auth.NewTokenService("logout-test-secret", 15*time.Minute, 7*24*time.Hour, rdb)
	h := authhandler.NewHandler(users, sessions, tokens)

	seedUser(t, users, "ada@example.com", "correctpassword123")

	loginRec := postJSON(t, h.Login, map[string]string{
		"email":    "ada@example.com",
		"password": "correctpassword123",
	})
	accessToken, _ := decodeBody(t, loginRec)["access_token"].(string)

	// Simulate auth middleware: parse claims and inject into context.
	claims, err := tokens.ValidateAccessToken(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	ctx := auth.ContextWithClaims(context.Background(), claims)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	if ok, _ := decodeBody(t, rec)["ok"].(bool); !ok {
		t.Error("expected ok=true in response")
	}

	// Token must now be on the denylist.
	_, err = tokens.ValidateAccessToken(context.Background(), accessToken)
	if err == nil {
		t.Fatal("expected token to be revoked after logout, but validation succeeded")
	}
}
