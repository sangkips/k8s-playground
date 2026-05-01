package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/http/middleware"

	"github.com/redis/go-redis/v9"
)

func newTokenSvc(t *testing.T) *auth.TokenService {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	t.Cleanup(func() { _ = rdb.Close() })
	return auth.NewTokenService("middleware-test-secret", 15*time.Minute, 7*24*time.Hour, rdb)
}

// okHandler is a simple next handler that records whether it was called.
func okHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthenticate_MissingHeader_Returns401(t *testing.T) {
	t.Parallel()
	svc := newTokenSvc(t)
	called := false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	middleware.Authenticate(svc)(okHandler(&called)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("next handler should not have been called")
	}
}

func TestAuthenticate_MalformedHeader_Returns401(t *testing.T) {
	t.Parallel()
	svc := newTokenSvc(t)
	called := false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc123") // wrong scheme
	rec := httptest.NewRecorder()

	middleware.Authenticate(svc)(okHandler(&called)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("next handler should not have been called")
	}
}

func TestAuthenticate_InvalidToken_Returns401(t *testing.T) {
	t.Parallel()
	svc := newTokenSvc(t)
	called := false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()

	middleware.Authenticate(svc)(okHandler(&called)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("next handler should not have been called")
	}
}

func TestAuthenticate_ValidToken_CallsNext(t *testing.T) {
	t.Parallel()
	svc := newTokenSvc(t)
	called := false

	tokenStr, _, _, err := svc.IssueAccessToken("user-1", "ada@example.com", "learner")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	middleware.Authenticate(svc)(okHandler(&called)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestAuthenticate_ValidToken_StoresClaimsInContext(t *testing.T) {
	t.Parallel()
	svc := newTokenSvc(t)

	tokenStr, _, _, err := svc.IssueAccessToken("user-42", "ada@example.com", "instructor")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	var gotClaims *auth.Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in context, got none")
			return
		}
		gotClaims = c
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	middleware.Authenticate(svc)(next).ServeHTTP(rec, req)

	if gotClaims == nil {
		t.Fatal("claims were nil after middleware")
	}
	if gotClaims.UserID != "user-42" {
		t.Errorf("expected UserID=user-42, got %s", gotClaims.UserID)
	}
	if gotClaims.Role != "instructor" {
		t.Errorf("expected role=instructor, got %s", gotClaims.Role)
	}
}

func TestAuthenticate_TokenSignedWithDifferentSecret_Returns401(t *testing.T) {
	t.Parallel()

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()

	svcA := auth.NewTokenService("secret-A", 15*time.Minute, 7*24*time.Hour, rdb)
	svcB := auth.NewTokenService("secret-B", 15*time.Minute, 7*24*time.Hour, rdb)

	tokenStr, _, _, _ := svcA.IssueAccessToken("user-1", "ada@example.com", "learner")

	called := false
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	middleware.Authenticate(svcB)(okHandler(&called)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong-secret token, got %d", rec.Code)
	}
	if called {
		t.Fatal("next handler should not have been called")
	}
}
