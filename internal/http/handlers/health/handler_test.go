package healthhandler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	healthhandler "sangkips/k8s-playground/internal/http/handlers/health"
)

func TestHealthz_ReturnsOK(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	healthhandler.Healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got == "" {
		t.Fatal("expected Content-Type header to be set")
	}
}

func TestHealthz_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(method, "/healthz", nil)
			rec := httptest.NewRecorder()

			healthhandler.Healthz(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 for %s, got %d", method, rec.Code)
			}
		})
	}
}
