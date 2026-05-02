package authhandler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authhandler "sangkips/k8s-playground/internal/http/handlers/auth"
)

func newOAuthHandler(t *testing.T) (*authhandler.OAuthHandler, *fakeOAuthStateStore) {
	t.Helper()
	states := newFakeOAuthStateStore()
	h := authhandler.NewOAuthHandler(states, "gh-client-id", "gh-client-secret", "gg-client-id", "gg-client-secret")
	return h, states
}

// postJSONWithPathValue builds a request with a path value set (Go 1.22+).
func postJSONWithPathValue(t *testing.T, fn http.HandlerFunc, provider string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/"+provider, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", provider)
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

// ── OAuthStart ────────────────────────────────────────────────────────────────

func TestOAuthStart_GitHub_ReturnsAuthorizationURL(t *testing.T) {
	t.Parallel()
	h, states := newOAuthHandler(t)

	rec := postJSONWithPathValue(t, h.OAuthStart, "github", map[string]string{
		"redirect_uri": "https://app.example.com/oauth/callback",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}

	body := decodeBody(t, rec)
	authURL, ok := body["authorization_url"].(string)
	if !ok || authURL == "" {
		t.Fatal("expected non-empty authorization_url in response")
	}
	if !strings.Contains(authURL, "github.com") {
		t.Errorf("expected GitHub authorization URL, got: %s", authURL)
	}
	if !strings.Contains(authURL, "state=") {
		t.Error("expected state param in authorization URL")
	}

	// State must have been persisted.
	if len(states.states) != 1 {
		t.Errorf("expected 1 state stored, got %d", len(states.states))
	}
}

func TestOAuthStart_Google_ReturnsAuthorizationURL(t *testing.T) {
	t.Parallel()
	h, _ := newOAuthHandler(t)

	rec := postJSONWithPathValue(t, h.OAuthStart, "google", map[string]string{
		"redirect_uri": "https://app.example.com/oauth/callback",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	authURL, _ := decodeBody(t, rec)["authorization_url"].(string)
	if !strings.Contains(authURL, "google") && !strings.Contains(authURL, "accounts.google.com") {
		t.Errorf("expected Google authorization URL, got: %s", authURL)
	}
}

func TestOAuthStart_UnknownProvider_Returns400(t *testing.T) {
	t.Parallel()
	h, _ := newOAuthHandler(t)

	rec := postJSONWithPathValue(t, h.OAuthStart, "twitter", map[string]string{
		"redirect_uri": "https://app.example.com/oauth/callback",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown provider, got %d", rec.Code)
	}
}

func TestOAuthStart_MissingRedirectURI_Returns422(t *testing.T) {
	t.Parallel()
	h, _ := newOAuthHandler(t)

	rec := postJSONWithPathValue(t, h.OAuthStart, "github", map[string]string{})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestOAuthStart_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()
	h, _ := newOAuthHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/github", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("provider", "github")
	rec := httptest.NewRecorder()
	h.OAuthStart(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestOAuthStart_EachCallGeneratesUniqueState(t *testing.T) {
	t.Parallel()
	h, states := newOAuthHandler(t)

	postJSONWithPathValue(t, h.OAuthStart, "github", map[string]string{
		"redirect_uri": "https://app.example.com/callback",
	})
	postJSONWithPathValue(t, h.OAuthStart, "github", map[string]string{
		"redirect_uri": "https://app.example.com/callback",
	})

	if len(states.states) != 2 {
		t.Errorf("expected 2 unique states, got %d", len(states.states))
	}
}
