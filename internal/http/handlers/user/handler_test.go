package userhandler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"
	userhandler "sangkips/k8s-playground/internal/http/handlers/user"
	"sangkips/k8s-playground/internal/store"

	"github.com/golang-jwt/jwt/v5"
)

// ── helpers ───────────────────────────────────────────────────────────────────

const appBaseURL = "https://platform.example.com"

func newHandler(t *testing.T) (*userhandler.Handler, *fakeProfileStore) {
	t.Helper()
	ps := newFakeProfileStore()
	return userhandler.NewHandler(ps, appBaseURL), ps
}

// ctxWithClaims injects JWT claims into a request context, simulating the
// auth middleware.
func ctxWithClaims(userID, role string) context.Context {
	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-test",
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		UserID: userID,
		Role:   role,
		Email:  userID + "@example.com",
	}
	return auth.ContextWithClaims(context.Background(), claims)
}

func getWithCtx(t *testing.T, fn http.HandlerFunc, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func patchWithCtx(t *testing.T, fn http.HandlerFunc, ctx context.Context, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(b)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&m); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return m
}

// defaultProfile returns a seeded profile for use across tests.
func defaultProfile(userID string) store.UserProfile {
	return store.UserProfile{
		ID:          userID,
		Email:       userID + "@example.com",
		DisplayName: "Ada Lovelace",
		AvatarURL:   "https://example.com/avatar.png",
		Timezone:    "UTC",
		Role:        "learner",
		Plan:        "pro",
		CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Orgs: []store.UserOrg{
			{ID: "org-1", Name: "Acme", Role: "member"},
		},
	}
}

// ── GET /users/me ─────────────────────────────────────────────────────────────

func TestGetMe_Success(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-1"))

	rec := getWithCtx(t, h.GetMe, ctxWithClaims("user-1", "learner"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)

	if body["id"] != "user-1" {
		t.Errorf("id: got %v, want user-1", body["id"])
	}
	if body["plan"] != "pro" {
		t.Errorf("plan: got %v, want pro", body["plan"])
	}
	orgs, _ := body["orgs"].([]any)
	if len(orgs) != 1 {
		t.Errorf("orgs: got %d, want 1", len(orgs))
	}
}

func TestGetMe_NoAuth_Returns401(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil) // no claims in context
	rec := httptest.NewRecorder()
	h.GetMe(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestGetMe_UserNotFound_Returns404(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t) // empty store

	rec := getWithCtx(t, h.GetMe, ctxWithClaims("ghost-user", "learner"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// ── PATCH /users/me ───────────────────────────────────────────────────────────

func TestPatchMe_Success(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-1"))

	newName := "Ada King"
	rec := patchWithCtx(t, h.PatchMe, ctxWithClaims("user-1", "learner"), map[string]any{
		"display_name": newName,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["display_name"] != newName {
		t.Errorf("display_name: got %v, want %s", body["display_name"], newName)
	}
	if _, ok := body["updated_at"]; !ok {
		t.Error("expected updated_at in response")
	}
}

func TestPatchMe_NoFieldsIsNoOp(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-1"))

	rec := patchWithCtx(t, h.PatchMe, ctxWithClaims("user-1", "learner"), map[string]any{})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for no-op patch, got %d", rec.Code)
	}
}

func TestPatchMe_MultipleFields(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-1"))

	rec := patchWithCtx(t, h.PatchMe, ctxWithClaims("user-1", "learner"), map[string]any{
		"display_name": "New Name",
		"timezone":     "Africa/Nairobi",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// Verify the store was updated.
	updated, _ := ps.GetProfile(context.Background(), "user-1")
	if updated.Timezone != "Africa/Nairobi" {
		t.Errorf("timezone not updated: got %s", updated.Timezone)
	}
}

func TestPatchMe_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-1"))

	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("{bad")).
		WithContext(ctxWithClaims("user-1", "learner"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.PatchMe(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestPatchMe_NoAuth_Returns401(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.PatchMe(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ── GET /users/me/progress ────────────────────────────────────────────────────

func TestGetProgress_Success(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	completed := time.Now()
	ps.seedProgress("user-1", []store.EnrollmentProgress{
		{
			TrackID:       "track-1",
			TrackTitle:    "Docker to K8s",
			EnrolledAt:    time.Now().Add(-24 * time.Hour),
			CompletedAt:   &completed,
			PctComplete:   100,
			StepsPassed:   5,
			TotalSteps:    5,
			TotalTimeSecs: 4820,
			HintsUsed:     2,
		},
	})

	rec := getWithCtx(t, h.GetProgress, ctxWithClaims("user-1", "learner"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	enrollments, _ := body["enrollments"].([]any)
	if len(enrollments) != 1 {
		t.Fatalf("expected 1 enrollment, got %d", len(enrollments))
	}
	e, _ := enrollments[0].(map[string]any)
	if e["track_id"] != "track-1" {
		t.Errorf("track_id: got %v, want track-1", e["track_id"])
	}
	if e["pct_complete"] != float64(100) {
		t.Errorf("pct_complete: got %v, want 100", e["pct_complete"])
	}
}

func TestGetProgress_EmptyEnrollments(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t) // no progress seeded

	rec := getWithCtx(t, h.GetProgress, ctxWithClaims("user-1", "learner"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := decodeBody(t, rec)
	// enrollments key must exist and be an empty array (or null).
	if _, ok := body["enrollments"]; !ok {
		t.Error("expected enrollments key in response")
	}
}

func TestGetProgress_NoAuth_Returns401(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.GetProgress(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ── GET /users/me/certificates ────────────────────────────────────────────────

func TestGetCertificates_Success(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	score := 94.5
	ps.seedCerts("user-1", []store.Certificate{
		{
			ID:          "cert-1",
			TrackTitle:  "Docker to K8s",
			IssuedAt:    time.Now(),
			FinalScore:  &score,
			VerifyToken: "abc123",
		},
	})

	rec := getWithCtx(t, h.GetCertificates, ctxWithClaims("user-1", "learner"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	certs, _ := body["certificates"].([]any)
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	c, _ := certs[0].(map[string]any)
	if c["verify_token"] != "abc123" {
		t.Errorf("verify_token: got %v, want abc123", c["verify_token"])
	}
	wantURL := appBaseURL + "/verify/abc123"
	if c["verify_url"] != wantURL {
		t.Errorf("verify_url: got %v, want %s", c["verify_url"], wantURL)
	}
}

func TestGetCertificates_Empty(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	rec := getWithCtx(t, h.GetCertificates, ctxWithClaims("user-1", "learner"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestGetCertificates_NoAuth_Returns401(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.GetCertificates(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ── GET /users/{id} ───────────────────────────────────────────────────────────

func getWithPathValue(t *testing.T, fn http.HandlerFunc, ctx context.Context, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+id, nil).WithContext(ctx)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func TestGetUser_PublicView_ForOtherUser(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-2"))
	score := 90.0
	ps.seedCerts("user-2", []store.Certificate{
		{ID: "c1", TrackTitle: "K8s", IssuedAt: time.Now(), FinalScore: &score, VerifyToken: "tok1"},
		{ID: "c2", TrackTitle: "Docker", IssuedAt: time.Now(), FinalScore: &score, VerifyToken: "tok2"},
		{ID: "c3", TrackTitle: "Helm", IssuedAt: time.Now(), FinalScore: &score, VerifyToken: "tok3"},
	})

	// user-1 (learner) looking at user-2 → public view.
	rec := getWithPathValue(t, h.GetUser, ctxWithClaims("user-1", "learner"), "user-2")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)

	// Public view must NOT expose email or plan.
	if _, ok := body["email"]; ok {
		t.Error("public view must not expose email")
	}
	if _, ok := body["plan"]; ok {
		t.Error("public view must not expose plan")
	}
	if body["certificates_count"] != float64(3) {
		t.Errorf("certificates_count: got %v, want 3", body["certificates_count"])
	}
}

func TestGetUser_FullView_ForSelf(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-1"))

	// user-1 looking at themselves → full view.
	rec := getWithPathValue(t, h.GetUser, ctxWithClaims("user-1", "learner"), "user-1")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if _, ok := body["email"]; !ok {
		t.Error("self view must include email")
	}
}

func TestGetUser_FullView_ForAdmin(t *testing.T) {
	t.Parallel()
	h, ps := newHandler(t)
	ps.seedProfile(defaultProfile("user-2"))

	// superadmin looking at user-2 → full view.
	rec := getWithPathValue(t, h.GetUser, ctxWithClaims("admin-1", "superadmin"), "user-2")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if _, ok := body["email"]; !ok {
		t.Error("admin view must include email")
	}
}

func TestGetUser_NotFound_Returns404(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	rec := getWithPathValue(t, h.GetUser, ctxWithClaims("user-1", "learner"), "ghost-user")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetUser_NoAuth_Returns401(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/user-2", nil)
	req.SetPathValue("id", "user-2")
	rec := httptest.NewRecorder()
	h.GetUser(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
