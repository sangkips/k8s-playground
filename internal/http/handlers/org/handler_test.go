package orghandler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sangkips/k8s-playground/internal/auth"
	orghandler "sangkips/k8s-playground/internal/http/handlers/org"
	"sangkips/k8s-playground/internal/http/middleware"
	"sangkips/k8s-playground/internal/store"

	"github.com/golang-jwt/jwt/v5"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newHandler(t *testing.T) (*orghandler.Handler, *fakeOrgStore) {
	t.Helper()
	fs := newFakeOrgStore()
	return orghandler.NewHandler(fs), fs
}

func claimsCtx(userID, role string) context.Context {
	c := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-" + userID,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		UserID: userID,
		Role:   role,
		Email:  userID + "@example.com",
	}
	return auth.ContextWithClaims(context.Background(), c)
}

// withOrgID injects both JWT claims and the orgId path value into the context,
// matching what the authn + OrgID middlewares do in production.
func withOrgID(ctx context.Context, orgID string) context.Context {
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	req.SetPathValue("orgId", orgID)
	// Run the OrgID middleware to store it in context.
	var captured context.Context
	middleware.OrgID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	return captured
}

func postJSON(t *testing.T, fn http.HandlerFunc, ctx context.Context, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func doRequest(t *testing.T, method string, fn http.HandlerFunc, ctx context.Context, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "/", bytes.NewReader(b)).WithContext(ctx)
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

// seedOrg creates an org with an owner and returns the org.
func seedOrg(fs *fakeOrgStore, orgID, ownerID string) store.Org {
	org := store.Org{ID: orgID, Name: "Acme", Slug: "acme", Plan: "free", CreatedAt: time.Now()}
	fs.seedOrg(org)
	fs.seedMember(orgID, ownerID, ownerID+"@example.com", "Owner", "owner", true)
	return org
}

// ── POST /orgs ────────────────────────────────────────────────────────────────

func TestCreateOrg_Success(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	rec := postJSON(t, h.CreateOrg, claimsCtx("user-1", "learner"), map[string]string{
		"name": "Acme Engineering",
		"slug": "acme",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["slug"] != "acme" {
		t.Errorf("slug: got %v, want acme", body["slug"])
	}
	if body["plan"] != "free" {
		t.Errorf("plan: got %v, want free", body["plan"])
	}
}

func TestCreateOrg_DuplicateSlug(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-acme", "user-1")

	rec := postJSON(t, h.CreateOrg, claimsCtx("user-2", "learner"), map[string]string{
		"name": "Another Acme",
		"slug": "acme",
	})

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestCreateOrg_MissingName(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	rec := postJSON(t, h.CreateOrg, claimsCtx("user-1", "learner"), map[string]string{"slug": "acme"})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestCreateOrg_NoAuth(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x","slug":"x"}`))
	rec := httptest.NewRecorder()
	h.CreateOrg(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ── GET /orgs/{orgId} ─────────────────────────────────────────────────────────

func TestGetOrg_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetOrg(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["id"] != "org-1" {
		t.Errorf("id: got %v, want org-1", body["id"])
	}
}

func TestGetOrg_NonMember_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("outsider", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetOrg(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestGetOrg_NotFound(t *testing.T) {
	t.Parallel()
	h, _ := newHandler(t)

	ctx := withOrgID(claimsCtx("user-1", "learner"), "ghost-org")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetOrg(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// ── GET /orgs/{orgId}/members ─────────────────────────────────────────────────

func TestListMembers_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ListMembers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	members, _ := body["members"].([]any)
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

func TestListMembers_NonMember_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("outsider", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ListMembers(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

// ── POST /orgs/{orgId}/members/invite ─────────────────────────────────────────

func TestInviteMember_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	rec := postJSON(t, h.InviteMember, ctx, map[string]string{
		"email": "new@example.com",
		"role":  "member",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["email"] != "new@example.com" {
		t.Errorf("email: got %v, want new@example.com", body["email"])
	}
}

func TestInviteMember_NonAdmin_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-2", "learner"), "org-1")
	rec := postJSON(t, h.InviteMember, ctx, map[string]string{
		"email": "new@example.com",
		"role":  "member",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestInviteMember_InvalidEmail(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	rec := postJSON(t, h.InviteMember, ctx, map[string]string{
		"email": "not-an-email",
		"role":  "member",
	})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestInviteMember_InvalidRole(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	rec := postJSON(t, h.InviteMember, ctx, map[string]string{
		"email": "new@example.com",
		"role":  "superadmin",
	})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

// ── PATCH /orgs/{orgId}/members/{userId} ──────────────────────────────────────

func TestUpdateMemberRole_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(`{"role":"admin"}`)).
		WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("userId", "user-2")
	rec := httptest.NewRecorder()
	h.UpdateMemberRole(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["role"] != "admin" {
		t.Errorf("role: got %v, want admin", body["role"])
	}
}

func TestUpdateMemberRole_NonAdmin_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-2", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(`{"role":"admin"}`)).
		WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("userId", "user-1")
	rec := httptest.NewRecorder()
	h.UpdateMemberRole(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestUpdateMemberRole_InvalidRole(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(`{"role":"owner"}`)).
		WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("userId", "user-2")
	rec := httptest.NewRecorder()
	h.UpdateMemberRole(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

// ── DELETE /orgs/{orgId}/members/{userId} ─────────────────────────────────────

func TestRemoveMember_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodDelete, "/", nil).WithContext(ctx)
	req.SetPathValue("userId", "user-2")
	rec := httptest.NewRecorder()
	h.RemoveMember(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	if ok, _ := decodeBody(t, rec)["ok"].(bool); !ok {
		t.Error("expected ok=true")
	}
}

func TestRemoveMember_NonAdmin_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-2", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodDelete, "/", nil).WithContext(ctx)
	req.SetPathValue("userId", "user-1")
	rec := httptest.NewRecorder()
	h.RemoveMember(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRemoveMember_NotFound(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodDelete, "/", nil).WithContext(ctx)
	req.SetPathValue("userId", "ghost-user")
	rec := httptest.NewRecorder()
	h.RemoveMember(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// ── GET /orgs/{orgId}/progress ────────────────────────────────────────────────

func TestGetCohortProgress_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedProgress("org-1", []store.OrgMemberProgress{
		{
			UserID:      "user-1",
			DisplayName: "Ada",
			Tracks: []store.OrgTrackProgress{
				{TrackID: "track-1", TrackTitle: "Docker to K8s", PctComplete: 80, HintsUsed: 4, GateAttempts: 7},
			},
		},
	})

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetCohortProgress(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	members, _ := body["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
}

func TestGetCohortProgress_NonAdmin_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	fs.seedMember("org-1", "user-2", "user-2@example.com", "Bob", "member", true)

	ctx := withOrgID(claimsCtx("user-2", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetCohortProgress(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

// ── GET /orgs/{orgId}/leaderboard ─────────────────────────────────────────────

func TestGetLeaderboard_Success(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")
	score := 98.0
	completed := time.Now()
	fs.seedLeaderboard("org-1", "track-1", []store.LeaderboardEntry{
		{Rank: 1, UserID: "user-1", DisplayName: "Ada", FinalScore: &score, TotalTimeSecs: 3600, CompletedAt: &completed},
	})

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/?track_id=track-1", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetLeaderboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["track_id"] != "track-1" {
		t.Errorf("track_id: got %v, want track-1", body["track_id"])
	}
	lb, _ := body["leaderboard"].([]any)
	if len(lb) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(lb))
	}
	entry, _ := lb[0].(map[string]any)
	if entry["rank"] != float64(1) {
		t.Errorf("rank: got %v, want 1", entry["rank"])
	}
}

func TestGetLeaderboard_MissingTrackID(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("user-1", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx) // no track_id
	rec := httptest.NewRecorder()
	h.GetLeaderboard(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}

func TestGetLeaderboard_NonMember_Returns403(t *testing.T) {
	t.Parallel()
	h, fs := newHandler(t)
	seedOrg(fs, "org-1", "user-1")

	ctx := withOrgID(claimsCtx("outsider", "learner"), "org-1")
	req := httptest.NewRequest(http.MethodGet, "/?track_id=track-1", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.GetLeaderboard(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}
