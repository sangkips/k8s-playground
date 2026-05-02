package orghandler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/http/middleware"
	"sangkips/k8s-playground/internal/store"
)

// Handler handles all /orgs/* endpoints.
type Handler struct {
	orgs OrgStorer
}

func NewHandler(orgs OrgStorer) *Handler {
	return &Handler{orgs: orgs}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func mustClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	c, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
	}
	return c, ok
}

func orgID(r *http.Request) string {
	return middleware.OrgIDFromContext(r.Context())
}

// mapStoreErr converts store sentinel errors to HTTP status codes.
func mapStoreErr(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, store.ErrSlugTaken):
		writeError(w, http.StatusConflict, "slug already taken")
	default:
		slog.Error(op, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// ── POST /api/v1/orgs ─────────────────────────────────────────────────────────

type createOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	var req createOrgRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))

	if req.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	if req.Slug == "" {
		writeError(w, http.StatusUnprocessableEntity, "slug is required")
		return
	}

	org, err := h.orgs.Create(r.Context(), req.Name, req.Slug, claims.UserID)
	if err != nil {
		mapStoreErr(w, err, "create org")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":   org.ID,
		"name": org.Name,
		"slug": org.Slug,
		"plan": org.Plan,
	})
}

// ── GET /api/v1/orgs/{orgId} ──────────────────────────────────────────────────

func (h *Handler) GetOrg(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	org, err := h.orgs.GetByID(r.Context(), orgID(r), claims.UserID)
	if err != nil {
		mapStoreErr(w, err, "get org")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         org.ID,
		"name":       org.Name,
		"slug":       org.Slug,
		"plan":       org.Plan,
		"seat_limit": org.SeatLimit,
		"seats_used": org.SeatsUsed,
		"created_at": org.CreatedAt,
	})
}

// ── GET /api/v1/orgs/{orgId}/members ─────────────────────────────────────────

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	members, err := h.orgs.ListMembers(r.Context(), orgID(r), claims.UserID)
	if err != nil {
		mapStoreErr(w, err, "list members")
		return
	}

	out := make([]map[string]any, len(members))
	for i, m := range members {
		out[i] = map[string]any{
			"user_id":      m.UserID,
			"display_name": m.DisplayName,
			"role":         m.Role,
			"joined_at":    m.JoinedAt,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

// ── POST /api/v1/orgs/{orgId}/members/invite ─────────────────────────────────

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *Handler) InviteMember(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	var req inviteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Role = strings.TrimSpace(req.Role)

	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusUnprocessableEntity, "valid email is required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "member" && req.Role != "admin" {
		writeError(w, http.StatusUnprocessableEntity, "role must be member or admin")
		return
	}

	email, invitedAt, err := h.orgs.InviteMember(r.Context(), orgID(r), claims.UserID, req.Email, req.Role)
	if err != nil {
		mapStoreErr(w, err, "invite member")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"email":      email,
		"invited_at": invitedAt,
	})
}

// ── PATCH /api/v1/orgs/{orgId}/members/{userId} ───────────────────────────────

type updateRoleRequest struct {
	Role string `json:"role"`
}

func (h *Handler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	var req updateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Role = strings.TrimSpace(req.Role)
	if req.Role != "member" && req.Role != "admin" {
		writeError(w, http.StatusUnprocessableEntity, "role must be member or admin")
		return
	}

	targetUserID := r.PathValue("userId")
	if targetUserID == "" {
		writeError(w, http.StatusBadRequest, "userId is required")
		return
	}

	if err := h.orgs.UpdateMemberRole(r.Context(), orgID(r), claims.UserID, targetUserID, req.Role); err != nil {
		mapStoreErr(w, err, "update member role")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"user_id": targetUserID,
		"role":    req.Role,
	})
}

// ── DELETE /api/v1/orgs/{orgId}/members/{userId} ──────────────────────────────

func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	targetUserID := r.PathValue("userId")
	if targetUserID == "" {
		writeError(w, http.StatusBadRequest, "userId is required")
		return
	}

	if err := h.orgs.RemoveMember(r.Context(), orgID(r), claims.UserID, targetUserID); err != nil {
		mapStoreErr(w, err, "remove member")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── GET /api/v1/orgs/{orgId}/progress ────────────────────────────────────────

func (h *Handler) GetCohortProgress(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	cohort, err := h.orgs.GetCohortProgress(r.Context(), orgID(r), claims.UserID)
	if err != nil {
		mapStoreErr(w, err, "get cohort progress")
		return
	}

	members := make([]map[string]any, len(cohort))
	for i, m := range cohort {
		tracks := make([]map[string]any, len(m.Tracks))
		for j, t := range m.Tracks {
			tracks[j] = map[string]any{
				"track_id":       t.TrackID,
				"track_title":    t.TrackTitle,
				"pct_complete":   t.PctComplete,
				"last_active_at": t.LastActiveAt,
				"hints_used":     t.HintsUsed,
				"gate_attempts":  t.GateAttempts,
			}
		}
		members[i] = map[string]any{
			"user_id":      m.UserID,
			"display_name": m.DisplayName,
			"tracks":       tracks,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

// ── GET /api/v1/orgs/{orgId}/leaderboard ─────────────────────────────────────

func (h *Handler) GetLeaderboard(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	trackID := r.URL.Query().Get("track_id")
	if trackID == "" {
		writeError(w, http.StatusUnprocessableEntity, "track_id query param is required")
		return
	}

	entries, err := h.orgs.GetLeaderboard(r.Context(), orgID(r), claims.UserID, trackID)
	if err != nil {
		mapStoreErr(w, err, "get leaderboard")
		return
	}

	out := make([]map[string]any, len(entries))
	for i, e := range entries {
		out[i] = map[string]any{
			"rank":            e.Rank,
			"user_id":         e.UserID,
			"display_name":    e.DisplayName,
			"final_score":     e.FinalScore,
			"total_time_secs": e.TotalTimeSecs,
			"hints_used":      e.HintsUsed,
			"completed_at":    e.CompletedAt,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"track_id":    trackID,
		"leaderboard": out,
	})
}
