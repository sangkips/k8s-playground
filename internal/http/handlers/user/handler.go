package userhandler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/store"
)

// Handler handles all /users/* endpoints.
type Handler struct {
	profiles   ProfileStorer
	appBaseURL string
}

func NewHandler(profiles ProfileStorer, appBaseURL string) *Handler {
	return &Handler{profiles: profiles, appBaseURL: appBaseURL}
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

// mustClaims extracts JWT claims from the context, returning false and writing
// a 401 if they are absent.
func mustClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	c, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
	}
	return c, ok
}

// ── GET /api/v1/users/me ──────────────────────────────────────────────────────

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	profile, err := h.profiles.GetProfile(r.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		slog.Error("get profile", "err", err, "user_id", claims.UserID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Build org list.
	orgs := make([]map[string]string, len(profile.Orgs))
	for i, o := range profile.Orgs {
		orgs[i] = map[string]string{"id": o.ID, "name": o.Name, "role": o.Role}
	}

	certs := make([]map[string]any, len(profile.Certificates))
	for i, c := range profile.Certificates {
		certs[i] = map[string]any{
			"id":         c.ID,
			"title":      c.TrackTitle,
			"issue_date": c.IssuedAt,
		}

	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           profile.ID,
		"email":        profile.Email,
		"display_name": profile.DisplayName,
		"role":         profile.Role,
		"plan":         profile.Plan,
		"orgs":         orgs,
		"certificates": certs,
		"created_at":   profile.CreatedAt,
	})
}

// ── PATCH /api/v1/users/me ────────────────────────────────────────────────────

type patchMeRequest struct {
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Timezone    *string `json:"timezone"`
}

func (h *Handler) PatchMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	var req patchMeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Sanitise string fields.
	if req.DisplayName != nil {
		trimmed := strings.TrimSpace(*req.DisplayName)
		req.DisplayName = &trimmed
	}
	if req.AvatarURL != nil {
		trimmed := strings.TrimSpace(*req.AvatarURL)
		req.AvatarURL = &trimmed
	}
	if req.Timezone != nil {
		trimmed := strings.TrimSpace(*req.Timezone)
		req.Timezone = &trimmed
	}

	updated, err := h.profiles.UpdateProfile(r.Context(), claims.UserID, store.UpdateProfileParams{
		DisplayName: req.DisplayName,
		AvatarURL:   req.AvatarURL,
		Timezone:    req.Timezone,
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		slog.Error("update profile", "err", err, "user_id", claims.UserID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           updated.ID,
		"display_name": updated.DisplayName,
		"updated_at":   updated.UpdatedAt,
	})
}

// ── GET /api/v1/users/me/progress ────────────────────────────────────────────

func (h *Handler) GetProgress(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	progress, err := h.profiles.GetProgress(r.Context(), claims.UserID)
	if err != nil {
		slog.Error("get progress", "err", err, "user_id", claims.UserID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	enrollments := make([]map[string]any, len(progress))
	for i, ep := range progress {
		enrollments[i] = map[string]any{
			"track_id":        ep.TrackID,
			"track_title":     ep.TrackTitle,
			"enrolled_at":     ep.EnrolledAt,
			"completed_at":    ep.CompletedAt,
			"pct_complete":    ep.PctComplete,
			"steps_passed":    ep.StepsPassed,
			"total_steps":     ep.TotalSteps,
			"total_time_secs": ep.TotalTimeSecs,
			"hints_used":      ep.HintsUsed,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"enrollments": enrollments})
}

// ── GET /api/v1/users/me/certificates ────────────────────────────────────────

func (h *Handler) GetCertificates(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	certs, err := h.profiles.GetCertificates(r.Context(), claims.UserID)
	if err != nil {
		slog.Error("get certificates", "err", err, "user_id", claims.UserID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]map[string]any, len(certs))
	for i, c := range certs {
		out[i] = map[string]any{
			"id":           c.ID,
			"track_title":  c.TrackTitle,
			"issued_at":    c.IssuedAt,
			"final_score":  c.FinalScore,
			"verify_token": c.VerifyToken,
			"verify_url":   h.appBaseURL + "/verify/" + c.VerifyToken,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

// ── GET /api/v1/users/{id} ────────────────────────────────────────────────────

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := mustClaims(w, r)
	if !ok {
		return
	}

	targetID := r.PathValue("id")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "user id is required")
		return
	}

	// Admins and superadmins see the full profile; everyone else sees the
	// public profile unless they are looking at themselves.
	isAdmin := claims.Role == "org_admin" || claims.Role == "superadmin"
	isSelf := claims.UserID == targetID

	if isAdmin || isSelf {
		profile, err := h.profiles.GetProfile(r.Context(), targetID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "user not found")
				return
			}
			slog.Error("get full profile for admin", "err", err, "target_id", targetID)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		orgs := make([]map[string]string, len(profile.Orgs))
		for i, o := range profile.Orgs {
			orgs[i] = map[string]string{"id": o.ID, "name": o.Name, "role": o.Role}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":           profile.ID,
			"email":        profile.Email,
			"display_name": profile.DisplayName,
			"role":         profile.Role,
			"plan":         profile.Plan,
			"orgs":         orgs,
			"created_at":   profile.CreatedAt,
		})
		return
	}

	// Public view for other users.
	pub, err := h.profiles.GetPublicProfile(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		slog.Error("get public profile", "err", err, "target_id", targetID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":                 pub.ID,
		"display_name":       pub.DisplayName,
		"avatar_url":         pub.AvatarURL,
		"certificates_count": pub.CertificatesCount,
	})
}
