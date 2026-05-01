package authhandler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/store"
)

// Handler holds dependencies for all auth endpoints.
type Handler struct {
	users    UserStorer
	sessions SessionStorer
	tokens   *auth.TokenService
}

func NewHandler(users UserStorer, sessions SessionStorer, tokens *auth.TokenService) *Handler {
	return &Handler{users: users, sessions: sessions, tokens: tokens}
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
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20) // 1 MB limit
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// ── POST /api/v1/auth/register ────────────────────────────────────────────────

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusUnprocessableEntity, "valid email is required")
		return
	}
	if utf8.RuneCountInString(req.Password) < 12 {
		writeError(w, http.StatusUnprocessableEntity, "password must be at least 12 characters")
		return
	}
	if req.DisplayName == "" {
		writeError(w, http.StatusUnprocessableEntity, "display_name is required")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		slog.Error("hash password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	user, err := h.users.Create(r.Context(), req.Email, hash, req.DisplayName)
	if err != nil {
		if errors.Is(err, store.ErrEmailTaken) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		slog.Error("create user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	accessToken, jti, _, refreshToken, err := h.issueTokenPair(r, user.ID, user.Email, user.Role)
	if err != nil {
		slog.Error("issue token pair on register", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = jti

	writeJSON(w, http.StatusCreated, map[string]any{
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    h.tokens.AccessTokenTTLSeconds(),
	})
}

// ── POST /api/v1/auth/login ───────────────────────────────────────────────────

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	user, err := h.users.GetByEmail(r.Context(), req.Email)
	if err != nil {
		// Same error for not-found and wrong password to prevent enumeration.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := auth.CheckPassword(user.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	accessToken, _, _, refreshToken, err := h.issueTokenPair(r, user.ID, user.Email, user.Role)
	if err != nil {
		slog.Error("issue token pair on login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	_ = h.users.UpdateLastSeen(r.Context(), user.ID)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    h.tokens.AccessTokenTTLSeconds(),
	})
}

// ── POST /api/v1/auth/refresh ─────────────────────────────────────────────────

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusUnprocessableEntity, "refresh_token is required")
		return
	}

	tokenHash := auth.HashRefreshToken(req.RefreshToken)
	row, err := h.sessions.GetRefreshToken(r.Context(), tokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Rotate: revoke old token and session before issuing a new pair.
	_ = h.sessions.RevokeRefreshToken(r.Context(), row.ID)
	_ = h.sessions.RevokeSession(r.Context(), row.SessionID)

	userRow, err := h.users.GetByID(r.Context(), row.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	accessToken, _, _, _, err := h.issueTokenPair(r, userRow.ID, userRow.Email, userRow.Role)
	if err != nil {
		slog.Error("issue token pair on refresh", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"expires_in":   h.tokens.AccessTokenTTLSeconds(),
	})
}

// ── POST /api/v1/auth/logout 🔒 ───────────────────────────────────────────────

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.tokens.DenyToken(r.Context(), claims.ID, claims.ExpiresAt.Time); err != nil {
		slog.Error("deny token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if sessionID, _, err := h.sessions.GetSessionByJTI(r.Context(), claims.ID); err == nil {
		_ = h.sessions.RevokeSession(r.Context(), sessionID)
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── shared helper ─────────────────────────────────────────────────────────────

func (h *Handler) issueTokenPair(r *http.Request, userID, email, role string) (
	accessToken, jti string, expiresAt time.Time, refreshToken string, err error,
) {
	accessToken, jti, expiresAt, err = h.tokens.IssueAccessToken(userID, email, role)
	if err != nil {
		return
	}

	sessionID, err := h.sessions.CreateSession(r.Context(), userID, jti, expiresAt)
	if err != nil {
		return
	}

	rawRefresh, refreshHash, err := auth.IssueRefreshToken()
	if err != nil {
		return
	}

	refreshExpiresAt := time.Now().Add(h.tokens.RefreshTokenTTL())
	err = h.sessions.CreateRefreshToken(r.Context(), userID, sessionID, refreshHash, refreshExpiresAt)
	if err != nil {
		return
	}

	refreshToken = rawRefresh
	return
}
