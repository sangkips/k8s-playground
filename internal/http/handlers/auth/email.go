package authhandler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/store"
)

const (
	verificationTokenTTL = 24 * time.Hour
	passwordResetTTL     = 1 * time.Hour
)

// EmailHandler handles email-verification and password-reset endpoints.
type EmailHandler struct {
	users        UserStorer
	verification VerificationStorer
	mailer       Mailer
	appBaseURL   string
}

func NewEmailHandler(users UserStorer, verification VerificationStorer, mailer Mailer, appBaseURL string) *EmailHandler {
	return &EmailHandler{
		users:        users,
		verification: verification,
		mailer:       mailer,
		appBaseURL:   appBaseURL,
	}
}

// ── POST /api/v1/auth/verify-email ───────────────────────────────────────────

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (h *EmailHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusUnprocessableEntity, "token is required")
		return
	}

	tokenHash := auth.HashRefreshToken(req.Token) // reuse SHA-256 helper
	row, err := h.verification.ConsumeToken(r.Context(), tokenHash, store.TokenKindEmailVerification)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid or expired verification token")
		return
	}

	if err := h.verification.MarkEmailVerified(r.Context(), row.UserID); err != nil {
		slog.Error("mark email verified", "err", err, "user_id", row.UserID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── POST /api/v1/auth/forgot-password ────────────────────────────────────────

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

func (h *EmailHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Always return ok — never reveal whether the email exists.
	defer writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	user, err := h.users.GetByEmail(r.Context(), req.Email)
	if err != nil {
		return // user not found — silently return ok
	}

	raw, tokenHash, err := auth.IssueRefreshToken() // reuse random token generator
	if err != nil {
		slog.Error("generate password reset token", "err", err)
		return
	}

	expiresAt := time.Now().Add(passwordResetTTL)
	if err := h.verification.CreateToken(r.Context(), user.ID, store.TokenKindPasswordReset, tokenHash, expiresAt); err != nil {
		slog.Error("store password reset token", "err", err)
		return
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", h.appBaseURL, raw)
	if err := h.mailer.SendPasswordResetEmail(r.Context(), user.Email, resetURL); err != nil {
		slog.Error("send password reset email", "err", err, "email", user.Email)
	}
}

// ── POST /api/v1/auth/reset-password ─────────────────────────────────────────

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *EmailHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusUnprocessableEntity, "token is required")
		return
	}
	if utf8.RuneCountInString(req.NewPassword) < 12 {
		writeError(w, http.StatusUnprocessableEntity, "new_password must be at least 12 characters")
		return
	}

	tokenHash := auth.HashRefreshToken(req.Token)
	row, err := h.verification.ConsumeToken(r.Context(), tokenHash, store.TokenKindPasswordReset)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid or expired reset token")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		slog.Error("hash new password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.verification.UpdatePassword(r.Context(), row.UserID, hash); err != nil {
		slog.Error("update password", "err", err, "user_id", row.UserID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
