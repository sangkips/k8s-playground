package httpapi

import (
	"net/http"
	"time"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/cache"
	authhandler "sangkips/k8s-playground/internal/http/handlers/auth"
	healthhandler "sangkips/k8s-playground/internal/http/handlers/health"
	"sangkips/k8s-playground/internal/http/middleware"
	"sangkips/k8s-playground/internal/mailer"
	"sangkips/k8s-playground/internal/store"
)

// Dependencies holds all shared services needed by HTTP handlers.
type Dependencies struct {
	UserStore         *store.UserStore
	SessionStore      *store.SessionStore
	VerificationStore *store.VerificationStore
	TokenService      *auth.TokenService
	OAuthStateStore   *cache.OAuthStateStore
	Mailer            mailer.Mailer
	AppBaseURL        string

	// OAuth provider credentials
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
}

func NewServer(addr string, deps Dependencies) *http.Server {
	mux := http.NewServeMux()

	// ── Health ────────────────────────────────────────────────────────────────
	mux.HandleFunc("/healthz", healthhandler.Healthz)

	// ── Auth ──────────────────────────────────────────────────────────────────
	authn := middleware.Authenticate(deps.TokenService)

	authH := authhandler.NewHandler(
		deps.UserStore,
		deps.SessionStore,
		deps.TokenService,
		deps.VerificationStore,
		deps.Mailer,
		deps.AppBaseURL,
	)

	emailH := authhandler.NewEmailHandler(
		deps.UserStore,
		deps.VerificationStore,
		deps.Mailer,
		deps.AppBaseURL,
	)

	oauthH := authhandler.NewOAuthHandler(
		deps.OAuthStateStore,
		deps.GitHubClientID,
		deps.GitHubClientSecret,
		deps.GoogleClientID,
		deps.GoogleClientSecret,
	)

	// Public auth routes
	mux.HandleFunc("POST /api/v1/auth/register", authH.Register)
	mux.HandleFunc("POST /api/v1/auth/login", authH.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authH.Refresh)
	mux.HandleFunc("POST /api/v1/auth/verify-email", emailH.VerifyEmail)
	mux.HandleFunc("POST /api/v1/auth/forgot-password", emailH.ForgotPassword)
	mux.HandleFunc("POST /api/v1/auth/reset-password", emailH.ResetPassword)
	mux.HandleFunc("POST /api/v1/auth/oauth/{provider}", oauthH.OAuthStart)

	// Protected routes
	mux.Handle("POST /api/v1/auth/logout", authn(http.HandlerFunc(authH.Logout)))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
