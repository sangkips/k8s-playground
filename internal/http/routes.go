package httpapi

import (
	"net/http"
	"time"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/cache"
	authhandler "sangkips/k8s-playground/internal/http/handlers/auth"
	healthhandler "sangkips/k8s-playground/internal/http/handlers/health"
	orghandler "sangkips/k8s-playground/internal/http/handlers/org"
	userhandler "sangkips/k8s-playground/internal/http/handlers/user"
	"sangkips/k8s-playground/internal/http/middleware"
	"sangkips/k8s-playground/internal/mailer"
	"sangkips/k8s-playground/internal/store"
)

// Dependencies holds all shared services needed by HTTP handlers.
type Dependencies struct {
	UserStore         *store.UserStore
	SessionStore      *store.SessionStore
	VerificationStore *store.VerificationStore
	ProfileStore      *store.ProfileStore
	OrgStore          *store.OrgStore
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

	authn := middleware.Authenticate(deps.TokenService)

	// ── Auth ──────────────────────────────────────────────────────────────────
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

	mux.HandleFunc("POST /api/v1/auth/register", authH.Register)
	mux.HandleFunc("POST /api/v1/auth/login", authH.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authH.Refresh)
	mux.HandleFunc("POST /api/v1/auth/verify-email", emailH.VerifyEmail)
	mux.HandleFunc("POST /api/v1/auth/forgot-password", emailH.ForgotPassword)
	mux.HandleFunc("POST /api/v1/auth/reset-password", emailH.ResetPassword)
	mux.HandleFunc("POST /api/v1/auth/oauth/{provider}", oauthH.OAuthStart)
	mux.Handle("POST /api/v1/auth/logout", authn(http.HandlerFunc(authH.Logout)))

	// ── Users (all protected) ─────────────────────────────────────────────────
	userH := userhandler.NewHandler(deps.ProfileStore, deps.AppBaseURL)

	mux.Handle("GET /api/v1/users/me", authn(http.HandlerFunc(userH.GetMe)))
	mux.Handle("PATCH /api/v1/users/me", authn(http.HandlerFunc(userH.PatchMe)))
	mux.Handle("GET /api/v1/users/me/progress", authn(http.HandlerFunc(userH.GetProgress)))
	mux.Handle("GET /api/v1/users/me/certificates", authn(http.HandlerFunc(userH.GetCertificates)))
	mux.Handle("GET /api/v1/users/{id}", authn(http.HandlerFunc(userH.GetUser)))

	// ── Orgs (all protected) ──────────────────────────────────────────────────
	orgH := orghandler.NewHandler(deps.OrgStore)
	// orgAuthn chains auth + OrgID path-value extractor.
	orgAuthn := func(h http.Handler) http.Handler { return authn(middleware.OrgID(h)) }

	mux.Handle("POST /api/v1/orgs", authn(http.HandlerFunc(orgH.CreateOrg)))
	mux.Handle("GET /api/v1/orgs/{orgId}", orgAuthn(http.HandlerFunc(orgH.GetOrg)))
	mux.Handle("GET /api/v1/orgs/{orgId}/members", orgAuthn(http.HandlerFunc(orgH.ListMembers)))
	mux.Handle("POST /api/v1/orgs/{orgId}/members/invite", orgAuthn(http.HandlerFunc(orgH.InviteMember)))
	mux.Handle("PATCH /api/v1/orgs/{orgId}/members/{userId}", orgAuthn(http.HandlerFunc(orgH.UpdateMemberRole)))
	mux.Handle("DELETE /api/v1/orgs/{orgId}/members/{userId}", orgAuthn(http.HandlerFunc(orgH.RemoveMember)))
	mux.Handle("GET /api/v1/orgs/{orgId}/progress", orgAuthn(http.HandlerFunc(orgH.GetCohortProgress)))
	mux.Handle("GET /api/v1/orgs/{orgId}/leaderboard", orgAuthn(http.HandlerFunc(orgH.GetLeaderboard)))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
