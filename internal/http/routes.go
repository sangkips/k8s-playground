package httpapi

import (
	"net/http"
	"time"

	"sangkips/k8s-playground/internal/auth"
	authhandler "sangkips/k8s-playground/internal/http/handlers/auth"
	healthhandler "sangkips/k8s-playground/internal/http/handlers/health"
	"sangkips/k8s-playground/internal/http/middleware"
	"sangkips/k8s-playground/internal/store"
)

// Dependencies holds all shared services needed by HTTP handlers.
type Dependencies struct {
	UserStore    *store.UserStore
	SessionStore *store.SessionStore
	TokenService *auth.TokenService
}

func NewServer(addr string, deps Dependencies) *http.Server {
	mux := http.NewServeMux()

	// Health — no auth required.
	mux.HandleFunc("/healthz", healthhandler.Healthz)

	// Auth routes — /api/v1/auth/...
	authH := authhandler.NewHandler(deps.UserStore, deps.SessionStore, deps.TokenService)
	authn := middleware.Authenticate(deps.TokenService)

	mux.HandleFunc("POST /api/v1/auth/register", authH.Register)
	mux.HandleFunc("POST /api/v1/auth/login", authH.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authH.Refresh)

	// Protected: logout requires a valid JWT.
	mux.Handle("POST /api/v1/auth/logout", authn(http.HandlerFunc(authH.Logout)))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
