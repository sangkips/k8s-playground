package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sangkips/k8s-playground/internal/auth"
	"sangkips/k8s-playground/internal/cache"
	"sangkips/k8s-playground/internal/config"
	"sangkips/k8s-playground/internal/db"
	httpapi "sangkips/k8s-playground/internal/http"
	"sangkips/k8s-playground/internal/mailer"
	"sangkips/k8s-playground/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── Database ──────────────────────────────────────────────────────────────
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connection failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if cfg.RunMigrationsOnStart {
		slog.Info("running migrations")
		if err := db.MigrateUp(ctx, pool, cfg.MigrationsDir); err != nil {
			slog.Error("migrations failed", "err", err)
			os.Exit(1)
		}
	}

	// ── Redis ─────────────────────────────────────────────────────────────────
	rdb, err := cache.NewRedis(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		slog.Error("redis connection failed", "err", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// ── Services ──────────────────────────────────────────────────────────────
	tokenSvc := auth.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, rdb)

	// ── Mailer ────────────────────────────────────────────────────────────────
	var ml mailer.Mailer
	if cfg.SMTPHost != "" {
		ml = mailer.NewSMTPMailer(mailer.SMTPConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
			UseTLS:   cfg.SMTPUseTLS,
		})
		slog.Info("mailer ready", "host", cfg.SMTPHost, "port", cfg.SMTPPort)
	} else {
		ml = mailer.NoOp{}
		slog.Warn("SMTP_HOST not set — email sending disabled (NoOp mailer active)")
	}

	deps := httpapi.Dependencies{
		UserStore:         store.NewUserStore(pool),
		SessionStore:      store.NewSessionStore(pool),
		VerificationStore: store.NewVerificationStore(pool),
		ProfileStore:      store.NewProfileStore(pool),
		TokenService:      tokenSvc,
		OAuthStateStore:   cache.NewOAuthStateStore(rdb),
		Mailer:            ml,
		AppBaseURL:        cfg.AppBaseURL,

		GitHubClientID:     cfg.GitHubClientID,
		GitHubClientSecret: cfg.GitHubClientSecret,
		GoogleClientID:     cfg.GoogleClientID,
		GoogleClientSecret: cfg.GoogleClientSecret,
	}

	// ── HTTP server ───────────────────────────────────────────────────────────
	srv := httpapi.NewServer(cfg.HTTPAddr, deps)
	go func() {
		slog.Info("listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown failed", "err", err)
		os.Exit(1)
	}
}
