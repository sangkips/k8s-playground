package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"sangkips/k8s-playground/internal/config"
	"sangkips/k8s-playground/internal/db"
)

func main() {
	action := flag.String("action", "status", "migration action: up|down|status")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	slog.Info("starting migrations", "action", *action)

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connection failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	switch *action {
	case "up":
		if err := db.MigrateUp(ctx, pool, cfg.MigrationsDir); err != nil {
			slog.Error("migrate up failed", "err", err)
			os.Exit(1)
		}
	case "down":
		if err := db.MigrateDown(ctx, pool, cfg.MigrationsDir); err != nil {
			slog.Error("migrate down failed", "err", err)
			os.Exit(1)
		}
	case "status":
		ver, dirty, err := db.MigrateStatus(ctx, pool, cfg.MigrationsDir)
		if err != nil {
			slog.Error("migrate status failed", "err", err)
			os.Exit(1)
		}
		fmt.Printf("schema_migrations version=%d dirty=%v\n", ver, dirty)
	default:
		slog.Error("unknown action", "action", *action)
		os.Exit(2)
	}
}

