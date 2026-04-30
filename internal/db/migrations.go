package db

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	postgresDriver "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

func MigrateUp(ctx context.Context, pool *pgxpool.Pool, migrationsDir string) error {
	return runMigration(ctx, pool, migrationsDir, "up")
}

func MigrateDown(ctx context.Context, pool *pgxpool.Pool, migrationsDir string) error {
	return runMigration(ctx, pool, migrationsDir, "down")
}

// MigrateStatus returns current migration version and dirty flag.
func MigrateStatus(ctx context.Context, pool *pgxpool.Pool, migrationsDir string) (int, bool, error) {
	m, drv, err := newMigrator(ctx, pool, migrationsDir)
	if err != nil {
		return 0, false, err
	}
	// Ensure we close the driver-owned database handle.
	defer drv.Close()

	ver, dirty, err := m.Version()
	if err != nil {
		return 0, false, err
	}
	return int(ver), dirty, nil
}

func runMigration(ctx context.Context, pool *pgxpool.Pool, migrationsDir string, action string) error {
	m, drv, err := newMigrator(ctx, pool, migrationsDir)
	if err != nil {
		return err
	}
	defer drv.Close()

	slog.Info("running database migrations", "migrations_dir", migrationsDir)
	switch action {
	case "up":
		if err := m.Up(); err != nil {
			if err == migrate.ErrNoChange {
				slog.Info("no new migrations to apply")
				return nil
			}
			return err
		}
		return nil
	case "down":
		if err := m.Down(); err != nil {
			if err == migrate.ErrNoChange {
				slog.Info("no migrations to roll back")
				return nil
			}
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown migration action %q", action)
	}
}

func newMigrator(ctx context.Context, pool *pgxpool.Pool, migrationsDir string) (*migrate.Migrate, database.Driver, error) {
	if pool == nil {
		return nil, nil, fmt.Errorf("pgx pool is required")
	}
	if migrationsDir == "" {
		migrationsDir = "./migrations"
	}

	absDir, err := filepath.Abs(migrationsDir)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve migrations dir: %w", err)
	}

	// golang-migrate expects a *sql.DB for the postgres driver; we create it from the pgx pool.
	sqlDB := stdlib.OpenDBFromPool(pool)
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, nil, fmt.Errorf("ping database for migrations: %w", err)
	}

	// Create the postgres migration driver.
	drv, err := postgresDriver.WithInstance(sqlDB, &postgresDriver.Config{})
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, fmt.Errorf("create postgres migrate driver: %w", err)
	}

	// File source reads ./migrations/*.up.sql / *.down.sql.
	// Using an absolute dir is fine; the file source parser normalizes it.
	sourceURL := "file://" + absDir

	m, err := migrate.NewWithDatabaseInstance(sourceURL, "postgres", drv)
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, fmt.Errorf("create migrate instance: %w", err)
	}
	return m, drv, nil
}

