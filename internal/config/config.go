package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL            string
	HTTPAddr               string
	RunMigrationsOnStart  bool
	MigrationsDir         string
}

func Load() (Config, error) {
	var cfg Config

	cfg.DatabaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if cfg.DatabaseURL == "" {
		localDBURL, err := localDatabaseURLFromEnv()
		if err != nil {
			return Config{}, err
		}
		cfg.DatabaseURL = localDBURL
	}

	cfg.HTTPAddr = strings.TrimSpace(os.Getenv("HTTP_ADDR"))
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8080"
	}

	if v := strings.TrimSpace(os.Getenv("RUN_MIGRATIONS_ON_START")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("RUN_MIGRATIONS_ON_START: %w", err)
		}
		cfg.RunMigrationsOnStart = b
	}

	cfg.MigrationsDir = strings.TrimSpace(os.Getenv("MIGRATIONS_DIR"))
	if cfg.MigrationsDir == "" {
		cfg.MigrationsDir = "./migrations"
	}

	return cfg, nil
}

func localDatabaseURLFromEnv() (string, error) {
	// Local-first defaults so the app can run without DATABASE_URL.
	host := strings.TrimSpace(os.Getenv("LOCAL_DB_HOST"))
	if host == "" {
		host = "localhost"
	}

	port := strings.TrimSpace(os.Getenv("LOCAL_DB_PORT"))
	if port == "" {
		port = "5432"
	}

	user := strings.TrimSpace(os.Getenv("LOCAL_DB_USER"))
	if user == "" {
		user = "postgres"
	}

	password := strings.TrimSpace(os.Getenv("LOCAL_DB_PASSWORD"))

	dbName := strings.TrimSpace(os.Getenv("LOCAL_DB_NAME"))
	if dbName == "" {
		dbName = "k8s"
	}

	sslMode := strings.TrimSpace(os.Getenv("LOCAL_DB_SSLMODE"))
	if sslMode == "" {
		sslMode = "disable"
	}

	u := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%s", host, port),
		Path:   dbName,
	}

	if user != "" {
		if password != "" {
			u.User = url.UserPassword(user, password)
		} else {
			u.User = url.User(user)
		}
	}

	query := u.Query()
	query.Set("sslmode", sslMode)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

