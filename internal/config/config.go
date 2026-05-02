package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL          string
	HTTPAddr             string
	RunMigrationsOnStart bool
	MigrationsDir        string

	// Auth
	JWTSecret       string
	AccessTokenTTL  time.Duration // default 15 min
	RefreshTokenTTL time.Duration // default 7 days

	// Redis (token denylist + refresh token store)
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// OAuth providers
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string

	// Email (used for verification and password-reset mails)
	AppBaseURL string // e.g. https://app.example.com — used to build callback links

	// SMTP
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string // "Display Name <addr@example.com>"
	SMTPUseTLS   bool   // true = implicit TLS port 465, false = STARTTLS port 587
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

	// JWT
	cfg.JWTSecret = strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if cfg.JWTSecret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required")
	}

	cfg.AccessTokenTTL = 15 * time.Minute
	if v := strings.TrimSpace(os.Getenv("ACCESS_TOKEN_TTL_SECS")); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("ACCESS_TOKEN_TTL_SECS: %w", err)
		}
		cfg.AccessTokenTTL = time.Duration(secs) * time.Second
	}

	cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	if v := strings.TrimSpace(os.Getenv("REFRESH_TOKEN_TTL_SECS")); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("REFRESH_TOKEN_TTL_SECS: %w", err)
		}
		cfg.RefreshTokenTTL = time.Duration(secs) * time.Second
	}

	// Redis
	cfg.RedisAddr = strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = "localhost:6379"
	}
	cfg.RedisPassword = strings.TrimSpace(os.Getenv("REDIS_PASSWORD"))
	if v := strings.TrimSpace(os.Getenv("REDIS_DB")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("REDIS_DB: %w", err)
		}
		cfg.RedisDB = n
	}

	// OAuth
	cfg.GitHubClientID = strings.TrimSpace(os.Getenv("GITHUB_CLIENT_ID"))
	cfg.GitHubClientSecret = strings.TrimSpace(os.Getenv("GITHUB_CLIENT_SECRET"))
	cfg.GoogleClientID = strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID"))
	cfg.GoogleClientSecret = strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET"))

	// App base URL (used in email links)
	cfg.AppBaseURL = strings.TrimSpace(os.Getenv("APP_BASE_URL"))
	if cfg.AppBaseURL == "" {
		cfg.AppBaseURL = "http://localhost:8080"
	}

	// SMTP
	cfg.SMTPHost = strings.TrimSpace(os.Getenv("SMTP_HOST"))
	cfg.SMTPUsername = strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	cfg.SMTPPassword = strings.TrimSpace(os.Getenv("SMTP_PASSWORD"))
	cfg.SMTPFrom = strings.TrimSpace(os.Getenv("SMTP_FROM"))
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = "K8s Platform <no-reply@example.com>"
	}

	cfg.SMTPPort = 587 // default: STARTTLS
	if v := strings.TrimSpace(os.Getenv("SMTP_PORT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("SMTP_PORT: %w", err)
		}
		cfg.SMTPPort = n
	}

	if v := strings.TrimSpace(os.Getenv("SMTP_USE_TLS")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("SMTP_USE_TLS: %w", err)
		}
		cfg.SMTPUseTLS = b
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
