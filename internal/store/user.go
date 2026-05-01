package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// ErrEmailTaken is returned when the email is already registered.
var ErrEmailTaken = errors.New("email already taken")

// User mirrors the relevant columns from the users table.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	DisplayName  string
}

// UserStore handles user-related DB operations.
type UserStore struct {
	pool *pgxpool.Pool
}

func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

// Create inserts a new user and returns the created record.
func (s *UserStore) Create(ctx context.Context, email, passwordHash, displayName string) (User, error) {
	const q = `
		INSERT INTO users (email, password_hash, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, email, password_hash, role, display_name`

	var u User
	err := s.pool.QueryRow(ctx, q, email, passwordHash, displayName).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.DisplayName)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetByEmail fetches a user by email address.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	const q = `
		SELECT id, email, password_hash, role, display_name
		FROM users
		WHERE email = $1 AND is_active = true`

	var u User
	err := s.pool.QueryRow(ctx, q, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.DisplayName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetByID fetches a user by their UUID.
func (s *UserStore) GetByID(ctx context.Context, id string) (User, error) {
	const q = `
		SELECT id, email, password_hash, role, display_name
		FROM users
		WHERE id = $1 AND is_active = true`

	var u User
	err := s.pool.QueryRow(ctx, q, id).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.DisplayName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}
func (s *UserStore) UpdateLastSeen(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_seen_at = now() WHERE id = $1`, userID)
	return err
}

// isUniqueViolation detects PostgreSQL unique constraint errors (code 23505).
func isUniqueViolation(err error) bool {
	// pgx wraps pgconn.PgError; check the SQLState code.
	type pgErr interface{ SQLState() string }
	var pe pgErr
	if errors.As(err, &pe) {
		return pe.SQLState() == "23505"
	}
	return false
}

// SessionStore handles user_sessions and refresh_tokens DB operations.
type SessionStore struct {
	pool *pgxpool.Pool
}

func NewSessionStore(pool *pgxpool.Pool) *SessionStore {
	return &SessionStore{pool: pool}
}

// CreateSession inserts a user_session row and returns its id.
func (s *SessionStore) CreateSession(ctx context.Context, userID, jti string, expiresAt time.Time) (string, error) {
	const q = `
		INSERT INTO user_sessions (user_id, jwt_jti, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id`

	var id string
	err := s.pool.QueryRow(ctx, q, userID, jti, expiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

// CreateRefreshToken stores the hashed refresh token linked to a session.
func (s *SessionStore) CreateRefreshToken(ctx context.Context, userID, sessionID, tokenHash string, expiresAt time.Time) error {
	const q = `
		INSERT INTO refresh_tokens (user_id, session_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`

	_, err := s.pool.Exec(ctx, q, userID, sessionID, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

// RefreshTokenRow is the data returned when looking up a refresh token.
type RefreshTokenRow struct {
	ID        string
	UserID    string
	SessionID string
	ExpiresAt time.Time
}

// GetRefreshToken looks up a non-revoked, non-expired refresh token by its hash.
func (s *SessionStore) GetRefreshToken(ctx context.Context, tokenHash string) (RefreshTokenRow, error) {
	const q = `
		SELECT id, user_id, session_id, expires_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > now()`

	var row RefreshTokenRow
	err := s.pool.QueryRow(ctx, q, tokenHash).
		Scan(&row.ID, &row.UserID, &row.SessionID, &row.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshTokenRow{}, ErrNotFound
		}
		return RefreshTokenRow{}, fmt.Errorf("get refresh token: %w", err)
	}
	return row, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *SessionStore) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, id)
	return err
}

// RevokeSession marks a user_session as revoked.
func (s *SessionStore) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_sessions SET revoked_at = now() WHERE id = $1`, sessionID)
	return err
}

// GetSessionByJTI fetches a session by its JWT jti.
func (s *SessionStore) GetSessionByJTI(ctx context.Context, jti string) (string, time.Time, error) {
	const q = `SELECT id, expires_at FROM user_sessions WHERE jwt_jti = $1`
	var id string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, q, jti).Scan(&id, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, ErrNotFound
		}
		return "", time.Time{}, fmt.Errorf("get session by jti: %w", err)
	}
	return id, expiresAt, nil
}
