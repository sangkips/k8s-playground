package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenKind maps to the verification_tokens.kind enum.
type TokenKind string

const (
	TokenKindEmailVerification TokenKind = "email_verification"
	TokenKindPasswordReset     TokenKind = "password_reset"
)

// VerificationStore handles verification_tokens DB operations.
type VerificationStore struct {
	pool *pgxpool.Pool
}

func NewVerificationStore(pool *pgxpool.Pool) *VerificationStore {
	return &VerificationStore{pool: pool}
}

// CreateToken inserts a new verification token and returns its id.
func (s *VerificationStore) CreateToken(ctx context.Context, userID string, kind TokenKind, tokenHash string, expiresAt time.Time) error {
	const q = `
		INSERT INTO verification_tokens (user_id, kind, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`
	_, err := s.pool.Exec(ctx, q, userID, string(kind), tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("create verification token: %w", err)
	}
	return nil
}

// VerificationTokenRow is returned when consuming a token.
type VerificationTokenRow struct {
	ID     string
	UserID string
	Kind   TokenKind
}

// ConsumeToken looks up a valid (non-expired, unused) token by hash,
// marks it as used, and returns the associated user id.
// Returns ErrNotFound if the token is invalid, expired, or already used.
func (s *VerificationStore) ConsumeToken(ctx context.Context, tokenHash string, kind TokenKind) (VerificationTokenRow, error) {
	const q = `
		UPDATE verification_tokens
		SET    used_at = now()
		WHERE  token_hash = $1
		  AND  kind       = $2
		  AND  used_at    IS NULL
		  AND  expires_at > now()
		RETURNING id, user_id, kind`

	var row VerificationTokenRow
	var kindStr string
	err := s.pool.QueryRow(ctx, q, tokenHash, string(kind)).Scan(&row.ID, &row.UserID, &kindStr)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VerificationTokenRow{}, ErrNotFound
		}
		return VerificationTokenRow{}, fmt.Errorf("consume verification token: %w", err)
	}
	row.Kind = TokenKind(kindStr)
	return row, nil
}

// MarkEmailVerified sets email_verified = true for the given user.
func (s *VerificationStore) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET email_verified = true WHERE id = $1`, userID)
	return err
}

// UpdatePassword sets a new password hash for the given user.
func (s *VerificationStore) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, userID)
	return err
}
