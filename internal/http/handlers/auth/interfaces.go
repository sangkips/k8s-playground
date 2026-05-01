package authhandler

import (
	"context"
	"time"

	"sangkips/k8s-playground/internal/store"
)

// UserStorer is the subset of store.UserStore the auth handlers need.
// Using an interface lets tests inject a fake without a real database.
type UserStorer interface {
	Create(ctx context.Context, email, passwordHash, displayName string) (store.User, error)
	GetByEmail(ctx context.Context, email string) (store.User, error)
	GetByID(ctx context.Context, id string) (store.User, error)
	UpdateLastSeen(ctx context.Context, userID string) error
}

// SessionStorer is the subset of store.SessionStore the auth handlers need.
type SessionStorer interface {
	CreateSession(ctx context.Context, userID, jti string, expiresAt time.Time) (string, error)
	CreateRefreshToken(ctx context.Context, userID, sessionID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (store.RefreshTokenRow, error)
	RevokeRefreshToken(ctx context.Context, id string) error
	RevokeSession(ctx context.Context, sessionID string) error
	GetSessionByJTI(ctx context.Context, jti string) (string, time.Time, error)
}
