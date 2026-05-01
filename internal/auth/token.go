package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

const denylistPrefix = "jwt:deny:"

// Claims are the JWT payload fields.
type Claims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}

// TokenService handles JWT and refresh token operations.
type TokenService struct {
	secret          []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	rdb             *redis.Client
}

func NewTokenService(secret string, accessTTL, refreshTTL time.Duration, rdb *redis.Client) *TokenService {
	return &TokenService{
		secret:          []byte(secret),
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		rdb:             rdb,
	}
}

// IssueAccessToken creates a signed JWT for the given user.
// Returns the token string and the jti (used to track the session).
func (s *TokenService) IssueAccessToken(userID, email, role string) (tokenStr, jti string, expiresAt time.Time, err error) {
	jtiBytes := make([]byte, 16)
	if _, err = rand.Read(jtiBytes); err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate jti: %w", err)
	}
	jti = hex.EncodeToString(jtiBytes)
	expiresAt = time.Now().Add(s.accessTokenTTL)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID: userID,
		Role:   role,
		Email:  email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err = token.SignedString(s.secret)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return tokenStr, jti, expiresAt, nil
}

// ValidateAccessToken parses and validates a JWT, checking the denylist.
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check denylist in Redis.
	denied, err := s.rdb.Exists(ctx, denylistPrefix+claims.ID).Result()
	if err != nil {
		return nil, fmt.Errorf("denylist check: %w", err)
	}
	if denied > 0 {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// DenyToken adds a JWT jti to the Redis denylist until it expires.
func (s *TokenService) DenyToken(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // already expired, no need to store
	}
	return s.rdb.Set(ctx, denylistPrefix+jti, "1", ttl).Err()
}

// IssueRefreshToken generates a cryptographically random opaque token.
// Returns the raw token (sent to client) and its SHA-256 hash (stored in DB).
func IssueRefreshToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	raw = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

// HashRefreshToken returns the SHA-256 hex hash of a raw refresh token.
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RefreshTokenTTL exposes the configured refresh token lifetime.
func (s *TokenService) RefreshTokenTTL() time.Duration {
	return s.refreshTokenTTL
}

// AccessTokenTTLSeconds returns the access token TTL in seconds (for expires_in field).
func (s *TokenService) AccessTokenTTLSeconds() int {
	return int(s.accessTokenTTL.Seconds())
}
