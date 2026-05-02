package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const oauthStatePrefix = "oauth:state:"
const oauthStateTTL = 10 * time.Minute

// OAuthStateStore stores and validates short-lived OAuth state parameters in Redis.
type OAuthStateStore struct {
	rdb *redis.Client
}

func NewOAuthStateStore(rdb *redis.Client) *OAuthStateStore {
	return &OAuthStateStore{rdb: rdb}
}

// Save persists a state value keyed by the state string itself.
// The value is the redirect_uri supplied by the client.
func (s *OAuthStateStore) Save(ctx context.Context, state, redirectURI string) error {
	return s.rdb.Set(ctx, oauthStatePrefix+state, redirectURI, oauthStateTTL).Err()
}

// Consume retrieves and deletes the redirect_uri for a given state.
// Returns ("", ErrNotFound) if the state is unknown or expired.
func (s *OAuthStateStore) Consume(ctx context.Context, state string) (redirectURI string, err error) {
	key := oauthStatePrefix + state
	val, err := s.rdb.GetDel(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("oauth state not found or expired")
	}
	if err != nil {
		return "", fmt.Errorf("consume oauth state: %w", err)
	}
	return val, nil
}
