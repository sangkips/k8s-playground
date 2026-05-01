package authhandler_test

import (
	"context"
	"sync"
	"time"

	"sangkips/k8s-playground/internal/store"
)

// ── fakeUserStore ─────────────────────────────────────────────────────────────

type fakeUserStore struct {
	mu      sync.Mutex
	byEmail map[string]store.User
	byID    map[string]store.User
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		byEmail: make(map[string]store.User),
		byID:    make(map[string]store.User),
	}
}

func (f *fakeUserStore) Create(_ context.Context, email, passwordHash, displayName string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.byEmail[email]; exists {
		return store.User{}, store.ErrEmailTaken
	}
	u := store.User{
		ID:           "fake-uuid-" + email,
		Email:        email,
		PasswordHash: passwordHash,
		Role:         "learner",
		DisplayName:  displayName,
	}
	f.byEmail[email] = u
	f.byID[u.ID] = u
	return u, nil
}

func (f *fakeUserStore) GetByEmail(_ context.Context, email string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byEmail[email]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (f *fakeUserStore) GetByID(_ context.Context, id string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (f *fakeUserStore) UpdateLastSeen(_ context.Context, _ string) error { return nil }

// ── fakeSessionStore ──────────────────────────────────────────────────────────

type fakeSessionStore struct {
	mu            sync.Mutex
	sessions      map[string]fakeSession      // sessionID → session
	refreshTokens map[string]fakeRefreshToken // tokenHash → token
	jtiToSession  map[string]string           // jti → sessionID
}

type fakeSession struct {
	id        string
	userID    string
	jti       string
	expiresAt time.Time
	revoked   bool
}

type fakeRefreshToken struct {
	id        string
	userID    string
	sessionID string
	hash      string
	expiresAt time.Time
	revoked   bool
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		sessions:      make(map[string]fakeSession),
		refreshTokens: make(map[string]fakeRefreshToken),
		jtiToSession:  make(map[string]string),
	}
}

func (f *fakeSessionStore) CreateSession(_ context.Context, userID, jti string, expiresAt time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := "sess-" + jti
	f.sessions[id] = fakeSession{id: id, userID: userID, jti: jti, expiresAt: expiresAt}
	f.jtiToSession[jti] = id
	return id, nil
}

func (f *fakeSessionStore) CreateRefreshToken(_ context.Context, userID, sessionID, tokenHash string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := "rt-" + tokenHash[:8]
	f.refreshTokens[tokenHash] = fakeRefreshToken{
		id:        id,
		userID:    userID,
		sessionID: sessionID,
		hash:      tokenHash,
		expiresAt: expiresAt,
	}
	return nil
}

func (f *fakeSessionStore) GetRefreshToken(_ context.Context, tokenHash string) (store.RefreshTokenRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rt, ok := f.refreshTokens[tokenHash]
	if !ok || rt.revoked || rt.expiresAt.Before(time.Now()) {
		return store.RefreshTokenRow{}, store.ErrNotFound
	}
	return store.RefreshTokenRow{
		ID:        rt.id,
		UserID:    rt.userID,
		SessionID: rt.sessionID,
		ExpiresAt: rt.expiresAt,
	}, nil
}

func (f *fakeSessionStore) RevokeRefreshToken(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for k, rt := range f.refreshTokens {
		if rt.id == id {
			rt.revoked = true
			f.refreshTokens[k] = rt
			return nil
		}
	}
	return nil
}

func (f *fakeSessionStore) RevokeSession(_ context.Context, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if s, ok := f.sessions[sessionID]; ok {
		s.revoked = true
		f.sessions[sessionID] = s
	}
	return nil
}

func (f *fakeSessionStore) GetSessionByJTI(_ context.Context, jti string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id, ok := f.jtiToSession[jti]
	if !ok {
		return "", time.Time{}, store.ErrNotFound
	}
	s := f.sessions[id]
	return s.id, s.expiresAt, nil
}
