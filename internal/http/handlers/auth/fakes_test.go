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
	sessions      map[string]fakeSession
	refreshTokens map[string]fakeRefreshToken
	jtiToSession  map[string]string
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
		id: id, userID: userID, sessionID: sessionID, hash: tokenHash, expiresAt: expiresAt,
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
	return store.RefreshTokenRow{ID: rt.id, UserID: rt.userID, SessionID: rt.sessionID, ExpiresAt: rt.expiresAt}, nil
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

// ── fakeVerificationStore ─────────────────────────────────────────────────────

type fakeVerificationStore struct {
	mu               sync.Mutex
	tokens           map[string]fakeVerifToken // tokenHash → token
	verifiedUsers    map[string]bool
	updatedPasswords map[string]string
}

type fakeVerifToken struct {
	id        string
	userID    string
	kind      store.TokenKind
	hash      string
	expiresAt time.Time
	used      bool
}

func newFakeVerificationStore() *fakeVerificationStore {
	return &fakeVerificationStore{
		tokens:           make(map[string]fakeVerifToken),
		verifiedUsers:    make(map[string]bool),
		updatedPasswords: make(map[string]string),
	}
}

func (f *fakeVerificationStore) CreateToken(_ context.Context, userID string, kind store.TokenKind, tokenHash string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[tokenHash] = fakeVerifToken{
		id: "vt-" + tokenHash[:8], userID: userID, kind: kind, hash: tokenHash, expiresAt: expiresAt,
	}
	return nil
}

func (f *fakeVerificationStore) ConsumeToken(_ context.Context, tokenHash string, kind store.TokenKind) (store.VerificationTokenRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[tokenHash]
	if !ok || t.used || t.kind != kind || t.expiresAt.Before(time.Now()) {
		return store.VerificationTokenRow{}, store.ErrNotFound
	}
	t.used = true
	f.tokens[tokenHash] = t
	return store.VerificationTokenRow{ID: t.id, UserID: t.userID, Kind: t.kind}, nil
}

func (f *fakeVerificationStore) MarkEmailVerified(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifiedUsers[userID] = true
	return nil
}

func (f *fakeVerificationStore) UpdatePassword(_ context.Context, userID, passwordHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updatedPasswords[userID] = passwordHash
	return nil
}

// ── fakeOAuthStateStore ───────────────────────────────────────────────────────

type fakeOAuthStateStore struct {
	mu     sync.Mutex
	states map[string]string // state → redirectURI
}

func newFakeOAuthStateStore() *fakeOAuthStateStore {
	return &fakeOAuthStateStore{states: make(map[string]string)}
}

func (f *fakeOAuthStateStore) Save(_ context.Context, state, redirectURI string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[state] = redirectURI
	return nil
}

func (f *fakeOAuthStateStore) Consume(_ context.Context, state string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uri, ok := f.states[state]
	if !ok {
		return "", store.ErrNotFound
	}
	delete(f.states, state)
	return uri, nil
}

// ── fakeMailer ────────────────────────────────────────────────────────────────

type fakeMailer struct {
	mu                sync.Mutex
	verificationsSent []string // email addresses
	resetsSent        []string
}

func (m *fakeMailer) SendVerificationEmail(_ context.Context, to, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verificationsSent = append(m.verificationsSent, to)
	return nil
}

func (m *fakeMailer) SendPasswordResetEmail(_ context.Context, to, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetsSent = append(m.resetsSent, to)
	return nil
}
