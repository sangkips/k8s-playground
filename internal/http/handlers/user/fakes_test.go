package userhandler_test

import (
	"context"
	"sync"
	"time"

	"sangkips/k8s-playground/internal/store"
)

// fakeProfileStore is an in-memory implementation of ProfileStorer.
type fakeProfileStore struct {
	mu       sync.Mutex
	profiles map[string]store.UserProfile // userID → profile
	progress map[string][]store.EnrollmentProgress
	certs    map[string][]store.Certificate
}

func newFakeProfileStore() *fakeProfileStore {
	return &fakeProfileStore{
		profiles: make(map[string]store.UserProfile),
		progress: make(map[string][]store.EnrollmentProgress),
		certs:    make(map[string][]store.Certificate),
	}
}

// seed helpers ─────────────────────────────────────────────────────────────────

func (f *fakeProfileStore) seedProfile(p store.UserProfile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[p.ID] = p
}

func (f *fakeProfileStore) seedProgress(userID string, rows []store.EnrollmentProgress) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.progress[userID] = rows
}

func (f *fakeProfileStore) seedCerts(userID string, rows []store.Certificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[userID] = rows
}

// ProfileStorer interface ──────────────────────────────────────────────────────

func (f *fakeProfileStore) GetProfile(_ context.Context, userID string) (store.UserProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[userID]
	if !ok {
		return store.UserProfile{}, store.ErrNotFound
	}
	return p, nil
}

func (f *fakeProfileStore) UpdateProfile(_ context.Context, userID string, params store.UpdateProfileParams) (store.UpdatedProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[userID]
	if !ok {
		return store.UpdatedProfile{}, store.ErrNotFound
	}
	if params.DisplayName != nil {
		p.DisplayName = *params.DisplayName
	}
	if params.AvatarURL != nil {
		p.AvatarURL = *params.AvatarURL
	}
	if params.Timezone != nil {
		p.Timezone = *params.Timezone
	}
	f.profiles[userID] = p
	return store.UpdatedProfile{
		ID:          p.ID,
		DisplayName: p.DisplayName,
		UpdatedAt:   time.Now(),
	}, nil
}

func (f *fakeProfileStore) GetProgress(_ context.Context, userID string) ([]store.EnrollmentProgress, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.progress[userID], nil
}

func (f *fakeProfileStore) GetCertificates(_ context.Context, userID string) ([]store.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs[userID], nil
}

func (f *fakeProfileStore) GetPublicProfile(_ context.Context, targetID string) (store.PublicProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[targetID]
	if !ok {
		return store.PublicProfile{}, store.ErrNotFound
	}
	return store.PublicProfile{
		ID:                p.ID,
		DisplayName:       p.DisplayName,
		AvatarURL:         p.AvatarURL,
		CertificatesCount: len(f.certs[targetID]),
	}, nil
}
