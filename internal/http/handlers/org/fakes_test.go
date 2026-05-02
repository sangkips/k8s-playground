package orghandler_test

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sangkips/k8s-playground/internal/store"
)

// fakeOrgStore is a thread-safe in-memory OrgStorer.
type fakeOrgStore struct {
	mu          sync.Mutex
	orgs        map[string]store.Org                 // orgID → org
	members     map[string][]fakeMember              // orgID → members
	progress    map[string][]store.OrgMemberProgress // orgID → cohort
	leaderboard map[string][]store.LeaderboardEntry  // orgID+trackID → entries
}

type fakeMember struct {
	orgID    string
	userID   string
	email    string
	name     string
	role     string
	joinedAt *time.Time
}

func newFakeOrgStore() *fakeOrgStore {
	return &fakeOrgStore{
		orgs:        make(map[string]store.Org),
		members:     make(map[string][]fakeMember),
		progress:    make(map[string][]store.OrgMemberProgress),
		leaderboard: make(map[string][]store.LeaderboardEntry),
	}
}

// ── seed helpers ──────────────────────────────────────────────────────────────

func (f *fakeOrgStore) seedOrg(org store.Org) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgs[org.ID] = org
}

func (f *fakeOrgStore) seedMember(orgID, userID, email, name, role string, joined bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var jt *time.Time
	if joined {
		t := time.Now()
		jt = &t
	}
	f.members[orgID] = append(f.members[orgID], fakeMember{
		orgID: orgID, userID: userID, email: email,
		name: name, role: role, joinedAt: jt,
	})
}

func (f *fakeOrgStore) seedProgress(orgID string, rows []store.OrgMemberProgress) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.progress[orgID] = rows
}

func (f *fakeOrgStore) seedLeaderboard(orgID, trackID string, rows []store.LeaderboardEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaderboard[orgID+":"+trackID] = rows
}

// ── OrgStorer interface ───────────────────────────────────────────────────────

func (f *fakeOrgStore) Create(_ context.Context, name, slug, creatorID string) (store.Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.orgs {
		if o.Slug == slug {
			return store.Org{}, store.ErrSlugTaken
		}
	}
	id := "org-" + slug
	org := store.Org{ID: id, Name: name, Slug: slug, Plan: "free", CreatedAt: time.Now()}
	f.orgs[id] = org
	t := time.Now()
	f.members[id] = append(f.members[id], fakeMember{
		orgID: id, userID: creatorID, role: "owner", joinedAt: &t,
	})
	return org, nil
}

func (f *fakeOrgStore) GetByID(_ context.Context, orgID, callerID string) (store.Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	org, ok := f.orgs[orgID]
	if !ok {
		return store.Org{}, store.ErrNotFound
	}
	if !f.isMember(orgID, callerID) {
		return store.Org{}, store.ErrForbidden
	}
	return org, nil
}

func (f *fakeOrgStore) ListMembers(_ context.Context, orgID, callerID string) ([]store.OrgMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.orgs[orgID]; !ok {
		return nil, store.ErrNotFound
	}
	if !f.isMember(orgID, callerID) {
		return nil, store.ErrForbidden
	}
	var out []store.OrgMember
	for _, m := range f.members[orgID] {
		out = append(out, store.OrgMember{
			UserID:      m.userID,
			DisplayName: m.name,
			Role:        m.role,
			JoinedAt:    m.joinedAt,
		})
	}
	return out, nil
}

func (f *fakeOrgStore) InviteMember(_ context.Context, orgID, callerID, email, role string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.hasRole(orgID, callerID, "admin", "owner") {
		return "", time.Time{}, store.ErrForbidden
	}
	// Check email resolves to a known user (fake: email == userID for simplicity).
	for _, m := range f.members[orgID] {
		if m.email == email {
			return "", time.Time{}, fmt.Errorf("user is already a member")
		}
	}
	now := time.Now()
	f.members[orgID] = append(f.members[orgID], fakeMember{
		orgID: orgID, userID: "user-" + email, email: email, role: role,
	})
	return email, now, nil
}

func (f *fakeOrgStore) UpdateMemberRole(_ context.Context, orgID, callerID, targetUserID, newRole string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.hasRole(orgID, callerID, "admin", "owner") {
		return store.ErrForbidden
	}
	for i, m := range f.members[orgID] {
		if m.userID == targetUserID {
			f.members[orgID][i].role = newRole
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeOrgStore) RemoveMember(_ context.Context, orgID, callerID, targetUserID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.hasRole(orgID, callerID, "admin", "owner") {
		return store.ErrForbidden
	}
	for _, m := range f.members[orgID] {
		if m.userID == targetUserID && m.role == "owner" {
			return fmt.Errorf("cannot remove the org owner")
		}
	}
	newList := f.members[orgID][:0]
	found := false
	for _, m := range f.members[orgID] {
		if m.userID == targetUserID {
			found = true
			continue
		}
		newList = append(newList, m)
	}
	if !found {
		return store.ErrNotFound
	}
	f.members[orgID] = newList
	return nil
}

func (f *fakeOrgStore) GetCohortProgress(_ context.Context, orgID, callerID string) ([]store.OrgMemberProgress, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.hasRole(orgID, callerID, "admin", "owner") {
		return nil, store.ErrForbidden
	}
	return f.progress[orgID], nil
}

func (f *fakeOrgStore) GetLeaderboard(_ context.Context, orgID, callerID, trackID string) ([]store.LeaderboardEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.isMember(orgID, callerID) {
		return nil, store.ErrForbidden
	}
	return f.leaderboard[orgID+":"+trackID], nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (f *fakeOrgStore) isMember(orgID, userID string) bool {
	for _, m := range f.members[orgID] {
		if m.userID == userID {
			return true
		}
	}
	return false
}

func (f *fakeOrgStore) hasRole(orgID, userID string, roles ...string) bool {
	for _, m := range f.members[orgID] {
		if m.userID != userID {
			continue
		}
		for _, r := range roles {
			if m.role == r {
				return true
			}
		}
	}
	return false
}
