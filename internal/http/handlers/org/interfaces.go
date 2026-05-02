package orghandler

import (
	"context"
	"time"

	"sangkips/k8s-playground/internal/store"
)

// OrgStorer is the subset of store.OrgStore the org handlers need.
type OrgStorer interface {
	Create(ctx context.Context, name, slug, creatorID string) (store.Org, error)
	GetByID(ctx context.Context, orgID, callerID string) (store.Org, error)
	ListMembers(ctx context.Context, orgID, callerID string) ([]store.OrgMember, error)
	InviteMember(ctx context.Context, orgID, callerID, email, role string) (string, time.Time, error)
	UpdateMemberRole(ctx context.Context, orgID, callerID, targetUserID, newRole string) error
	RemoveMember(ctx context.Context, orgID, callerID, targetUserID string) error
	GetCohortProgress(ctx context.Context, orgID, callerID string) ([]store.OrgMemberProgress, error)
	GetLeaderboard(ctx context.Context, orgID, callerID, trackID string) ([]store.LeaderboardEntry, error)
}
