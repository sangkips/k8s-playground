package userhandler

import (
	"context"

	"sangkips/k8s-playground/internal/store"
)

// ProfileStorer is the subset of store.ProfileStore the user handlers need.
type ProfileStorer interface {
	GetProfile(ctx context.Context, userID string) (store.UserProfile, error)
	UpdateProfile(ctx context.Context, userID string, p store.UpdateProfileParams) (store.UpdatedProfile, error)
	GetProgress(ctx context.Context, userID string) ([]store.EnrollmentProgress, error)
	GetCertificates(ctx context.Context, userID string) ([]store.Certificate, error)
	GetPublicProfile(ctx context.Context, targetID string) (store.PublicProfile, error)
}
