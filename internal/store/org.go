package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── sentinel errors ───────────────────────────────────────────────────────────

var ErrSlugTaken = errors.New("slug already taken")
var ErrForbidden = errors.New("forbidden")

// ── types ─────────────────────────────────────────────────────────────────────

// Org is the core org record.
type Org struct {
	ID        string
	Name      string
	Slug      string
	Plan      string // active plan slug
	SeatLimit *int   // nil = unlimited
	SeatsUsed int
	CreatedAt time.Time
}

// OrgMember is one row in the members list.
type OrgMember struct {
	UserID      string
	DisplayName string
	Role        string
	JoinedAt    *time.Time
}

// OrgMemberProgress is one member's progress across all tracks (cohort report).
type OrgMemberProgress struct {
	UserID      string
	DisplayName string
	Tracks      []OrgTrackProgress
}

// OrgTrackProgress is one track entry inside a cohort report row.
type OrgTrackProgress struct {
	TrackID      string
	TrackTitle   string
	PctComplete  float64
	LastActiveAt *time.Time
	HintsUsed    int
	GateAttempts int
}

// LeaderboardEntry is one row in the org leaderboard.
type LeaderboardEntry struct {
	Rank          int
	UserID        string
	DisplayName   string
	FinalScore    *float64
	TotalTimeSecs int
	HintsUsed     int
	CompletedAt   *time.Time
}

// ── OrgStore ──────────────────────────────────────────────────────────────────

// OrgStore handles all organisation DB operations.
type OrgStore struct {
	pool *pgxpool.Pool
}

func NewOrgStore(pool *pgxpool.Pool) *OrgStore {
	return &OrgStore{pool: pool}
}

// Create inserts a new org and adds the creator as owner in one transaction.
func (s *OrgStore) Create(ctx context.Context, name, slug, creatorID string) (Org, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Org{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var org Org
	err = tx.QueryRow(ctx, `
		INSERT INTO organisations (name, slug, created_by)
		VALUES ($1, $2, $3)
		RETURNING id::text, name, slug, created_at`,
		name, slug, creatorID,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Org{}, ErrSlugTaken
		}
		return Org{}, fmt.Errorf("insert org: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO org_members (org_id, user_id, role, joined_at)
		VALUES ($1, $2, 'owner', now())`,
		org.ID, creatorID,
	)
	if err != nil {
		return Org{}, fmt.Errorf("add owner member: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Org{}, fmt.Errorf("commit: %w", err)
	}

	org.Plan = "free"
	return org, nil
}

// GetByID returns org details including plan and seat counts.
// Returns ErrNotFound if the org doesn't exist.
// Returns ErrForbidden if the caller is not a member.
func (s *OrgStore) GetByID(ctx context.Context, orgID, callerID string) (Org, error) {
	// Verify membership first.
	if err := s.requireMember(ctx, orgID, callerID); err != nil {
		return Org{}, err
	}

	const q = `
		SELECT
			o.id::text,
			o.name,
			o.slug,
			o.created_at,
			COALESCE(
				(SELECT p.slug::text
				 FROM   subscriptions sub
				 JOIN   plans p ON p.id = sub.plan_id
				 WHERE  sub.org_id = o.id
				   AND  sub.status IN ('trialing','active')
				 ORDER  BY p.price_monthly DESC
				 LIMIT  1),
				'free'
			) AS plan,
			(SELECT p2.max_seats
			 FROM   subscriptions sub2
			 JOIN   plans p2 ON p2.id = sub2.plan_id
			 WHERE  sub2.org_id = o.id
			   AND  sub2.status IN ('trialing','active')
			 ORDER  BY p2.price_monthly DESC
			 LIMIT  1) AS seat_limit,
			(SELECT COUNT(*) FROM org_members om2
			 WHERE  om2.org_id = o.id AND om2.joined_at IS NOT NULL) AS seats_used
		FROM organisations o
		WHERE o.id = $1`

	var org Org
	err := s.pool.QueryRow(ctx, q, orgID).
		Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedAt,
			&org.Plan, &org.SeatLimit, &org.SeatsUsed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Org{}, ErrNotFound
		}
		return Org{}, fmt.Errorf("get org: %w", err)
	}
	return org, nil
}

// ListMembers returns all members of an org.
// Caller must be a member.
func (s *OrgStore) ListMembers(ctx context.Context, orgID, callerID string) ([]OrgMember, error) {
	if err := s.requireMember(ctx, orgID, callerID); err != nil {
		return nil, err
	}

	const q = `
		SELECT
			om.user_id::text,
			COALESCE(u.display_name, u.email) AS display_name,
			om.role::text,
			om.joined_at
		FROM org_members om
		JOIN users u ON u.id = om.user_id
		WHERE om.org_id = $1
		ORDER BY om.joined_at ASC NULLS LAST, u.display_name`

	rows, err := s.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()

	var members []OrgMember
	for rows.Next() {
		var m OrgMember
		if err := rows.Scan(&m.UserID, &m.DisplayName, &m.Role, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// InviteMember inserts a pending org_members row (joined_at = NULL).
// Caller must be admin or owner.
func (s *OrgStore) InviteMember(ctx context.Context, orgID, callerID, email, role string) (string, time.Time, error) {
	if err := s.requireRole(ctx, orgID, callerID, "admin", "owner"); err != nil {
		return "", time.Time{}, err
	}

	// Resolve email → user id.
	var inviteeID string
	err := s.pool.QueryRow(ctx,
		`SELECT id::text FROM users WHERE email = $1 AND is_active = true`, email,
	).Scan(&inviteeID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, ErrNotFound
		}
		return "", time.Time{}, fmt.Errorf("resolve invitee: %w", err)
	}

	var invitedAt time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO org_members (org_id, user_id, role, invited_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, user_id) DO NOTHING
		RETURNING invited_at`,
		orgID, inviteeID, role, callerID,
	).Scan(&invitedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ON CONFLICT DO NOTHING — already a member.
			return "", time.Time{}, fmt.Errorf("user is already a member")
		}
		return "", time.Time{}, fmt.Errorf("invite member: %w", err)
	}

	return email, invitedAt, nil
}

// UpdateMemberRole changes a member's role.
// Caller must be admin or owner.
func (s *OrgStore) UpdateMemberRole(ctx context.Context, orgID, callerID, targetUserID, newRole string) error {
	if err := s.requireRole(ctx, orgID, callerID, "admin", "owner"); err != nil {
		return err
	}

	result, err := s.pool.Exec(ctx, `
		UPDATE org_members SET role = $1
		WHERE org_id = $2 AND user_id = $3`,
		newRole, orgID, targetUserID,
	)
	if err != nil {
		return fmt.Errorf("update member role: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveMember deletes a member from the org.
// Caller must be admin or owner. An owner cannot be removed.
func (s *OrgStore) RemoveMember(ctx context.Context, orgID, callerID, targetUserID string) error {
	if err := s.requireRole(ctx, orgID, callerID, "admin", "owner"); err != nil {
		return err
	}

	// Prevent removing the last owner.
	var targetRole string
	err := s.pool.QueryRow(ctx,
		`SELECT role::text FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, targetUserID,
	).Scan(&targetRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("get target role: %w", err)
	}
	if targetRole == "owner" {
		return fmt.Errorf("cannot remove the org owner")
	}

	_, err = s.pool.Exec(ctx,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, targetUserID,
	)
	return err
}

// GetCohortProgress returns all members' progress across all enrolled tracks.
// Caller must be admin or owner.
func (s *OrgStore) GetCohortProgress(ctx context.Context, orgID, callerID string) ([]OrgMemberProgress, error) {
	if err := s.requireRole(ctx, orgID, callerID, "admin", "owner"); err != nil {
		return nil, err
	}

	// Fetch all members.
	const memberQ = `
		SELECT om.user_id::text, COALESCE(u.display_name, u.email)
		FROM   org_members om
		JOIN   users u ON u.id = om.user_id
		WHERE  om.org_id = $1
		ORDER  BY u.display_name`

	mRows, err := s.pool.Query(ctx, memberQ, orgID)
	if err != nil {
		return nil, fmt.Errorf("list cohort members: %w", err)
	}
	defer mRows.Close()

	type memberRow struct {
		id   string
		name string
	}
	var memberList []memberRow
	for mRows.Next() {
		var m memberRow
		if err := mRows.Scan(&m.id, &m.name); err != nil {
			return nil, fmt.Errorf("scan cohort member: %w", err)
		}
		memberList = append(memberList, m)
	}
	if err := mRows.Err(); err != nil {
		return nil, err
	}

	// For each member, fetch their track progress.
	const progressQ = `
		SELECT
			e.track_id::text,
			t.title,
			COALESCE(uts.pct_complete, 0),
			e.last_active_at,
			COALESCE(uts.total_hints, 0),
			COALESCE(uts.total_attempts, 0)
		FROM enrollments e
		JOIN tracks t ON t.id = e.track_id
		LEFT JOIN user_track_summary uts
			ON uts.user_id = e.user_id AND uts.track_id = e.track_id
		WHERE e.user_id = $1
		ORDER BY e.enrolled_at DESC`

	result := make([]OrgMemberProgress, 0, len(memberList))
	for _, m := range memberList {
		pRows, err := s.pool.Query(ctx, progressQ, m.id)
		if err != nil {
			return nil, fmt.Errorf("get member progress: %w", err)
		}

		var tracks []OrgTrackProgress
		for pRows.Next() {
			var tp OrgTrackProgress
			if err := pRows.Scan(
				&tp.TrackID, &tp.TrackTitle, &tp.PctComplete,
				&tp.LastActiveAt, &tp.HintsUsed, &tp.GateAttempts,
			); err != nil {
				pRows.Close()
				return nil, fmt.Errorf("scan track progress: %w", err)
			}
			tracks = append(tracks, tp)
		}
		pRows.Close()
		if err := pRows.Err(); err != nil {
			return nil, err
		}

		result = append(result, OrgMemberProgress{
			UserID:      m.id,
			DisplayName: m.name,
			Tracks:      tracks,
		})
	}
	return result, nil
}

// GetLeaderboard returns a ranked leaderboard for a specific track within the org.
// Caller must be a member.
func (s *OrgStore) GetLeaderboard(ctx context.Context, orgID, callerID, trackID string) ([]LeaderboardEntry, error) {
	if err := s.requireMember(ctx, orgID, callerID); err != nil {
		return nil, err
	}

	const q = `
		SELECT
			ROW_NUMBER() OVER (ORDER BY c.final_score DESC NULLS LAST, uts.total_time_secs ASC) AS rank,
			om.user_id::text,
			COALESCE(u.display_name, u.email) AS display_name,
			c.final_score,
			COALESCE(uts.total_time_secs, 0)  AS total_time_secs,
			COALESCE(uts.total_hints, 0)       AS hints_used,
			e.completed_at
		FROM org_members om
		JOIN users u ON u.id = om.user_id
		JOIN enrollments e ON e.user_id = om.user_id AND e.track_id = $2
		LEFT JOIN certificates c ON c.user_id = om.user_id AND c.track_id = $2
		LEFT JOIN user_track_summary uts ON uts.user_id = om.user_id AND uts.track_id = $2
		WHERE om.org_id = $1
		ORDER BY rank`

	rows, err := s.pool.Query(ctx, q, orgID, trackID)
	if err != nil {
		return nil, fmt.Errorf("get leaderboard: %w", err)
	}
	defer rows.Close()

	var entries []LeaderboardEntry
	for rows.Next() {
		var e LeaderboardEntry
		if err := rows.Scan(
			&e.Rank, &e.UserID, &e.DisplayName,
			&e.FinalScore, &e.TotalTimeSecs, &e.HintsUsed, &e.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan leaderboard: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ── access-control helpers ────────────────────────────────────────────────────

// requireMember returns ErrForbidden if callerID is not a member of orgID.
func (s *OrgStore) requireMember(ctx context.Context, orgID, callerID string) error {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`,
		orgID, callerID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check membership: %w", err)
	}
	if !exists {
		return ErrForbidden
	}
	return nil
}

// requireRole returns ErrForbidden if the caller's role is not in allowedRoles.
func (s *OrgStore) requireRole(ctx context.Context, orgID, callerID string, allowedRoles ...string) error {
	var role string
	err := s.pool.QueryRow(ctx,
		`SELECT role::text FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, callerID,
	).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbidden
		}
		return fmt.Errorf("check role: %w", err)
	}
	for _, r := range allowedRoles {
		if role == r {
			return nil
		}
	}
	return ErrForbidden
}
