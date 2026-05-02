package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── types ─────────────────────────────────────────────────────────────────────

// UserProfile is the full profile returned for GET /users/me.
type UserProfile struct {
	ID           string
	Email        string
	DisplayName  string
	AvatarURL    string
	Timezone     string
	Role         string
	Plan         string // active plan slug, defaults to "free"
	CreatedAt    time.Time
	Orgs         []UserOrg
	Certificates []Certificate
}

// UserOrg is one org membership entry inside a profile.
type UserOrg struct {
	ID   string
	Name string
	Role string
}

// UpdateProfileParams carries the optional fields for PATCH /users/me.
// A nil pointer means "don't update this field".
type UpdateProfileParams struct {
	DisplayName *string
	AvatarURL   *string
	Timezone    *string
}

// UpdatedProfile is returned after a successful PATCH /users/me.
type UpdatedProfile struct {
	ID          string
	DisplayName string
	UpdatedAt   time.Time
}

// EnrollmentProgress is one row in GET /users/me/progress.
type EnrollmentProgress struct {
	TrackID       string
	TrackTitle    string
	EnrolledAt    time.Time
	CompletedAt   *time.Time
	PctComplete   float64
	StepsPassed   int
	TotalSteps    int
	TotalTimeSecs int
	HintsUsed     int
}

// Certificate is one row in GET /users/me/certificates.
type Certificate struct {
	ID          string
	TrackTitle  string
	IssuedAt    time.Time
	FinalScore  *float64
	VerifyToken string
}

// PublicProfile is returned for GET /users/:id.
type PublicProfile struct {
	ID                string
	DisplayName       string
	AvatarURL         string
	CertificatesCount int
}

// ── ProfileStore ──────────────────────────────────────────────────────────────

// ProfileStore handles user profile DB operations.
type ProfileStore struct {
	pool *pgxpool.Pool
}

func NewProfileStore(pool *pgxpool.Pool) *ProfileStore {
	return &ProfileStore{pool: pool}
}

// GetProfile returns the full profile for the authenticated user.
func (s *ProfileStore) GetProfile(ctx context.Context, userID string) (UserProfile, error) {
	const q = `
		SELECT
			u.id,
			u.email,
			COALESCE(u.display_name, '')  AS display_name,
			COALESCE(u.avatar_url, '')    AS avatar_url,
			u.timezone,
			u.role::text,
			u.created_at,
			-- active plan: look up the org the user belongs to and its subscription,
			-- fall back to 'free' when there is no active subscription.
			COALESCE(
				(SELECT p.slug::text
				 FROM   org_members om
				 JOIN   subscriptions sub ON sub.org_id = om.org_id
				 JOIN   plans p           ON p.id = sub.plan_id
				 WHERE  om.user_id = u.id
				   AND  sub.status IN ('trialing','active')
				 ORDER  BY p.price_monthly DESC
				 LIMIT  1),
				'free'
			) AS plan
		FROM users u
		WHERE u.id = $1 AND u.is_active = true`

	var p UserProfile
	err := s.pool.QueryRow(ctx, q, userID).Scan(
		&p.ID, &p.Email, &p.DisplayName, &p.AvatarURL,
		&p.Timezone, &p.Role, &p.CreatedAt, &p.Plan,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserProfile{}, ErrNotFound
		}
		return UserProfile{}, fmt.Errorf("get profile: %w", err)
	}

	orgs, err := s.getOrgs(ctx, userID)
	if err != nil {
		return UserProfile{}, err
	}
	p.Orgs = orgs
	return p, nil
}

func (s *ProfileStore) getOrgs(ctx context.Context, userID string) ([]UserOrg, error) {
	const q = `
		SELECT o.id, o.name, om.role::text
		FROM   org_members om
		JOIN   organisations o ON o.id = om.org_id
		WHERE  om.user_id = $1
		ORDER  BY o.name`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get user orgs: %w", err)
	}
	defer rows.Close()

	var orgs []UserOrg
	for rows.Next() {
		var o UserOrg
		if err := rows.Scan(&o.ID, &o.Name, &o.Role); err != nil {
			return nil, fmt.Errorf("scan org: %w", err)
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

// UpdateProfile applies a partial update to the authenticated user's profile.
func (s *ProfileStore) UpdateProfile(ctx context.Context, userID string, p UpdateProfileParams) (UpdatedProfile, error) {
	// Build the SET clause dynamically from non-nil fields.
	setClauses := []string{}
	args := []any{}
	argIdx := 1

	if p.DisplayName != nil {
		setClauses = append(setClauses, fmt.Sprintf("display_name = $%d", argIdx))
		args = append(args, *p.DisplayName)
		argIdx++
	}
	if p.AvatarURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("avatar_url = $%d", argIdx))
		args = append(args, *p.AvatarURL)
		argIdx++
	}
	if p.Timezone != nil {
		setClauses = append(setClauses, fmt.Sprintf("timezone = $%d", argIdx))
		args = append(args, *p.Timezone)
		argIdx++
	}

	if len(setClauses) == 0 {
		// Nothing to update — return current values.
		const sel = `SELECT id, COALESCE(display_name,''), updated_at FROM users WHERE id = $1`
		var u UpdatedProfile
		if err := s.pool.QueryRow(ctx, sel, userID).Scan(&u.ID, &u.DisplayName, &u.UpdatedAt); err != nil {
			return UpdatedProfile{}, fmt.Errorf("get profile for no-op update: %w", err)
		}
		return u, nil
	}

	// Append the WHERE clause argument.
	args = append(args, userID)
	query := fmt.Sprintf(
		`UPDATE users SET %s WHERE id = $%d RETURNING id, COALESCE(display_name,''), updated_at`,
		joinClauses(setClauses),
		argIdx,
	)

	var u UpdatedProfile
	err := s.pool.QueryRow(ctx, query, args...).Scan(&u.ID, &u.DisplayName, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UpdatedProfile{}, ErrNotFound
		}
		return UpdatedProfile{}, fmt.Errorf("update profile: %w", err)
	}
	return u, nil
}

// GetProgress returns enrollment + step progress for all tracks the user is enrolled in.
func (s *ProfileStore) GetProgress(ctx context.Context, userID string) ([]EnrollmentProgress, error) {
	const q = `
		SELECT
			e.track_id::text,
			t.title,
			e.enrolled_at,
			e.completed_at,
			COALESCE(uts.pct_complete, 0)       AS pct_complete,
			COALESCE(uts.steps_passed, 0)        AS steps_passed,
			COALESCE(uts.total_steps, 0)         AS total_steps,
			COALESCE(uts.total_time_secs, 0)     AS total_time_secs,
			COALESCE(uts.total_hints, 0)         AS hints_used
		FROM enrollments e
		JOIN tracks t ON t.id = e.track_id
		LEFT JOIN user_track_summary uts
			ON uts.user_id = e.user_id AND uts.track_id = e.track_id
		WHERE e.user_id = $1
		ORDER BY e.enrolled_at DESC`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get progress: %w", err)
	}
	defer rows.Close()

	var result []EnrollmentProgress
	for rows.Next() {
		var ep EnrollmentProgress
		if err := rows.Scan(
			&ep.TrackID, &ep.TrackTitle, &ep.EnrolledAt, &ep.CompletedAt,
			&ep.PctComplete, &ep.StepsPassed, &ep.TotalSteps,
			&ep.TotalTimeSecs, &ep.HintsUsed,
		); err != nil {
			return nil, fmt.Errorf("scan progress: %w", err)
		}
		result = append(result, ep)
	}
	return result, rows.Err()
}

// GetCertificates returns all certificates earned by the user.
func (s *ProfileStore) GetCertificates(ctx context.Context, userID string) ([]Certificate, error) {
	const q = `
		SELECT
			c.id::text,
			t.title,
			c.issued_at,
			c.final_score,
			c.verify_token
		FROM certificates c
		JOIN tracks t ON t.id = c.track_id
		WHERE c.user_id = $1
		ORDER BY c.issued_at DESC`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.TrackTitle, &c.IssuedAt, &c.FinalScore, &c.VerifyToken); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// GetPublicProfile returns the public-facing profile for any user.
func (s *ProfileStore) GetPublicProfile(ctx context.Context, targetID string) (PublicProfile, error) {
	const q = `
		SELECT
			u.id::text,
			COALESCE(u.display_name, '') AS display_name,
			COALESCE(u.avatar_url, '')   AS avatar_url,
			COUNT(c.id)                  AS certificates_count
		FROM users u
		LEFT JOIN certificates c ON c.user_id = u.id
		WHERE u.id = $1 AND u.is_active = true
		GROUP BY u.id`

	var p PublicProfile
	err := s.pool.QueryRow(ctx, q, targetID).
		Scan(&p.ID, &p.DisplayName, &p.AvatarURL, &p.CertificatesCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicProfile{}, ErrNotFound
		}
		return PublicProfile{}, fmt.Errorf("get public profile: %w", err)
	}
	return p, nil
}

// joinClauses joins SET clause fragments with ", ".
func joinClauses(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}
