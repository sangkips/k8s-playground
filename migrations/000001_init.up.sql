-- ============================================================
--  K8S GUIDED LEARNING PLATFORM — PostgreSQL Schema
--  Database: PostgreSQL 15+
--  Extensions: pgcrypto (uuid), pg_trgm (search)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================
--  ENUMS
-- ============================================================

CREATE TYPE user_role AS ENUM ('learner', 'instructor', 'org_admin', 'superadmin');
CREATE TYPE org_member_role AS ENUM ('member', 'admin', 'owner');
CREATE TYPE plan_slug AS ENUM ('free', 'pro', 'team', 'enterprise');
CREATE TYPE sub_status AS ENUM ('trialing', 'active', 'past_due', 'cancelled', 'paused');
CREATE TYPE track_status AS ENUM ('draft', 'review', 'published', 'archived');
CREATE TYPE difficulty AS ENUM ('beginner', 'intermediate', 'advanced');
CREATE TYPE step_status AS ENUM ('locked', 'unlocked', 'in_progress', 'passed', 'skipped');
CREATE TYPE session_status AS ENUM ('provisioning', 'active', 'idle', 'expired', 'destroyed', 'error');
CREATE TYPE check_type AS ENUM (
  'k8s_resource_exists',     -- deployment/svc/cm exists in namespace
  'k8s_resource_state',      -- replicas ready, pod running, etc.
  'k8s_config_field',        -- specific field value on a resource
  'k8s_probe_defined',       -- liveness/readiness probe present
  'k8s_no_root_container',   -- securityContext.runAsNonRoot
  'k8s_resource_limits_set', -- requests + limits both present
  'k8s_secret_not_in_env',   -- no raw secrets in env vars
  'k8s_hpa_exists',          -- HPA attached to workload
  'k8s_pdb_exists',          -- PodDisruptionBudget present
  'k8s_ingress_tls',         -- ingress has TLS block
  'k8s_rbac_scoped',         -- no cluster-admin bindings
  'cicd_pipeline_passed',    -- GitHub Actions / GitLab latest run green
  'cicd_trivy_clean',        -- no CRITICAL CVEs in last scan
  'file_content_match',      -- regex match on a file in the repo
  'http_endpoint_healthy',   -- GET /healthz returns 2xx
  'custom_script'            -- arbitrary shell script, exit 0 = pass
);
CREATE TYPE event_type AS ENUM (
  'sandbox.created', 'sandbox.destroyed', 'sandbox.expired',
  'gate.passed', 'gate.failed', 'gate.evaluated',
  'step.started', 'step.completed',
  'track.enrolled', 'track.completed',
  'cert.issued',
  'hint.revealed',
  'user.created', 'user.login', 'user.logout',
  'org.member_invited', 'org.member_joined',
  'billing.subscription_created', 'billing.subscription_cancelled'
);

-- ============================================================
--  1. AUTH — users & sessions
-- ============================================================

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  password_hash text, -- null for OAuth-only accounts
  role user_role NOT NULL DEFAULT 'learner',
  display_name text,
  avatar_url text,
  timezone text NOT NULL DEFAULT 'UTC',
  is_active boolean NOT NULL DEFAULT true,
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- OAuth / SSO identities linked to a user
CREATE TABLE user_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL, -- 'github', 'google', 'saml'
  provider_id text NOT NULL, -- provider's user id
  access_token_enc text, -- encrypted, for GitHub API calls
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_id)
);

-- JWT jti allowlist (revocation list lives in Redis; this is the DB source)
CREATE TABLE user_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  jwt_jti text NOT NULL UNIQUE, -- matches JWT `jti` claim
  ip_address inet,
  user_agent text,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON user_sessions (user_id);
CREATE INDEX ON user_sessions (jwt_jti);
CREATE INDEX ON user_sessions (expires_at) WHERE revoked_at IS NULL;

-- ============================================================
--  2. ORGS & BILLING
-- ============================================================

CREATE TABLE plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug plan_slug NOT NULL UNIQUE,
  name text NOT NULL,
  price_monthly numeric(10,2) NOT NULL DEFAULT 0, -- USD, 0 = free
  max_seats int, -- null = unlimited
  max_sessions int NOT NULL DEFAULT 3, -- concurrent lab sessions per user
  max_tracks int, -- null = unlimited
  session_ttl_mins int NOT NULL DEFAULT 60,
  features jsonb NOT NULL DEFAULT '{}', -- feature flags
  is_public boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Seed default plans
INSERT INTO plans (slug, name, price_monthly, max_seats, max_sessions, max_tracks, session_ttl_mins) VALUES
  ('free', 'Free', 0, 1, 1, 1, 45),
  ('pro', 'Pro', 19, 1, 3, NULL, 120),
  ('team', 'Team', 99, 25, 5, NULL, 180),
  ('enterprise', 'Enterprise', 0, NULL, 10, NULL, 480); -- price negotiated

CREATE TABLE organisations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  logo_url text,
  stripe_customer_id text UNIQUE,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role org_member_role NOT NULL DEFAULT 'member',
  invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
  invited_at timestamptz NOT NULL DEFAULT now(),
  joined_at timestamptz,
  UNIQUE (org_id, user_id)
);

CREATE INDEX ON org_members (org_id);
CREATE INDEX ON org_members (user_id);

CREATE TABLE subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  plan_id uuid NOT NULL REFERENCES plans(id),
  status sub_status NOT NULL DEFAULT 'trialing',
  stripe_sub_id text UNIQUE,
  current_period_start timestamptz,
  current_period_end timestamptz,
  cancelled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON subscriptions (org_id);
CREATE INDEX ON subscriptions (stripe_sub_id);

-- ============================================================
--  3. TRACKS & COURSE CONTENT
-- ============================================================

CREATE TABLE tracks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  title text NOT NULL,
  description_md text,
  cover_image_url text,
  author_id uuid REFERENCES users(id) ON DELETE SET NULL,
  org_id uuid REFERENCES organisations(id) ON DELETE SET NULL, -- null = platform-owned
  difficulty difficulty NOT NULL DEFAULT 'beginner',
  tags text[] NOT NULL DEFAULT '{}',
  status track_status NOT NULL DEFAULT 'draft',
  version int NOT NULL DEFAULT 1, -- bumped on breaking changes
  estimated_mins int, -- total track estimate
  is_free boolean NOT NULL DEFAULT false, -- free preview track
  published_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON tracks USING gin(tags);
CREATE INDEX ON tracks USING gin(to_tsvector('english', title || ' ' || coalesce(description_md, '')));

-- Steps within a track (ordered)
CREATE TABLE steps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  track_id uuid NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
  position int NOT NULL, -- 1-based display order
  title text NOT NULL,
  concept_md text NOT NULL, -- the "why" — concept explanation
  task_md text NOT NULL, -- the "what to do" instruction
  prereq_state jsonb, -- sandbox bootstrap spec (injected before step starts)
  tools_required text[] NOT NULL DEFAULT '{}', -- e.g. ['helm','trivy']
  estimated_mins int,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (track_id, position)
);

CREATE INDEX ON steps (track_id, position);

-- Ordered hints per step (revealed one at a time)
CREATE TABLE step_hints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  step_id uuid NOT NULL REFERENCES steps(id) ON DELETE CASCADE,
  position int NOT NULL, -- reveal order
  body_md text NOT NULL,
  is_ai_fallback boolean NOT NULL DEFAULT false, -- true = used when scripted hints exhausted
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (step_id, position)
);

CREATE INDEX ON step_hints (step_id, position);

-- Gate checks — what must be true for a step to pass
-- A step can have multiple checks; all required=true checks must pass
CREATE TABLE gate_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  step_id uuid NOT NULL REFERENCES steps(id) ON DELETE CASCADE,
  check_type check_type NOT NULL,
  spec jsonb NOT NULL,
  -- spec examples:
  --   k8s_resource_exists:   {"kind":"Deployment","name":"nginx","namespace":"web"}
  --   k8s_resource_state:    {"kind":"Deployment","name":"nginx","namespace":"web","field":"status.readyReplicas","op":"gte","value":2}
  --   k8s_probe_defined:     {"kind":"Deployment","name":"nginx","namespace":"web","probe":"readiness"}
  --   cicd_pipeline_passed:  {"provider":"github","repo":"org/repo","branch":"main"}
  --   http_endpoint_healthy: {"url":"http://nginx.web.svc/healthz","expected_status":200}
  --   custom_script:         {"script":"kubectl get cm app-config -n web -o json | jq -e '.data.LOG_LEVEL'"}
  weight int NOT NULL DEFAULT 1, -- for partial scoring
  required boolean NOT NULL DEFAULT true, -- false = advisory only
  error_message text NOT NULL, -- shown when check fails
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON gate_checks (step_id);

-- ============================================================
--  4. ENROLLMENTS & PROGRESS
-- ============================================================

CREATE TABLE enrollments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  track_id uuid NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
  org_id uuid REFERENCES organisations(id) ON DELETE SET NULL, -- set if enrolled via org
  enrolled_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  last_active_at timestamptz,
  UNIQUE (user_id, track_id)
);

CREATE INDEX ON enrollments (user_id);
CREATE INDEX ON enrollments (track_id);
CREATE INDEX ON enrollments (org_id);

-- Per-step progress (one row per step per enrollment)
CREATE TABLE step_progress (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id uuid NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
  step_id uuid NOT NULL REFERENCES steps(id) ON DELETE CASCADE,
  status step_status NOT NULL DEFAULT 'locked',
  started_at timestamptz,
  completed_at timestamptz,
  time_spent_secs int NOT NULL DEFAULT 0,
  hints_used int NOT NULL DEFAULT 0,
  gate_attempts int NOT NULL DEFAULT 0,
  last_score numeric(5,2), -- 0-100, last gate run score
  UNIQUE (enrollment_id, step_id)
);

CREATE INDEX ON step_progress (enrollment_id);
CREATE INDEX ON step_progress (step_id);

-- ============================================================
--  5. LAB SESSIONS & SANDBOXES
-- ============================================================

CREATE TABLE lab_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  enrollment_id uuid NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
  step_id uuid NOT NULL REFERENCES steps(id),
  -- vcluster details
  vcluster_name text NOT NULL UNIQUE, -- e.g. "lab-{short-uuid}"
  namespace text NOT NULL, -- host namespace it lives in
  kubeconfig_enc text, -- AES-256 encrypted kubeconfig
  terminal_token text NOT NULL UNIQUE, -- short-lived WS auth token
  -- lifecycle
  status session_status NOT NULL DEFAULT 'provisioning',
  provisioned_at timestamptz,
  expires_at timestamptz NOT NULL, -- hard TTL from plan
  last_active_at timestamptz,
  destroyed_at timestamptz,
  error_message text,
  -- resource tracking
  cpu_limit text NOT NULL DEFAULT '2', -- e.g. "2" cores
  memory_limit text NOT NULL DEFAULT '4Gi',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON lab_sessions (user_id);
CREATE INDEX ON lab_sessions (enrollment_id);
CREATE INDEX ON lab_sessions (status) WHERE status IN ('provisioning','active','idle');
CREATE INDEX ON lab_sessions (expires_at) WHERE destroyed_at IS NULL;

-- Results of each gate validation run
CREATE TABLE gate_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES lab_sessions(id) ON DELETE CASCADE,
  step_id uuid NOT NULL REFERENCES steps(id),
  user_id uuid NOT NULL REFERENCES users(id),
  passed boolean NOT NULL,
  score numeric(5,2), -- 0-100 weighted score
  check_details jsonb NOT NULL DEFAULT '[]',
  -- check_details structure:
  -- [{"check_id":"uuid","type":"k8s_resource_exists","passed":true,"message":"Deployment nginx found"},...]
  evaluated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON gate_results (session_id, step_id);
CREATE INDEX ON gate_results (user_id, step_id);

-- ============================================================
--  6. CERTIFICATES
-- ============================================================

CREATE TABLE certificates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  track_id uuid NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
  enrollment_id uuid NOT NULL REFERENCES enrollments(id),
  verify_token text NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(24), 'hex'),
  track_version int NOT NULL, -- snapshot of version at issue time
  final_score numeric(5,2),
  total_time_secs int,
  hints_used int,
  gate_attempts int,
  issued_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, track_id) -- one cert per track per user
);

CREATE INDEX ON certificates (user_id);
CREATE INDEX ON certificates (verify_token);

-- ============================================================
--  7. AUDIT LOG
-- ============================================================

-- Append-only. Never UPDATE or DELETE rows here.
-- Partitioned by month for long-term retention manageability.
CREATE TABLE audit_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  org_id uuid REFERENCES organisations(id) ON DELETE SET NULL,
  session_id uuid REFERENCES lab_sessions(id) ON DELETE SET NULL,
  event_type event_type NOT NULL,
  entity_type text, -- 'track', 'step', 'sandbox', etc.
  entity_id uuid,
  payload jsonb NOT NULL DEFAULT '{}', -- event-specific data
  ip_address inet,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (created_at, id)
) PARTITION BY RANGE (created_at);

-- Create partitions for the current quarter + next 3 quarters.
-- This replaces the earlier hard-coded 2025/2026 list so fresh tenants can insert immediately.
DO $$
DECLARE
  start_q date := date_trunc('quarter', current_date)::date;
  i int;
  from_date date;
  to_date date;
  part_name text;
BEGIN
  FOR i IN 0..3 LOOP
    from_date := (start_q + (i * interval '3 months'))::date;
    to_date := (start_q + ((i + 1) * interval '3 months'))::date;

    -- part_name example: audit_events_2026_q2
    part_name := format('audit_events_%s', to_char(from_date, 'YYYY"_q"Q'));

    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L);',
      part_name,
      from_date,
      to_date
    );
  END LOOP;
END $$;

CREATE INDEX ON audit_events (user_id, created_at);
CREATE INDEX ON audit_events (org_id, created_at);
CREATE INDEX ON audit_events (event_type, created_at);
CREATE INDEX ON audit_events (entity_type, entity_id);

-- ============================================================
--  8. USEFUL VIEWS
-- ============================================================

-- Current active lab session per user (at most one active per user)
CREATE VIEW active_lab_sessions AS
SELECT
  ls.*,
  u.email,
  u.display_name,
  e.track_id,
  s.title AS step_title,
  s.position AS step_position
FROM lab_sessions ls
JOIN users u ON u.id = ls.user_id
JOIN enrollments e ON e.id = ls.enrollment_id
JOIN steps s ON s.id = ls.step_id
WHERE ls.status IN ('provisioning', 'active', 'idle')
  AND ls.destroyed_at IS NULL;

-- Per-user track completion summary
CREATE VIEW user_track_summary AS
SELECT
  e.user_id,
  e.track_id,
  t.title AS track_title,
  t.difficulty,
  e.enrolled_at,
  e.completed_at,
  COUNT(sp.id) AS total_steps,
  COUNT(sp.id) FILTER (WHERE sp.status = 'passed') AS steps_passed,
  SUM(sp.time_spent_secs) AS total_time_secs,
  SUM(sp.hints_used) AS total_hints,
  SUM(sp.gate_attempts) AS total_attempts,
  ROUND(
    100.0 * COUNT(sp.id) FILTER (WHERE sp.status = 'passed') / NULLIF(COUNT(sp.id), 0), 1
  ) AS pct_complete
FROM enrollments e
JOIN tracks t ON t.id = e.track_id
LEFT JOIN step_progress sp ON sp.enrollment_id = e.id
GROUP BY e.user_id, e.track_id, t.title, t.difficulty, e.enrolled_at, e.completed_at;

-- Org-wide leaderboard for a given track
CREATE VIEW org_track_leaderboard AS
SELECT
  om.org_id,
  e.track_id,
  u.id AS user_id,
  u.display_name,
  u.avatar_url,
  e.completed_at,
  SUM(sp.time_spent_secs) AS total_time_secs,
  SUM(sp.hints_used) AS total_hints,
  SUM(sp.gate_attempts) AS total_attempts,
  c.final_score
FROM org_members om
JOIN users u ON u.id = om.user_id
JOIN enrollments e ON e.user_id = u.id
LEFT JOIN step_progress sp ON sp.enrollment_id = e.id
LEFT JOIN certificates c ON c.user_id = u.id AND c.track_id = e.track_id
GROUP BY om.org_id, e.track_id, u.id, u.display_name, u.avatar_url, e.completed_at, c.final_score;

-- ============================================================
--  9. TRIGGERS — updated_at auto-maintenance
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_organisations_updated_at
  BEFORE UPDATE ON organisations
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_tracks_updated_at
  BEFORE UPDATE ON tracks
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_steps_updated_at
  BEFORE UPDATE ON steps
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_subscriptions_updated_at
  BEFORE UPDATE ON subscriptions
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
--  10. ROW-LEVEL SECURITY (enable after app user is created)
-- ============================================================

-- Example: learners can only see their own progress
-- ALTER TABLE step_progress ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY learner_own_progress ON step_progress
--   USING (enrollment_id IN (
--     SELECT id FROM enrollments WHERE user_id = current_setting('app.user_id')::uuid
--   ));

-- ============================================================
--  END OF SCHEMA
-- ============================================================

