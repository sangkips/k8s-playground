-- Opaque refresh tokens stored server-side.
-- Each row is tied to a user_session (JWT jti) so revoking a session
-- also invalidates its refresh token.
CREATE TABLE refresh_tokens (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id  uuid        NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
  token_hash  text        NOT NULL UNIQUE, -- SHA-256 hex of the opaque token
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON refresh_tokens (user_id);
CREATE INDEX ON refresh_tokens (token_hash);
CREATE INDEX ON refresh_tokens (expires_at) WHERE revoked_at IS NULL;
