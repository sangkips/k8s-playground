-- Tokens for email verification and password reset.
-- A single table covers both use-cases via the `kind` column.
CREATE TYPE token_kind AS ENUM ('email_verification', 'password_reset');

CREATE TABLE verification_tokens (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       token_kind  NOT NULL,
  token_hash text        NOT NULL UNIQUE, -- SHA-256 hex of the opaque token
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON verification_tokens (user_id, kind);
CREATE INDEX ON verification_tokens (token_hash);
CREATE INDEX ON verification_tokens (expires_at) WHERE used_at IS NULL;
