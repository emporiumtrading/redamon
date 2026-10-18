CREATE TABLE gabriel_identity.organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100)
);
CREATE TABLE gabriel_identity.users (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    id uuid NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, username)
);
CREATE TABLE gabriel_identity.memberships (
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id, user_id)
        REFERENCES gabriel_identity.users(organization_id, id)
);
CREATE TABLE gabriel_identity.sessions (
    token_digest text PRIMARY KEY CHECK (length(token_digest) = 64),
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    audience text NOT NULL CHECK (audience = 'gabriel-identity-v1'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    FOREIGN KEY (organization_id, user_id)
        REFERENCES gabriel_identity.memberships(organization_id, user_id),
    CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user ON gabriel_identity.sessions(organization_id, user_id);
CREATE TABLE gabriel_identity.login_attempts (
    identity_digest text PRIMARY KEY,
    attempts integer NOT NULL CHECK (attempts BETWEEN 0 AND 6),
    window_started timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE gabriel_identity.audit_events (
    id uuid PRIMARY KEY,
    organization_id uuid,
    actor_id uuid,
    event text NOT NULL,
    target_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA gabriel_identity FROM PUBLIC;
GRANT USAGE ON SCHEMA gabriel_identity TO gabriel_identity_app;
GRANT SELECT ON gabriel_identity.organizations TO gabriel_identity_app;
GRANT SELECT, INSERT, UPDATE ON gabriel_identity.users,
    gabriel_identity.memberships, gabriel_identity.sessions,
    gabriel_identity.login_attempts TO gabriel_identity_app;
GRANT SELECT, INSERT ON gabriel_identity.audit_events TO gabriel_identity_app;
