CREATE TABLE gabriel_identity.service_grants (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    token_digest text NOT NULL UNIQUE CHECK (token_digest ~ '^[a-f0-9]{64}$'),
    issued_by uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    task_id uuid NOT NULL,
    issuer text NOT NULL CHECK (issuer = 'gabriel-identity-service-v1'),
    audience text NOT NULL CHECK (audience = 'gabriel-local-worker-v1'),
    resource text NOT NULL CHECK (resource = 'local-inspection-v1'),
    operations text[] NOT NULL CHECK (
        cardinality(operations) BETWEEN 1 AND 2
        AND operations <@ ARRAY['capabilities.list','evidence.hash']::text[]
        AND array_position(operations, NULL) IS NULL),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, issued_by)
        REFERENCES gabriel_identity.memberships(organization_id, user_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 hour')
);
CREATE INDEX service_grants_issuer ON gabriel_identity.service_grants(organization_id, issued_by);
REVOKE ALL ON gabriel_identity.service_grants FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON gabriel_identity.service_grants TO gabriel_identity_app;
