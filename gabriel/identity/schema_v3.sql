CREATE TABLE gabriel_identity.provider_key_registry (
    key_id text PRIMARY KEY,
    fingerprint text NOT NULL UNIQUE CHECK (fingerprint ~ '^[a-f0-9]{64}$')
);
CREATE TABLE gabriel_identity.provider_key_state (
    organization_id uuid PRIMARY KEY REFERENCES gabriel_identity.organizations(id),
    active_key_id text NOT NULL REFERENCES gabriel_identity.provider_key_registry(key_id),
    generation integer NOT NULL CHECK (generation BETWEEN 1 AND 1000000)
);
CREATE TABLE gabriel_identity.provider_secrets (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    id uuid NOT NULL,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{0,63}$'),
    purpose text NOT NULL CHECK (purpose = 'model-provider-v1'),
    revision integer NOT NULL CHECK (revision > 0),
    updated_by uuid NOT NULL,
    key_id text REFERENCES gabriel_identity.provider_key_registry(key_id),
    nonce bytea,
    ciphertext bytea,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, provider),
    UNIQUE (key_id, nonce),
    FOREIGN KEY (organization_id, updated_by)
        REFERENCES gabriel_identity.memberships(organization_id, user_id),
    CHECK ((revoked_at IS NULL AND key_id IS NOT NULL
            AND nonce IS NOT NULL AND octet_length(nonce) = 12
            AND ciphertext IS NOT NULL AND octet_length(ciphertext) BETWEEN 17 AND 8208)
        OR (revoked_at IS NOT NULL AND key_id IS NULL AND nonce IS NULL AND ciphertext IS NULL))
);
CREATE INDEX provider_secrets_member ON gabriel_identity.provider_secrets(organization_id, updated_by);
CREATE INDEX provider_secrets_key ON gabriel_identity.provider_secrets(key_id);
CREATE INDEX provider_key_state_key ON gabriel_identity.provider_key_state(active_key_id);
REVOKE ALL ON gabriel_identity.provider_key_registry,
    gabriel_identity.provider_key_state, gabriel_identity.provider_secrets FROM PUBLIC;
GRANT SELECT, INSERT ON gabriel_identity.provider_key_registry TO gabriel_identity_app;
GRANT SELECT, INSERT, UPDATE ON gabriel_identity.provider_key_state,
    gabriel_identity.provider_secrets TO gabriel_identity_app;
