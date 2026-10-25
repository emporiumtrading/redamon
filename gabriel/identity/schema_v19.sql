CREATE TABLE gabriel_identity.provider_onboarding_checks (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    secret_id uuid NOT NULL,
    secret_revision integer NOT NULL CHECK (secret_revision>0),
    provider text NOT NULL CHECK (provider IN ('openrouter','nvidia')),
    status text NOT NULL CHECK (status IN ('funding_verified','validation_pending')),
    account_available_microusd bigint,
    key_available_microusd bigint,
    checked_by uuid NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,secret_id) REFERENCES gabriel_identity.provider_secrets(organization_id,id),
    FOREIGN KEY (organization_id,checked_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK ((provider='openrouter' AND status='funding_verified'
        AND account_available_microusd IS NOT NULL AND account_available_microusd>=18000000
        AND key_available_microusd IS NOT NULL AND key_available_microusd>=18000000)
        OR (provider='nvidia' AND status='validation_pending'
            AND account_available_microusd IS NULL AND key_available_microusd IS NULL))
);
CREATE INDEX provider_onboarding_secret ON gabriel_identity.provider_onboarding_checks
    (organization_id,secret_id,secret_revision,checked_at DESC,id DESC);
CREATE INDEX provider_onboarding_actor ON gabriel_identity.provider_onboarding_checks (organization_id,checked_by);
REVOKE ALL ON gabriel_identity.provider_onboarding_checks FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.provider_onboarding_checks TO gabriel_identity_app;
