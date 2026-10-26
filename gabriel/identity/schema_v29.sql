CREATE TABLE gabriel_identity.personal_provider_secrets (
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    id uuid NOT NULL,
    provider text NOT NULL CHECK (provider='openrouter'),
    revision integer NOT NULL CHECK (revision>0),
    key_id text NOT NULL,
    nonce bytea,
    ciphertext bytea,
    checked boolean NOT NULL,
    revoked_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,user_id,provider),
    UNIQUE (organization_id,id),
    UNIQUE (key_id,nonce),
    FOREIGN KEY (organization_id,user_id) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (key_id) REFERENCES gabriel_identity.provider_key_registry(key_id),
    CHECK ((revoked_at IS NULL AND octet_length(nonce)=12 AND octet_length(ciphertext)>16)
        OR (revoked_at IS NOT NULL AND nonce IS NULL AND ciphertext IS NULL AND NOT checked))
);
REVOKE ALL ON gabriel_identity.personal_provider_secrets FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON gabriel_identity.personal_provider_secrets TO gabriel_identity_app;

ALTER TABLE gabriel_identity.model_price_quotes ADD COLUMN purpose text NOT NULL DEFAULT 'operator'
    CHECK (purpose IN ('operator','personal_specialist'));

ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_plan_bounds;
ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_plan_bounds CHECK (
    (plan_version='local-coordinator-v1' AND input_evidence_id IS NULL AND max_steps BETWEEN 1 AND 2) OR
    (plan_version='local-specialist-coordinator-v2' AND input_evidence_id IS NOT NULL AND max_steps=12) OR
    (plan_version IN ('browser-ai-coordinator-v1','specialist-ai-coordinator-v1') AND input_evidence_id IS NOT NULL AND max_steps=1)
);

CREATE TABLE gabriel_identity.specialist_agent_jobs (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    request_id uuid NOT NULL,
    input_evidence_id uuid NOT NULL,
    role text NOT NULL,
    model text NOT NULL,
    key_scope text NOT NULL CHECK (key_scope IN ('personal','organization')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,requested_by,request_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,input_evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id)
);
CREATE TABLE gabriel_identity.specialist_agent_stops (
    organization_id uuid NOT NULL,
    job_id uuid NOT NULL,
    stopped_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,job_id),
    FOREIGN KEY (organization_id,job_id) REFERENCES gabriel_identity.specialist_agent_jobs(organization_id,id),
    FOREIGN KEY (organization_id,stopped_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
REVOKE ALL ON gabriel_identity.specialist_agent_jobs,gabriel_identity.specialist_agent_stops FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.specialist_agent_jobs,gabriel_identity.specialist_agent_stops TO gabriel_identity_app;
