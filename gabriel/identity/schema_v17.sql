CREATE TABLE gabriel_identity.coordinator_runs (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    request_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    plan_version text NOT NULL CHECK (plan_version='local-coordinator-v1'),
    source_digest text NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    max_steps integer NOT NULL CHECK (max_steps BETWEEN 1 AND 2),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '15 minutes'),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,id),
    UNIQUE (organization_id,request_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX coordinator_run_case ON gabriel_identity.coordinator_runs(organization_id,case_id,created_at DESC);
CREATE INDEX coordinator_run_actor ON gabriel_identity.coordinator_runs(organization_id,requested_by);

CREATE TABLE gabriel_identity.coordinator_sources (
    organization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    case_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    PRIMARY KEY (organization_id,run_id,evidence_id),
    FOREIGN KEY (organization_id,case_id,run_id) REFERENCES gabriel_identity.coordinator_runs(organization_id,case_id,id),
    FOREIGN KEY (organization_id,case_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id)
);
CREATE INDEX coordinator_source_case_run ON gabriel_identity.coordinator_sources(organization_id,case_id,run_id);
CREATE INDEX coordinator_source_evidence ON gabriel_identity.coordinator_sources(organization_id,case_id,evidence_id);

CREATE TABLE gabriel_identity.coordinator_steps (
    organization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 2),
    operation text NOT NULL,
    request_id uuid NOT NULL,
    CHECK ((sequence=1 AND operation='evidence_inventory') OR (sequence=2 AND operation='telemetry_health')),
    PRIMARY KEY (organization_id,run_id,sequence),
    UNIQUE (organization_id,request_id),
    FOREIGN KEY (organization_id,run_id) REFERENCES gabriel_identity.coordinator_runs(organization_id,id)
);

CREATE TABLE gabriel_identity.coordinator_claims (
    organization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    sequence integer NOT NULL,
    claimed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,run_id,sequence),
    FOREIGN KEY (organization_id,run_id,sequence) REFERENCES gabriel_identity.coordinator_steps(organization_id,run_id,sequence),
    FOREIGN KEY (organization_id,claimed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX coordinator_claim_actor ON gabriel_identity.coordinator_claims(organization_id,claimed_by);

CREATE TABLE gabriel_identity.coordinator_results (
    organization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    sequence integer NOT NULL,
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=262144),
    result_digest text NOT NULL CHECK (result_digest ~ '^[a-f0-9]{64}$'),
    completed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,run_id,sequence),
    FOREIGN KEY (organization_id,run_id,sequence) REFERENCES gabriel_identity.coordinator_claims(organization_id,run_id,sequence),
    FOREIGN KEY (organization_id,completed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX coordinator_result_actor ON gabriel_identity.coordinator_results(organization_id,completed_by);

CREATE TABLE gabriel_identity.coordinator_stops (
    organization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    stopped_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,run_id),
    FOREIGN KEY (organization_id,run_id) REFERENCES gabriel_identity.coordinator_runs(organization_id,id),
    FOREIGN KEY (organization_id,stopped_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX coordinator_stop_actor ON gabriel_identity.coordinator_stops(organization_id,stopped_by);
REVOKE ALL ON gabriel_identity.coordinator_runs,gabriel_identity.coordinator_sources,
    gabriel_identity.coordinator_steps,gabriel_identity.coordinator_claims,
    gabriel_identity.coordinator_results,gabriel_identity.coordinator_stops FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.coordinator_runs,gabriel_identity.coordinator_sources,
    gabriel_identity.coordinator_steps,gabriel_identity.coordinator_claims,
    gabriel_identity.coordinator_results,gabriel_identity.coordinator_stops TO gabriel_identity_app;
