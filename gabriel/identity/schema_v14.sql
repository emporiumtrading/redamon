CREATE TABLE gabriel_identity.specialist_runs (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    request_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    role text NOT NULL CHECK (role='telemetry_health'),
    engine_version text NOT NULL CHECK (engine_version='telemetry-health-v1'),
    packet jsonb NOT NULL CHECK (jsonb_typeof(packet)='object' AND octet_length(packet::text)<=262144),
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=131072),
    packet_digest text NOT NULL CHECK (packet_digest ~ '^[0-9a-f]{64}$'),
    result_digest text NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,request_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX specialist_run_actor ON gabriel_identity.specialist_runs(organization_id,requested_by);
CREATE INDEX specialist_run_case_time ON gabriel_identity.specialist_runs(organization_id,case_id,created_at DESC,id DESC);
REVOKE ALL ON gabriel_identity.specialist_runs FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.specialist_runs TO gabriel_identity_app;
