CREATE TABLE gabriel_identity.browser_event_snapshots (
    organization_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    case_id uuid NOT NULL,
    created_by uuid NOT NULL,
    normalizer_version text NOT NULL CHECK (normalizer_version='generated-browser-events-v1'),
    source_refs jsonb NOT NULL CHECK (jsonb_typeof(source_refs)='array' AND jsonb_array_length(source_refs) BETWEEN 1 AND 32
        AND octet_length(source_refs::text)<=16384),
    source_digest text NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    omitted_observations integer NOT NULL CHECK (omitted_observations BETWEEN 0 AND 32),
    capture_received_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,observation_id),
    FOREIGN KEY (organization_id,observation_id) REFERENCES gabriel_identity.browser_observations(organization_id,id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX browser_event_snapshot_actor ON gabriel_identity.browser_event_snapshots(organization_id,created_by);
CREATE INDEX browser_event_snapshot_case ON gabriel_identity.browser_event_snapshots(organization_id,case_id);
REVOKE ALL ON gabriel_identity.browser_event_snapshots FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.browser_event_snapshots TO gabriel_identity_app;
