ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_extension_version_check;
ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_extension_version_check
    CHECK (extension_version IN ('0.1.0','0.2.0','0.3.0'));
ALTER TABLE gabriel_identity.browser_event_snapshots ADD CONSTRAINT browser_snapshot_case_observation
    UNIQUE (organization_id,case_id,observation_id);

CREATE TABLE gabriel_identity.browser_specialist_suites (
    organization_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    case_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    created_by uuid NOT NULL,
    projector_version text NOT NULL CHECK (projector_version='browser-specialist-facts-v1'),
    normalized_evidence_id uuid NOT NULL,
    facts_evidence_id uuid NOT NULL,
    source_digest text NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    facts_digest text NOT NULL CHECK (facts_digest ~ '^[a-f0-9]{64}$'),
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=16384),
    result_digest text NOT NULL CHECK (result_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,observation_id),
    FOREIGN KEY (organization_id,case_id,observation_id) REFERENCES gabriel_identity.browser_event_snapshots(organization_id,case_id,observation_id),
    FOREIGN KEY (organization_id,lease_id) REFERENCES gabriel_identity.browser_leases(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,case_id,normalized_evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id),
    FOREIGN KEY (organization_id,case_id,facts_evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id)
);
CREATE INDEX browser_specialist_suite_actor ON gabriel_identity.browser_specialist_suites(organization_id,created_by);
CREATE INDEX browser_specialist_suite_lease ON gabriel_identity.browser_specialist_suites(organization_id,lease_id);
CREATE INDEX browser_specialist_suite_normalized ON gabriel_identity.browser_specialist_suites(organization_id,case_id,normalized_evidence_id);
CREATE INDEX browser_specialist_suite_facts ON gabriel_identity.browser_specialist_suites(organization_id,case_id,facts_evidence_id);
REVOKE ALL ON gabriel_identity.browser_specialist_suites FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.browser_specialist_suites TO gabriel_identity_app;
