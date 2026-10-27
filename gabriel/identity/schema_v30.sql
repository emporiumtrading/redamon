CREATE TABLE gabriel_identity.hermes_runs (
    organization_id uuid NOT NULL,
    run_id uuid NOT NULL,
    input_evidence_id uuid NOT NULL,
    model text NOT NULL,
    specialist_model text NOT NULL,
    key_scope text NOT NULL CHECK (key_scope IN ('personal','organization')),
    selected_leases uuid[] NOT NULL CHECK (cardinality(selected_leases)<=8 AND array_position(selected_leases,NULL) IS NULL),
    PRIMARY KEY (organization_id,run_id),
    FOREIGN KEY (organization_id,run_id) REFERENCES gabriel_identity.coordinator_runs(organization_id,id),
    FOREIGN KEY (organization_id,input_evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id)
);
ALTER TABLE gabriel_identity.specialist_agent_jobs ADD COLUMN supervisor_run_id uuid;
ALTER TABLE gabriel_identity.specialist_agent_jobs ADD CONSTRAINT specialist_hermes_run
    FOREIGN KEY (organization_id,supervisor_run_id) REFERENCES gabriel_identity.hermes_runs(organization_id,run_id);
REVOKE ALL ON gabriel_identity.hermes_runs FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.hermes_runs TO gabriel_identity_app;
