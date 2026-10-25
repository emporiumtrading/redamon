ALTER TABLE gabriel_identity.coordinator_runs ADD COLUMN input_evidence_id uuid;
ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_input_case
    FOREIGN KEY (organization_id,case_id,input_evidence_id)
    REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id);
CREATE INDEX coordinator_input_evidence ON gabriel_identity.coordinator_runs(organization_id,case_id,input_evidence_id);
ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_runs_plan_version_check;
ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_runs_max_steps_check;
ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_plan_bounds CHECK (
    (plan_version='local-coordinator-v1' AND input_evidence_id IS NULL AND max_steps BETWEEN 1 AND 2) OR
    (plan_version='local-specialist-coordinator-v2' AND input_evidence_id IS NOT NULL AND max_steps=12)
);
ALTER TABLE gabriel_identity.coordinator_steps DROP CONSTRAINT coordinator_steps_sequence_check;
ALTER TABLE gabriel_identity.coordinator_steps DROP CONSTRAINT coordinator_steps_check;
ALTER TABLE gabriel_identity.coordinator_steps ADD CONSTRAINT coordinator_operation_bounds CHECK (
    (sequence=1 AND operation IN ('evidence_inventory','telemetry_health')) OR
    (sequence=2 AND operation IN ('telemetry_health','alert_triage')) OR
    (sequence=3 AND operation='incident_scoping') OR
    (sequence=4 AND operation='threat_intelligence') OR
    (sequence=5 AND operation='threat_hunting') OR
    (sequence=6 AND operation='dfir_evidence') OR
    (sequence=7 AND operation='detection_engineering') OR
    (sequence=8 AND operation='exposure_vulnerability') OR
    (sequence=9 AND operation='identity_access') OR
    (sequence=10 AND operation='cloud_supply_chain') OR
    (sequence=11 AND operation='response_remediation') OR
    (sequence=12 AND operation='recovery_learning')
);
