ALTER TABLE gabriel_identity.specialist_runs DROP CONSTRAINT specialist_runs_role_check;
ALTER TABLE gabriel_identity.specialist_runs DROP CONSTRAINT specialist_runs_engine_version_check;
ALTER TABLE gabriel_identity.specialist_runs ADD CONSTRAINT specialist_runs_engine_version_check CHECK (
    (role='telemetry_health' AND engine_version='telemetry-health-v1') OR
    (engine_version='specialist-rules-v1' AND role IN ('telemetry_health','alert_triage','incident_scoping',
        'threat_intelligence','threat_hunting','dfir_evidence','detection_engineering','exposure_vulnerability',
        'identity_access','cloud_supply_chain','response_remediation','recovery_learning'))
);
