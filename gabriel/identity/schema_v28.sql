ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_outcome_check;
ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_check;
ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_outcome_check
    CHECK (outcome IN ('operator_reported','not_sent','completed_upper_bound'));
ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_check
    CHECK ((outcome='not_sent' AND actual_microusd=0 AND receipt_digest IS NULL)
        OR (outcome IN ('operator_reported','completed_upper_bound') AND receipt_digest IS NOT NULL));

CREATE FUNCTION gabriel_identity.require_completed_model_ceiling() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE ceiling bigint;
BEGIN
    IF NEW.outcome='completed_upper_bound' THEN
        SELECT reserved_microusd INTO ceiling FROM gabriel_identity.model_reservations
            WHERE organization_id=NEW.organization_id AND id=NEW.reservation_id;
        IF ceiling IS NULL OR NEW.actual_microusd<>ceiling OR NOT EXISTS(
            SELECT 1 FROM gabriel_identity.model_answer_receipts r
            JOIN gabriel_identity.model_dispatch_claims c USING(organization_id,reservation_id)
            WHERE r.organization_id=NEW.organization_id AND r.reservation_id=NEW.reservation_id
                AND c.claimed_by=NEW.attested_by) THEN
            RAISE EXCEPTION 'completed_model_ceiling_receipt_required' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_completed_model_ceiling() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_completed_model_ceiling() TO gabriel_identity_app;
CREATE TRIGGER require_completed_model_ceiling BEFORE INSERT ON gabriel_identity.model_settlements
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_completed_model_ceiling();

ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_plan_bounds;
ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_plan_bounds CHECK (
    (plan_version='local-coordinator-v1' AND input_evidence_id IS NULL AND max_steps BETWEEN 1 AND 2) OR
    (plan_version='local-specialist-coordinator-v2' AND input_evidence_id IS NOT NULL AND max_steps=12) OR
    (plan_version='browser-ai-coordinator-v1' AND input_evidence_id IS NOT NULL AND max_steps=1)
);
