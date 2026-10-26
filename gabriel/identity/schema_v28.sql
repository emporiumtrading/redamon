ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_outcome_check;
ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_check;
ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_outcome_check
    CHECK (outcome IN ('operator_reported','not_sent','completed_upper_bound'));
ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_check
    CHECK ((outcome='not_sent' AND actual_microusd=0 AND receipt_digest IS NULL)
        OR (outcome IN ('operator_reported','completed_upper_bound') AND receipt_digest IS NOT NULL));
