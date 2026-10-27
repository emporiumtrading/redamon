ALTER TABLE gabriel_identity.cases ADD COLUMN purpose text NOT NULL DEFAULT 'investigation'
    CHECK (purpose IN ('investigation','performance_test'));
CREATE FUNCTION gabriel_identity.require_case_purpose() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.purpose<>OLD.purpose THEN
        RAISE EXCEPTION 'case_purpose_immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER require_case_purpose BEFORE UPDATE OF purpose ON gabriel_identity.cases
    FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_case_purpose();
CREATE FUNCTION gabriel_identity.require_memory_case_purpose() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM gabriel_identity.cases
        WHERE organization_id=NEW.organization_id AND id=NEW.case_id AND purpose='investigation') THEN
        RAISE EXCEPTION 'performance_test_memory_excluded';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER require_memory_case_purpose BEFORE INSERT ON gabriel_identity.memory_records
    FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_memory_case_purpose();
REVOKE ALL ON FUNCTION gabriel_identity.require_case_purpose(),
    gabriel_identity.require_memory_case_purpose() FROM PUBLIC;
