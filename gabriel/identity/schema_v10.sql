CREATE TABLE gabriel_identity.evidence_key_epochs (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    generation integer NOT NULL CHECK (generation BETWEEN 1 AND 1000000),
    active_key_id text NOT NULL REFERENCES gabriel_identity.evidence_key_registry(key_id),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,generation),
    UNIQUE (organization_id,active_key_id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX evidence_epoch_actor ON gabriel_identity.evidence_key_epochs(organization_id,created_by);
CREATE INDEX evidence_epoch_key ON gabriel_identity.evidence_key_epochs(active_key_id);
CREATE TABLE gabriel_identity.evidence_rewraps (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 64),
    generation integer NOT NULL,
    source_key_id text NOT NULL REFERENCES gabriel_identity.evidence_key_registry(key_id),
    target_key_id text NOT NULL REFERENCES gabriel_identity.evidence_key_registry(key_id),
    context_digest text NOT NULL CHECK (context_digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','completed','aborted')),
    prepared_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,evidence_id,sequence),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    FOREIGN KEY (organization_id,generation) REFERENCES gabriel_identity.evidence_key_epochs(organization_id,generation),
    FOREIGN KEY (organization_id,prepared_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (source_key_id<>target_key_id)
);
CREATE UNIQUE INDEX evidence_one_rewrap ON gabriel_identity.evidence_rewraps(organization_id,evidence_id) WHERE state='prepared';
CREATE INDEX evidence_rewrap_source ON gabriel_identity.evidence_rewraps(source_key_id);
CREATE INDEX evidence_rewrap_target ON gabriel_identity.evidence_rewraps(target_key_id);
CREATE INDEX evidence_rewrap_epoch ON gabriel_identity.evidence_rewraps(organization_id,generation);
CREATE INDEX evidence_rewrap_actor ON gabriel_identity.evidence_rewraps(organization_id,prepared_by);
CREATE TABLE gabriel_identity.evidence_rewrap_results (
    organization_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('completed','aborted')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,attempt_id),
    FOREIGN KEY (organization_id,attempt_id) REFERENCES gabriel_identity.evidence_rewraps(organization_id,id),
    FOREIGN KEY (organization_id,actor_id) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX evidence_rewrap_result_actor ON gabriel_identity.evidence_rewrap_results(organization_id,actor_id);
REVOKE ALL ON gabriel_identity.evidence_key_epochs,gabriel_identity.evidence_rewraps,gabriel_identity.evidence_rewrap_results FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.evidence_key_epochs,gabriel_identity.evidence_rewraps,gabriel_identity.evidence_rewrap_results TO gabriel_identity_app;
GRANT UPDATE(state) ON gabriel_identity.evidence_rewraps TO gabriel_identity_app;
CREATE FUNCTION gabriel_identity.require_evidence_epoch() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE epoch record;
BEGIN
    SELECT * INTO epoch FROM gabriel_identity.evidence_key_epochs WHERE organization_id=NEW.organization_id ORDER BY generation DESC LIMIT 1;
    IF FOUND AND (current_setting('gabriel.evidence_generation',true) IS DISTINCT FROM epoch.generation::text
        OR (TG_OP='INSERT' AND NEW.key_id<>epoch.active_key_id)) THEN
        RAISE EXCEPTION 'evidence_key_epoch_required' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_evidence_epoch() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_evidence_epoch() TO gabriel_identity_app;
CREATE TRIGGER require_evidence_insert_epoch BEFORE INSERT ON gabriel_identity.evidence_objects
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_evidence_epoch();
CREATE TRIGGER require_evidence_update_epoch BEFORE UPDATE OF state,failure_code ON gabriel_identity.evidence_objects
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_evidence_epoch();
CREATE FUNCTION gabriel_identity.require_rewrap_result() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF OLD.state<>'prepared' OR NEW.state NOT IN ('completed','aborted') OR NOT EXISTS (
        SELECT 1 FROM gabriel_identity.evidence_rewrap_results r
        WHERE r.organization_id=NEW.organization_id AND r.attempt_id=NEW.id AND r.outcome=NEW.state
    ) THEN
        RAISE EXCEPTION 'rewrap_result_required' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_rewrap_result() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_rewrap_result() TO gabriel_identity_app;
CREATE TRIGGER require_rewrap_result BEFORE UPDATE ON gabriel_identity.evidence_rewraps
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_rewrap_result();
