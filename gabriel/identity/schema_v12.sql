ALTER TABLE gabriel_identity.browser_leases ADD COLUMN intake_enabled boolean NOT NULL DEFAULT false;
CREATE TABLE gabriel_identity.browser_observations (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    lease_id uuid NOT NULL,
    request_id uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000),
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    content_digest text NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    byte_length integer NOT NULL CHECK (byte_length BETWEEN 1 AND 65536),
    observed_at timestamptz NOT NULL,
    visibility text NOT NULL CHECK (visibility IN ('visible_text_only','partial')),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','captured')),
    evidence_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,lease_id,request_id),
    UNIQUE (organization_id,lease_id,sequence),
    FOREIGN KEY (organization_id,lease_id) REFERENCES gabriel_identity.browser_leases(organization_id,id),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    CHECK ((state='prepared' AND evidence_id IS NULL) OR (state='captured' AND evidence_id IS NOT NULL))
);
CREATE UNIQUE INDEX browser_one_pending_observation ON gabriel_identity.browser_observations(organization_id,lease_id) WHERE state='prepared';
CREATE INDEX browser_observation_evidence ON gabriel_identity.browser_observations(organization_id,evidence_id);
CREATE TABLE gabriel_identity.browser_observation_receipts (
    organization_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    completed_by uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('peer_intake','engineer_reconciled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,observation_id),
    FOREIGN KEY (organization_id,observation_id) REFERENCES gabriel_identity.browser_observations(organization_id,id),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    FOREIGN KEY (organization_id,completed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX browser_observation_receipt_evidence ON gabriel_identity.browser_observation_receipts(organization_id,evidence_id);
CREATE INDEX browser_observation_receipt_actor ON gabriel_identity.browser_observation_receipts(organization_id,completed_by);
REVOKE ALL ON gabriel_identity.browser_observations,gabriel_identity.browser_observation_receipts FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.browser_observations,gabriel_identity.browser_observation_receipts TO gabriel_identity_app;
GRANT UPDATE(state,evidence_id) ON gabriel_identity.browser_observations TO gabriel_identity_app;
CREATE FUNCTION gabriel_identity.require_browser_observation_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF OLD.state<>'prepared' OR NEW.state<>'captured' OR NOT EXISTS (
        SELECT 1 FROM gabriel_identity.browser_observation_receipts r WHERE r.organization_id=NEW.organization_id
            AND r.observation_id=NEW.id AND r.evidence_id=NEW.evidence_id
    ) THEN
        RAISE EXCEPTION 'browser_observation_receipt_required' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_browser_observation_receipt() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_browser_observation_receipt() TO gabriel_identity_app;
CREATE TRIGGER require_browser_observation_receipt BEFORE UPDATE ON gabriel_identity.browser_observations
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_browser_observation_receipt();
