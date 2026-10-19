CREATE TABLE gabriel_identity.checkpoint_keys (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
    public_document jsonb NOT NULL CHECK (jsonb_typeof(public_document)='object'),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,fingerprint),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX checkpoint_key_actor ON gabriel_identity.checkpoint_keys(organization_id,created_by);
CREATE TABLE gabriel_identity.checkpoint_key_revocations (
    organization_id uuid NOT NULL,
    fingerprint text NOT NULL,
    revoked_by uuid NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 400),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,fingerprint),
    FOREIGN KEY (organization_id,fingerprint) REFERENCES gabriel_identity.checkpoint_keys(organization_id,fingerprint),
    FOREIGN KEY (organization_id,revoked_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX checkpoint_revocation_actor ON gabriel_identity.checkpoint_key_revocations(organization_id,revoked_by);
CREATE TABLE gabriel_identity.checkpoint_policies (
    organization_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision BETWEEN 1 AND 1024),
    fingerprint text NOT NULL,
    max_age_seconds integer NOT NULL CHECK (max_age_seconds BETWEEN 60 AND 86400),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,revision),
    FOREIGN KEY (organization_id,fingerprint) REFERENCES gabriel_identity.checkpoint_keys(organization_id,fingerprint),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX checkpoint_policy_key ON gabriel_identity.checkpoint_policies(organization_id,fingerprint);
CREATE INDEX checkpoint_policy_actor ON gabriel_identity.checkpoint_policies(organization_id,created_by);
CREATE TABLE gabriel_identity.checkpoint_captures (
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    nonce uuid NOT NULL,
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^[a-f0-9]{64}$'),
    captured_at timestamptz NOT NULL,
    created_by uuid NOT NULL,
    PRIMARY KEY (organization_id,case_id,nonce),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX checkpoint_capture_actor ON gabriel_identity.checkpoint_captures(organization_id,created_by);
CREATE TABLE gabriel_identity.checkpoint_receipts (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision BETWEEN 1 AND 4096),
    nonce uuid NOT NULL,
    policy_revision integer NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope)='object'),
    accepted_by uuid NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,revision),
    UNIQUE (organization_id,case_id,nonce),
    UNIQUE (organization_id,digest),
    FOREIGN KEY (organization_id,case_id,nonce) REFERENCES gabriel_identity.checkpoint_captures(organization_id,case_id,nonce),
    FOREIGN KEY (organization_id,policy_revision) REFERENCES gabriel_identity.checkpoint_policies(organization_id,revision),
    FOREIGN KEY (organization_id,accepted_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX checkpoint_receipt_actor ON gabriel_identity.checkpoint_receipts(organization_id,accepted_by);
CREATE INDEX checkpoint_receipt_policy ON gabriel_identity.checkpoint_receipts(organization_id,policy_revision);
REVOKE ALL ON gabriel_identity.checkpoint_keys,gabriel_identity.checkpoint_key_revocations,
    gabriel_identity.checkpoint_policies,gabriel_identity.checkpoint_captures,gabriel_identity.checkpoint_receipts FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.checkpoint_keys,gabriel_identity.checkpoint_key_revocations,
    gabriel_identity.checkpoint_policies,gabriel_identity.checkpoint_captures,gabriel_identity.checkpoint_receipts TO gabriel_identity_app;

CREATE FUNCTION gabriel_identity.require_case_checkpoint() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM gabriel_identity.checkpoint_policies WHERE organization_id=NEW.organization_id) THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM gabriel_identity.checkpoint_policies p
        JOIN gabriel_identity.checkpoint_receipts r ON r.organization_id=p.organization_id AND r.policy_revision=p.revision
        JOIN gabriel_identity.checkpoint_captures c ON (c.organization_id,c.case_id,c.nonce)=(r.organization_id,r.case_id,r.nonce)
        WHERE p.organization_id=NEW.organization_id AND r.case_id=NEW.id
          AND p.revision=(SELECT max(revision) FROM gabriel_identity.checkpoint_policies WHERE organization_id=p.organization_id)
          AND r.revision=(SELECT max(revision) FROM gabriel_identity.checkpoint_receipts WHERE organization_id=r.organization_id AND case_id=r.case_id)
          AND r.id::text=current_setting('gabriel.checkpoint_receipt',true)
          AND r.digest=current_setting('gabriel.checkpoint_digest',true)
          AND c.captured_at<=clock_timestamp()
          AND c.captured_at+make_interval(secs=>p.max_age_seconds)>clock_timestamp()
          AND NOT EXISTS (SELECT 1 FROM gabriel_identity.checkpoint_key_revocations k WHERE k.organization_id=p.organization_id AND k.fingerprint=p.fingerprint)
          AND NOT EXISTS (
              SELECT 1 FROM gabriel_identity.evidence_objects e WHERE e.organization_id=r.organization_id AND e.case_id=r.case_id
              AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(r.envelope->'body'->'snapshot'->'evidence') b WHERE b->>'evidence_id'=e.id::text)
          )
          AND NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements(r.envelope->'body'->'snapshot'->'evidence') b
              WHERE NOT EXISTS (SELECT 1 FROM gabriel_identity.evidence_objects e
                  JOIN gabriel_identity.custody_events v ON (v.organization_id,v.evidence_id)=(e.organization_id,e.id)
                  WHERE e.organization_id=r.organization_id AND e.case_id=r.case_id AND e.id::text=b->>'evidence_id'
                    AND v.sequence::text=b->>'sequence' AND v.event_hash=b->>'head')
          )
    ) THEN
        RAISE EXCEPTION 'case_checkpoint_required' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_case_checkpoint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_case_checkpoint() TO gabriel_identity_app;
CREATE TRIGGER require_case_checkpoint BEFORE UPDATE OF state,closed_at ON gabriel_identity.cases
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_case_checkpoint();
