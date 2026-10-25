ALTER TABLE gabriel_identity.evidence_objects
    DROP CONSTRAINT IF EXISTS evidence_objects_source_kind_check,
    DROP CONSTRAINT IF EXISTS evidence_objects_parser_version_check,
    DROP CONSTRAINT IF EXISTS evidence_objects_content_format;
ALTER TABLE gabriel_identity.evidence_objects ADD CONSTRAINT evidence_objects_content_format CHECK (
    (source_kind='user_supplied_text' AND parser_version='supplied-utf8-v1') OR
    (source_kind='model_generated_text' AND parser_version='model-json-v1')
);

CREATE TABLE gabriel_identity.model_answer_intents (
    organization_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    case_id uuid NOT NULL,
    coordinator_run_id uuid NOT NULL,
    normalized_evidence_id uuid NOT NULL,
    ingestion_id uuid NOT NULL,
    created_by uuid NOT NULL,
    input_digest text NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
    configuration_digest text NOT NULL CHECK (configuration_digest ~ '^[a-f0-9]{64}$'),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
    provider_response_digest text NOT NULL CHECK (provider_response_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,reservation_id),
    UNIQUE (organization_id,ingestion_id),
    UNIQUE (organization_id,case_id,reservation_id),
    FOREIGN KEY (organization_id,reservation_id) REFERENCES gabriel_identity.model_dispatch_claims(organization_id,reservation_id),
    FOREIGN KEY (organization_id,case_id,coordinator_run_id) REFERENCES gabriel_identity.coordinator_runs(organization_id,case_id,id),
    FOREIGN KEY (organization_id,case_id,normalized_evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_answer_intent_run ON gabriel_identity.model_answer_intents(organization_id,case_id,coordinator_run_id);
CREATE INDEX model_answer_intent_input ON gabriel_identity.model_answer_intents(organization_id,case_id,normalized_evidence_id);
CREATE INDEX model_answer_intent_actor ON gabriel_identity.model_answer_intents(organization_id,created_by);

CREATE TABLE gabriel_identity.model_answer_receipts (
    organization_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    case_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    completed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,reservation_id),
    UNIQUE (organization_id,evidence_id),
    FOREIGN KEY (organization_id,case_id,reservation_id) REFERENCES gabriel_identity.model_answer_intents(organization_id,case_id,reservation_id),
    FOREIGN KEY (organization_id,case_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id),
    FOREIGN KEY (organization_id,completed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_answer_receipt_case ON gabriel_identity.model_answer_receipts(organization_id,case_id,created_at DESC);
CREATE INDEX model_answer_receipt_actor ON gabriel_identity.model_answer_receipts(organization_id,completed_by);
REVOKE ALL ON gabriel_identity.model_answer_intents,gabriel_identity.model_answer_receipts FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.model_answer_intents,gabriel_identity.model_answer_receipts TO gabriel_identity_app;
