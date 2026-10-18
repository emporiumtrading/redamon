CREATE TABLE gabriel_identity.cases (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    id uuid NOT NULL,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
    created_by uuid NOT NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at timestamptz,
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK ((state='open' AND closed_at IS NULL) OR (state='closed' AND closed_at IS NOT NULL))
);
CREATE INDEX cases_creator ON gabriel_identity.cases(organization_id,created_by);
CREATE TABLE gabriel_identity.case_tasks (
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    task_id uuid NOT NULL,
    PRIMARY KEY (organization_id,case_id,task_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,task_id) REFERENCES gabriel_identity.investigation_tasks(organization_id,id)
);
CREATE INDEX case_tasks_task ON gabriel_identity.case_tasks(organization_id,task_id);
CREATE TABLE gabriel_identity.evidence_key_registry (
    key_id text PRIMARY KEY,
    fingerprint text NOT NULL UNIQUE CHECK (fingerprint ~ '^[a-f0-9]{64}$')
);
CREATE TABLE gabriel_identity.evidence_objects (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    ingestion_id uuid NOT NULL,
    intake_digest text NOT NULL CHECK (intake_digest ~ '^[a-f0-9]{64}$'),
    object_id uuid NOT NULL UNIQUE,
    acquired_by uuid NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    byte_length integer NOT NULL CHECK (byte_length BETWEEN 1 AND 131072),
    key_id text NOT NULL REFERENCES gabriel_identity.evidence_key_registry(key_id),
    source_kind text NOT NULL CHECK (source_kind='user_supplied_text'),
    source_label text NOT NULL CHECK (length(source_label) BETWEEN 1 AND 128),
    source_event_time timestamptz,
    observed_at timestamptz NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version=1),
    parser_version text NOT NULL CHECK (parser_version='supplied-utf8-v1'),
    redaction_state text NOT NULL CHECK (redaction_state IN ('not_redacted','user_declared_redacted')),
    parent_id uuid,
    acquisition_hash text NOT NULL CHECK (acquisition_hash ~ '^[a-f0-9]{64}$'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','ready','quarantined')),
    failure_code text,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,ingestion_id),
    UNIQUE (organization_id,case_id,id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,acquired_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,case_id,parent_id)
        REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id)
);
CREATE INDEX evidence_acquirer ON gabriel_identity.evidence_objects(organization_id,acquired_by);
CREATE INDEX evidence_parent ON gabriel_identity.evidence_objects(organization_id,case_id,parent_id);
CREATE INDEX evidence_key ON gabriel_identity.evidence_objects(key_id);
CREATE TABLE gabriel_identity.custody_events (
    organization_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence>0),
    actor_id uuid NOT NULL,
    event text NOT NULL CHECK (event IN ('acquisition_intent','acquired','recovered','accessed','export_prepared','export_completed','export_failed','quarantined')),
    previous_hash text NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
    event_hash text NOT NULL CHECK (event_hash ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,evidence_id,sequence),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    FOREIGN KEY (organization_id,actor_id) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX custody_actor ON gabriel_identity.custody_events(organization_id,actor_id);
CREATE TABLE gabriel_identity.evidence_exports (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    prepared_by uuid NOT NULL,
    digest text NOT NULL,
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','completed','file_write_failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    FOREIGN KEY (organization_id,prepared_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX evidence_exports_object ON gabriel_identity.evidence_exports(organization_id,evidence_id);
CREATE INDEX evidence_exports_actor ON gabriel_identity.evidence_exports(organization_id,prepared_by);
REVOKE ALL ON gabriel_identity.cases,gabriel_identity.case_tasks,gabriel_identity.evidence_key_registry,
    gabriel_identity.evidence_objects,gabriel_identity.custody_events,gabriel_identity.evidence_exports FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.cases,gabriel_identity.case_tasks,gabriel_identity.evidence_key_registry,
    gabriel_identity.evidence_objects,gabriel_identity.custody_events,gabriel_identity.evidence_exports TO gabriel_identity_app;
GRANT UPDATE(state,closed_at) ON gabriel_identity.cases TO gabriel_identity_app;
GRANT UPDATE(state,failure_code) ON gabriel_identity.evidence_objects TO gabriel_identity_app;
GRANT UPDATE(state) ON gabriel_identity.evidence_exports TO gabriel_identity_app;
