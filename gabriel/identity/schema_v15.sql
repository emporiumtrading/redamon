CREATE TABLE gabriel_identity.memory_records (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    request_id uuid NOT NULL,
    proposed_by uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('fact','preference')),
    scope text NOT NULL CHECK (scope IN ('case','organization')),
    topic text NOT NULL CHECK (topic ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    epoch bigint NOT NULL CHECK (epoch>=0),
    supersedes uuid,
    source_digest text NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    sensitivity text NOT NULL CHECK (sensitivity IN ('internal','confidential','restricted')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,request_id),
    UNIQUE (organization_id,supersedes),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '30 days'),
    FOREIGN KEY (organization_id,case_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id),
    FOREIGN KEY (organization_id,proposed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,supersedes) REFERENCES gabriel_identity.memory_records(organization_id,id)
);
CREATE UNIQUE INDEX memory_case_topic ON gabriel_identity.memory_records(organization_id,case_id,kind,topic,epoch)
    WHERE scope='case' AND supersedes IS NULL;
CREATE UNIQUE INDEX memory_org_topic ON gabriel_identity.memory_records(organization_id,kind,topic,epoch)
    WHERE scope='organization' AND supersedes IS NULL;
CREATE INDEX memory_proposer ON gabriel_identity.memory_records(organization_id,proposed_by);
CREATE INDEX memory_source ON gabriel_identity.memory_records(organization_id,case_id,evidence_id);
CREATE INDEX memory_retrieval ON gabriel_identity.memory_records(organization_id,epoch,scope,case_id,created_at DESC);
CREATE TABLE gabriel_identity.memory_reviews (
    organization_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    reviewed_by uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approved','rejected')),
    source_digest text NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,memory_id),
    FOREIGN KEY (organization_id,memory_id) REFERENCES gabriel_identity.memory_records(organization_id,id),
    FOREIGN KEY (organization_id,reviewed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX memory_reviewer ON gabriel_identity.memory_reviews(organization_id,reviewed_by);
CREATE TABLE gabriel_identity.memory_invalidations (
    organization_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    invalidated_by uuid NOT NULL,
    reason text NOT NULL CHECK (reason IN ('analyst_requested','source_invalid')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,memory_id),
    FOREIGN KEY (organization_id,memory_id) REFERENCES gabriel_identity.memory_records(organization_id,id),
    FOREIGN KEY (organization_id,invalidated_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX memory_invalidator ON gabriel_identity.memory_invalidations(organization_id,invalidated_by);
CREATE TABLE gabriel_identity.memory_resets (
    organization_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 1000000),
    reset_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,sequence),
    FOREIGN KEY (organization_id,reset_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX memory_reset_actor ON gabriel_identity.memory_resets(organization_id,reset_by);
REVOKE ALL ON gabriel_identity.memory_records,gabriel_identity.memory_reviews,gabriel_identity.memory_invalidations,gabriel_identity.memory_resets FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.memory_records,gabriel_identity.memory_reviews,gabriel_identity.memory_invalidations,gabriel_identity.memory_resets TO gabriel_identity_app;
