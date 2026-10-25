CREATE TABLE gabriel_identity.retention_policies (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    revision integer NOT NULL CHECK (revision BETWEEN 1 AND 1024),
    days integer NOT NULL CHECK (days BETWEEN 1 AND 3650),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,revision),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX retention_policy_actor ON gabriel_identity.retention_policies(organization_id,created_by);
CREATE TABLE gabriel_identity.case_hold_versions (
    organization_id uuid NOT NULL,
    case_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 1000000000),
    PRIMARY KEY (organization_id,case_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id)
);
CREATE TABLE gabriel_identity.legal_holds (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    created_by uuid NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 400),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    coverage jsonb NOT NULL CHECK (jsonb_typeof(coverage)='array'),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','released')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX legal_hold_case ON gabriel_identity.legal_holds(organization_id,case_id,state);
CREATE INDEX legal_hold_actor ON gabriel_identity.legal_holds(organization_id,created_by);
CREATE TABLE gabriel_identity.hold_releases (
    organization_id uuid NOT NULL,
    hold_id uuid NOT NULL,
    released_by uuid NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 400),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,hold_id),
    FOREIGN KEY (organization_id,hold_id) REFERENCES gabriel_identity.legal_holds(organization_id,id),
    FOREIGN KEY (organization_id,released_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX hold_release_actor ON gabriel_identity.hold_releases(organization_id,released_by);
CREATE TABLE gabriel_identity.purge_requests (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    request_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    requester_session text NOT NULL CHECK (requester_session ~ '^[a-f0-9]{64}$'),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed','approved','cancelled','completed')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,request_id),
    UNIQUE (organization_id,id,evidence_id),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (expires_at=created_at+interval '15 minutes')
);
CREATE INDEX purge_request_evidence ON gabriel_identity.purge_requests(organization_id,evidence_id);
CREATE INDEX purge_request_actor ON gabriel_identity.purge_requests(organization_id,requested_by);
CREATE TABLE gabriel_identity.purge_approvals (
    organization_id uuid NOT NULL,
    request_id uuid NOT NULL,
    approved_by uuid NOT NULL,
    approver_session text NOT NULL CHECK (approver_session ~ '^[a-f0-9]{64}$'),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,request_id),
    FOREIGN KEY (organization_id,request_id) REFERENCES gabriel_identity.purge_requests(organization_id,id),
    FOREIGN KEY (organization_id,approved_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE INDEX purge_approval_actor ON gabriel_identity.purge_approvals(organization_id,approved_by);
CREATE TABLE gabriel_identity.purge_attempts (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    request_id uuid NOT NULL,
    prepared_by uuid NOT NULL,
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','completed','aborted')),
    outcome text CHECK (outcome IN ('removed','absence_confirmed','verified_present')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,request_id),
    FOREIGN KEY (organization_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,id),
    FOREIGN KEY (organization_id,request_id,evidence_id) REFERENCES gabriel_identity.purge_requests(organization_id,id,evidence_id),
    FOREIGN KEY (organization_id,prepared_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK ((state='prepared' AND outcome IS NULL) OR
        (state='completed' AND outcome IN ('removed','absence_confirmed')) OR
        (state='aborted' AND outcome='verified_present'))
);
CREATE UNIQUE INDEX purge_one_disposition ON gabriel_identity.purge_attempts(organization_id,evidence_id) WHERE state IN ('prepared','completed');
CREATE INDEX purge_attempt_actor ON gabriel_identity.purge_attempts(organization_id,prepared_by);
CREATE TABLE gabriel_identity.retention_events (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    id uuid NOT NULL,
    actor_id uuid NOT NULL,
    target_id uuid NOT NULL,
    event text NOT NULL CHECK (event IN ('hold_placed','hold_released','purge_proposed','purge_approved','purge_cancelled','purge_prepared','purge_completed','purge_reconciled','purge_aborted')),
    detail jsonb NOT NULL CHECK (jsonb_typeof(detail)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,actor_id) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX retention_event_actor ON gabriel_identity.retention_events(organization_id,actor_id);
CREATE INDEX retention_event_target ON gabriel_identity.retention_events(organization_id,target_id);
REVOKE ALL ON gabriel_identity.retention_policies,gabriel_identity.case_hold_versions,gabriel_identity.legal_holds,
    gabriel_identity.hold_releases,gabriel_identity.purge_requests,gabriel_identity.purge_approvals,
    gabriel_identity.purge_attempts,gabriel_identity.retention_events FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.retention_policies,gabriel_identity.case_hold_versions,gabriel_identity.legal_holds,
    gabriel_identity.hold_releases,gabriel_identity.purge_requests,gabriel_identity.purge_approvals,
    gabriel_identity.purge_attempts,gabriel_identity.retention_events TO gabriel_identity_app;
GRANT UPDATE(revision) ON gabriel_identity.case_hold_versions TO gabriel_identity_app;
GRANT UPDATE(state) ON gabriel_identity.legal_holds,gabriel_identity.purge_requests TO gabriel_identity_app;
GRANT UPDATE(state,outcome) ON gabriel_identity.purge_attempts TO gabriel_identity_app;
