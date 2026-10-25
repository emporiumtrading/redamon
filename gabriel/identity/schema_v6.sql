CREATE TABLE gabriel_identity.action_policies (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    revision integer NOT NULL CHECK (revision BETWEEN 1 AND 1024),
    distinct_approver boolean NOT NULL,
    approval_ttl integer NOT NULL CHECK (approval_ttl BETWEEN 60 AND 900),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,revision),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX action_policy_actor ON gabriel_identity.action_policies(organization_id,created_by);
CREATE TABLE gabriel_identity.action_policy_state (
    organization_id uuid PRIMARY KEY,
    revision integer NOT NULL,
    FOREIGN KEY (organization_id,revision) REFERENCES gabriel_identity.action_policies(organization_id,revision)
);
CREATE TABLE gabriel_identity.action_requests (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    request_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation='case.close'),
    case_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    requester_session text NOT NULL CHECK (requester_session ~ '^[a-f0-9]{64}$'),
    policy_revision integer NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed','pending_approval','approved','dispatching','succeeded','rejected','cancelled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,operation,request_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,policy_revision) REFERENCES gabriel_identity.action_policies(organization_id,revision),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '1 hour')
);
CREATE INDEX action_request_case ON gabriel_identity.action_requests(organization_id,case_id);
CREATE INDEX action_request_actor ON gabriel_identity.action_requests(organization_id,requested_by);
CREATE INDEX action_request_policy ON gabriel_identity.action_requests(organization_id,policy_revision);
CREATE TABLE gabriel_identity.action_approvals (
    organization_id uuid NOT NULL,
    request_id uuid NOT NULL,
    approved_by uuid NOT NULL,
    approver_session text NOT NULL CHECK (approver_session ~ '^[a-f0-9]{64}$'),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,request_id),
    FOREIGN KEY (organization_id,request_id) REFERENCES gabriel_identity.action_requests(organization_id,id),
    FOREIGN KEY (organization_id,approved_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '15 minutes')
);
CREATE INDEX action_approval_actor ON gabriel_identity.action_approvals(organization_id,approved_by);
CREATE TABLE gabriel_identity.action_decisions (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    request_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('submitted','approved','rejected','cancelled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,request_id) REFERENCES gabriel_identity.action_requests(organization_id,id),
    FOREIGN KEY (organization_id,actor_id) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX action_decision_request ON gabriel_identity.action_decisions(organization_id,request_id);
CREATE INDEX action_decision_actor ON gabriel_identity.action_decisions(organization_id,actor_id);
CREATE TABLE gabriel_identity.action_executions (
    organization_id uuid NOT NULL,
    request_id uuid NOT NULL,
    executor_id uuid NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,request_id),
    FOREIGN KEY (organization_id,request_id) REFERENCES gabriel_identity.action_requests(organization_id,id),
    FOREIGN KEY (organization_id,executor_id) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX action_execution_actor ON gabriel_identity.action_executions(organization_id,executor_id);
REVOKE ALL ON gabriel_identity.action_policies,gabriel_identity.action_policy_state,
    gabriel_identity.action_requests,gabriel_identity.action_approvals,gabriel_identity.action_decisions,
    gabriel_identity.action_executions FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.action_policies,gabriel_identity.action_policy_state,
    gabriel_identity.action_requests,gabriel_identity.action_approvals,gabriel_identity.action_decisions,
    gabriel_identity.action_executions TO gabriel_identity_app;
GRANT UPDATE(revision) ON gabriel_identity.action_policy_state TO gabriel_identity_app;
GRANT UPDATE(state) ON gabriel_identity.action_requests TO gabriel_identity_app;
