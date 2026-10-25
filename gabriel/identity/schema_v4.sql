CREATE TABLE gabriel_identity.investigation_tasks (
    organization_id uuid NOT NULL REFERENCES gabriel_identity.organizations(id),
    id uuid NOT NULL,
    created_by uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    resource text NOT NULL CHECK (resource = 'local-inspection-v1'),
    operations text[] NOT NULL CHECK (cardinality(operations) BETWEEN 1 AND 2
        AND operations <@ ARRAY['capabilities.list','evidence.hash']::text[]
        AND array_position(operations,NULL) IS NULL),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','cancelled','completed','exhausted')),
    max_steps integer NOT NULL CHECK (max_steps BETWEEN 1 AND 1000),
    used_steps integer NOT NULL DEFAULT 0 CHECK (used_steps >= 0 AND used_steps <= max_steps),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,created_by)
        REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '1 hour')
);
CREATE INDEX investigation_tasks_creator ON gabriel_identity.investigation_tasks(organization_id,created_by);
ALTER TABLE gabriel_identity.service_grants ADD COLUMN bound_task_id uuid;
-- Old correlation IDs cannot be converted into invented authorized tasks.
INSERT INTO gabriel_identity.audit_events (id,organization_id,event,target_id)
    SELECT gen_random_uuid(),organization_id,'identity.unbound_service_migrated',id
    FROM gabriel_identity.service_grants WHERE revoked_at IS NULL;
UPDATE gabriel_identity.service_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp());
ALTER TABLE gabriel_identity.service_grants DROP CONSTRAINT service_grants_audience_check;
ALTER TABLE gabriel_identity.service_grants ADD CONSTRAINT service_grants_audience_check
    CHECK (audience='gabriel-local-worker-v2'
        OR (audience='gabriel-local-worker-v1' AND revoked_at IS NOT NULL));
ALTER TABLE gabriel_identity.service_grants ADD CONSTRAINT service_grants_task_fk
    FOREIGN KEY (organization_id,bound_task_id)
    REFERENCES gabriel_identity.investigation_tasks(organization_id,id);
ALTER TABLE gabriel_identity.service_grants ADD CONSTRAINT service_grants_task_binding
    CHECK ((bound_task_id IS NOT NULL AND bound_task_id=task_id)
        OR (bound_task_id IS NULL AND revoked_at IS NOT NULL));
ALTER TABLE gabriel_identity.service_grants ADD CONSTRAINT service_grants_bound_task_service
    UNIQUE (organization_id,bound_task_id,id);
CREATE TABLE gabriel_identity.task_executions (
    organization_id uuid NOT NULL,
    task_id uuid NOT NULL,
    request_id uuid NOT NULL,
    service_id uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response jsonb NOT NULL CHECK (jsonb_typeof(response)='object' AND octet_length(response::text)<=16384),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,task_id,request_id),
    FOREIGN KEY (organization_id,task_id) REFERENCES gabriel_identity.investigation_tasks(organization_id,id),
    FOREIGN KEY (organization_id,task_id,service_id)
        REFERENCES gabriel_identity.service_grants(organization_id,bound_task_id,id)
);
CREATE INDEX task_executions_service ON gabriel_identity.task_executions(organization_id,service_id);
REVOKE ALL ON gabriel_identity.investigation_tasks,gabriel_identity.task_executions FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON gabriel_identity.investigation_tasks TO gabriel_identity_app;
GRANT SELECT,INSERT ON gabriel_identity.task_executions TO gabriel_identity_app;
