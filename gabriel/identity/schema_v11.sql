ALTER TABLE gabriel_identity.investigation_tasks DROP CONSTRAINT investigation_tasks_resource_check;
ALTER TABLE gabriel_identity.investigation_tasks DROP CONSTRAINT investigation_tasks_operations_check;
ALTER TABLE gabriel_identity.investigation_tasks ADD CONSTRAINT investigation_tasks_browser_scope CHECK (
    (resource='local-inspection-v1' AND cardinality(operations) BETWEEN 1 AND 2
        AND operations <@ ARRAY['capabilities.list','evidence.hash']::text[] AND array_position(operations,NULL) IS NULL)
    OR (resource='browser-observation-v1' AND operations=ARRAY['browser.observe']::text[])
);
CREATE TABLE gabriel_identity.browser_leases (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    token_digest text NOT NULL UNIQUE CHECK (token_digest ~ '^[a-f0-9]{64}$'),
    issued_by uuid NOT NULL,
    human_session_digest text NOT NULL REFERENCES gabriel_identity.sessions(token_digest),
    task_id uuid NOT NULL,
    case_id uuid NOT NULL,
    browser text NOT NULL CHECK (browser IN ('chrome','brave')),
    extension_version text NOT NULL CHECK (extension_version='0.1.0'),
    installation_id uuid NOT NULL,
    tab_id integer NOT NULL CHECK (tab_id BETWEEN 0 AND 2147483647),
    document_id uuid NOT NULL,
    page_url text NOT NULL CHECK (length(page_url) BETWEEN 9 AND 2048),
    account_label text NOT NULL CHECK (length(account_label) BETWEEN 1 AND 64),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','active','disconnected')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_seen timestamptz,
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,issued_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,task_id) REFERENCES gabriel_identity.investigation_tasks(organization_id,id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
    CHECK (last_seen IS NULL OR last_seen>=created_at)
);
CREATE INDEX browser_lease_actor ON gabriel_identity.browser_leases(organization_id,issued_by);
CREATE INDEX browser_lease_task ON gabriel_identity.browser_leases(organization_id,task_id);
CREATE INDEX browser_lease_case ON gabriel_identity.browser_leases(organization_id,case_id);
CREATE INDEX browser_lease_session ON gabriel_identity.browser_leases(human_session_digest);
REVOKE ALL ON gabriel_identity.browser_leases FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.browser_leases TO gabriel_identity_app;
GRANT UPDATE(state,last_seen) ON gabriel_identity.browser_leases TO gabriel_identity_app;
CREATE FUNCTION gabriel_identity.require_browser_lease_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NOT ((OLD.state='pending' AND NEW.state IN ('active','disconnected'))
        OR (OLD.state='active' AND NEW.state IN ('active','disconnected')))
        OR (OLD.last_seen IS NOT NULL AND NEW.last_seen IS NOT NULL AND NEW.last_seen<OLD.last_seen)
        OR (NEW.state='active' AND NEW.last_seen IS NULL) THEN
        RAISE EXCEPTION 'browser_lease_transition_invalid' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_browser_lease_transition() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_browser_lease_transition() TO gabriel_identity_app;
CREATE TRIGGER require_browser_lease_transition BEFORE UPDATE ON gabriel_identity.browser_leases
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_browser_lease_transition();
