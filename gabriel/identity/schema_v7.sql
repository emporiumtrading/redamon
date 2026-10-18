CREATE FUNCTION gabriel_identity.require_case_close_approval() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF OLD.state<>'open' OR NEW.state<>'closed' OR NEW.closed_at IS NULL OR NOT EXISTS (
        SELECT 1 FROM gabriel_identity.action_requests r
        JOIN gabriel_identity.action_approvals a ON (a.organization_id,a.request_id)=(r.organization_id,r.id)
        JOIN gabriel_identity.action_policy_state p ON p.organization_id=r.organization_id
        WHERE r.organization_id=NEW.organization_id AND r.case_id=NEW.id
          AND r.id::text=current_setting('gabriel.action_request',true)
          AND r.operation='case.close' AND r.state='dispatching'
          AND a.digest=r.digest AND p.revision=r.policy_revision
          AND r.expires_at>clock_timestamp() AND a.expires_at>clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'case_closure_approval_required' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_case_close_approval() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_case_close_approval() TO gabriel_identity_app;
CREATE TRIGGER require_case_close_approval BEFORE UPDATE OF state,closed_at ON gabriel_identity.cases
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_case_close_approval();
