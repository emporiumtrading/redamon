CREATE TABLE gabriel_identity.browser_navigation_grants (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    lease_id uuid NOT NULL,
    request_id uuid NOT NULL,
    created_by uuid NOT NULL,
    contract_version text NOT NULL CHECK (length(contract_version) BETWEEN 1 AND 64),
    destinations jsonb NOT NULL CHECK (jsonb_typeof(destinations)='array' AND jsonb_array_length(destinations) BETWEEN 1 AND 20),
    initial_context_digest text NOT NULL CHECK (initial_context_digest ~ '^[a-f0-9]{64}$'),
    max_moves integer NOT NULL CHECK (max_moves BETWEEN 1 AND 20),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,lease_id),
    UNIQUE (organization_id,request_id),
    FOREIGN KEY (organization_id,lease_id) REFERENCES gabriel_identity.browser_leases(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE TABLE gabriel_identity.browser_navigation_intents (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    grant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 20),
    source_context jsonb NOT NULL CHECK (jsonb_typeof(source_context)='object' AND octet_length(source_context::text)<=8192),
    destination_url text NOT NULL CHECK (length(destination_url) BETWEEN 9 AND 2048),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,grant_id,sequence),
    UNIQUE (organization_id,grant_id,request_id),
    FOREIGN KEY (organization_id,grant_id) REFERENCES gabriel_identity.browser_navigation_grants(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '30 seconds')
);
CREATE TABLE gabriel_identity.browser_navigation_receipts (
    organization_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    context jsonb NOT NULL CHECK (jsonb_typeof(context)='object' AND octet_length(context::text)<=8192),
    context_digest text NOT NULL CHECK (context_digest ~ '^[a-f0-9]{64}$'),
    completed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,intent_id),
    FOREIGN KEY (organization_id,intent_id) REFERENCES gabriel_identity.browser_navigation_intents(organization_id,id),
    FOREIGN KEY (organization_id,completed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE TABLE gabriel_identity.browser_navigation_commits (
    organization_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,intent_id),
    FOREIGN KEY (organization_id,intent_id) REFERENCES gabriel_identity.browser_navigation_receipts(organization_id,intent_id)
);
CREATE TABLE gabriel_identity.browser_navigation_stops (
    organization_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    stopped_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,grant_id),
    FOREIGN KEY (organization_id,grant_id) REFERENCES gabriel_identity.browser_navigation_grants(organization_id,id),
    FOREIGN KEY (organization_id,stopped_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX navigation_grant_actor ON gabriel_identity.browser_navigation_grants(organization_id,created_by);
CREATE INDEX navigation_intent_actor ON gabriel_identity.browser_navigation_intents(organization_id,requested_by);
CREATE INDEX navigation_receipt_actor ON gabriel_identity.browser_navigation_receipts(organization_id,completed_by);
CREATE INDEX navigation_stop_actor ON gabriel_identity.browser_navigation_stops(organization_id,stopped_by);
REVOKE ALL ON gabriel_identity.browser_navigation_grants,gabriel_identity.browser_navigation_intents,
    gabriel_identity.browser_navigation_receipts,gabriel_identity.browser_navigation_commits,gabriel_identity.browser_navigation_stops FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.browser_navigation_grants,gabriel_identity.browser_navigation_intents,
    gabriel_identity.browser_navigation_receipts,gabriel_identity.browser_navigation_stops TO gabriel_identity_app;
GRANT SELECT ON gabriel_identity.browser_navigation_commits TO gabriel_identity_app;

CREATE FUNCTION gabriel_identity.apply_browser_navigation(org uuid,intent uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE i record; r record; g record; l record; n integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(org::text,73582302));
    SELECT * INTO i FROM gabriel_identity.browser_navigation_intents WHERE organization_id=org AND id=intent FOR UPDATE;
    SELECT * INTO r FROM gabriel_identity.browser_navigation_receipts WHERE organization_id=org AND intent_id=intent;
    SELECT * INTO g FROM gabriel_identity.browser_navigation_grants WHERE organization_id=org AND id=i.grant_id;
    SELECT * INTO l FROM gabriel_identity.browser_leases WHERE organization_id=org AND id=g.lease_id FOR UPDATE;
    IF i.id IS NULL OR r.intent_id IS NULL OR g.id IS NULL OR l.id IS NULL
        OR clock_timestamp()>=i.expires_at OR clock_timestamp()>=g.expires_at
        OR clock_timestamp()>=l.expires_at OR l.state<>'active'
        OR i.requested_by<>l.issued_by OR r.completed_by<>l.issued_by OR g.created_by<>l.issued_by
        OR EXISTS(SELECT 1 FROM gabriel_identity.browser_navigation_stops WHERE organization_id=org AND grant_id=g.id)
        OR i.source_context->>'document_id' IS DISTINCT FROM l.document_id::text
        OR i.source_context->>'page_url' IS DISTINCT FROM l.page_url
        OR NOT g.destinations ? i.destination_url
        OR (r.context-'document_id'-'page_url') IS DISTINCT FROM (i.source_context-'document_id'-'page_url')
        OR r.context->>'account_label' IS DISTINCT FROM l.account_label
        OR r.context->>'browser' IS DISTINCT FROM l.browser
        OR r.context->>'installation_id' IS DISTINCT FROM l.installation_id::text
        OR r.context->>'tab_id' IS DISTINCT FROM l.tab_id::text
        OR r.context->>'extension_version' IS DISTINCT FROM l.extension_version
        OR r.context->>'page_url' IS DISTINCT FROM i.destination_url
        OR r.context->>'document_id' IS NULL
        OR i.sequence>g.max_moves
        OR NOT EXISTS(SELECT 1 FROM gabriel_identity.sessions s
            JOIN gabriel_identity.memberships m USING(organization_id,user_id)
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
            WHERE s.token_digest=l.human_session_digest AND s.organization_id=org AND s.user_id=l.issued_by
            AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active AND u.active
            AND m.role IN ('owner','admin','analyst'))
        OR NOT EXISTS(SELECT 1 FROM gabriel_identity.cases WHERE organization_id=org AND id=l.case_id AND state='open')
        OR NOT EXISTS(SELECT 1 FROM gabriel_identity.investigation_tasks t
            JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(t.organization_id,t.created_by)
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
            WHERE t.organization_id=org AND t.id=l.task_id AND t.expires_at>clock_timestamp()
            AND t.state IN ('active','exhausted') AND t.resource='browser-observation-v1' AND t.operations=ARRAY['browser.observe']::text[]
            AND m.active AND u.active AND m.role IN ('owner','admin','analyst')) THEN
        RAISE EXCEPTION 'navigation_not_admitted' USING ERRCODE='23514';
    END IF;
    INSERT INTO gabriel_identity.browser_navigation_commits VALUES(org,intent,clock_timestamp()) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n=ROW_COUNT;
    IF n<>1 THEN RAISE EXCEPTION 'navigation_already_applied' USING ERRCODE='23514'; END IF;
    UPDATE gabriel_identity.browser_leases SET page_url=i.destination_url,
        document_id=(r.context->>'document_id')::uuid,last_seen=clock_timestamp()
        WHERE organization_id=org AND id=l.id;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.apply_browser_navigation(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.apply_browser_navigation(uuid,uuid) TO gabriel_identity_app;
