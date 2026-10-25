ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_extension_version_check;
ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_extension_version_check
    CHECK (extension_version IN ('0.1.0','0.2.0','0.3.0','0.4.0'));
ALTER TABLE gabriel_identity.browser_leases ADD COLUMN scheduled_review_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE gabriel_identity.browser_leases ADD COLUMN discovery_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_discovery_consent CHECK (NOT discovery_enabled OR scheduled_review_enabled);
ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_check;
ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_lease_lifetime CHECK (
    expires_at>created_at AND expires_at<=created_at+CASE WHEN scheduled_review_enabled THEN interval '1 hour' ELSE interval '5 minutes' END
    AND (NOT scheduled_review_enabled OR intake_enabled));
ALTER TABLE gabriel_identity.browser_navigation_grants DROP CONSTRAINT browser_navigation_grants_check;
ALTER TABLE gabriel_identity.browser_navigation_grants ADD CONSTRAINT navigation_grant_lifetime
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '1 hour');
ALTER TABLE gabriel_identity.browser_navigation_grants DROP CONSTRAINT browser_navigation_grants_max_moves_check;
ALTER TABLE gabriel_identity.browser_navigation_grants ADD CONSTRAINT browser_navigation_grants_max_moves_check CHECK (max_moves BETWEEN 1 AND 1000);
ALTER TABLE gabriel_identity.browser_navigation_intents DROP CONSTRAINT browser_navigation_intents_sequence_check;
ALTER TABLE gabriel_identity.browser_navigation_intents ADD CONSTRAINT browser_navigation_intents_sequence_check CHECK (sequence BETWEEN 1 AND 1000);

CREATE TABLE gabriel_identity.browser_discovered_destinations (
    organization_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    destination_url text NOT NULL CHECK (length(destination_url) BETWEEN 9 AND 2048),
    source_url text NOT NULL CHECK (length(source_url) BETWEEN 9 AND 2048),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,grant_id,destination_url),
    FOREIGN KEY (organization_id,grant_id) REFERENCES gabriel_identity.browser_navigation_grants(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
REVOKE ALL ON gabriel_identity.browser_discovered_destinations FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.browser_discovered_destinations TO gabriel_identity_app;
CREATE FUNCTION gabriel_identity.require_discovered_destination() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE g gabriel_identity.browser_navigation_grants%ROWTYPE;
        l gabriel_identity.browser_leases%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.organization_id::text,73582302));
    SELECT * INTO g FROM gabriel_identity.browser_navigation_grants WHERE organization_id=NEW.organization_id AND id=NEW.grant_id;
    SELECT * INTO l FROM gabriel_identity.browser_leases WHERE organization_id=NEW.organization_id AND id=g.lease_id;
    IF g.id IS NULL OR l.id IS NULL OR g.contract_version<>'operator-discovered-readonly-v1'
        OR NOT l.discovery_enabled OR NOT l.scheduled_review_enabled OR NOT l.intake_enabled
        OR l.state<>'active' OR g.expires_at<=clock_timestamp() OR l.expires_at<=clock_timestamp()
        OR NEW.created_by<>l.issued_by OR NEW.source_url<>l.page_url
        OR NEW.destination_url NOT LIKE 'https://%'
        OR split_part(NEW.destination_url,'/',3)<>split_part(l.page_url,'/',3) THEN
        RAISE EXCEPTION 'discovery_destination_not_admitted' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM gabriel_identity.browser_discovered_destinations d
        WHERE d.organization_id=NEW.organization_id AND d.grant_id=NEW.grant_id AND d.destination_url=NEW.destination_url)
        AND (SELECT count(*) FROM gabriel_identity.browser_discovered_destinations d
             WHERE d.organization_id=NEW.organization_id AND d.grant_id=NEW.grant_id)>=19 THEN
        RAISE EXCEPTION 'discovery_page_limit' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION gabriel_identity.require_discovered_destination() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gabriel_identity.require_discovered_destination() TO gabriel_identity_app;
CREATE TRIGGER require_discovered_destination BEFORE INSERT ON gabriel_identity.browser_discovered_destinations
FOR EACH ROW EXECUTE FUNCTION gabriel_identity.require_discovered_destination();

CREATE OR REPLACE FUNCTION gabriel_identity.apply_browser_navigation(org uuid,intent uuid) RETURNS void
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
        OR (NOT g.destinations ? i.destination_url AND NOT (
            g.contract_version='operator-discovered-readonly-v1' AND l.discovery_enabled AND l.scheduled_review_enabled
            AND EXISTS(SELECT 1 FROM gabriel_identity.browser_discovered_destinations d
                WHERE d.organization_id=org AND d.grant_id=g.id AND d.destination_url=i.destination_url
                  AND d.created_by=l.issued_by
                  AND split_part(d.source_url,'/',3)=split_part(i.source_context->>'page_url','/',3))))
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
