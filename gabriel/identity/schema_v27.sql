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
