ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_extension_version_check;
ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_extension_version_check
    CHECK (extension_version IN ('0.1.0','0.2.0'));
