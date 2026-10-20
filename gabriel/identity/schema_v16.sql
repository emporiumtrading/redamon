CREATE TABLE gabriel_identity.model_budget_policies (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    enabled boolean NOT NULL,
    month_microusd bigint NOT NULL CHECK (month_microusd BETWEEN 1 AND 18000000),
    day_microusd bigint NOT NULL CHECK (day_microusd BETWEEN 1 AND 500000),
    investigation_microusd bigint NOT NULL CHECK (investigation_microusd BETWEEN 1 AND 50000),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_budget_policy_latest ON gabriel_identity.model_budget_policies(organization_id,created_at DESC,id DESC);

CREATE TABLE gabriel_identity.model_price_quotes (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    created_by uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('openrouter','nvidia')),
    model text NOT NULL,
    configuration_digest text NOT NULL CHECK (configuration_digest ~ '^[a-f0-9]{64}$'),
    input_microusd_per_million bigint NOT NULL CHECK (input_microusd_per_million BETWEEN 0 AND 100000000),
    output_microusd_per_million bigint NOT NULL CHECK (output_microusd_per_million BETWEEN 0 AND 100000000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '1 hour'),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_quote_expiry ON gabriel_identity.model_price_quotes(organization_id,expires_at);

CREATE TABLE gabriel_identity.model_investigations (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at=created_at+interval '15 minutes'),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,request_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,requested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_investigation_case ON gabriel_identity.model_investigations(organization_id,case_id,created_at DESC);
CREATE INDEX model_investigation_actor ON gabriel_identity.model_investigations(organization_id,requested_by);

CREATE TABLE gabriel_identity.model_reservations (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    quote_id uuid NOT NULL,
    request_id uuid NOT NULL,
    input_digest text NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
    max_input_tokens integer NOT NULL CHECK (max_input_tokens BETWEEN 1 AND 8000),
    max_output_tokens integer NOT NULL CHECK (max_output_tokens BETWEEN 1 AND 1500),
    reserved_microusd bigint NOT NULL CHECK (reserved_microusd BETWEEN 1 AND 50000),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 6),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,investigation_id,request_id),
    UNIQUE (organization_id,investigation_id,attempt),
    FOREIGN KEY (organization_id,investigation_id) REFERENCES gabriel_identity.model_investigations(organization_id,id),
    FOREIGN KEY (organization_id,quote_id) REFERENCES gabriel_identity.model_price_quotes(organization_id,id)
);
CREATE INDEX model_reservation_time ON gabriel_identity.model_reservations(organization_id,created_at);
CREATE INDEX model_reservation_quote ON gabriel_identity.model_reservations(organization_id,quote_id);

CREATE TABLE gabriel_identity.model_dispatch_claims (
    organization_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    id uuid NOT NULL,
    claimed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,reservation_id),
    UNIQUE (organization_id,id),
    FOREIGN KEY (organization_id,reservation_id) REFERENCES gabriel_identity.model_reservations(organization_id,id),
    FOREIGN KEY (organization_id,claimed_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_claim_actor ON gabriel_identity.model_dispatch_claims(organization_id,claimed_by);

CREATE TABLE gabriel_identity.model_settlements (
    organization_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    attested_by uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('operator_reported','not_sent')),
    actual_microusd bigint NOT NULL CHECK (actual_microusd BETWEEN 0 AND 100000000),
    receipt_digest text CHECK (receipt_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((outcome='not_sent' AND actual_microusd=0 AND receipt_digest IS NULL)
        OR (outcome='operator_reported' AND receipt_digest IS NOT NULL)),
    PRIMARY KEY (organization_id,reservation_id),
    UNIQUE (organization_id,receipt_digest),
    FOREIGN KEY (organization_id,reservation_id) REFERENCES gabriel_identity.model_reservations(organization_id,id),
    FOREIGN KEY (organization_id,attested_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_settlement_actor ON gabriel_identity.model_settlements(organization_id,attested_by);
CREATE INDEX model_settlement_time ON gabriel_identity.model_settlements(organization_id,created_at);

CREATE TABLE gabriel_identity.model_investigation_stops (
    organization_id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    stopped_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,investigation_id),
    FOREIGN KEY (organization_id,investigation_id) REFERENCES gabriel_identity.model_investigations(organization_id,id),
    FOREIGN KEY (organization_id,stopped_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX model_stop_actor ON gabriel_identity.model_investigation_stops(organization_id,stopped_by);

REVOKE ALL ON gabriel_identity.model_budget_policies,gabriel_identity.model_price_quotes,
    gabriel_identity.model_investigations,gabriel_identity.model_reservations,
    gabriel_identity.model_dispatch_claims,gabriel_identity.model_settlements,
    gabriel_identity.model_investigation_stops FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.model_budget_policies,gabriel_identity.model_price_quotes,
    gabriel_identity.model_investigations,gabriel_identity.model_reservations,
    gabriel_identity.model_dispatch_claims,gabriel_identity.model_settlements,
    gabriel_identity.model_investigation_stops TO gabriel_identity_app;
