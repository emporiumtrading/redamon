"""Prepare historical states only inside the generated disposable test database."""


def remove_v4(conn):
    remove_v5(conn)
    conn.execute('DROP TABLE gabriel_identity.task_executions')
    conn.execute('ALTER TABLE gabriel_identity.service_grants DROP COLUMN bound_task_id')
    conn.execute('DROP TABLE gabriel_identity.investigation_tasks')
    conn.execute('ALTER TABLE gabriel_identity.service_grants DROP CONSTRAINT service_grants_audience_check')
    # Reconstruct the actual v3 protocol. Tokens remain test fixtures, never used as live credentials.
    conn.execute("UPDATE gabriel_identity.service_grants SET audience='gabriel-local-worker-v1'")
    conn.execute("ALTER TABLE gabriel_identity.service_grants ADD CONSTRAINT service_grants_audience_check CHECK (audience='gabriel-local-worker-v1')")
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=4')


def remove_v5(conn):
    remove_v6(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.cases') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.evidence_exports,gabriel_identity.custody_events,
            gabriel_identity.evidence_objects,gabriel_identity.case_tasks,gabriel_identity.cases,
            gabriel_identity.evidence_key_registry''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=5')


def remove_v6(conn):
    remove_v7(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.action_requests') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.action_executions,gabriel_identity.action_decisions,
            gabriel_identity.action_approvals,gabriel_identity.action_requests,
            gabriel_identity.action_policy_state,gabriel_identity.action_policies''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=6')


def remove_v7(conn):
    remove_v8(conn)
    conn.execute('DROP TRIGGER IF EXISTS require_case_close_approval ON gabriel_identity.cases')
    conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.require_case_close_approval()')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=7')


def remove_v8(conn):
    remove_v9(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.retention_policies') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.retention_events,gabriel_identity.purge_attempts,
            gabriel_identity.purge_approvals,gabriel_identity.purge_requests,gabriel_identity.hold_releases,
            gabriel_identity.legal_holds,gabriel_identity.case_hold_versions,gabriel_identity.retention_policies''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=8')


def remove_v9(conn):
    remove_v10(conn)
    conn.execute('DROP TRIGGER IF EXISTS require_case_checkpoint ON gabriel_identity.cases')
    conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.require_case_checkpoint()')
    if conn.execute("SELECT to_regclass('gabriel_identity.checkpoint_keys') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.checkpoint_receipts,gabriel_identity.checkpoint_captures,
            gabriel_identity.checkpoint_policies,gabriel_identity.checkpoint_key_revocations,gabriel_identity.checkpoint_keys''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=9')


def remove_v10(conn):
    remove_v11(conn)
    conn.execute('DROP TRIGGER IF EXISTS require_evidence_insert_epoch ON gabriel_identity.evidence_objects')
    conn.execute('DROP TRIGGER IF EXISTS require_evidence_update_epoch ON gabriel_identity.evidence_objects')
    conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.require_evidence_epoch()')
    if conn.execute("SELECT to_regclass('gabriel_identity.evidence_rewraps') AS t").fetchone()['t']:
        conn.execute('DROP TRIGGER IF EXISTS require_rewrap_result ON gabriel_identity.evidence_rewraps')
    conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.require_rewrap_result()')
    if conn.execute("SELECT to_regclass('gabriel_identity.evidence_key_epochs') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.evidence_rewrap_results,gabriel_identity.evidence_rewraps,gabriel_identity.evidence_key_epochs')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=10')


def remove_v11(conn):
    remove_v12(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.browser_leases') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.browser_leases')
    conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.require_browser_lease_transition()')
    if conn.execute("SELECT 1 FROM pg_constraint WHERE conname='investigation_tasks_browser_scope'").fetchone():
        conn.execute("DELETE FROM gabriel_identity.case_tasks WHERE task_id IN (SELECT id FROM gabriel_identity.investigation_tasks WHERE resource='browser-observation-v1')")
        conn.execute("DELETE FROM gabriel_identity.investigation_tasks WHERE resource='browser-observation-v1'")
        conn.execute('ALTER TABLE gabriel_identity.investigation_tasks DROP CONSTRAINT investigation_tasks_browser_scope')
        conn.execute("ALTER TABLE gabriel_identity.investigation_tasks ADD CONSTRAINT investigation_tasks_resource_check CHECK (resource='local-inspection-v1')")
        conn.execute("ALTER TABLE gabriel_identity.investigation_tasks ADD CONSTRAINT investigation_tasks_operations_check CHECK (cardinality(operations) BETWEEN 1 AND 2 AND operations <@ ARRAY['capabilities.list','evidence.hash']::text[] AND array_position(operations,NULL) IS NULL)")
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=11')


def remove_v12(conn):
    remove_v13(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.browser_observations') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.browser_observation_receipts,gabriel_identity.browser_observations')
        conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.require_browser_observation_receipt()')
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP COLUMN intake_enabled')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=12')


def remove_v13(conn):
    remove_v14(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.case_questions') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.case_question_answers,gabriel_identity.case_questions,gabriel_identity.case_assignments')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=13')


def remove_v14(conn):
    remove_v15(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.specialist_runs') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.specialist_runs')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=14')


def remove_v15(conn):
    remove_v16(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.memory_records') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.memory_reviews,gabriel_identity.memory_invalidations,gabriel_identity.memory_resets,gabriel_identity.memory_records')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=15')


def remove_v16(conn):
    remove_v17(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.model_reservations') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.model_investigation_stops,
            gabriel_identity.model_settlements,gabriel_identity.model_dispatch_claims,
            gabriel_identity.model_reservations,gabriel_identity.model_investigations,
            gabriel_identity.model_price_quotes,gabriel_identity.model_budget_policies''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=16')


def remove_v17(conn):
    remove_v18(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.coordinator_runs') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.coordinator_results,gabriel_identity.coordinator_claims,
            gabriel_identity.coordinator_steps,gabriel_identity.coordinator_sources,
            gabriel_identity.coordinator_stops,gabriel_identity.coordinator_runs''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=17')


def remove_v18(conn):
    remove_v19(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.model_answer_intents') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.model_answer_receipts,gabriel_identity.model_answer_intents')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=18')


def remove_v19(conn):
    remove_v20(conn)
    if conn.execute("SELECT to_regclass('gabriel_identity.provider_onboarding_checks') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.provider_onboarding_checks')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=19')


def remove_v20(conn):
    remove_v21(conn)
    applied=conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=20').fetchone()
    if applied:
        conn.execute("DELETE FROM gabriel_identity.specialist_runs WHERE engine_version='specialist-rules-v1'")
        conn.execute('ALTER TABLE gabriel_identity.specialist_runs DROP CONSTRAINT specialist_runs_engine_version_check')
        conn.execute("ALTER TABLE gabriel_identity.specialist_runs ADD CONSTRAINT specialist_runs_engine_version_check CHECK (engine_version='telemetry-health-v1')")
        conn.execute("ALTER TABLE gabriel_identity.specialist_runs ADD CONSTRAINT specialist_runs_role_check CHECK (role='telemetry_health')")
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=20')


def remove_v21(conn):
    remove_v22(conn)
    conn.execute('DROP FUNCTION IF EXISTS gabriel_identity.apply_browser_navigation(uuid,uuid)')
    if conn.execute("SELECT to_regclass('gabriel_identity.browser_navigation_grants') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.browser_navigation_commits,gabriel_identity.browser_navigation_receipts,
            gabriel_identity.browser_navigation_intents,gabriel_identity.browser_navigation_stops,gabriel_identity.browser_navigation_grants''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=21')


def remove_v22(conn):
    remove_v23(conn)
    if conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=22').fetchone():
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_extension_version_check')
        conn.execute("ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_extension_version_check CHECK (extension_version='0.1.0')")
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=22')


def remove_v23(conn):
    remove_v24(conn)
    conn.execute('DROP TABLE IF EXISTS gabriel_identity.attack_pattern_runs')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=23')


def remove_v24(conn):
    remove_v25(conn)
    conn.execute('DROP TABLE IF EXISTS gabriel_identity.browser_event_snapshots')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=24')


def remove_v25(conn):
    remove_v26(conn)
    if conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=25').fetchone():
        for table in ('coordinator_results','coordinator_claims','coordinator_steps','coordinator_sources','coordinator_stops'):
            conn.execute('DELETE FROM gabriel_identity.'+table+" WHERE (organization_id,run_id) IN (SELECT organization_id,id FROM gabriel_identity.coordinator_runs WHERE plan_version='local-specialist-coordinator-v2')")
        conn.execute("DELETE FROM gabriel_identity.coordinator_runs WHERE plan_version='local-specialist-coordinator-v2'")
        conn.execute('ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_plan_bounds')
        conn.execute('ALTER TABLE gabriel_identity.coordinator_runs DROP COLUMN input_evidence_id')
        conn.execute("ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_runs_plan_version_check CHECK (plan_version='local-coordinator-v1')")
        conn.execute('ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_runs_max_steps_check CHECK (max_steps BETWEEN 1 AND 2)')
        conn.execute('ALTER TABLE gabriel_identity.coordinator_steps DROP CONSTRAINT coordinator_operation_bounds')
        conn.execute('ALTER TABLE gabriel_identity.coordinator_steps ADD CONSTRAINT coordinator_steps_sequence_check CHECK (sequence BETWEEN 1 AND 2)')
        conn.execute("ALTER TABLE gabriel_identity.coordinator_steps ADD CONSTRAINT coordinator_steps_check CHECK ((sequence=1 AND operation='evidence_inventory') OR (sequence=2 AND operation='telemetry_health'))")
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=25')


def remove_v26(conn):
    remove_v27(conn)
    conn.execute('DROP TABLE IF EXISTS gabriel_identity.browser_specialist_suites')
    if conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=26').fetchone():
        conn.execute('ALTER TABLE gabriel_identity.browser_event_snapshots DROP CONSTRAINT browser_snapshot_case_observation')
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_extension_version_check')
        conn.execute("ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_extension_version_check CHECK (extension_version IN ('0.1.0','0.2.0'))")
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=26')


def remove_v27(conn):
    remove_v28(conn)
    if conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=27').fetchone():
        from pathlib import Path
        from gabriel.identity import service
        original=(Path(service.__file__).parent/'schema_v21.sql').read_text()
        original=original[original.index('CREATE FUNCTION gabriel_identity.apply_browser_navigation'):]
        conn.execute(original.replace('CREATE FUNCTION gabriel_identity.apply_browser_navigation','CREATE OR REPLACE FUNCTION gabriel_identity.apply_browser_navigation',1))
        conn.execute('DROP TABLE gabriel_identity.browser_discovered_destinations')
        conn.execute('DROP FUNCTION gabriel_identity.require_discovered_destination()')
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_leases_extension_version_check')
        conn.execute("ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_extension_version_check CHECK (extension_version IN ('0.1.0','0.2.0','0.3.0'))")
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP CONSTRAINT browser_lease_lifetime')
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP COLUMN discovery_enabled')
        conn.execute('ALTER TABLE gabriel_identity.browser_leases DROP COLUMN scheduled_review_enabled')
        conn.execute("ALTER TABLE gabriel_identity.browser_leases ADD CONSTRAINT browser_leases_check CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes')")
        conn.execute('ALTER TABLE gabriel_identity.browser_navigation_grants DROP CONSTRAINT navigation_grant_lifetime')
        conn.execute("ALTER TABLE gabriel_identity.browser_navigation_grants ADD CONSTRAINT browser_navigation_grants_check CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes')")
        conn.execute('ALTER TABLE gabriel_identity.browser_navigation_grants DROP CONSTRAINT browser_navigation_grants_max_moves_check')
        conn.execute('ALTER TABLE gabriel_identity.browser_navigation_grants ADD CONSTRAINT browser_navigation_grants_max_moves_check CHECK (max_moves BETWEEN 1 AND 20)')
        conn.execute('ALTER TABLE gabriel_identity.browser_navigation_intents DROP CONSTRAINT browser_navigation_intents_sequence_check')
        conn.execute('ALTER TABLE gabriel_identity.browser_navigation_intents ADD CONSTRAINT browser_navigation_intents_sequence_check CHECK (sequence BETWEEN 1 AND 20)')
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=27')


def remove_v28(conn):
    remove_v29(conn)
    if conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=28').fetchone():
        conn.execute('DROP TRIGGER require_completed_model_ceiling ON gabriel_identity.model_settlements')
        conn.execute('DROP FUNCTION gabriel_identity.require_completed_model_ceiling()')
        conn.execute('ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_outcome_check')
        conn.execute('ALTER TABLE gabriel_identity.model_settlements DROP CONSTRAINT model_settlements_check')
        conn.execute("ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_outcome_check CHECK (outcome IN ('operator_reported','not_sent'))")
        conn.execute("ALTER TABLE gabriel_identity.model_settlements ADD CONSTRAINT model_settlements_check CHECK ((outcome='not_sent' AND actual_microusd=0 AND receipt_digest IS NULL) OR (outcome='operator_reported' AND receipt_digest IS NOT NULL))")
        conn.execute('ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_plan_bounds')
        conn.execute("ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_plan_bounds CHECK ((plan_version='local-coordinator-v1' AND input_evidence_id IS NULL AND max_steps BETWEEN 1 AND 2) OR (plan_version='local-specialist-coordinator-v2' AND input_evidence_id IS NOT NULL AND max_steps=12))")
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=28')


def remove_v29(conn):
    if conn.execute('SELECT 1 FROM gabriel_identity.migrations WHERE version=29').fetchone():
        conn.execute('DROP TABLE gabriel_identity.specialist_agent_stops,gabriel_identity.specialist_agent_jobs,gabriel_identity.personal_provider_secrets')
        conn.execute('ALTER TABLE gabriel_identity.model_price_quotes DROP COLUMN purpose')
        conn.execute('ALTER TABLE gabriel_identity.coordinator_runs DROP CONSTRAINT coordinator_plan_bounds')
        conn.execute("ALTER TABLE gabriel_identity.coordinator_runs ADD CONSTRAINT coordinator_plan_bounds CHECK ((plan_version='local-coordinator-v1' AND input_evidence_id IS NULL AND max_steps BETWEEN 1 AND 2) OR (plan_version='local-specialist-coordinator-v2' AND input_evidence_id IS NOT NULL AND max_steps=12) OR (plan_version='browser-ai-coordinator-v1' AND input_evidence_id IS NOT NULL AND max_steps=1))")
        conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=29')
