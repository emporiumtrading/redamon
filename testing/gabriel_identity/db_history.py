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
    if conn.execute("SELECT to_regclass('gabriel_identity.case_questions') AS t").fetchone()['t'] is not None:
        conn.execute('DROP TABLE gabriel_identity.case_question_answers,gabriel_identity.case_questions,gabriel_identity.case_assignments')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=13')
