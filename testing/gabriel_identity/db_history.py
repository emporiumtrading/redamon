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
    if conn.execute("SELECT to_regclass('gabriel_identity.action_requests') AS t").fetchone()['t'] is not None:
        conn.execute('''DROP TABLE gabriel_identity.action_executions,gabriel_identity.action_decisions,
            gabriel_identity.action_approvals,gabriel_identity.action_requests,
            gabriel_identity.action_policy_state,gabriel_identity.action_policies''')
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=6')
