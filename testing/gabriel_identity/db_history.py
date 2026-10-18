"""Prepare historical states only inside the generated disposable test database."""


def remove_v4(conn):
    conn.execute('DROP TABLE gabriel_identity.task_executions')
    conn.execute('ALTER TABLE gabriel_identity.service_grants DROP COLUMN bound_task_id')
    conn.execute('DROP TABLE gabriel_identity.investigation_tasks')
    conn.execute('ALTER TABLE gabriel_identity.service_grants DROP CONSTRAINT service_grants_audience_check')
    # Reconstruct the actual v3 protocol. Tokens remain test fixtures, never used as live credentials.
    conn.execute("UPDATE gabriel_identity.service_grants SET audience='gabriel-local-worker-v1'")
    conn.execute("ALTER TABLE gabriel_identity.service_grants ADD CONSTRAINT service_grants_audience_check CHECK (audience='gabriel-local-worker-v1')")
    conn.execute('DELETE FROM gabriel_identity.migrations WHERE version=4')
