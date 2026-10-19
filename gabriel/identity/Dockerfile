FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY gabriel/identity/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY gabriel/__init__.py gabriel/capabilities.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/service.py gabriel/identity/machine.py gabriel/identity/tasks.py gabriel/identity/cli.py gabriel/identity/vault.py gabriel/identity/vault_cli.py gabriel/identity/retention.py gabriel/identity/actions.py gabriel/identity/cases.py gabriel/identity/evidence_store.py gabriel/identity/case_cli.py gabriel/identity/schema.sql gabriel/identity/schema_v2.sql gabriel/identity/schema_v3.sql gabriel/identity/schema_v4.sql gabriel/identity/schema_v5.sql gabriel/identity/schema_v6.sql gabriel/identity/schema_v7.sql gabriel/identity/schema_v8.sql /app/gabriel/identity/
RUN mkdir -p /var/lib/gabriel-evidence /intake && chown 10001:10001 /var/lib/gabriel-evidence
COPY gabriel/identity/checkpoints.py gabriel/identity/checkpoint_service.py /app/gabriel/identity/
USER 10001:10001
ENTRYPOINT ["python", "-m", "gabriel.identity.cli"]

FROM runtime AS test
USER 0:0
RUN pip install --no-cache-dir pytest==8.3.5 pytest-cov==6.0.0 pytest-asyncio==0.25.3
ENV PYTHONPATH=/app:/repo
WORKDIR /repo
COPY conftest.py pytest.ini /repo/
COPY tooling/scripts/pytest_isolated.py tooling/scripts/gabriel_identity_prepare.py tooling/scripts/gabriel_provider_keys.py tooling/scripts/gabriel_evidence_keys.py /repo/tooling/scripts/
COPY testing/gabriel_identity/ /repo/testing/gabriel_identity/
COPY gabriel/identity/checkpoint_cli.py /app/gabriel/identity/
USER 10001:10001
ENTRYPOINT ["python", "tooling/scripts/pytest_isolated.py", "all", "testing/gabriel_identity", "--strict", "--parallel", "1"]

FROM python:3.11-slim AS checkpoint-signer
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN pip install --no-cache-dir cryptography==50.0.2
COPY gabriel/__init__.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/checkpoints.py gabriel/identity/checkpoint_cli.py /app/gabriel/identity/
USER 10001:10001
ENTRYPOINT ["python", "-m", "gabriel.identity.checkpoint_cli"]

FROM runtime AS production
