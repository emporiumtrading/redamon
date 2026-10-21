FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY gabriel/identity/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY gabriel/__init__.py gabriel/capabilities.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/service.py gabriel/identity/machine.py gabriel/identity/tasks.py gabriel/identity/cli.py gabriel/identity/vault.py gabriel/identity/vault_cli.py gabriel/identity/retention.py gabriel/identity/actions.py gabriel/identity/cases.py gabriel/identity/evidence_store.py gabriel/identity/case_cli.py gabriel/identity/schema.sql gabriel/identity/schema_v2.sql gabriel/identity/schema_v3.sql gabriel/identity/schema_v4.sql gabriel/identity/schema_v5.sql gabriel/identity/schema_v6.sql gabriel/identity/schema_v7.sql gabriel/identity/schema_v8.sql /app/gabriel/identity/
RUN mkdir -p /var/lib/gabriel-evidence /intake && chown 10001:10001 /var/lib/gabriel-evidence
COPY gabriel/identity/checkpoints.py gabriel/identity/checkpoint_service.py gabriel/identity/checkpoint_policy.py gabriel/identity/schema_v9.sql /app/gabriel/identity/
COPY gabriel/identity/evidence_crypto.py gabriel/identity/evidence_keys.py gabriel/identity/key_retirement.py gabriel/identity/schema_v10.sql /app/gabriel/identity/
COPY gabriel/identity/browser_sessions.py gabriel/identity/browser_cli.py gabriel/identity/schema_v11.sql /app/gabriel/identity/
COPY gabriel/identity/browser_observations.py gabriel/identity/schema_v12.sql /app/gabriel/identity/
COPY gabriel/identity/browser_gateway.py gabriel/identity/gateway_cli.py /app/gabriel/identity/
COPY gabriel/identity/reports.py /app/gabriel/identity/
COPY gabriel/identity/workbench.py gabriel/identity/workbench_cli.py /app/gabriel/identity/
COPY gabriel/identity/analyst_views.py /app/gabriel/identity/
COPY gabriel/identity/case_workflow.py gabriel/identity/schema_v13.sql /app/gabriel/identity/
COPY gabriel/identity/case_graph.py /app/gabriel/identity/
COPY gabriel/identity/specialists.py gabriel/identity/specialist_contracts.py gabriel/identity/schema_v14.sql /app/gabriel/identity/
COPY gabriel/identity/memory.py gabriel/identity/schema_v15.sql /app/gabriel/identity/
COPY gabriel/identity/model_evaluation.py gabriel/identity/model_protocol.py gabriel/identity/model_routes.py gabriel/identity/model_transport.py gabriel/identity/model_worker.py /app/gabriel/identity/
COPY gabriel/identity/model_input.py /app/gabriel/identity/
COPY gabriel/identity/coordinator.py gabriel/identity/schema_v17.sql /app/gabriel/identity/
COPY gabriel/identity/model_budget.py gabriel/identity/budget_cli.py gabriel/identity/schema_v16.sql /app/gabriel/identity/
RUN python -c "import ast,pathlib; [ast.parse(p.read_text(),filename=str(p)) for p in pathlib.Path('/app/gabriel').rglob('*.py')]"
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
COPY testing/gabriel_model_lab/ /repo/testing/gabriel_model_lab/
COPY gabriel/browser_extension/ /repo/gabriel/browser_extension/
COPY tooling/scripts/gabriel_extension_package.py /repo/tooling/scripts/
COPY gabriel/identity/checkpoint_cli.py /app/gabriel/identity/
COPY gabriel/identity/provider_probe.py gabriel/identity/model_lab.py /app/gabriel/identity/
RUN python -c "import ast,pathlib; [ast.parse(p.read_text(),filename=str(p)) for p in pathlib.Path('/repo/testing/gabriel_identity').rglob('*.py')]"
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

FROM runtime AS browser-lab
USER 0:0
ARG LAB_UID=10001
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip libnss3-tools xvfb xauth xdotool openbox scrot fonts-liberation \
    && curl --fail --location --proto '=https' --tlsv1.2 https://github.com/brave/brave-browser/releases/download/v1.97.59/brave-browser_1.97.59_amd64.deb -o /tmp/brave.deb \
    && echo '666f817b640a3284fbb5c9b34917b78854e2acd92fa7febad704dc2b29349be5  /tmp/brave.deb' | sha256sum -c - \
    && curl --fail --location --proto '=https' --tlsv1.2 https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg -o /usr/share/keyrings/brave-browser-archive-keyring.gpg \
    && curl --fail --location --proto '=https' --tlsv1.2 https://brave-browser-apt-release.s3.brave.com/brave-browser.sources -o /etc/apt/sources.list.d/brave-browser-release.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/brave.deb \
    && curl --fail --location --proto '=https' --tlsv1.2 https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.84/linux64/chrome-linux64.zip -o /tmp/chrome.zip \
    && unzip -q /tmp/chrome.zip -d /opt \
    && pip install --no-cache-dir websocket-client==1.9.0 \
    && useradd --uid "$LAB_UID" --create-home browserlab
COPY gabriel/browser_extension/ /repo/gabriel/browser_extension/
COPY testing/gabriel_browser/ /repo/testing/gabriel_browser/
COPY testing/gabriel_identity/tls_lab.py /repo/testing/gabriel_identity/
COPY tooling/scripts/gabriel_extension_package.py /repo/tooling/scripts/
ENV PYTHONPATH=/app:/repo
WORKDIR /repo
USER browserlab
ENTRYPOINT ["timeout", "--kill-after=10", "300", "bash", "testing/gabriel_browser/start.sh"]

FROM runtime AS production
