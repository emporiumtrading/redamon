ARG IDENTITY_BASE=python@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211
FROM ${IDENTITY_BASE} AS dependencies
WORKDIR /build
COPY gabriel/identity/requirements.txt /build/requirements.txt
RUN apk add --no-cache build-base \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r /build/requirements.txt

FROM ${IDENTITY_BASE} AS runtime
LABEL org.gabriel.browser-installation="v1" org.gabriel.tls-profile="rfc5280-strict-v1"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY gabriel/identity/requirements.txt /tmp/requirements.txt
RUN --mount=type=bind,from=dependencies,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels -r /tmp/requirements.txt
COPY gabriel/__init__.py gabriel/capabilities.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/service.py gabriel/identity/machine.py gabriel/identity/tasks.py gabriel/identity/cli.py gabriel/identity/vault.py gabriel/identity/vault_cli.py gabriel/identity/retention.py gabriel/identity/actions.py gabriel/identity/cases.py gabriel/identity/evidence_store.py gabriel/identity/case_cli.py gabriel/identity/schema.sql gabriel/identity/schema_v2.sql gabriel/identity/schema_v3.sql gabriel/identity/schema_v4.sql gabriel/identity/schema_v5.sql gabriel/identity/schema_v6.sql gabriel/identity/schema_v7.sql gabriel/identity/schema_v8.sql /app/gabriel/identity/
RUN mkdir -p /var/lib/gabriel-evidence /intake && chown 10001:10001 /var/lib/gabriel-evidence
COPY gabriel/identity/checkpoints.py gabriel/identity/checkpoint_service.py gabriel/identity/checkpoint_policy.py gabriel/identity/schema_v9.sql /app/gabriel/identity/
COPY gabriel/identity/evidence_crypto.py gabriel/identity/evidence_keys.py gabriel/identity/key_retirement.py gabriel/identity/schema_v10.sql /app/gabriel/identity/
COPY gabriel/identity/browser_sessions.py gabriel/identity/browser_cli.py gabriel/identity/schema_v11.sql /app/gabriel/identity/
COPY gabriel/identity/browser_observations.py gabriel/identity/schema_v12.sql /app/gabriel/identity/
COPY gabriel/identity/browser_navigation.py gabriel/identity/schema_v21.sql /app/gabriel/identity/
COPY gabriel/identity/schema_v22.sql /app/gabriel/identity/
COPY gabriel/identity/browser_gateway.py gabriel/identity/gateway_cli.py /app/gabriel/identity/
COPY gabriel/identity/reports.py gabriel/identity/environment.py /app/gabriel/identity/
COPY gabriel/identity/browser_text_review.py gabriel/identity/browser_memory.py /app/gabriel/identity/
COPY gabriel/identity/specialist_qualification.py /app/gabriel/identity/
COPY gabriel/identity/personal_providers.py gabriel/identity/specialist_agents.py gabriel/identity/schema_v29.sql /app/gabriel/identity/
COPY gabriel/identity/schema_v27.sql gabriel/identity/schema_v28.sql gabriel/identity/browser_ai.py /app/gabriel/identity/
COPY gabriel/hermes/runtime.py gabriel/hermes/server.py gabriel/hermes/prepare_runtime.py gabriel/hermes/Dockerfile gabriel/hermes/requirements.lock /app/gabriel/hermes/
COPY gabriel/identity/browser_semantics.py gabriel/identity/browser_hermes.py gabriel/identity/hermes_qualification.py gabriel/identity/hermes_bridge.py gabriel/identity/hermes_supervisor.py gabriel/identity/schema_v30.sql gabriel/identity/schema_v31.sql /app/gabriel/identity/
COPY gabriel/identity/release_qualification.py /app/gabriel/identity/
COPY gabriel/identity/installation.py /app/gabriel/identity/
RUN mkdir -p /var/lib/gabriel-workbench && chown 10001:10001 /var/lib/gabriel-workbench && chmod 700 /var/lib/gabriel-workbench
RUN mkdir -p /var/lib/gabriel-browser && chown 10001:10001 /var/lib/gabriel-browser && chmod 700 /var/lib/gabriel-browser
COPY gabriel/identity/workbench.py gabriel/identity/workbench_cli.py /app/gabriel/identity/
COPY gabriel/identity/analyst_views.py /app/gabriel/identity/
COPY gabriel/identity/case_workflow.py gabriel/identity/schema_v13.sql /app/gabriel/identity/
COPY gabriel/identity/case_graph.py /app/gabriel/identity/
COPY gabriel/identity/specialists.py gabriel/identity/specialist_contracts.py gabriel/identity/schema_v14.sql /app/gabriel/identity/
COPY gabriel/identity/memory.py gabriel/identity/schema_v15.sql /app/gabriel/identity/
COPY gabriel/identity/model_evaluation.py gabriel/identity/model_protocol.py gabriel/identity/model_routes.py gabriel/identity/model_transport.py gabriel/identity/model_worker.py /app/gabriel/identity/
COPY gabriel/identity/model_input.py /app/gabriel/identity/
COPY gabriel/identity/attack_patterns.py /app/gabriel/identity/
COPY gabriel/identity/wazuh_events.py /app/gabriel/identity/
COPY gabriel/identity/attack_pattern_runs.py gabriel/identity/schema_v23.sql /app/gabriel/identity/
COPY gabriel/identity/browser_events.py gabriel/identity/browser_specialists.py gabriel/identity/schema_v24.sql gabriel/identity/schema_v26.sql /app/gabriel/identity/
COPY gabriel/identity/specialist_analysis_runs.py gabriel/identity/schema_v20.sql /app/gabriel/identity/
COPY gabriel/identity/provider_onboarding.py gabriel/identity/schema_v19.sql gabriel/identity/specialist_analysis.py /app/gabriel/identity/
COPY gabriel/identity/model_answers.py gabriel/identity/schema_v18.sql /app/gabriel/identity/
COPY gabriel/identity/coordinator.py gabriel/identity/schema_v17.sql gabriel/identity/schema_v25.sql /app/gabriel/identity/
COPY gabriel/identity/model_budget.py gabriel/identity/budget_cli.py gabriel/identity/schema_v16.sql /app/gabriel/identity/
RUN python -c "import ast,pathlib; [ast.parse(p.read_text(),filename=str(p)) for p in pathlib.Path('/app/gabriel').rglob('*.py')]"
COPY gabriel/toolbox/ /app/gabriel/toolbox/
COPY gabriel/identity/investigation_tools.py gabriel/identity/reviewed_memory.py /app/gabriel/identity/
COPY gabriel/identity/investigation_skills/ /app/gabriel/identity/investigation_skills/
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
COPY tooling/scripts/gabriel_extension_package.py tooling/scripts/gabriel_candidate_export.py /repo/tooling/scripts/
COPY gabriel/identity/checkpoint_cli.py /app/gabriel/identity/
COPY gabriel/identity/provider_probe.py gabriel/identity/model_lab.py /app/gabriel/identity/
COPY gabriel/identity/model_validation.py /app/gabriel/identity/
RUN python -c "import ast,pathlib; [ast.parse(p.read_text(),filename=str(p)) for p in pathlib.Path('/repo/testing/gabriel_identity').rglob('*.py')]"
USER 10001:10001
ENTRYPOINT ["python", "tooling/scripts/pytest_isolated.py", "all", "testing/gabriel_identity", "--strict", "--parallel", "1"]

FROM ${IDENTITY_BASE} AS checkpoint-signer
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN pip install --no-cache-dir cryptography==50.0.2
COPY gabriel/__init__.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/checkpoints.py gabriel/identity/checkpoint_cli.py /app/gabriel/identity/
RUN ["apk", "add", "--no-network", "ca-certificates-bundle", "alpine-baselayout-data"]
RUN ["apk", "del", "--rdepends", "--no-scripts", "--no-cache", "busybox", "busybox-binsh", "ssl_client"]
USER 10001:10001
ENTRYPOINT ["python", "-m", "gabriel.identity.checkpoint_cli"]

# Browser binaries require glibc; this test harness installs its own Debian dependencies.
FROM python:3.11-slim AS browser-lab
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY gabriel/identity/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY --from=runtime /app/gabriel /app/gabriel
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
ENTRYPOINT ["timeout", "--kill-after=10", "420", "bash", "testing/gabriel_browser/start.sh"]

FROM runtime AS production
USER 0:0
# Production installs dependencies at build time; bundled build tools add attack surface.
RUN python -m pip uninstall --yes setuptools wheel pip \
    && python -c "from importlib.util import find_spec; assert all(find_spec(name) is None for name in ('setuptools','wheel','pip')); import psycopg, argon2, cryptography, gunicorn, yara, dpkt"
RUN ["apk", "add", "--no-network", "ca-certificates-bundle", "alpine-baselayout-data"]
RUN ["apk", "del", "--rdepends", "--no-scripts", "--no-cache", "busybox", "busybox-binsh", "ssl_client"]
RUN ["python", "-c", "import shutil,ssl; assert ssl.create_default_context().cert_store_stats()['x509_ca'] > 0; assert all(shutil.which(n) is None for n in ('busybox','wget','ssl_client','gcc','cc')); import psycopg,argon2,cryptography,gunicorn,yara,dpkt"]
USER 10001:10001
