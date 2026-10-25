FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 GABRIEL_PROFILE=local-inspection
WORKDIR /app
COPY gabriel/__init__.py gabriel/__main__.py gabriel/capabilities.py /app/gabriel/
USER 10001:10001
ENTRYPOINT ["python", "-m", "gabriel"]

FROM runtime AS test
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir pytest==8.3.5 pytest-cov==6.0.0 pytest-asyncio==0.25.3
ENV PYTHONPATH=/app:/repo
WORKDIR /repo
COPY conftest.py pytest.ini /repo/
COPY tooling/scripts/pytest_isolated.py tooling/scripts/gabriel_inventory.py /repo/tooling/scripts/
COPY testing/gabriel_runtime/ /repo/testing/gabriel_runtime/
USER 10001:10001
ENTRYPOINT ["python", "tooling/scripts/pytest_isolated.py", "unit", "testing/gabriel_runtime", "--strict", "--parallel", "1"]

FROM runtime AS production
