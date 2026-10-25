FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir pytest==8.3.5 pytest-cov==6.0.0 pytest-asyncio==0.25.3
WORKDIR /repo
COPY conftest.py pytest.ini ./
COPY tooling/scripts/pytest_isolated.py tooling/scripts/pytest_isolated.py
COPY testing/gabriel_foundation/test_gate_runner.py testing/gabriel_foundation/test_gate_runner.py
COPY tests/test_pytest_isolated_tiers.py tests/test_pytest_isolated_tiers.py
USER 65534:65534
ENTRYPOINT ["python", "tooling/scripts/pytest_isolated.py", "unit", "testing/gabriel_foundation", "tests/test_pytest_isolated_tiers.py", "--strict", "--parallel", "1"]
