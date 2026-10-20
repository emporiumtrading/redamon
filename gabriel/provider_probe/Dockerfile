FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY gabriel/__init__.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/model_evaluation.py gabriel/identity/provider_probe.py /app/gabriel/identity/
COPY testing/gabriel_model_lab/development_corpus.json /app/development_corpus.json
RUN python -c "import ast,pathlib; [ast.parse(p.read_text(),filename=str(p)) for p in pathlib.Path('/app/gabriel').rglob('*.py')]"
USER 10001:10001
ENTRYPOINT ["python","-m","gabriel.identity.provider_probe"]

FROM runtime AS test
USER 0:0
RUN pip install --no-cache-dir pytest==8.3.5
ENV PYTHONPATH=/app:/repo
WORKDIR /repo
COPY conftest.py pytest.ini /repo/
COPY tooling/scripts/pytest_isolated.py /repo/tooling/scripts/
COPY testing/gabriel_identity/test_provider_probe.py /repo/testing/gabriel_identity/
COPY gabriel/identity/model_input.py /app/gabriel/identity/
COPY testing/gabriel_identity/test_model_input.py /repo/testing/gabriel_identity/
USER 10001:10001
ENTRYPOINT ["python","tooling/scripts/pytest_isolated.py","unit","testing/gabriel_identity","--strict","--parallel","1"]
