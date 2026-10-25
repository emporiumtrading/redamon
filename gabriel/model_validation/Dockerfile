FROM python@sha256:5fb4bc53dd0180955e31e5245b648bbb24a4ac4ab03a1de81513642325220bcd AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY gabriel/__init__.py /app/gabriel/
COPY gabriel/identity/__init__.py gabriel/identity/model_evaluation.py gabriel/identity/model_protocol.py gabriel/identity/model_routes.py gabriel/identity/model_transport.py gabriel/identity/model_lab.py gabriel/identity/model_validation.py /app/gabriel/identity/
COPY testing/gabriel_model_lab/candidate_corpus_v1.json /app/corpus.json
USER 10001:10001
ENTRYPOINT ["python","-m","gabriel.identity.model_validation"]

FROM runtime AS test
USER 0:0
RUN pip install --no-cache-dir pytest==8.3.5
ENV PYTHONPATH=/app:/repo
WORKDIR /repo
COPY conftest.py pytest.ini /repo/
COPY tooling/scripts/pytest_isolated.py /repo/tooling/scripts/
COPY testing/gabriel_identity/test_model_validation.py /repo/testing/gabriel_identity/
COPY testing/gabriel_model_lab/candidate_corpus_v1.json /repo/testing/gabriel_model_lab/
USER 10001:10001
ENTRYPOINT ["python","tooling/scripts/pytest_isolated.py","unit","testing/gabriel_identity","--strict","--parallel","1"]
