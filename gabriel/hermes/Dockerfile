FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d AS upstream
USER 0:0
COPY gabriel/hermes/prepare_runtime.py /prepare-runtime.py
RUN /opt/hermes/.venv/bin/python /prepare-runtime.py

FROM python@sha256:bc62fbcb684904b1bb81a6240041bb60e9c1ee19ddeaf17a6b4297e1cc9c95d2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/tmp HERMES_HOME=/tmp HERMES_DISABLE_LAZY_INSTALLS=1
COPY --from=upstream /payload/hermes /opt/hermes
COPY --from=upstream /payload/requirements.lock /opt/gabriel-hermes/requirements.lock
COPY --from=upstream /payload/image-provenance.json /etc/hermes/image-provenance.json
RUN python -m venv /opt/hermes/.venv \
    && /opt/hermes/.venv/bin/pip install --no-cache-dir -r /opt/gabriel-hermes/requirements.lock
COPY gabriel/hermes/runtime.py gabriel/hermes/server.py gabriel/hermes/prepare_runtime.py gabriel/hermes/Dockerfile /opt/gabriel-hermes/
USER 10001:10001
WORKDIR /opt/gabriel-hermes
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/gabriel-hermes/server.py"]
