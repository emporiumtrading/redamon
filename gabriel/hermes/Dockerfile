FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d
COPY gabriel/hermes/runtime.py gabriel/hermes/server.py /opt/gabriel-hermes/
USER 10001:10001
WORKDIR /opt/gabriel-hermes
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp HERMES_HOME=/tmp
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/gabriel-hermes/server.py"]
