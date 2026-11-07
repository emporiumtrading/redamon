FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d AS upstream
USER 0:0
COPY gabriel/hermes/prepare_runtime.py /prepare-runtime.py
COPY gabriel/hermes/requirements.lock /expected-requirements.lock
RUN /opt/hermes/.venv/bin/python /prepare-runtime.py

FROM python@sha256:bc62fbcb684904b1bb81a6240041bb60e9c1ee19ddeaf17a6b4297e1cc9c95d2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/tmp HERMES_HOME=/tmp HERMES_DISABLE_LAZY_INSTALLS=1
# Keep the signed Alpine stable package above the CVE-2026-4738 fix floor.
RUN apk add --no-cache 'zlib>=1.4-r0'
# Hermes retains SQLite for its native runtime. Fetch only the signed library
# package from Alpine edge and resolve installation against the existing image.
RUN set -eux; \
    arch="$(apk --print-arch)"; \
    package=sqlite-libs-3.54.1-r0.apk; \
    wget -O "/tmp/$package" "https://dl-cdn.alpinelinux.org/alpine/edge/main/$arch/$package"; \
    apk add --no-network "/tmp/$package"; \
    rm "/tmp/$package"
RUN python - <<'PY'
import shutil
import sqlite3
import zlib

assert zlib.decompress(zlib.compress(b"Gabriel")) == b"Gabriel"
assert sqlite3.sqlite_version == "3.54.1"
assert shutil.which("sqlite3") is None
with sqlite3.connect(":memory:") as db:
    db.execute("CREATE VIRTUAL TABLE notes USING fts5(body)")
    db.execute("INSERT INTO notes VALUES ('incident evidence')")
    assert db.execute("SELECT body FROM notes WHERE notes MATCH 'incident'").fetchone() == ("incident evidence",)
PY
COPY --from=upstream /payload/hermes /opt/hermes
COPY --from=upstream /payload/requirements.lock /opt/gabriel-hermes/requirements.lock
COPY --from=upstream /payload/image-provenance.json /etc/hermes/image-provenance.json
RUN python -m venv /opt/hermes/.venv \
    && /opt/hermes/.venv/bin/pip install --no-cache-dir --no-deps --no-compile -r /opt/gabriel-hermes/requirements.lock \
    && /opt/hermes/.venv/bin/pip check
COPY gabriel/hermes/runtime.py gabriel/hermes/server.py gabriel/hermes/prepare_runtime.py gabriel/hermes/Dockerfile /opt/gabriel-hermes/
USER 10001:10001
WORKDIR /opt/gabriel-hermes
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/gabriel-hermes/server.py"]
