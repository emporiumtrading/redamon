FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY gabriel/identity/requirements.txt /tmp/requirements.txt
COPY --from=gabriel-gallery-core /app/gabriel/ /app/gabriel/
USER 0:0
ARG LAB_UID=10001
RUN apt-get update && apt-get install -y --no-install-recommends chromium libnss3-tools ca-certificates \
    && pip install --no-cache-dir -r /tmp/requirements.txt websocket-client==1.9.0 \
    && useradd --uid "$LAB_UID" --create-home gallery
RUN rm -rf /var/lib/apt/lists/*
COPY testing/gabriel_gallery/ /gallery/
COPY testing/gabriel_identity/tls_lab.py /gallery/tls_lab.py
ENV PYTHONPATH=/app:/gallery HOME=/tmp/gallery-home
USER gallery
ENTRYPOINT ["python", "/gallery/capture.py"]
