FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ARG LAB_UID=10001
RUN apt-get update && apt-get install -y --no-install-recommends chromium libnss3-tools ca-certificates \
    && pip install --no-cache-dir websocket-client==1.9.0 \
    && useradd --uid "$LAB_UID" --create-home browserlab
WORKDIR /lab
COPY testing/gabriel_console/browser.py /lab/browser.py
USER browserlab
ENTRYPOINT ["python", "/lab/browser.py"]
