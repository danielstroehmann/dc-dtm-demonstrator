FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /srv
# scep: scepclient (micromdm) for SCEP enrollment – no Python SCEP client of good standing exists.
RUN apt-get update && apt-get install -y --no-install-recommends scep && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/bin/scepserver
COPY requirements.txt .
# gid 10001 is fixed: the proxy and the tls service join it (compose group_add) to read the TLS files the app writes.
RUN pip install --no-cache-dir -r requirements.txt \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app /data
COPY app ./app

# Build identity (/version, footer): CI passes tag or branch, commit and build time; scripts/dev-up the same from git.
ARG APP_VERSION=dev
ARG GIT_SHA=""
ARG BUILD_TIME=""
ENV APP_VERSION=${APP_VERSION} GIT_SHA=${GIT_SHA} BUILD_TIME=${BUILD_TIME}
USER app
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"
# Only Caddy reaches the app (internal network), so its forwarded client IP is trusted.
CMD ["uvicorn", "app.main:build", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
