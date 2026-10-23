FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app /data
COPY app ./app

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}
USER app
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"
# Only Caddy reaches the app (internal network), so its forwarded client IP is trusted.
CMD ["uvicorn", "app.main:build", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
