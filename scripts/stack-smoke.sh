#!/usr/bin/env bash
# Starts the real compose stack (app, tls, proxy) from deploy/ with a given image and a self-signed PEM pair
# (no PKCS#12 – that path is bind-mounted as /dev/null), then checks /healthz through the proxy.
# CI runs it on every push; locally: scripts/stack-smoke.sh <image>.
set -euo pipefail
image=${1:?usage: stack-smoke.sh IMAGE}
repo=$(cd "$(dirname "$0")/.." && pwd)
dir=$(mktemp -d)
project=stack-smoke-$$
compose() { docker compose -p "$project" --project-directory "$dir" -f "$dir/docker-compose.yml" "$@"; }
cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$dir"; }
trap cleanup EXIT

cp "$repo/deploy/docker-compose.yml" "$repo/deploy/Caddyfile" "$dir/"
mkdir -p "$dir/tls" "$dir/tls-live" "$dir/caddy-data" "$dir/data"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost" -keyout "$dir/tls/key.pem" -out "$dir/tls/cert.pem" 2>/dev/null
cat >"$dir/.env" <<EOF
DEMONSTRATOR_IMAGE=$image
ADMIN_PASSWORD=stack-smoke-password-$$-not-a-secret
JWT_SECRET=$(openssl rand -hex 32)
SITE_HOSTS=localhost
DEFAULT_SNI=localhost
HTTPS_PORT=18443
HTTP_PORT=18080
TLS_CERT_FILE=./tls/cert.pem
TLS_KEY_FILE=./tls/key.pem
TLS_PKCS12_FILE=
TLS_PKCS12_PASSWORD=
EOF

compose up -d --quiet-pull || { compose logs tls proxy app; exit 1; }
for _ in $(seq 1 60); do
	if curl -fsk --resolve localhost:18443:127.0.0.1 https://localhost:18443/healthz >/dev/null; then
		echo "stack smoke: proxy and app healthy"
		exit 0
	fi
	sleep 2
done
compose logs tls proxy app
echo "stack smoke: /healthz not reachable through the proxy" >&2
exit 1
