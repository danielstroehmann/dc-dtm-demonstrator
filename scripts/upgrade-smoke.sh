#!/usr/bin/env bash
# Upgrade test (lossless update): boots the previous release's compose stack (app, tls, proxy) on a fresh install
# directory laid out like its install.sh, seeds data through the old app (password, connection, run, event), then
# swaps in this tree's compose file, Caddyfile and image the way install.sh does on an update and checks that the
# new version comes up healthy on the same ./data, ./tls-live and .env: schema migrated, data intact, the old
# password and session still valid, the same certificate served. Then the HTTPS certificate is changed in Settings
# (live, through Caddy's admin socket), survives a restart and a killed proxy, and is reset to the default.
#
# usage: scripts/upgrade-smoke.sh OLD_IMAGE NEW_IMAGE [OLD_REF]
#   OLD_REF (default: the latest v* tag before HEAD) names the old deploy files; OLD_DEPLOY_DIR=<dir> with its
#   docker-compose.yml and Caddyfile instead. SKIP_INSTALLER_CHOWN=1: leave ./tls-live as the old installer left
#   it (root, 0700) – the tls service alone must hand it to the app's group.
# Ownership is only meaningful on Linux (Docker Desktop maps owners itself): run as root or with sudo -n there.
set -euo pipefail
old_image=${1:?usage: upgrade-smoke.sh OLD_IMAGE NEW_IMAGE [OLD_REF]}
new_image=${2:?usage: upgrade-smoke.sh OLD_IMAGE NEW_IMAGE [OLD_REF]}
repo=$(cd "$(dirname "$0")/.." && pwd)
dir=$(mktemp -d)
project=upgrade-smoke-$$
port=${UPGRADE_SMOKE_PORT:-18443}
password="upgrade-smoke-password-$$-not-a-secret"
as_root=""; [ "$(uname)" = Linux ] && [ "$(id -u)" != 0 ] && as_root="sudo -n"
linux=false; [ "$(uname)" = Linux ] && linux=true
compose() { docker compose -p "$project" --project-directory "$dir" -f "$dir/docker-compose.yml" "$@"; }
# shellcheck disable=SC2329  # invoked by the trap
cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; $as_root rm -rf "$dir"; }
trap cleanup EXIT
fail() { echo "upgrade smoke: FAIL – $*" >&2; compose logs tls proxy app 2>&1 | tail -60 >&2; exit 1; }
ok() { echo "upgrade smoke: ok – $*"; }

url="https://localhost:$port"
curl_() { curl -sk --resolve "localhost:$port:127.0.0.1" -H "Origin: $url" "$@"; }
healthy() {
	for _ in $(seq 1 60); do
		curl_ -f "$url/healthz" >/dev/null && return 0
		sleep 2
	done
	fail "/healthz not reachable through the proxy ($1)"
}
served() {  # SHA-256 of the certificate the proxy serves
	openssl s_client -connect "127.0.0.1:$port" -servername localhost </dev/null 2>/dev/null \
		| openssl x509 -noout -fingerprint -sha256 | cut -d= -f2
}
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
app_py() { compose exec -T app python -c "$1"; }
env_set() { grep -v "^$1=" "$dir/.env" >"$dir/.env.new" || true; echo "$1=$2" >>"$dir/.env.new"; mv "$dir/.env.new" "$dir/.env"; }

# --- the previous release, laid out like its install.sh -------------------------------------------------------------
if [ -n "${OLD_DEPLOY_DIR:-}" ]; then
	cp "$OLD_DEPLOY_DIR/docker-compose.yml" "$OLD_DEPLOY_DIR/Caddyfile" "$dir/"
else
	old_ref=${3:-$(git -C "$repo" describe --tags --abbrev=0 --match 'v*' HEAD^)}
	git -C "$repo" show "$old_ref:deploy/docker-compose.yml" >"$dir/docker-compose.yml"
	git -C "$repo" show "$old_ref:deploy/Caddyfile" >"$dir/Caddyfile"
fi
mkdir -p "$dir/tls" "$dir/tls-live" "$dir/caddy-data" "$dir/data"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
	-subj "/O=DTM Demonstrator self-signed/CN=localhost" -addext "subjectAltName=DNS:localhost" \
	-keyout "$dir/tls/key.pem" -out "$dir/tls/cert.pem" 2>/dev/null
chmod 600 "$dir/tls/key.pem"
if $linux; then
	$as_root chown -R 0:0 "$dir/tls" "$dir/tls-live" && $as_root chmod 700 "$dir/tls" "$dir/tls-live"
	$as_root chown 10001 "$dir/data" && $as_root chmod 700 "$dir/data"
fi
cat >"$dir/.env" <<EOF
DEMONSTRATOR_IMAGE=$old_image
ADMIN_PASSWORD=$password
JWT_SECRET=$(openssl rand -hex 32)
SITE_HOSTS=localhost
DEFAULT_SNI=localhost
HTTPS_PORT=$port
HTTP_PORT=$((port - 1))
TLS_CERT_FILE=./tls/cert.pem
TLS_KEY_FILE=./tls/key.pem
TLS_PKCS12_FILE=
TLS_PKCS12_PASSWORD=
EOF
chmod 600 "$dir/.env"

compose up -d --quiet-pull app tls proxy || fail "old stack does not start"
healthy "old version"
[ "$(served)" = "$(fingerprint "$dir/tls/cert.pem")" ] || fail "old version does not serve the .env certificate"
code=$(curl_ -o /dev/null -w '%{http_code}' -c "$dir/cookies" --data-urlencode "password=$password" "$url/login")
[ "$code" = 303 ] || fail "login on the old version: HTTP $code"
app_py "
from pathlib import Path
from app.store import Store
s = Store(Path('/data/demonstrator.db'))
cid = s.save_connection(None, 'Upgrade', 'one.nl.digicert.com', 'upgrade-account', 'not-a-key')
s.create_run('upgr1', 'uc01', {'mode': 'single', 'connection_id': cid})
s.update_run('upgr1', status='completed', result={'certificates': [{'serial': 'AB12', 'common_name': 'robot-upgr1'}]})
s.add_event('upgr1', 'seeded before the upgrade')
print(s._exec('PRAGMA user_version').fetchone()[0])" >"$dir/old-version" || fail "seeding the old version"
ok "old version ($old_image) healthy, schema v$(cat "$dir/old-version"), data seeded"
old_cert=$(served)

# --- the update, as install.sh does it: new deploy files and image, .env kept, new keys added -----------------------
compose down --remove-orphans >/dev/null
cp "$repo/deploy/docker-compose.yml" "$repo/deploy/Caddyfile" "$dir/"
env_set DEMONSTRATOR_IMAGE "$new_image"
grep -q '^MINION_INSTANCE=' "$dir/.env" || env_set MINION_INSTANCE "dtm-$(openssl rand -hex 4)"
if $linux && [ "${SKIP_INSTALLER_CHOWN:-}" != 1 ]; then
	$as_root chown 0:10001 "$dir/tls-live" && $as_root chmod 770 "$dir/tls-live"
fi
compose up -d --quiet-pull app tls proxy || fail "new stack does not start on the old data"
healthy "new version"

[ "$(served)" = "$old_cert" ] || fail "the update changed the served certificate"
[ "$(curl_ -o /dev/null -w '%{http_code}' -b "$dir/cookies" "$url/")" = 200 ] || fail "the old session is not valid any more"
rm "$dir/cookies"
code=$(curl_ -o /dev/null -w '%{http_code}' -c "$dir/cookies" --data-urlencode "password=$password" "$url/login")
[ "$code" = 303 ] || fail "login with the old password after the update: HTTP $code"
app_py "
from pathlib import Path
from app.store import SCHEMA_VERSION, Store
s = Store(Path('/data/demonstrator.db'))
assert s._exec('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION, 'schema not migrated'
run = s.get_run('upgr1')
assert run and run['status'] == 'completed' and run['watchdog'] is None, run
assert run['result']['certificates'][0]['serial'] == 'AB12', run
assert [e['message'] for e in s.events('upgr1')] == ['seeded before the upgrade']
assert [c['name'] for c in s.connections()] == ['Upgrade']
" || fail "data after the update"
curl_ -b "$dir/cookies" "$url/" | grep -q 'upgr1' || fail "the run is not listed after the update"
settings=$(curl_ -b "$dir/cookies" "$url/settings")
grep -q '<span class="badge">Self-signed default</span>' <<<"$settings" || fail "Settings does not show the default certificate"
grep -q 'Reset to default' <<<"$settings" && fail "Settings offers a reset without a Settings certificate"
ok "new version ($new_image) healthy on the old data: schema, run, events, connection, password, session, certificate"

# --- the certificate set in Settings: live, kept across restarts, reset --------------------------------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost" -keyout "$dir/up-key.pem" -out "$dir/up-cert.pem" 2>/dev/null
upload() {
	curl_ -o "$dir/upload.html" -w '%{http_code}' -b "$dir/cookies" -F mode=pem \
		-F "certificate=@$dir/up-cert.pem" -F "private_key=@$dir/up-key.pem" "$url/settings/tls"
}
code=$(upload)
[ "$code" = 303 ] || { grep -o '<p class="error"[^<]*' "$dir/upload.html" >&2 || true; fail "upload in Settings: HTTP $code"; }
[ "$(served)" = "$(fingerprint "$dir/up-cert.pem")" ] || fail "the Settings certificate is not served live"
ok "Settings certificate applied live"
compose down >/dev/null
compose up -d app tls proxy >/dev/null || fail "restart"
healthy "restart"
[ "$(served)" = "$(fingerprint "$dir/up-cert.pem")" ] || fail "the Settings certificate is lost after a restart"
docker kill "$(compose ps -q proxy)" >/dev/null && compose up -d proxy >/dev/null
healthy "proxy killed and started again"
code=$(curl_ -o /dev/null -w '%{http_code}' -b "$dir/cookies" -X POST "$url/settings/tls/reset")
[ "$code" = 303 ] || fail "reset to default after a killed proxy (stale admin socket?): HTTP $code"
[ "$(served)" = "$old_cert" ] || fail "reset to default does not serve the .env certificate"
ok "Settings certificate kept across a restart; reset works after a killed proxy"
if $linux; then
	stat -c '%A %u:%g %n' "$dir/tls-live" "$dir/tls-live"/*
fi
echo "upgrade smoke: passed"
