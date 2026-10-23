#!/usr/bin/env bash
# DTM Demonstrator installer – prepares a fresh Ubuntu Server and starts the demonstrator.
# Re-running it updates the installation in place (data and secrets are kept).
#
#   curl -fsSL https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh | sudo bash
#   … | sudo bash -s -- --version v0.1.0      install a specific release
#   … | sudo bash -s -- --branch dev          install the preview image of a branch
#   … | sudo bash -s -- --uninstall [--purge] remove it (purge: also data and Docker if we installed it)
set -euo pipefail

REPO="danielstroehmann/dc-dtm-demonstrator"
IMAGE_REPO="ghcr.io/danielstroehmann/dc-dtm-demonstrator"
INSTALL_DIR="/opt/dtm-demonstrator"
APP_UID=10001

version="" branch="" tls_mode="" tls_cert="" tls_key="" hosts="" port="" local_image=""
uninstall=false purge=false assume_yes=false

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
	cat <<'EOF'
Options:
  --version vX.Y.Z      install this release (default: latest release, asked interactively)
  --branch NAME         install the preview image of a branch instead of a release
  --tls selfsigned|custom
  --tls-cert PATH       certificate (PEM, full chain) for --tls custom
  --tls-key PATH        private key (PEM) for --tls custom
  --host NAME           host name or IP the UI is reached by (repeatable; default: host name + IPs)
  --port N              HTTPS port (default 443)
  --local-image IMAGE   use an already loaded image instead of pulling (testing)
  --yes                 no questions; with neither --version nor --branch the latest release is used
  --uninstall           stop and remove the demonstrator (data is kept)
  --purge               with --uninstall: also delete all data and Docker if this script installed it
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--version) version="${2:?}"; shift 2 ;;
		--branch) branch="${2:?}"; shift 2 ;;
		--tls) tls_mode="${2:?}"; shift 2 ;;
		--tls-cert) tls_cert="${2:?}"; shift 2 ;;
		--tls-key) tls_key="${2:?}"; shift 2 ;;
		--host) hosts="${hosts:+$hosts }${2:?}"; shift 2 ;;
		--port) port="${2:?}"; shift 2 ;;
		--local-image) local_image="${2:?}"; shift 2 ;;
		--yes) assume_yes=true; shift ;;
		--uninstall) uninstall=true; shift ;;
		--purge) purge=true; shift ;;
		-h|--help) usage; exit 0 ;;
		*) usage; die "unknown option: $1" ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (e.g. with sudo)"
[ -z "$version" ] || [ -z "$branch" ] || die "use either --version or --branch"
[ -z "$version" ] || [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "invalid version: $version"
[ -z "$branch" ] || [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || die "invalid branch: $branch"
[ -z "$port" ] || { [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } || die "invalid port: $port"
[ -z "$tls_mode" ] || [[ "$tls_mode" =~ ^(selfsigned|custom)$ ]] || die "--tls must be selfsigned or custom"

compose() { docker compose --project-directory "$INSTALL_DIR" -p dtm-demonstrator "$@"; }

# --- uninstall -------------------------------------------------------------------------------
if $uninstall; then
	if [ -f "$INSTALL_DIR/docker-compose.yml" ] && command -v docker >/dev/null; then
		info "Stopping the demonstrator"
		if $purge; then compose down --remove-orphans --rmi all || true; else compose down --remove-orphans || true; fi
	fi
	if $purge; then
		info "Deleting $INSTALL_DIR (data included)"
		if [ -f "$INSTALL_DIR/.installed-docker" ]; then
			info "Removing Docker (installed by this script)"
			apt-get purge -y docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin
			apt-get autoremove -y
			rm -rf /var/lib/docker /var/lib/containerd /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
			getent group docker >/dev/null && groupdel docker || true
			apt-get update -qq
		fi
		rm -rf "$INSTALL_DIR"
	else
		info "Data kept in $INSTALL_DIR – use --uninstall --purge to delete it"
	fi
	exit 0
fi

# --- choose what to install (explicit choice, never a silent install of main) -----------------
tty_read() { # prompt default -> answer; works when the script itself comes from a pipe
	local answer=""
	if [ -r /dev/tty ]; then read -r -p "$1" answer </dev/tty || true; fi
	echo "${answer:-$2}"
}

if [ -z "$version" ] && [ -z "$branch" ]; then
	latest=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
		| sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)
	if $assume_yes || [ ! -r /dev/tty ]; then
		[ -n "$latest" ] || die "no release published yet – choose one with --branch NAME"
		version="$latest"
	else
		echo "Available releases: ${latest:-none yet}"
		choice=$(tty_read "Version to install (vX.Y.Z, or branch:NAME)${latest:+ [$latest]}: " "$latest")
		case "$choice" in
			branch:*) branch="${choice#branch:}" ;;
			"") die "nothing selected" ;;
			*) version="$choice" ;;
		esac
	fi
	[ -z "$version" ] || [[ "$version" =~ ^v[0-9] ]] || die "invalid version: $version"
	[ -z "$branch" ] || [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || die "invalid branch: $branch"
fi

if [ -n "$version" ]; then
	ref="$version" image="$IMAGE_REPO:$version"
else
	ref="$branch" image="$IMAGE_REPO:branch-$(echo "$branch" | tr '/' '-' | tr -cd 'A-Za-z0-9._-')"
fi
[ -z "$local_image" ] || image="$local_image"
info "Installing $ref ($image)"

# --- Docker ---------------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
if ! command -v docker >/dev/null; then
	info "Installing Docker Engine from Docker's apt repository"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq ca-certificates curl >/dev/null
	install -m 0755 -d /etc/apt/keyrings
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
	chmod a+r /etc/apt/keyrings/docker.asc
	. /etc/os-release
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" \
		>/etc/apt/sources.list.d/docker.list
	apt-get update -qq
	apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin >/dev/null
	touch "$INSTALL_DIR/.installed-docker"
fi
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"

# --- files ----------------------------------------------------------------------------------
fetch() { curl -fsSL "https://raw.githubusercontent.com/$REPO/$ref/$1" -o "$2" || die "could not download $1 for $ref"; }
fetch deploy/docker-compose.yml "$INSTALL_DIR/docker-compose.yml"

env_file="$INSTALL_DIR/.env"
touch "$env_file" && chmod 600 "$env_file"
env_get() { sed -n "s/^$1=//p" "$env_file" | tail -1 | sed 's/^"\(.*\)"$/\1/'; }
env_set() { # replace or append KEY=VALUE
	if grep -q "^$1=" "$env_file"; then sed -i "s|^$1=.*|$1=$2|" "$env_file"; else echo "$1=$2" >>"$env_file"; fi
}

# Secrets: generated once, never overwritten on later runs.
new_password=""
if [ -z "$(env_get ADMIN_PASSWORD)" ]; then
	new_password=$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-24)
	env_set ADMIN_PASSWORD "$new_password"
fi
[ -n "$(env_get JWT_SECRET)" ] || env_set JWT_SECRET "$(openssl rand -hex 32)"

# Settings: kept from the previous run unless given again.
tls_mode="${tls_mode:-$(env_get TLS_MODE)}"; tls_mode="${tls_mode:-selfsigned}"
port="${port:-$(env_get HTTPS_PORT)}"; port="${port:-443}"
if [ -z "$hosts" ]; then hosts="$(env_get SITE_HOSTS)"; fi
if [ -z "$hosts" ]; then hosts="$(hostname -f 2>/dev/null || hostname) $(hostname -I 2>/dev/null)"; fi
# IPv4 and host names only; loopback is useless for remote access.
hosts=$(echo "$hosts" | xargs -n1 | grep -E '^[A-Za-z0-9.-]+$' | grep -v -E '^(127\.|localhost$)' | sort -u | xargs)
[ -n "$hosts" ] || die "could not determine host names – pass --host"
first_ip=$(echo "$hosts" | xargs -n1 | grep -E '^[0-9.]+$' | head -1)

env_set DEMONSTRATOR_IMAGE "$image"
env_set TLS_MODE "$tls_mode"
env_set HTTPS_PORT "$port"
env_set SITE_HOSTS "\"$hosts\""
env_set SITE_ADDRESSES "\"$(echo "$hosts" | xargs -n1 | sed 's/.*/https:\/\/&:443/' | paste -sd, - | sed 's/,/, /g')\""
env_set DEFAULT_SNI "${first_ip:-$(echo "$hosts" | awk '{print $1}')}"

mkdir -p "$INSTALL_DIR/tls" "$INSTALL_DIR/caddy-data" "$INSTALL_DIR/data"
chown "$APP_UID" "$INSTALL_DIR/data" && chmod 700 "$INSTALL_DIR/data"
if [ "$tls_mode" = custom ]; then
	if [ -n "$tls_cert" ] || [ -n "$tls_key" ]; then
		[ -r "$tls_cert" ] && [ -r "$tls_key" ] || die "--tls custom needs readable --tls-cert and --tls-key"
		openssl x509 -in "$tls_cert" -noout 2>/dev/null || die "$tls_cert is not a PEM certificate"
		openssl pkey -in "$tls_key" -noout 2>/dev/null || die "$tls_key is not a PEM private key"
		install -m 0644 "$tls_cert" "$INSTALL_DIR/tls/cert.pem"
		install -m 0600 "$tls_key" "$INSTALL_DIR/tls/key.pem"
	fi
	[ -f "$INSTALL_DIR/tls/cert.pem" ] && [ -f "$INSTALL_DIR/tls/key.pem" ] || die "--tls custom: no certificate installed yet"
fi
fetch "deploy/Caddyfile.$tls_mode" "$INSTALL_DIR/Caddyfile"

# --- start ----------------------------------------------------------------------------------
if [ -z "$local_image" ]; then
	info "Pulling images"
	compose pull --quiet
fi
compose up -d --remove-orphans
info "Waiting for the demonstrator to become healthy"
for _ in $(seq 1 60); do
	state=$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q app)" 2>/dev/null || true)
	[ "$state" = healthy ] && break
	sleep 2
done
[ "${state:-}" = healthy ] || { compose logs --tail 50 app; die "the demonstrator did not become healthy"; }

echo
info "DTM Demonstrator $ref is running:"
for h in $hosts; do
	echo "      https://$h$([ "$port" = 443 ] || echo ":$port")/"
done
[ "$tls_mode" = selfsigned ] && echo "    (self-signed certificate – your browser will ask you to accept it)"
if [ -n "$new_password" ]; then
	echo
	echo "    Login password (shown only once, stored in $env_file):"
	echo "      $new_password"
fi
