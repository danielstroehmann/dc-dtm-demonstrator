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

version="" branch="" tls_mode="" tls_cert="" tls_key="" hosts="" port="" http_port="" local_image=""
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
  --http-port N         HTTP port that redirects to HTTPS (default 80)
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
		--http-port) http_port="${2:?}"; shift 2 ;;
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
VERSION_RE='^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'
[ -z "$version" ] || [[ "$version" =~ $VERSION_RE ]] || die "invalid version: $version"
[ -z "$local_image" ] || [[ "$local_image" =~ ^[a-z0-9./_:-]+$ ]] || die "invalid image name: $local_image"
[ -z "$branch" ] || [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || die "invalid branch: $branch"
[ -z "$port" ] || { [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } || die "invalid port: $port"
[ -z "$http_port" ] || { [[ "$http_port" =~ ^[0-9]+$ ]] && [ "$http_port" -ge 1 ] && [ "$http_port" -le 65535 ]; } || die "invalid HTTP port: $http_port"
[ -z "$tls_mode" ] || [[ "$tls_mode" =~ ^(selfsigned|custom)$ ]] || die "--tls must be selfsigned or custom"

compose() { docker compose --project-directory "$INSTALL_DIR" -p dtm-demonstrator "$@"; }

# --- uninstall -------------------------------------------------------------------------------
if $uninstall; then
	if [ -f /etc/systemd/system/dtm-demonstrator.service ]; then
		systemctl disable --now --quiet dtm-demonstrator.service || true
		rm -f /etc/systemd/system/dtm-demonstrator.service
		systemctl daemon-reload
	fi
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
			if getent group docker >/dev/null; then groupdel docker; fi
			apt-get update -qq
		fi
		rm -rf "$INSTALL_DIR"
	else
		info "Data kept in $INSTALL_DIR – use --uninstall --purge to delete it"
	fi
	exit 0
fi

# --- choose what to install (explicit choice, never a silent install of main) -----------------
# [ -r /dev/tty ] is true even without a controlling terminal (mode 0666) – actually open it.
have_tty() { { : </dev/tty; } 2>/dev/null; }

tty_read() { # prompt default -> answer; works when the script itself comes from a pipe
	local answer=""
	if have_tty; then read -r -p "$1" answer </dev/tty || true; fi
	echo "${answer:-$2}"
}

if [ -z "$version" ] && [ -z "$branch" ]; then
	latest=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
		| sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)
	if $assume_yes || ! have_tty; then
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
	[ -z "$version" ] || [[ "$version" =~ $VERSION_RE ]] || die "invalid version: $version"
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
	# shellcheck source=/dev/null
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

env_file="$INSTALL_DIR/.env"
if [ ! -s "$env_file" ]; then
	cat >"$env_file" <<'EOF'
# DTM Demonstrator settings. Edit, then reboot or run: systemctl restart dtm-demonstrator
# SITE_HOSTS: space-separated host names / IPv4 addresses the HTTPS certificate covers.
# DEFAULT_SNI: the address used when a browser connects by IP (no SNI).
# HTTPS_PORT / HTTP_PORT: published ports; plain HTTP redirects to HTTPS.
EOF
fi
chmod 600 "$env_file"
env_tmp=""
trap 'rm -f "$env_tmp"' EXIT  # never leave a copy of the secrets behind
env_get() { sed -n "s/^$1=//p" "$env_file" | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'; }
env_rewrite() { # drop KEY, optionally append KEY='VALUE' – single quotes: compose takes the value literally
	env_tmp=$(mktemp "$env_file.XXXXXX")
	{ grep -a -v "^$1=" "$env_file" || true; [ $# -lt 2 ] || printf "%s='%s'\n" "$1" "$2"; } >"$env_tmp"
	chmod 600 "$env_tmp" && mv "$env_tmp" "$env_file"
	env_tmp=""
}
env_set() { env_rewrite "$1" "$2"; }

# Settings: kept from the previous run unless given again. The port checks run before a
# password is generated – a generated password is only shown at the end and would be lost otherwise.
tls_mode="${tls_mode:-$(env_get TLS_MODE)}"; tls_mode="${tls_mode:-selfsigned}"
port="${port:-$(env_get HTTPS_PORT)}"; port="${port:-443}"
previous_http_port=$(env_get HTTP_PORT)
http_port="${http_port:-$previous_http_port}"; http_port="${http_port:-80}"
[ "$http_port" != "$port" ] || die "HTTP and HTTPS port must differ"
# An update must not take a working install down: the HTTP port has to be free, unless our own
# proxy already holds it.
if ss -Hltn "sport = :$http_port" 2>/dev/null | grep -q . \
	&& ! { [ "$previous_http_port" = "$http_port" ] && [ -n "$(compose ps -q proxy 2>/dev/null)" ]; }; then
	die "port $http_port is in use by another service – pass --http-port N"
fi

# Secrets: set once, never overwritten on later runs.
new_password="" shown_password=""
if [ -z "$(env_get ADMIN_PASSWORD)" ]; then
	if ! $assume_yes && have_tty; then
		while true; do
			pw1="" pw2=""
			IFS= read -r -s -p "Initial login password (min. 12 characters, empty = generate one): " pw1 </dev/tty || true; echo
			[ -z "$pw1" ] && break
			if [ "${#pw1}" -lt 12 ]; then echo "  Too short."; continue; fi
			# ' and \ cannot be stored safely for docker compose
			case "$pw1" in *"'"* | *\\*) echo "  The password must not contain ' or \\ – pick another."; continue ;; esac
			IFS= read -r -s -p "Repeat the password: " pw2 </dev/tty || true; echo
			[ "$pw1" = "$pw2" ] && { new_password="$pw1"; break; }
			echo "  The passwords do not match."
		done
	fi
	if [ -z "$new_password" ]; then
		new_password=$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-24)
		shown_password="$new_password"  # generated: show it once at the end
	fi
	env_set ADMIN_PASSWORD "$new_password"
fi
[ -n "$(env_get JWT_SECRET)" ] || env_set JWT_SECRET "$(openssl rand -hex 32)"

if [ -z "$hosts" ]; then hosts="$(env_get SITE_HOSTS)"; fi
if [ -z "$hosts" ]; then
	# Host name + IPv4 addresses of real interfaces (not Docker's bridges).
	hosts="$(hostname -f 2>/dev/null || hostname) $(ip -4 -o addr show scope global 2>/dev/null \
		| awk '$2 !~ /^(docker|br-|veth)/ {split($4, a, "/"); print a[1]}' | xargs)"
	if ! $assume_yes && have_tty; then
		# The DNS name the browser uses is often not the local host name – the certificate must cover it.
		extra=$(tty_read "Additional host names for HTTPS, space-separated (detected: $(echo "$hosts" | xargs)) []: " "")
		hosts="$hosts $extra"
	fi
fi
# IPv4 and host names only; loopback is useless for remote access.
valid_hosts=""
for h in $(echo "$hosts" | tr ',' ' '); do  # word splitting handles spaces, tabs, newlines
	if [[ "$h" =~ ^[A-Za-z0-9.-]+$ ]] && ! [[ "$h" =~ ^(127\.|localhost$) ]]; then
		valid_hosts="$valid_hosts $h"
	else
		echo "WARNING: ignoring host '$h' (plain host names or IPv4 addresses only, no scheme or port)" >&2
	fi
done
hosts=$(echo "$valid_hosts" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ $//')
[ -n "$hosts" ] || die "could not determine host names – pass --host"
# Browsers send no SNI for IP addresses; default to the IP of the default route.
route_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}' || true)
previous_sni=$(env_get DEFAULT_SNI)
if [ -n "$previous_sni" ] && [[ " $hosts " == *" $previous_sni "* ]]; then
	default_sni="$previous_sni"  # keep a hand-picked value while it is still covered
elif [ -n "$route_ip" ] && [[ " $hosts " == *" $route_ip "* ]]; then
	default_sni="$route_ip"
else
	default_sni=$(echo "$hosts" | tr ' ' '\n' | { grep -E '^[0-9.]+$' || true; } | head -1)
	default_sni="${default_sni:-${hosts%% *}}"
fi

env_set DEMONSTRATOR_IMAGE "$image"
env_set TLS_MODE "$tls_mode"
env_set HTTPS_PORT "$port"
env_set HTTP_PORT "$http_port"
env_set SITE_HOSTS "$hosts"
env_rewrite SITE_ADDRESSES  # derived from SITE_HOSTS when the proxy starts (older installs stored it)
env_set DEFAULT_SNI "$default_sni"

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
fetch deploy/docker-compose.yml "$INSTALL_DIR/docker-compose.yml"
fetch "deploy/Caddyfile.$tls_mode" "$INSTALL_DIR/Caddyfile"

# --- boot integration: apply .env changes on every start ------------------------------------
# Containers keep the environment they were created with; `compose up -d` at boot recreates the
# ones whose configuration (e.g. .env) changed.
docker_bin=$(command -v docker)
[[ "$docker_bin" == /snap/* ]] && die "Docker from the snap store is not supported – remove it and re-run (the installer sets up Docker Engine)"
cat >/etc/systemd/system/dtm-demonstrator.service <<EOF
[Unit]
Description=DTM Demonstrator
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
# No ExecStop: Docker's restart policy stays the fallback if this unit fails at boot.
ExecStart=$docker_bin compose --project-directory $INSTALL_DIR -p dtm-demonstrator up -d --remove-orphans
TimeoutStartSec=300
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --quiet dtm-demonstrator.service

# --- start ----------------------------------------------------------------------------------
if [ -z "$local_image" ]; then
	info "Pulling images"
	compose pull --quiet
fi
systemctl restart dtm-demonstrator.service || {  # = compose up -d; keeps the unit state truthful
	journalctl -u dtm-demonstrator.service -n 30 --no-pager || true
	compose logs --tail 30 proxy || true
	die "the demonstrator did not start – see the log above"
}
info "Waiting for the demonstrator to become healthy"
for _ in $(seq 1 60); do
	state=$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q app)" 2>/dev/null || true)
	[ "$state" = healthy ] && break
	sleep 2
done
[ "${state:-}" = healthy ] || { compose logs --tail 50 app; die "the demonstrator did not become healthy"; }
# The app being healthy says nothing about the proxy (TLS config, certificate files).
for _ in $(seq 1 15); do
	curl -fsk --resolve "$default_sni:$port:127.0.0.1" "https://$default_sni:$port/healthz" >/dev/null 2>&1 && proxy_ok=true && break
	sleep 2
done
[ "${proxy_ok:-}" = true ] || { compose logs --tail 50 proxy; die "the HTTPS proxy is not reachable on port $port"; }
https_url="https://$default_sni$([ "$port" = 443 ] || echo ":$port")/"
redirect=$(curl -s -m 5 -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $default_sni" "http://127.0.0.1:$http_port/" || true)
[ "$redirect" = "302 $https_url" ] || echo "WARNING: http://$default_sni:$http_port/ does not redirect to $https_url (got: $redirect)" >&2

echo
info "DTM Demonstrator $ref is running:"
for h in $hosts; do
	echo "      https://$h$([ "$port" = 443 ] || echo ":$port")/"
done
if [ "$tls_mode" = selfsigned ]; then echo "    (self-signed certificate – your browser will ask you to accept it)"; fi
if [ -n "$shown_password" ]; then
	echo
	echo "    Login password (shown only once, stored in $env_file):"
	echo "      $shown_password"
fi
