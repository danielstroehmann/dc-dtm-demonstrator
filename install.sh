#!/usr/bin/env bash
# Demonstrator · Device Trust Manager installer – prepares a fresh Ubuntu Server and starts the demonstrator.
# Re-running it updates the installation in place (data and secrets are kept).
#
#   curl -fsSL https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh | sudo bash
#   … | sudo bash -s -- --version v0.1.0      install a specific release
#   … | sudo bash -s -- --branch dev          install the preview image of a branch
#   … | sudo bash -s -- --uninstall [--purge] remove it (purge: also data and Docker if we installed it)
#   … | sudo bash -s -- --reset-password      the next visitor sets a new login password
set -euo pipefail

REPO="danielstroehmann/dc-dtm-demonstrator"
IMAGE_REPO="ghcr.io/danielstroehmann/dc-dtm-demonstrator"
INSTALL_DIR="/opt/dtm-demonstrator"
APP_UID=10001

version="" branch="" tls_mode="" tls_cert="" tls_key="" tls_dir="" hosts="" port="" http_port="" local_image="" local_files=""
uninstall=false purge=false assume_yes=false reset_password=false tls_dir_set=false

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
	cat <<'EOF'
Options:
  --version vX.Y.Z      install this release (default: latest release, asked interactively)
  --branch NAME         install the preview image of a branch instead of a release
  --tls-cert PATH       use this certificate (PEM, with chain) – written to TLS_CERT_FILE in .env
  --tls-key PATH        use this private key (PEM) – written to TLS_KEY_FILE in .env
  --tls selfsigned      back to the generated self-signed certificate
  --tls-dir PATH        host directory (e.g. /etc/digicert) whose certificate files Settings may use by path,
                        renewals included – written to TLS_HOST_DIR in .env (--tls-dir "" clears it)
                        (TLS is configured in .env: TLS_CERT_FILE/TLS_KEY_FILE or TLS_PKCS12_FILE)
  --host NAME           host name or IP the UI is reached by (repeatable; default: host name + IPs)
  --port N              HTTPS port (default 443)
  --http-port N         HTTP port that redirects to HTTPS (default 80)
  --local-image IMAGE   use an already loaded image instead of pulling (testing)
  --local-files DIR     take deploy/ and minion/ from DIR instead of GitHub (testing)
  --yes                 no questions; with neither --version nor --branch the latest release is used
  --reset-password      remove the login password (the next visitor sets a new one) and end all sessions
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
		--tls-dir) tls_dir="${2?}"; tls_dir_set=true; shift 2 ;;
		--host) hosts="${hosts:+$hosts }${2:?}"; shift 2 ;;
		--port) port="${2:?}"; shift 2 ;;
		--http-port) http_port="${2:?}"; shift 2 ;;
		--local-image) local_image="${2:?}"; shift 2 ;;
		--local-files) local_files="${2:?}"; shift 2 ;;
		--yes) assume_yes=true; shift ;;
		--reset-password) reset_password=true; shift ;;
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
# "custom" is kept for older command lines: it means --tls-cert/--tls-key
[ -z "$tls_mode" ] || [[ "$tls_mode" =~ ^(selfsigned|custom)$ ]] || die "--tls must be selfsigned or custom"
[ "$tls_mode" != custom ] || [ -n "$tls_cert$tls_key" ] || die "--tls custom needs --tls-cert and --tls-key"
overlaps() { [[ "$1/" == "$2/"* || "$2/" == "$1/"* ]]; }  # one directory is, contains or lies inside the other
if [ -n "$tls_dir" ]; then
	# Mounted at the same path in the tls services' containers: it must not cover one of their system directories.
	{ [[ "$tls_dir" == /* ]] && [ -d "$tls_dir" ]; } || die "--tls-dir needs an existing absolute directory: $tls_dir"
	tls_dir=$(realpath "$tls_dir")
	{ [[ "$tls_dir" =~ ^(/[A-Za-z0-9._-]+){2,}$ ]] && ! [[ "$tls_dir" =~ ^/(bin|dev|lib[^/]*|proc|run|sbin|srv|sys|tmp|usr|tls[^/]*)/ ]]; } \
		|| die "--tls-dir must be a directory like /etc/digicert (two levels or more, no system directory, plain characters): $tls_dir"
	# Root reads below it: not the installation (.env, keys, data) nor Docker's data (other containers' files).
	for dir in "$INSTALL_DIR" /var/lib/docker; do
		! overlaps "$tls_dir" "$dir" || die "--tls-dir must not contain or lie inside $dir: $tls_dir"
	done
fi

compose() { docker compose --project-directory "$INSTALL_DIR" -p dtm-demonstrator "$@"; }

env_file="$INSTALL_DIR/.env"
env_tmp=""
trap 'rm -f "$env_tmp"; rm -rf "${minion_dir:-}"' EXIT  # never leave a copy of the secrets behind
env_get() { sed -n "s/^$1=//p" "$env_file" | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'; }
env_rewrite() { # drop KEY, optionally append KEY='VALUE' – single quotes: compose takes the value literally
	env_tmp=$(mktemp "$env_file.XXXXXX")
	{ grep -a -v "^$1=" "$env_file" || true; [ $# -lt 2 ] || printf "%s='%s'\n" "$1" "$2"; } >"$env_tmp"
	chmod 600 "$env_tmp" && mv "$env_tmp" "$env_file"
	env_tmp=""
}
env_set() { env_rewrite "$1" "$2"; }

# --- reset the login password ------------------------------------------------------------------
if $reset_password; then
	[ -s "$env_file" ] || die "no installation in $INSTALL_DIR"
	[ -n "$(compose ps -q app 2>/dev/null)" ] || die "the demonstrator is not running – install or start it first"
	# The app is down while the hash is gone and the secret changes – nobody can set a password in between.
	compose stop app >/dev/null
	compose run --rm --no-deps -T app python -m app.reset_password || { compose start app >/dev/null; die "reset failed – nothing changed"; }
	env_rewrite ADMIN_PASSWORD  # an old value would be taken over again at the next start
	env_set JWT_SECRET "$(openssl rand -hex 32)"  # a new secret ends every session, also a stranger's
	compose up -d app >/dev/null
	info "Login password removed – open the demonstrator and set a new one (whoever opens it first sets it)"
	exit 0
fi

# --- uninstall -------------------------------------------------------------------------------
if $uninstall; then
	if [ -f /etc/systemd/system/dtm-demonstrator.service ]; then
		systemctl disable --now --quiet dtm-demonstrator.service || true
		rm -f /etc/systemd/system/dtm-demonstrator.service
		systemctl daemon-reload
	fi
	if [ -f "$INSTALL_DIR/docker-compose.yml" ] && command -v docker >/dev/null; then
		info "Stopping the demonstrator"
		if $purge; then compose down --remove-orphans --volumes --rmi all || true; else compose down --remove-orphans || true; fi
	fi
	if command -v docker >/dev/null; then  # minions of runs that were not rolled back
		docker ps -aq --filter label=dtm-demonstrator.run | xargs -r docker rm -f >/dev/null || true
		docker network rm dtm-minions >/dev/null 2>&1 || true
		if $purge; then
			docker images -q dtm-minion | xargs -r docker rmi -f >/dev/null || true
		fi
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
if [ -n "$tls_dir" ]; then  # Docker's actual data root – daemon.json may have moved it
	docker_root=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)
	! overlaps "$tls_dir" "${docker_root:-/var/lib/docker}" || die "--tls-dir must not contain or lie inside ${docker_root:-/var/lib/docker}: $tls_dir"
fi

# --- files ----------------------------------------------------------------------------------
fetch() {
	if [ -n "${local_files:-}" ]; then cp "$local_files/$1" "$2" || die "$1 is missing in $local_files"; return; fi
	curl -fsSL "https://raw.githubusercontent.com/$REPO/$ref/$1" -o "$2" || die "could not download $1 for $ref"
}
# A release before the minions has no minion/ – that is no error
have() { if [ -n "${local_files:-}" ]; then [ -f "$local_files/$1" ]; else curl -fsSIL "https://raw.githubusercontent.com/$REPO/$ref/$1" >/dev/null 2>&1; fi; }

if [ ! -s "$env_file" ]; then
	cat >"$env_file" <<'EOF'
# Demonstrator · Device Trust Manager settings. Edit, then reboot or run: systemctl restart dtm-demonstrator
# SITE_HOSTS: space-separated host names / IPv4 addresses the HTTPS certificate covers.
# DEFAULT_SNI: the address used when a browser connects by IP (no SNI).
# HTTPS_PORT / HTTP_PORT: published ports; plain HTTP redirects to HTTPS.
EOF
fi
if ! grep -q '^# TLS:' "$env_file"; then
	cat >>"$env_file" <<'EOF'
# TLS: TLS_CERT_FILE + TLS_KEY_FILE – PEM certificate (with chain) and private key, e.g. from Let's Encrypt
#   (default: a self-signed pair in ./tls). Or TLS_PKCS12_FILE + TLS_PKCS12_PASSWORD – used only when
#   TLS_CERT_FILE and TLS_KEY_FILE are empty. Paths absolute or relative to this directory, readable by root.
#   Applied at every start: systemctl restart dtm-demonstrator
EOF
fi
if ! grep -q '^# TLS_HOST_DIR:' "$env_file"; then
	cat >>"$env_file" <<'EOF'
# TLS_HOST_DIR: a host directory (e.g. /etc/digicert) whose certificate files Settings → HTTPS certificate may use
#   by path – read-only, renewals applied within a minute. Set with: install.sh --tls-dir PATH (clear: --tls-dir "")
EOF
fi
chmod 600 "$env_file"


# Settings: kept from the previous run unless given again.
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

# Secrets: set once, never overwritten on later runs. The login password is not one of them: whoever
# opens the app first sets it (stored hashed in ./data); an ADMIN_PASSWORD of an older .env is taken over
# by the app once and removed below.
[ -n "$(env_get JWT_SECRET)" ] || env_set JWT_SECRET "$(openssl rand -hex 32)"
# Names this install's minions (Docker label): another demonstrator on the same Docker daemon keeps its own
[ -n "$(env_get MINION_INSTANCE)" ] || env_set MINION_INSTANCE "dtm-$(openssl rand -hex 4)"

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
env_set HTTPS_PORT "$port"
env_set HTTP_PORT "$http_port"
env_set SITE_HOSTS "$hosts"
env_rewrite SITE_ADDRESSES  # derived from SITE_HOSTS when the proxy starts (older installs stored it)
env_set DEFAULT_SNI "$default_sni"

mkdir -p "$INSTALL_DIR/tls" "$INSTALL_DIR/tls-host" "$INSTALL_DIR/tls-live" "$INSTALL_DIR/caddy-data" "$INSTALL_DIR/data"
chmod 700 "$INSTALL_DIR/tls" "$INSTALL_DIR/tls-host"  # tls-host: mounted in place of an unset TLS_HOST_DIR
# tls-live: the proxy serves from it; the app's group (gid = uid) swaps the certificate set in Settings live.
chown "0:$APP_UID" "$INSTALL_DIR/tls-live" && chmod 770 "$INSTALL_DIR/tls-live"
chown "$APP_UID" "$INSTALL_DIR/data" && chmod 700 "$INSTALL_DIR/data"

# --- TLS: .env names the certificate files; the `tls` service checks and applies them at every start
SELF_CERT="$INSTALL_DIR/tls/cert.pem" SELF_KEY="$INSTALL_DIR/tls/key.pem"
self_signed() { # the default: a self-signed PEM pair for the configured host names
	local san="" h
	for h in $hosts; do if [[ "$h" =~ ^[0-9.]+$ ]]; then san="$san,IP:$h"; else san="$san,DNS:$h"; fi; done
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 730 \
		-subj "/O=DTM Demonstrator self-signed/CN=$default_sni" -addext "subjectAltName=${san#,}" \
		-addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
		-addext "extendedKeyUsage=serverAuth" -keyout "$SELF_KEY.new" -out "$SELF_CERT.new" 2>/dev/null \
		|| die "could not create the self-signed certificate"
	chmod 600 "$SELF_KEY.new" && chmod 644 "$SELF_CERT.new"
	mv "$SELF_KEY.new" "$SELF_KEY" && mv "$SELF_CERT.new" "$SELF_CERT"
}
self_signed_by_us() { openssl x509 -in "$SELF_CERT" -noout -subject 2>/dev/null | grep -q "DTM Demonstrator self-signed"; }
self_signed_fits() { # covers every configured host and is valid for 30 more days
	local names h
	names=$(openssl x509 -in "$SELF_CERT" -noout -ext subjectAltName 2>/dev/null) || return 1
	openssl x509 -in "$SELF_CERT" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
	for h in $hosts; do [[ "$names" == *"DNS:$h"* || "$names" == *"IP Address:$h"* ]] || return 1; done
}
legacy_tls=$(env_get TLS_MODE)  # installs before v0.3: selfsigned (Caddy's internal CA) or custom (./tls)
if [ -n "$tls_cert$tls_key" ]; then
	{ [ -r "$tls_cert" ] && [ -r "$tls_key" ]; } || die "--tls-cert and --tls-key need readable files"
	openssl x509 -in "$tls_cert" -noout 2>/dev/null || die "$tls_cert is not a PEM certificate"
	openssl pkey -in "$tls_key" -noout -passin pass: 2>/dev/null || die "$tls_key is not an unencrypted PEM private key"
	env_set TLS_CERT_FILE "$(realpath "$tls_cert")"
	env_set TLS_KEY_FILE "$(realpath "$tls_key")"
elif [ "$tls_mode" = selfsigned ] || ! grep -q '^TLS_CERT_FILE=' "$env_file"; then
	if [ "$legacy_tls" = custom ] && [ "$tls_mode" != selfsigned ] && [ -s "$SELF_CERT" ] && [ -s "$SELF_KEY" ]; then
		: # an older install with its own pair in ./tls – keep using it
	elif ! { self_signed_by_us && self_signed_fits; }; then
		self_signed
	fi
	env_set TLS_CERT_FILE ./tls/cert.pem
	env_set TLS_KEY_FILE ./tls/key.pem
elif [ "$(env_get TLS_CERT_FILE)" = ./tls/cert.pem ] && self_signed_by_us && ! self_signed_fits; then
	self_signed  # other host names or about to expire
fi
env_rewrite TLS_MODE
grep -q '^TLS_PKCS12_FILE=' "$env_file" || env_set TLS_PKCS12_FILE ""
grep -q '^TLS_PKCS12_PASSWORD=' "$env_file" || env_set TLS_PKCS12_PASSWORD ""
! $tls_dir_set || env_set TLS_HOST_DIR "$tls_dir"  # checked with the options above; "" clears it
grep -q '^TLS_HOST_DIR=' "$env_file" || env_set TLS_HOST_DIR ""

fetch deploy/docker-compose.yml "$INSTALL_DIR/docker-compose.yml"
fetch deploy/Caddyfile "$INSTALL_DIR/Caddyfile"

# --- minions (TrustEdge use case): image built here from DigiCert's public TrustEdge release, pinned by
# version and checksum in minion/Dockerfile – the demonstrator does not redistribute TrustEdge.
minion_dir=$(mktemp -d)
if have minion/Dockerfile; then
	fetch minion/Dockerfile "$minion_dir/Dockerfile"
	fetch minion/entrypoint.sh "$minion_dir/entrypoint.sh"
	minion_version=$(sed -n 's/^ARG TRUSTEDGE=//p' "$minion_dir/Dockerfile")
	[[ "$minion_version" =~ ^[0-9.-]+$ ]] || die "unexpected TrustEdge version in minion/Dockerfile"
	# A changed entrypoint is a new image – the tag carries a hash of the minion sources
	minion_version="$minion_version-$(cat "$minion_dir/Dockerfile" "$minion_dir/entrypoint.sh" | sha256sum | cut -c1-8)"
	built=yes
	if ! docker image inspect "dtm-minion:$minion_version" >/dev/null 2>&1; then
		info "Building the minion image (DigiCert TrustEdge $minion_version)"
		# Not fatal: without the image only the TrustEdge use case is unavailable (the app greys it out)
		docker build -q -t "dtm-minion:$minion_version" "$minion_dir" >/dev/null \
			|| { built=no; echo "WARNING: could not build the minion image – TrustEdge managed devices stay unavailable" >&2; }
	fi
	if [ "$built" = yes ]; then
		env_set MINION_VERSION "$minion_version"
		# Older minion images go – one still used by a minion stays (rmi refuses)
		docker images dtm-minion --format '{{.Repository}}:{{.Tag}}' | grep -v ":$minion_version\$" \
			| xargs -r docker rmi >/dev/null 2>&1 || true
	fi
	docker network inspect dtm-minions >/dev/null 2>&1 || docker network create dtm-minions >/dev/null
fi

# --- boot integration: apply .env changes on every start ------------------------------------
# Containers keep the environment they were created with; `compose up -d` at boot recreates the
# ones whose configuration (e.g. .env) changed.
docker_bin=$(command -v docker)
[[ "$docker_bin" == /snap/* ]] && die "Docker from the snap store is not supported – remove it and re-run (the installer sets up Docker Engine)"
cat >/etc/systemd/system/dtm-demonstrator.service <<EOF
[Unit]
Description=Demonstrator · Device Trust Manager
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
# No ExecStop: Docker's restart policy stays the fallback if this unit fails at boot.
ExecStart=$docker_bin compose --project-directory $INSTALL_DIR -p dtm-demonstrator up -d --remove-orphans
# TLS files may have changed in place (e.g. a renewed certificate): check them again and let Caddy load them.
ExecStart=$docker_bin compose --project-directory $INSTALL_DIR -p dtm-demonstrator up -d --force-recreate tls proxy
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
	compose logs --tail 30 tls proxy || true  # tls: why the TLS files were refused
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
info "Demonstrator · Device Trust Manager $ref is running:"
for h in $hosts; do
	echo "      https://$h$([ "$port" = 443 ] || echo ":$port")/"
done
if [ "$(env_get TLS_CERT_FILE)" = ./tls/cert.pem ] && self_signed_by_us; then
	echo "    (self-signed certificate – your browser will ask you to accept it; your own: TLS_* in $env_file)"
fi
if [ -n "$(env_get ADMIN_PASSWORD)" ]; then
	# The app (healthy, so it has started) took the old password over or ignored it – either way it does not
	# belong in .env any more; recreate the container so it is gone from its environment, too.
	app_log=$(compose logs app 2>/dev/null || true)  # captured: grep -q on a pipe could SIGPIPE the producer
	if grep -q "ADMIN_PASSWORD ignored" <<<"$app_log"; then
		echo "WARNING: ADMIN_PASSWORD in $env_file was ignored – a login password is already set." >&2
		echo "         To set a new one: run this installer with --reset-password." >&2
	else
		echo "    Login password: unchanged (now stored hashed by the app)"
	fi
	env_rewrite ADMIN_PASSWORD
	compose up -d app >/dev/null
fi
# Ask the app, not .env: the login page offers the setup form while no password is set.
login_page=$(curl -fsk --resolve "$default_sni:$port:127.0.0.1" "https://$default_sni:$port/login" 2>/dev/null || true)
if grep -q 'action="/setup"' <<<"$login_page"; then
	echo "    Login password: not set yet – open the URL now (whoever opens it first sets it)"
elif [ -z "$login_page" ]; then
	echo "    Login password: if none is set yet, the first visit sets it"
fi
