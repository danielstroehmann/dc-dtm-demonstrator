"""Contract of the deploy files (no Docker): the HTTP → HTTPS redirect and TLS of the Caddyfile, the ports and
environment compose hands the proxy, and the proxy entrypoint snippet – executed for real with /bin/sh
and a stub `caddy`, not re-implemented."""

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
CADDYFILE = DEPLOY / "Caddyfile"


def site_block(text: str, address: str) -> list[str]:
    """Directive lines of the top-level site block that starts with `address {`."""
    match = re.search(rf"^{re.escape(address)} \{{\n(.*?)^\}}", text, re.M | re.S)
    assert match, f"no '{address} {{' site block"
    return [line.strip() for line in match.group(1).splitlines() if line.strip() and not line.strip().startswith("#")]


def proxy_service() -> dict:
    return yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())["services"]["proxy"]


def entrypoint_script() -> str:
    """The `sh -c` script as the container receives it: compose turns `$$` into a literal `$`."""
    entrypoint = proxy_service()["entrypoint"]
    assert entrypoint[:2] == ["/bin/sh", "-c"]
    return entrypoint[2].replace("$$", "$")


REDIR = "redir @known https://{host}{$HTTPS_SUFFIX}{uri} 302"
NOT_FOUND = 'respond "Unknown host name – use one of the configured addresses." 404'


def test_http_block_redirects_known_hosts_only():
    lines = site_block(CADDYFILE.read_text(), "http://")
    assert "@known host {$SITE_HOSTS}" in lines
    assert "header -Server" in lines
    # Every redirect is bound to the host matcher – an unguarded redir would be an open redirect.
    # 302, not a cached permanent redirect: the HTTPS port can change.
    assert [line for line in lines if line.startswith("redir")] == [REDIR]
    # The fallback is a fixed text; a {host} placeholder would reflect the attacker's Host header.
    assert [line for line in lines if line.startswith("respond")] == [NOT_FOUND]
    assert lines.index(NOT_FOUND) > lines.index(REDIR)


def test_one_caddyfile_only():
    assert sorted(p.name for p in DEPLOY.glob("Caddyfile*")) == ["Caddyfile"]


def test_https_block_serves_the_prepared_pem_pair():
    text = CADDYFILE.read_text()
    lines = site_block(text, "{$SITE_ADDRESSES}")
    assert "reverse_proxy app:8000" in lines and "header -Server" in lines
    assert [line for line in lines if line.startswith("tls")] == ["tls /tls/cert.pem /tls/key.pem"]
    # no ACME and no internal CA: Caddy only serves what the tls service prepared
    globals_ = re.search(r"^\{\n(.*?)^\}", text, re.M | re.S).group(1)
    assert "auto_https off" in globals_ and "default_sni {$DEFAULT_SNI}" in globals_
    code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))
    assert "internal" not in code and "acme" not in code.lower()


def test_compose_tls_service_contract():
    services = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())["services"]
    tls = services["tls"]
    assert tls["image"] == "${DEMONSTRATOR_IMAGE}" and tls["restart"] == "no" and tls["user"] == "0"
    assert tls["command"] == ["python", "-m", "app.tls_setup"]
    assert tls["environment"] == {"TLS_PKCS12_PASSWORD": "${TLS_PKCS12_PASSWORD:-}"}
    binds = [v for v in tls["volumes"] if isinstance(v, dict)]
    assert [(b["source"], b["target"]) for b in binds] == [
        ("${TLS_CERT_FILE:-/dev/null}", "/tls-in/cert.pem"), ("${TLS_KEY_FILE:-/dev/null}", "/tls-in/key.pem"),
        ("${TLS_PKCS12_FILE:-/dev/null}", "/tls-in/keystore.p12")]
    for b in binds:  # read-only, and a missing path is an error instead of a created directory
        assert b["type"] == "bind" and b["read_only"] is True and b["bind"] == {"create_host_path": False}
    assert "./tls-live:/tls" in tls["volumes"]
    assert tls["network_mode"] == "none" and tls["read_only"] is True and tls["cap_drop"] == ["ALL"]
    assert tls["security_opt"] == ["no-new-privileges:true"] and "ports" not in tls
    proxy = services["proxy"]
    assert proxy["depends_on"] == {"app": {"condition": "service_started"},
                                   "tls": {"condition": "service_completed_successfully"}}
    assert "./tls-live:/tls:ro" in proxy["volumes"] and "./Caddyfile:/etc/caddy/Caddyfile:ro" in proxy["volumes"]
    assert not any(str(v).startswith("./tls:") for v in proxy["volumes"])  # the proxy never reads the sources


def test_compose_publishes_http_and_https_ports():
    proxy = proxy_service()
    assert "${HTTP_PORT:-80}:80" in proxy["ports"]
    assert "${HTTPS_PORT:-443}:443" in proxy["ports"]
    assert proxy["environment"]["HTTPS_PORT"] == "${HTTPS_PORT:-443}"
    assert proxy["environment"]["SITE_HOSTS"] == "${SITE_HOSTS}"


def test_compose_app_is_not_published():
    """Only the proxy is reachable from outside – the redirect must not open a path around it."""
    app = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())["services"]["app"]
    assert "ports" not in app


@pytest.fixture
def run_entrypoint(tmp_path):
    """Run the real entrypoint with /bin/sh; a stub caddy prints the environment it was exec'd with."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    caddy = bin_dir / "caddy"
    caddy.write_text('#!/bin/sh\nprintf "SITE_ADDRESSES=[%s]\\nHTTPS_SUFFIX=[%s]\\nARGS=[%s]\\n" '
                     '"$SITE_ADDRESSES" "$HTTPS_SUFFIX" "$*"\n')
    caddy.chmod(caddy.stat().st_mode | stat.S_IEXEC)

    def run(**env) -> dict[str, str]:
        result = subprocess.run(["/bin/sh", "-c", entrypoint_script()], capture_output=True, text=True, timeout=10,
                                env={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", **env}, check=True)
        return dict(re.findall(r"^(\w+)=\[(.*)\]$", result.stdout, re.M))

    return run


def test_entrypoint_https_suffix_empty_for_443(run_entrypoint):
    out = run_entrypoint(SITE_HOSTS="demo.local 192.0.2.10", HTTPS_PORT="443")
    assert out["HTTPS_SUFFIX"] == ""
    assert out["SITE_ADDRESSES"] == "https://demo.local:443, https://192.0.2.10:443"
    assert out["ARGS"] == "run --config /etc/caddy/Caddyfile --adapter caddyfile"


def test_entrypoint_https_suffix_carries_non_default_port(run_entrypoint):
    out = run_entrypoint(SITE_HOSTS="demo.local", HTTPS_PORT="8443")
    assert out["HTTPS_SUFFIX"] == ":8443"
    # The container always listens on 443 internally; only the published port changes.
    assert out["SITE_ADDRESSES"] == "https://demo.local:443"


def test_dockerfile_installs_scepclient_in_its_own_cached_layer():
    """apt in its own RUN before the requirements (a requirements change keeps the apt layer cached);
    only the client – the bundled SCEP server is removed from the image."""
    text = (DEPLOY.parent / "Dockerfile").read_text()
    lines = [line.strip() for line in text.splitlines()]
    apt = next(i for i, line in enumerate(lines) if line.startswith("RUN apt-get update"))
    copy_req = lines.index("COPY requirements.txt .")
    assert apt < copy_req
    assert "apt-get install -y --no-install-recommends scep" in lines[apt]
    assert "rm -rf /var/lib/apt/lists/*" in lines[apt]
    apt_block = " ".join(lines[apt:copy_req])
    assert "rm -f /usr/bin/scepserver" in apt_block and "pip install" not in apt_block
