"""Contract of the deploy files (no Docker): the HTTP → HTTPS redirect in both Caddyfiles, the ports and
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
CADDYFILES = ["Caddyfile.selfsigned", "Caddyfile.custom"]


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


@pytest.mark.parametrize("name", CADDYFILES)
def test_http_block_redirects_known_hosts_only(name):
    lines = site_block((DEPLOY / name).read_text(), "http://")
    assert "@known host {$SITE_HOSTS}" in lines
    assert "header -Server" in lines
    # Every redirect is bound to the host matcher – an unguarded redir would be an open redirect.
    # 302, not a cached permanent redirect: the HTTPS port can change.
    assert [line for line in lines if line.startswith("redir")] == [REDIR]
    # The fallback is a fixed text; a {host} placeholder would reflect the attacker's Host header.
    assert [line for line in lines if line.startswith("respond")] == [NOT_FOUND]
    assert lines.index(NOT_FOUND) > lines.index(REDIR)


def test_both_caddyfiles_share_the_same_http_block():
    blocks = [site_block((DEPLOY / name).read_text(), "http://") for name in CADDYFILES]
    assert blocks[0] == blocks[1]


@pytest.mark.parametrize("name", CADDYFILES)
def test_https_block_is_unchanged_and_still_serves_tls(name):
    lines = site_block((DEPLOY / name).read_text(), "{$SITE_ADDRESSES}")
    assert "reverse_proxy app:8000" in lines and "header -Server" in lines
    assert any(line.startswith("tls ") for line in lines)


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
