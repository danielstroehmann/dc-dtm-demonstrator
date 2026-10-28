"""OWASP cases of the host paths beyond tests/unit/test_tls_watch.py: escapes out of TLS_HOST_DIR through linked
directories, link chains and same-prefix siblings – at request, at the minute check (a link swapped after applying)
and at start (a tampered settings-paths.json); every path field validated, not only the certificate's; the PKCS#12
password kept out of answers and logs when a request is refused."""

import json
import logging

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app import tls_settings, tls_setup, tls_watch
from app.tls_setup import TLSError
from tests.fakecaddy import caddy  # noqa: F401 – fixture
from tests.unit.test_tls_settings import p12
from tests.unit.test_tls_setup import make_cert
from tests.unit.test_tls_watch import NAME, answer, files, issue, pem_config, request
from tests.unit.test_tls_watch import applied, host, started  # noqa: F401 – fixtures


@pytest.fixture
def outside(tmp_path):
    """A directory next to TLS_HOST_DIR holding a usable pair – what an escape would serve."""
    root = (tmp_path / "elsewhere").resolve()
    (root / "archive" / NAME).mkdir(parents=True)
    (root / "live" / NAME).mkdir(parents=True)
    cert, _ = issue(root, 1)
    return root, cert


def test_a_linked_directory_out_of_the_directory_is_refused(host, outside):
    """Not the file is a link but a directory on the way: live/<name> → a directory outside."""
    root, _ = outside
    (host / "live" / NAME).rmdir()
    (host / "live" / NAME).symlink_to(root / "live" / NAME)
    path = f"{host}/live/{NAME}/fullchain.pem"
    with pytest.raises(TLSError) as caught:
        tls_setup.read_host(path, "the certificate file")
    assert str(caught.value) == f"the certificate file {path} is outside {host} (links followed)"


def test_a_chain_of_links_ending_outside_is_refused(host, outside):
    root, _ = outside
    (host / "hop2.pem").symlink_to(root / "archive" / NAME / "fullchain1.pem")
    (host / "hop1.pem").symlink_to("hop2.pem")  # inside → inside → outside
    with pytest.raises(TLSError) as caught:
        tls_setup.read_host(f"{host}/hop1.pem", "the certificate file")
    assert str(caught.value) == f"the certificate file {host}/hop1.pem is outside {host} (links followed)"


def test_a_link_to_a_sibling_with_the_same_prefix_is_refused(host):
    """<dir>-other starts with the text of <dir>: the check must compare path components, not strings."""
    sibling = host.with_name(host.name + "-other")
    sibling.mkdir()
    (sibling / "cert.pem").write_text("not for the admin")
    (host / "cert.pem").symlink_to(sibling / "cert.pem")
    with pytest.raises(TLSError) as caught:
        tls_setup.read_host(f"{host}/cert.pem", "the certificate file")
    assert str(caught.value) == f"the certificate file {host}/cert.pem is outside {host} (links followed)"


def test_a_link_between_files_inside_the_directory_is_followed(host):
    """The happy path next to the refusals: links that stay inside are fine (certbot's live → archive)."""
    (host / "real.pem").write_bytes(b"inside")
    (host / "live" / "alias.pem").symlink_to("../real.pem")
    assert tls_setup.read_host(f"{host}/live/alias.pem", "the certificate file") == b"inside"


def test_a_trailing_slash_in_the_host_directory_changes_nothing(host, monkeypatch):
    monkeypatch.setattr(tls_setup, "HOST_DIR", f"{host}/")
    issue(host, 1)
    config = pem_config(host)
    assert tls_settings.host_config("pem", config["certificate"], config["private_key"], "", "") == config
    assert tls_setup.load_host(pem_config(host))[0][0].subject.rfc4514_string() == f"CN={NAME}"
    with pytest.raises(TLSError, match=r"must be inside"):
        tls_settings.host_config("pem", f"{host}-other/c.pem", f"{host}/k.pem", "", "")


@pytest.mark.parametrize("field,message", [
    ("private_key", "the path of the private key file must be inside "),
    ("keystore", "the path of the PKCS#12 file must be inside "),
])
def test_every_path_field_is_kept_inside_the_directory(host, field, message):
    with pytest.raises(TLSError) as caught:
        if field == "private_key":
            tls_settings.host_config("pem", f"{host}/c.pem", f"{host}/../../etc/shadow", "", "")
        else:
            tls_settings.host_config("pkcs12", "", "", "/etc/shadow", "pw")
    assert str(caught.value).startswith(message)


@pytest.mark.parametrize("value", ["{root}/a\x00b.pem", "{root}/a\tb.pem", "{root}/a\rb.pem"])
def test_control_characters_are_refused(host, value):
    with pytest.raises(TLSError) as caught:
        tls_settings.host_config("pem", value.format(root=host), f"{host}/k.pem", "", "")
    assert str(caught.value) == "the path of the certificate file is not valid"


def test_a_link_swapped_out_of_the_directory_after_applying_is_refused_at_the_check(caddy, host, applied, outside):  # noqa: F811
    """Applied once, then the live link is pointed outside: the minute check keeps the current certificate."""
    root, foreign = outside
    link = host / "live" / NAME / "fullchain.pem"
    link.unlink()
    link.symlink_to(root / "archive" / NAME / "fullchain1.pem")
    before = files(caddy.live)
    tls_watch.check()
    assert caddy.served == applied and caddy.served != foreign and files(caddy.live) == before
    assert answer()["error"] == f"the certificate file {link} is outside {host} (links followed)"


def test_a_tampered_configuration_is_refused_at_start(caddy, host, applied, outside, capsys):  # noqa: F811
    """settings-paths.json is no authority either: paths outside TLS_HOST_DIR are not read by the `tls` service."""
    root, foreign = outside
    (caddy.live / tls_setup.HOST_PATHS).write_text(json.dumps(pem_config(root)))
    assert tls_setup.main() == 0
    from cryptography import x509
    assert x509.load_pem_x509_certificates((caddy.live / "cert.pem").read_bytes()) == [applied]
    err = capsys.readouterr().err
    assert f"the certificate from the host path is not usable (the certificate file {root}/live/{NAME}/fullchain.pem" \
        f" is outside {host} (links followed)) – keeping the last one applied" in err


def test_a_refused_pkcs12_request_keeps_the_password_out_of_answer_and_log(caddy, started, host, outside, caplog):  # noqa: F811
    root, _ = outside
    key = ec.generate_private_key(ec.SECP256R1())
    (root / "demo.p12").write_bytes(p12(key, make_cert(NAME, key), password=b"Leak-Me-Not-7"))
    (host / "demo.p12").symlink_to(root / "demo.p12")
    caplog.set_level(logging.DEBUG)
    request({"mode": "pkcs12", "keystore": f"{host}/demo.p12", "password": "Leak-Me-Not-7"})
    tls_watch.handle_request()
    status = (caddy.live / tls_settings.STATUS).read_text()
    assert json.loads(status)["request_error"] == f"the PKCS#12 file {host}/demo.p12 is outside {host} (links followed)"
    assert "Leak-Me-Not-7" not in status and "Leak-Me-Not-7" not in caplog.text
    assert caddy.served == started and caddy.requests == []
    assert not (caddy.live / tls_setup.HOST_PATHS).exists() and not (caddy.live / tls_settings.REQUEST).exists()
