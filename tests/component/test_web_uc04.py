"""UC-4 through the web UI: form, forced parameters, the renew route and its guards."""

import re

from tests.component.test_web_runs import cleaned, finished, form
from tests.conftest import wait_for
from tests.fakedtm import ECDSA_CA_ID, PROFILE_ID


def uc04_form(**overrides) -> dict:
    return {"run_id": "d1", "use_case": "uc04", "protocol": "est", "auth_method": "passcode", "count": "1",
            "variant": "api", "mode": "single", "ca_id": ECDSA_CA_ID, "profile_id": PROFILE_ID} | overrides


def renewals(store, run_id="d1") -> int:
    return len(store.get_run(run_id)["result"].get("renewals") or [])


def renewed(store, run_id="d1"):
    return wait_for(lambda: (r := store.get_run(run_id)) and r["status"] == "completed" and r,
                    what=f"renewal of {run_id} to end")


def test_uc04_form(configured_user):
    html = configured_user.get("/runs/new/uc04").text
    assert "<h3>Enrollment</h3>" in html
    assert 'type="radio" name="protocol"' not in html  # EST only
    assert '<input type="hidden" name="protocol" value="est">' in html
    assert '<input type="hidden" name="count" value="1">' in html
    auths = re.findall(r'<input type="radio" name="auth_method" value="([^"]+)"', html)
    assert auths == ["passcode", "certificate"] and 'name="approval"' not in html


def test_uc04_forces_est_and_one_device(configured_user, store, enroll_net):
    data = uc04_form(protocol="rest", count="7", variant="webui", mode="batch", approval="true",
                     auth_method="certificate")
    assert configured_user.post("/runs", data=data, follow_redirects=False).status_code == 303
    run = finished(store, "d1")
    assert run["status"] == "completed", run["error"]
    p = run["params"]
    assert (p["protocol"], p["count"], p["variant"], p["mode"], p["approval"], p["auth"]) == (
        "est", 1, "api", "single", False, "certificate")
    html = configured_user.get("/runs/d1").text
    assert "<h2>Renewal in the Field</h2>" in html and "Renew now" in html
    assert "Current certificate:" not in html  # nothing renewed yet
    # the renewal block of the reproducible steps is there before the first renewal
    assert "<h3>Renewal in the Field</h3>" in configured_user.get("/runs/d1/api?dialect=curl").text
    assert "devices ≈" not in html  # one device – no extrapolation


def test_uc04_rejects_unknown_auth(configured_user, store):
    response = configured_user.post("/runs", data=uc04_form(auth_method="basic"), follow_redirects=False)
    assert response.status_code == 400 and store.list_runs() == []


def test_renew_through_the_web(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    response = configured_user.post("/runs/d1/renew", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/d1"
    wait_for(lambda: renewals(store) == 1 and store.get_run("d1")["status"] == "completed", what="renewal")
    html = configured_user.get("/runs/d1").text
    serial = store.get_run("d1")["result"]["renewals"][0]["serial"]
    assert "<small>Renewals</small>" in html and "<small" in html and "Last renewal" in html
    assert f'Current certificate: <span class="mono">{serial}</span>' in html
    assert "PRIVATE KEY" not in html
    api = configured_user.get("/runs/d1/api?dialect=curl").text
    assert "<h3>Factory Enrollment</h3>" in api and "<h3>Renewal in the Field</h3>" in api
    assert "PRIVATE KEY" not in api
    assert len(enroll_net.issued()) == 2


def test_renew_double_click_starts_one_renewal(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    enroll_net.reenroll_delay = 0.5
    first = configured_user.post("/runs/d1/renew", follow_redirects=False)
    second = configured_user.post("/runs/d1/renew", follow_redirects=False)  # idempotent while renewing
    assert (first.status_code, second.status_code) == (303, 303)
    assert first.headers["location"] == second.headers["location"] == "/runs/d1"
    # button off while it runs
    assert re.search(r'class="btn-icon" disabled\s+aria-busy="true"', configured_user.get("/runs/d1").text)
    renewed(store)
    assert renewals(store) == 1 and len([r for r in enroll_net.enroll_requests
                                         if r.url.path.endswith("/simplereenroll")]) == 1


def test_renew_guards(configured_user, store, enroll_net):
    # wrong use case
    configured_user.post("/runs", data=form(run_id="u1"))
    finished(store, "u1")
    assert configured_user.post("/runs/u1/renew", follow_redirects=False).status_code == 409
    configured_user.post("/runs", data={**uc04_form(run_id="u3"), "use_case": "uc03"})
    finished(store, "u3")
    assert configured_user.post("/runs/u3/renew", follow_redirects=False).status_code == 409
    # unknown run
    assert configured_user.post("/runs/nope/renew", follow_redirects=False).status_code == 404
    # failed run
    from tests.fakedtm import _error
    enroll_net.enroll_fail = _error(401, "denied")
    configured_user.post("/runs", data=uc04_form(run_id="f1"))
    assert finished(store, "f1")["status"] == "failed"
    assert configured_user.post("/runs/f1/renew", follow_redirects=False).status_code == 409
    assert store.get_run("f1")["status"] == "failed"
    assert not [r for r in enroll_net.enroll_requests if r.url.path.endswith("/simplereenroll")]


def test_no_renewal_after_certificates_cleanup_or_rollback(configured_user, store, enroll_net, data_dir):
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    configured_user.post("/runs/d1/cleanup", data={"mode": "certificates"})
    assert cleaned(store, "d1")["cleanup_status"] == "done"
    assert configured_user.post("/runs/d1/renew", follow_redirects=False).status_code == 409
    assert "Renew now" not in configured_user.get("/runs/d1").text
    configured_user.post("/runs/d1/cleanup", data={"mode": "full"})
    assert cleaned(store, "d1")["cleanup_status"] == "done"
    assert configured_user.post("/runs/d1/renew", follow_redirects=False).status_code == 409
    assert enroll_net.issued() == [] and not (data_dir / "runs" / "d1").exists()
    assert renewals(store) == 0


def test_cleanup_refused_while_renewing(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    enroll_net.reenroll_delay = 0.5
    configured_user.post("/runs/d1/renew")
    response = configured_user.post("/runs/d1/cleanup", data={"mode": "full"}, follow_redirects=False)
    assert response.status_code == 409
    renewed(store)
    assert store.get_run("d1")["cleanup_status"] is None


def test_device_key_is_never_served(configured_user, store, enroll_net, data_dir):
    configured_user.post("/runs", data=uc04_form())
    run = finished(store, "d1")
    assert (data_dir / "runs" / "d1" / "device" / "device.pem").exists()
    for path in ("/runs/d1/certificates/device.pem", "/runs/d1/certificates/..%2Fdevice%2Fdevice.pem",
                 "/runs/d1/artifact", "/runs/d1/device/device.pem", "/static/../runs/d1/device/device.pem"):
        response = configured_user.get(path)
        assert response.status_code == 404, path
        assert "PRIVATE KEY" not in response.text
    serial = run["result"]["certificates"][0]["serial"]
    assert "PRIVATE KEY" not in configured_user.get(f"/runs/d1/certificates/{serial}.pem").text


def test_renew_requires_login(web, configured_store):
    response = web.post("/runs/d1/renew", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_renew_refuses_cross_origin(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    response = configured_user.post("/runs/d1/renew", headers={"Origin": "https://evil.example"},
                                    follow_redirects=False)
    assert response.status_code == 403 and store.get_run("d1")["status"] == "completed"
    assert renewals(store) == 0


def test_at_most_five_renewals(configured_user, store, enroll_net):
    from app import enrollment
    assert enrollment.MAX_RENEWALS == 5
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    for n in range(1, 6):
        assert 'data-tip="At most 5 renewals per run"' not in configured_user.get("/runs/d1").text
        assert configured_user.post("/runs/d1/renew", follow_redirects=False).status_code == 303
        wait_for(lambda: renewals(store) == n and store.get_run("d1")["status"] == "completed", what=f"renewal {n}")
    html = configured_user.get("/runs/d1").text
    assert re.search(r'<button type="submit" class="btn-icon" disabled\s+data-tip="At most 5 renewals per run">', html)
    assert configured_user.post("/runs/d1/renew", follow_redirects=False).status_code == 409
    assert renewals(store) == 5 and len(enroll_net.issued()) == 6
    assert len([r for r in enroll_net.enroll_requests if r.url.path.endswith("/simplereenroll")]) == 5


def test_certificates_cleanup_removes_the_device_dir(configured_user, store, enroll_net, data_dir):
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    configured_user.post("/runs/d1/cleanup", data={"mode": "certificates"})
    assert cleaned(store, "d1")["cleanup_status"] == "done"
    assert not (data_dir / "runs" / "d1" / "device").exists()
    assert (data_dir / "runs" / "d1" / "certificates").is_dir()
