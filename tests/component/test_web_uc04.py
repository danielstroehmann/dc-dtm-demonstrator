"""UC-4 through the web UI: form, forced parameters, the renew route and its guards."""

import re

import pytest

from tests.component.test_web_runs import assert_phase_titles, cleaned, finished, form
from tests.conftest import wait_for
from tests.fakedtm import ECDSA_CA_ID


def uc04_form(**overrides) -> dict:
    return {"run_id": "d1", "use_case": "uc04", "protocol": "est", "auth_method": "passcode", "count": "1",
            "variant": "api", "mode": "single", "ca_id": ECDSA_CA_ID} | overrides


def renewals(store, run_id="d1") -> int:
    return len(store.get_run(run_id)["result"].get("renewals") or [])


def renewed(store, run_id="d1"):
    return wait_for(lambda: (r := store.get_run(run_id)) and r["status"] == "completed" and r,
                    what=f"renewal of {run_id} to end")


def test_uc04_form(configured_user):
    html = configured_user.get("/runs/new/uc04").text
    assert "<h3>Issuance</h3>" in html and re.search(r'<form method="post" action="/runs" data-guide>', html)
    protocols = re.findall(r'<input type="radio" name="protocol" value="([^"]+)" ?(checked)?', html)
    assert protocols == [("est", "checked"), ("cmpv2", "")]  # enrollment and renewal
    assert '<input type="hidden" name="protocol"' not in html
    assert '<input type="hidden" name="count" value="1">' in html
    auths = re.findall(r'<input type="radio" name="auth_method" value="([^"]+)"', html)
    assert auths == ["passcode", "certificate"] and 'name="approval"' not in html


def test_uc04_forces_est_and_one_device(configured_user, store, enroll_net):
    data = uc04_form(protocol="", count="7", variant="webui", mode="batch", approval="true",
                     auth_method="certificate")  # no protocol → EST
    assert configured_user.post("/runs", data=data, follow_redirects=False).status_code == 303
    run = finished(store, "d1")
    assert run["status"] == "completed", run["error"]
    p = run["params"]
    assert (p["protocol"], p["count"], p["variant"], p["mode"], p["approval"], p["auth"]) == (
        "est", 1, "api", "single", False, "certificate")
    html = configured_user.get("/runs/d1").text
    assert "<h2>Renewal in the field</h2>" in html and "Renew now" in html
    assert "Renewable device certificates · EST · Factory certificate · 1 request" in html  # run-page title
    assert "Current certificate:" not in html  # nothing renewed yet
    # the renewal block of the reproducible steps is there before the first renewal
    assert_phase_titles(configured_user.get("/runs/d1/api?dialect=curl").text,
                        [("Factory enrollment", "factory"), ("Renewal in the field", "refresh")])
    assert "devices ≈" not in html  # one device – no extrapolation


@pytest.mark.parametrize("protocol,expected", [("cmpv2", "cmpv2"), ("est", "est"), ("", "est")])
def test_uc04_protocol_is_est_or_cmpv2(configured_user, store, enroll_net, cmp_openssl, protocol, expected):
    configured_user.post("/runs", data=uc04_form(protocol=protocol))
    run = finished(store, "d1")
    assert run["status"] == "completed", run["error"]
    assert run["params"]["protocol"] == expected
    label = {"est": "EST", "cmpv2": "CMPv2"}[expected]
    assert f"Renewable device certificates · {label} · Passcode · 1 request" in configured_user.get("/runs/d1").text


def test_uc04_cmp_renewal_through_the_web(configured_user, store, enroll_net, cmp_openssl):
    configured_user.post("/runs", data=uc04_form(protocol="cmpv2", auth_method="certificate"))
    assert finished(store, "d1")["status"] == "completed"
    cmp_openssl.sync_to_dtm()
    assert configured_user.post("/runs/d1/renew", follow_redirects=False).status_code == 303
    wait_for(lambda: renewals(store) == 1 and store.get_run("d1")["status"] == "completed", what="renewal")
    api = configured_user.get("/runs/d1/api?dialect=curl").text
    assert_phase_titles(api, [("Factory enrollment", "factory"), ("Renewal in the field", "refresh")])
    assert "openssl cmp -cmd kur" in api and "PRIVATE KEY" not in api


@pytest.mark.parametrize("protocol", ["scep", "rest", "EST", "cmp"])
def test_uc04_refuses_other_protocols(configured_user, store, fake, protocol):
    response = configured_user.post("/runs", data=uc04_form(protocol=protocol), follow_redirects=False)
    assert response.status_code == 400 and "Enrollment in the field: EST or CMPv2." in response.text
    assert store.list_runs() == [] and fake.route_order() == []  # checked before DTM is asked


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
    assert_phase_titles(api, [("Factory enrollment", "factory"), ("Renewal in the field", "refresh")])
    # the renewal steps sit in the orange field box, the factory steps in the blue one
    field = api[api.index('<section class="box accent field">'):]
    assert "simplereenroll" in field and "simplereenroll" not in api[:api.index('<section class="box accent field">')]
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
    response = configured_user.post("/runs/u1/renew", follow_redirects=False)
    assert response.status_code == 409
    assert "Only a completed run of renewable device certificates that is not cleaned up can be renewed" in response.text
    assert "UC-" not in response.text
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


# --- the shared renewal profile ------------------------------------------------------------------

def test_uc04_form_names_the_renewal_profile(configured_user):
    html = configured_user.get("/runs/new/uc04").text
    assert 'name="profile_id"' not in html
    assert re.search(r'<div class="field" data-when="protocol=est">\s*<span class="field-label">Certificate profile'
                     r'</span>\s*<div class="readonly-value mono"[^>]*>robot-renewal-6m-profile</div>\s*'
                     r'<small class="field-help">6 months · renew any time', html)
    assert re.search(r'<div class="field" data-when="protocol=cmpv2">\s*<span class="field-label">Certificate profile'
                     r'</span>\s*<div class="readonly-value mono"[^>]*>robot-renewal-cmp-6m-profile</div>\s*'
                     r'<small class="field-help">6 months · renew any time · bare key', html)
    from tests.guide_form import GuideForm
    form = GuideForm(html)
    assert form.visible_text("robot-renewal-6m-profile") and not form.visible_text("robot-renewal-cmp-6m-profile")
    form.choose("protocol", "cmpv2")
    assert form.visible_text("robot-renewal-cmp-6m-profile") and not form.visible_text("robot-renewal-6m-profile")
    assert form.submission()["protocol"] == "cmpv2" and form.submission()["count"] == "1"
    assert "<h3>Issuance</h3>" in html and html.count('class="fields q-grid"') == 2


def test_renewal_disabled_in_dtm_shows_the_hint(configured_user, store, enroll_net):
    """The profile was changed in DTM after the run started – DTM refuses, the run explains why."""
    configured_user.post("/runs", data=uc04_form())
    finished(store, "d1")
    from app import dtm
    profile = enroll_net.profile(dtm.PROFILE_RENEWAL.name)  # someone changes the shared profile in DTM
    next(e for e in profile["body"] if e["key"] == "renewal_settings.renew_valid_cert")["value"] = "dont_allow"
    configured_user.post("/runs/d1/renew")
    wait_for(lambda: any(e["message"].startswith("Renewal failed") for e in store.events("d1")), what="failure")
    renewed(store)
    hint = "the certificate profile does not allow renewing a valid certificate"
    assert hint in configured_user.get("/runs/d1/timeline").text
    assert renewals(store) == 0
