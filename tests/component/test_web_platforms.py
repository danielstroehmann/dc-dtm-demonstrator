"""Only two DTM platforms: US (one.digicert.com, shared profiles) and NL (one.nl.digicert.com, one
profile per run). Web side: NL form and settings, and connections to other hosts (saved before the
platforms were limited) refused for new runs."""

import re

import pytest

from tests.component.test_web_runs import finished, form
from tests.fakedtm import ACCOUNT_ID, API_KEY, NL_HOST, FakeDTM

REFUSED = "Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported"


@pytest.fixture
def fake() -> FakeDTM:  # the web app's client factory routes to the NL fake
    return FakeDTM(host=NL_HOST)


@pytest.fixture
def nl_user(store, user):
    store.save_connection(None, "NL", NL_HOST, ACCOUNT_ID, API_KEY)
    return user


def profile_reads(fake: FakeDTM) -> list[str]:
    return [n for n in fake.route_order() if n.startswith("profile")]


@pytest.mark.parametrize("path", ["/runs/new/evergreen", "/runs/new/uc04"])
def test_nl_form_shows_the_runs_own_profile_without_asking_dtm(nl_user, fake, path):
    html = nl_user.get(path).text
    assert "Own profile for this run" in html and "– deleted by the full rollback</small>" in html
    assert "robot-evergreen" not in html and "robot-renewal" not in html  # no shared profile names
    assert "DTM keeps it" not in html
    assert profile_reads(fake) == []  # no shared_profile_status on NL


def test_nl_settings_profiles(nl_user, store, fake):
    html = nl_user.get("/settings").text
    assert re.search(r'<summary class="meta">Profiles</summary>', html) and "Shared profiles" not in html
    conn = store.connection(None)
    fake.requests.clear()
    part = nl_user.get(f"/settings/connections/{conn['id']}/profiles").text
    assert "One profile per run, deleted by the full rollback – nothing shared." in part
    assert fake.requests == []  # rendered without calling DTM


def test_nl_run_through_the_web_records_and_rolls_back_its_profile(nl_user, store, fake):
    nl_user.post("/runs", data=form())
    run = finished(store, "r1")
    assert run["status"] == "completed", run["error"]
    (profile,) = store.objects("r1", "profile")
    assert profile["name"] == "robot-r1-uc01-profile"
    html = nl_user.get("/runs/r1").text
    assert "Create the certificate profile for this run" in html
    assert nl_user.post("/runs/r1/cleanup", data={"mode": "full"}, follow_redirects=False).status_code in (200, 303)
    done = finished_cleanup(store, "r1")
    assert done["cleanup_status"] == "done" and fake.profile("robot-r1-uc01-profile")["status"] == "DELETED"


def finished_cleanup(store, run_id):
    from tests.conftest import wait_for
    return wait_for(lambda: (r := store.get_run(run_id)) and r.get("cleanup_status") in ("done", "failed") and r,
                    what="cleanup")


# --- connections to other hosts (saved before the platforms were limited) ---------------------------

@pytest.fixture
def legacy_user(store, user):
    store.save_connection(None, "Old", "dtm.example.com", ACCOUNT_ID, API_KEY)  # bypasses the form check
    return user


def test_form_for_an_unsupported_host_is_an_error_page(legacy_user, fake):
    for path in ("/runs/new/evergreen", "/runs/new/uc04"):
        response = legacy_user.get(path)
        assert response.status_code == 400 and REFUSED in response.text, path
    assert fake.requests == []  # the key is not sent to that host


def test_run_on_an_unsupported_host_is_refused(legacy_user, store, fake):
    response = legacy_user.post("/runs", data=form(), follow_redirects=False)
    assert response.status_code == 400 and REFUSED in response.text
    assert store.list_runs() == [] and fake.requests == []


def test_settings_still_list_an_unsupported_connection(legacy_user):
    html = legacy_user.get("/settings").text
    assert "dtm.example.com" in html  # visible, so it can be fixed or deleted
