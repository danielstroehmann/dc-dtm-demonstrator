"""A connection saved before the platforms were limited (host outside dtm.PLATFORMS): it stays
editable and its runs can be rolled back, but no new runs – and no new or changed host outside the
two platforms is accepted."""

import pytest

from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST, NL_HOST, FakeDTM

LEGACY = "dtm.example.com"
REFUSED = "Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported."


@pytest.fixture
def fake() -> FakeDTM:  # the key check of an edit goes to the legacy host
    return FakeDTM(host=LEGACY)


@pytest.fixture
def legacy(store, user):
    store.save_connection(None, "Old", LEGACY, ACCOUNT_ID, API_KEY)  # bypasses the form check
    return store.connection(None)


def save(user, **form):
    data = {"name": "Old", "host": LEGACY, "account_id": ACCOUNT_ID, "api_key": ""} | form
    return user.post("/settings/connections", data=data, follow_redirects=False)


def test_legacy_connection_stays_editable_with_a_new_key(user, store, legacy, fake):
    fake.api_key = "new-key-for-the-old-host"  # the rotated key DTM accepts now
    response = save(user, id=str(legacy["id"]), name="Old renamed", api_key="new-key-for-the-old-host")
    assert response.status_code == 303, response.text
    conn = store.connection(legacy["id"])
    assert (conn["name"], conn["host"]) == ("Old renamed", LEGACY)
    assert fake.names("account")  # the new key was checked against the connection's own host


def test_legacy_connection_rename_without_key(user, store, legacy):
    assert save(user, id=str(legacy["id"]), name="Kept").status_code == 303
    assert store.connection(legacy["id"])["name"] == "Kept"


@pytest.mark.parametrize("host", ["other.example.com", "dtm2.example.com"])
def test_changing_to_another_unsupported_host_is_refused(user, store, legacy, fake, host):
    response = save(user, id=str(legacy["id"]), host=host, api_key="k")
    assert response.status_code == 400 and REFUSED in response.text
    assert store.connection(legacy["id"])["host"] == LEGACY and fake.requests == []


def test_a_new_connection_on_the_legacy_host_is_refused(user, store, legacy, fake):
    response = save(user, name="Second", api_key=API_KEY)
    assert response.status_code == 400 and REFUSED in response.text
    assert len(store.connections()) == 1 and fake.requests == []


def test_legacy_connection_can_move_to_a_supported_host(user, store, legacy):
    response = save(user, id=str(legacy["id"]), host=NL_HOST, api_key="")
    assert response.status_code == 400 and "Enter the API key again" in response.text  # key stays home
    assert store.connection(legacy["id"])["host"] == LEGACY


def test_profiles_part_for_an_unsupported_platform(user, legacy, fake):
    fake.requests.clear()
    html = user.get(f"/settings/connections/{legacy['id']}/profiles").text
    assert "<span class=\"meta\">Unsupported platform – no new runs.</span>" in html
    assert "One profile per run" not in html and fake.requests == []


def test_profiles_part_texts_per_platform(user, store, fake):
    store.save_connection(None, "NL", NL_HOST, ACCOUNT_ID, API_KEY)
    nl = next(c for c in store.connections() if c["host"] == NL_HOST)
    html = user.get(f"/settings/connections/{nl['id']}/profiles").text
    assert '<span class="meta">One profile per run.</span>' in html
    assert "Unsupported platform" not in html
    assert HOST != NL_HOST
