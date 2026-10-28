"""The autouse fast_kdf fixture (tests/conftest.py): tests get a cheap but real Argon2, tests marked real_kdf the
production one. If the fixture stopped injecting, the suite would silently get slow; if the marker stopped working,
the hashing tests would silently test the cheap parameters."""

import pytest
from argon2 import PasswordHasher, extract_parameters

from app.auth import PASSWORD_KEY, Auth
from app.store import Store
from tests.conftest import FAST_HASHER, PASSWORD, SECRET


def stored_parameters(tmp_path):
    store = Store(tmp_path / "db")
    Auth(PASSWORD, SECRET, store=store)
    return store.get_setting(PASSWORD_KEY), extract_parameters(store.get_setting(PASSWORD_KEY))


def test_unmarked_tests_get_the_cheap_hasher(tmp_path):
    stored, params = stored_parameters(tmp_path)
    assert (params.time_cost, params.memory_cost, params.parallelism) == (
        FAST_HASHER.time_cost, FAST_HASHER.memory_cost, FAST_HASHER.parallelism)
    assert params.memory_cost < PasswordHasher().memory_cost  # really cheaper than production
    auth = Auth(None, SECRET, store=Store(tmp_path / "db"))
    assert auth.check_password(PASSWORD) and not auth.check_password(PASSWORD + "!")  # still a real Argon2


@pytest.mark.real_kdf
def test_real_kdf_tests_get_the_production_hasher(tmp_path):
    _, params = stored_parameters(tmp_path)
    default = PasswordHasher()
    assert (params.time_cost, params.memory_cost, params.parallelism) == (
        default.time_cost, default.memory_cost, default.parallelism)
