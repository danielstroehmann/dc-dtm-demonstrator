"""The live-load guard (tests/live/conftest.py) itself – runs without DTM."""

import pytest

from app import evergreen
from tests.live import conftest as live


def test_limit_is_two():
    assert live.MAX_LIVE_CERTIFICATES == 2


@pytest.mark.parametrize("params,count", [({}, 1), ({"count": 2}, 2), ({"count": 3}, 3), ({"count": None}, 1)])
def test_requested_certificates(params, count):
    assert live.requested_certificates(params) == count


def test_payload_counting():
    assert live.certificates_in_payload(evergreen.batch_zip(["a", "b", "c"])) == 3
    assert live.certificates_in_payload(evergreen.batch_zip(["a"])) == 1
    assert live.certificates_in_payload(evergreen.csr_zip({"a": "X", "b": "Y"})) == 2


def test_check_fails_above_the_limit():
    live.check(2, "run")
    with pytest.raises(pytest.fail.Exception, match="limit is 2"):
        live.check(3, "run")


def test_live_tests_stay_within_the_limit():
    import ast
    import pathlib
    source = (pathlib.Path(live.__file__).parent / "test_live_uc01.py").read_text()
    tree = ast.parse(source)
    assignments = {t.id: n.value.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   for t in n.targets if isinstance(t, ast.Name) and isinstance(n.value, ast.Constant)}
    assert assignments["LIVE_COUNT"] <= live.MAX_LIVE_CERTIFICATES
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "execute"]
    assert calls
    for call in calls:
        count = next((k.value for k in call.keywords if k.arg == "count"), None)
        assert count is None or isinstance(count, ast.Name) and count.id == "LIVE_COUNT", ast.dump(call)
