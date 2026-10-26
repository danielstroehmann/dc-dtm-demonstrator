import io
import zipfile

from app import evergreen
from app.main import RUN_ID


def test_prefix_and_common_names():
    assert evergreen.prefix("x1", "uc01") == "robot-x1-uc01"
    assert evergreen.common_names("x1", "batch", 3, "uc01") == [
        "robot-x1-uc01-batch-0001", "robot-x1-uc01-batch-0002", "robot-x1-uc01-batch-0003"]
    assert evergreen.common_names("x1", "single", 1, "uc01") == ["robot-x1-uc01-single-0001"]
    assert evergreen.common_names("x1", "batch", 0, "uc01") == []


def test_common_names_are_unique_and_stay_within_cn_limit_at_max_batch():
    names = evergreen.common_names("a" * 16, "single", evergreen.MAX_BATCH, "uc01")
    assert len(set(names)) == evergreen.MAX_BATCH
    assert max(map(len, names)) <= 64  # X.520 upper bound for commonName


def test_batch_zip_layout():
    names = evergreen.common_names("x1", "batch", 2, "uc01")
    with zipfile.ZipFile(io.BytesIO(evergreen.batch_zip(names))) as archive:
        assert archive.namelist() == ["batch.csv"]
        assert archive.read("batch.csv").decode() == (
            "subject.common_name\nrobot-x1-uc01-batch-0001\nrobot-x1-uc01-batch-0002\n")


def test_run_id_pattern():
    for ok in ("a", "t1b2c3", "a" * 16, "2610231200"):
        assert RUN_ID.fullmatch(ok)
    for bad in ("", "A1", "a-b", "a_b", "a" * 17, "a b", "../x", "ä", "a\n"):
        assert not RUN_ID.fullmatch(bad), bad



def test_catalog_uses_the_field_wording():
    """The catalog texts say 'field enrollment/renewal', never 'in the field'; UC-6's CN is a serial or MAC."""
    from app import evergreen
    texts = {key: " ".join((uc.title, uc.summary, *uc.tags)) for key, uc in evergreen.USE_CASES.items()}
    assert all("in the field" not in t.lower() for t in texts.values()), texts
    assert "field renewal per click" in texts["uc04"].lower() and "Field enrollment via EST or CMPv2" in texts["uc05"]
    assert "common name is a serial number or MAC address" in texts["uc06"]
