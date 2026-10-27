import io
import zipfile

import pytest

# Binding author rule: testing surfaced a DTM revocation-timeout bug that endangers DTM
# SLAs, so live tests request at most this many certificates in one run.
MAX_LIVE_CERTIFICATES = 2


def pytest_configure(config):
    """Never print local variables of live tests – they may hold the API key."""
    config.option.showlocals = False
    if config.option.tbstyle in ("auto", "long"):
        config.option.tbstyle = "short"


def requested_certificates(params: dict) -> int:
    return int(params.get("count", 1) or 1)


def certificates_in_payload(payload: bytes) -> int:
    """Certificate requests inside a batch upload: CSV rows (server-side keys) or .csr files (CSRs)."""
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        csrs = [n for n in names if n.endswith(".csr")]
        if csrs:
            return len(csrs)
        rows = [r for n in names if n.endswith(".csv") for r in archive.read(n).decode().splitlines()[1:] if r.strip()]
        return len(rows)


def check(count: int, what: str) -> None:
    if count > MAX_LIVE_CERTIFICATES:
        pytest.fail(f"live test requests {count} certificates in one {what} – the limit is "
                    f"{MAX_LIVE_CERTIFICATES} (DTM load rule)", pytrace=False)


@pytest.fixture(autouse=True)
def limit_live_load(monkeypatch):
    """Fails the test before DTM sees more than MAX_LIVE_CERTIFICATES requests in one run – checked at
    run creation, at every batch upload and for single issuance per test."""
    from app.dtm import DTMClient
    from app.store import Store

    create_run, submit_batch, issue_single = Store.create_run, DTMClient.submit_batch, DTMClient.issue_single
    issued = {"single": 0}

    def guarded_create_run(self, run_id, use_case, params):
        check(requested_certificates(params), "run")
        return create_run(self, run_id, use_case, params)

    async def guarded_submit_batch(self, *args, **kwargs):
        check(certificates_in_payload(kwargs["payload"]), "batch upload")
        return await submit_batch(self, *args, **kwargs)

    async def guarded_issue_single(self, *args, **kwargs):
        issued["single"] += 1
        check(issued["single"], "test (single requests)")
        return await issue_single(self, *args, **kwargs)

    monkeypatch.setattr(Store, "create_run", guarded_create_run)
    monkeypatch.setattr(DTMClient, "submit_batch", guarded_submit_batch)
    monkeypatch.setattr(DTMClient, "issue_single", guarded_issue_single)
