"""A device's DTM log (POST device/logs): paged in the body, scoped to the device and the account."""

import pytest

from app.dtm import DTMError
from tests.fakedtm import OTHER_ACCOUNT_ID, FakeDTM


async def call(fake: FakeDTM, method: str, *args):
    client = fake.client()
    try:
        return await getattr(client, method)(*args)
    finally:
        await client.aclose()


def at(i: int) -> str:
    return f"2026-11-07T06:{i // 60:02d}:{i % 60:02d}.000Z"


async def test_all_pages_newest_first_and_only_the_devices_own(fake):
    for i in range(130):  # more than one page of 100
        fake.log_device_event("dev-1", "CONNECTION_STATUS", "CONNECTED", at(i))
    fake.log_device_event("dev-2", "CERTIFICATE", "ISSUED", at(200))  # another device
    fake.log_device_event("dev-1", "CERTIFICATE", "ISSUED", at(201), account_id=OTHER_ACCOUNT_ID)  # another account
    logs = await call(fake, "device_logs", "dev-1")
    assert len(logs) == 130 and {r["device_id"] for r in logs} == {"dev-1"}
    assert [r["created_on"] for r in logs] == sorted((r["created_on"] for r in logs), reverse=True)
    sent = [c for c in fake.calls if c[0] == "device_logs"]
    assert len(sent) == 2  # two body pages – the query parameters are not used for paging


async def test_limit_caps_the_events(fake):
    for i in range(30):
        fake.log_device_event("dev-1", "DEPLOYMENT", "PENDING", at(i))
    logs = await call(fake, "device_logs", "dev-1", 10)
    assert [r["created_on"] for r in logs] == [at(i) for i in range(29, 19, -1)]


async def test_an_unexpected_device_id_never_reaches_dtm(fake):
    with pytest.raises(DTMError, match="unexpected ID '../x'"):
        await call(fake, "device_logs", "../x")
    assert not any(c[0] == "device_logs" for c in fake.calls)
