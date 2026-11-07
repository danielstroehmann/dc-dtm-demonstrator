from app import tiles


def rec(kind, activity, at="2026-11-07T06:12:38.000Z"):
    return {"type": kind, "activity": activity, "created_on": at}


def test_known_events_read_as_text_with_a_kind_per_type():
    rows = tiles.log_entries([rec("DEPLOYMENT", "INSTALLED"), rec("CONNECTION_STATUS", "CONNECTED"),
                              rec("CERTIFICATE", "ISSUED"), rec("DEVICE_STATE", "ENROLLED")])
    assert [(r["text"], r["kind"]) for r in rows] == [
        ("Update installed", "deployment"), ("Connected", "connection"),
        ("Certificate issued", "certificate"), ("Enrolled", "state")]
    assert rows[0]["time"] == "06:12:38" and rows[0]["date"] == "2026-11-07"


def test_unknown_events_read_as_words_never_as_codes():
    rows = tiles.log_entries([rec("DEPLOYMENT", "ROLLED_BACK"), rec("FIRMWARE_CHECK", "UPDATE_SEARCHED")])
    assert [r["text"] for r in rows] == ["Update rolled back", "Firmware check update searched"]
    assert all("_" not in r["text"] for r in rows)


def test_failures_are_marked_and_disconnects_are_quiet():
    rows = tiles.log_entries([rec("DEPLOYMENT", "FAILED"), rec("CONNECTION_STATUS", "DISCONNECTED"),
                              rec("CERTIFICATE", "REVOKED")])
    assert [r["kind"] for r in rows] == ["failed", "offline", "failed"]  # TrustEdge disconnects between check-ins
    assert [r["text"] for r in rows] == ["Update failed", "Disconnected", "Certificate revoked"]
