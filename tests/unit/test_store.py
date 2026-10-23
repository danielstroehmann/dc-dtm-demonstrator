import sqlite3

import pytest

from app import store as store_module
from app.store import SCHEMA_VERSION, SchemaTooNewError, Store


def user_version(path) -> int:
    with sqlite3.connect(path) as db:
        return db.execute("PRAGMA user_version").fetchone()[0]


def tables(path) -> set[str]:
    with sqlite3.connect(path) as db:
        return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_fresh_database_is_migrated_to_current_version(tmp_path):
    path = tmp_path / "nested" / "dir" / "demonstrator.db"
    Store(path)
    assert user_version(path) == SCHEMA_VERSION
    assert {"settings", "runs", "run_objects", "run_events"} <= tables(path)


def test_reopen_is_idempotent_and_keeps_data(tmp_path):
    path = tmp_path / "demonstrator.db"
    first = Store(path)
    first.set_setting("dtm_host", "one.digicert.com")
    first.create_run("r1", "uc01", {"mode": "single"})
    # Re-applying the CREATE TABLE migration would raise "table already exists".
    second = Store(path)
    assert user_version(path) == SCHEMA_VERSION
    assert second.get_setting("dtm_host") == "one.digicert.com"
    assert second.get_run("r1")["params"] == {"mode": "single"}


def test_schema_newer_than_release_is_refused(tmp_path):
    path = tmp_path / "demonstrator.db"
    Store(path)
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(SchemaTooNewError):
        Store(path)
    assert user_version(path) == SCHEMA_VERSION + 1  # untouched, no silent downgrade


def test_upgrade_applies_only_new_migrations_and_keeps_data(tmp_path, monkeypatch):
    path = tmp_path / "demonstrator.db"
    Store(path).create_run("r1", "uc01", {})
    monkeypatch.setattr(store_module, "MIGRATIONS",
                        store_module.MIGRATIONS + ["ALTER TABLE runs ADD COLUMN note TEXT"])
    monkeypatch.setattr(store_module, "SCHEMA_VERSION", SCHEMA_VERSION + 1)
    upgraded = Store(path)
    assert user_version(path) == SCHEMA_VERSION + 1
    assert upgraded.get_run("r1")["note"] is None
    Store(path)  # a second open must not re-run the ALTER (would fail: duplicate column)


def test_failed_migration_rolls_back_completely(tmp_path, monkeypatch):
    path = tmp_path / "demonstrator.db"
    Store(path)
    monkeypatch.setattr(store_module, "MIGRATIONS",
                        store_module.MIGRATIONS + ["CREATE TABLE extra (a TEXT); THIS IS NOT SQL"])
    monkeypatch.setattr(store_module, "SCHEMA_VERSION", SCHEMA_VERSION + 1)
    with pytest.raises(sqlite3.OperationalError):
        Store(path)
    assert user_version(path) == SCHEMA_VERSION
    assert "extra" not in tables(path)


def test_settings_roundtrip_and_overwrite(store):
    assert store.get_setting("missing") is None
    store.set_setting("k", "v1")
    store.set_setting("k", "v2")
    assert store.get_setting("k") == "v2"


def test_runs_crud(store):
    store.create_run("a1", "uc01", {"count": 3})
    assert store.run_exists("a1") and not store.run_exists("zz")
    run = store.get_run("a1")
    assert run["status"] == "pending" and run["result"] is None and run["params"] == {"count": 3}
    store.update_run("a1", status="completed", result={"certificates": [{"common_name": "x"}]})
    run = store.get_run("a1")
    assert run["status"] == "completed"
    assert run["result"] == {"certificates": [{"common_name": "x"}]}
    assert store.get_run("zz") is None


def test_duplicate_run_id_is_rejected_by_the_database(store):
    store.create_run("a1", "uc01", {})
    with pytest.raises(sqlite3.IntegrityError):
        store.create_run("a1", "uc01", {})


def test_list_runs_newest_first(store, monkeypatch):
    stamps = iter(["2026-10-23T10:00:00+00:00", "2026-10-23T11:00:00+00:00"])
    monkeypatch.setattr(store_module, "now", lambda: next(stamps))
    store.create_run("old", "uc01", {})
    store.create_run("new", "uc01", {})
    assert [r["id"] for r in store.list_runs()] == ["new", "old"]


def test_mark_interrupted_only_touches_active_states(store):
    for run_id, status in (("p", "pending"), ("r", "running"), ("w", "waiting"), ("c", "completed"),
                           ("f", "failed")):
        store.create_run(run_id, "uc01", {})
        store.update_run(run_id, status=status)
    store.update_run("c", cleanup_status="running")
    store.update_run("f", cleanup_status="done")
    store.mark_interrupted()
    status = {r["id"]: (r["status"], r["cleanup_status"]) for r in store.list_runs()}
    assert status == {"p": ("interrupted", None), "r": ("interrupted", None), "w": ("waiting", None),
                      "c": ("completed", "interrupted"), "f": ("failed", "done")}


def test_object_ledger(store):
    store.create_run("a1", "uc01", {})
    store.add_object("a1", "division", "d1", "robot-a1-uc01-division")
    store.add_object("a1", "division", "d1", "robot-a1-uc01-division")  # idempotent
    store.add_object("a1", "policy", "p1", "robot-a1-uc01-policy")
    assert [o["dtm_id"] for o in store.objects("a1")] == ["d1", "p1"]
    assert [o["dtm_id"] for o in store.objects("a1", "policy")] == ["p1"]
    store.mark_removed("a1", "policy", "p1")
    assert [o["dtm_id"] for o in store.objects("a1")] == ["d1"]
    assert store.objects("a1", "policy", include_removed=True)[0]["removed"] == 1


def test_ledger_requires_existing_run(store):
    with pytest.raises(sqlite3.IntegrityError):
        store.add_object("ghost", "division", "d1", "robot-ghost-uc01-division")


def test_events_in_insertion_order(store):
    store.create_run("a1", "uc01", {})
    store.add_event("a1", "first")
    store.add_event("a1", "second", "error")
    events = store.events("a1")
    assert [(e["level"], e["message"]) for e in events] == [("info", "first"), ("error", "second")]
    assert store.events("other") == []


def _populate(store, run_id):
    store.create_run(run_id, "uc01", {})
    store.add_event(run_id, f"event of {run_id}")
    store.add_object(run_id, "policy", f"p-{run_id}", f"robot-{run_id}-uc01-policy")


def test_delete_run_removes_run_events_and_ledger_only_for_that_run(store):
    _populate(store, "a1")
    _populate(store, "a2")
    store.delete_run("a1")
    assert store.get_run("a1") is None and not store.run_exists("a1")
    assert store.events("a1") == [] and store.objects("a1", include_removed=True) == []
    assert store.get_run("a2") is not None
    assert [e["message"] for e in store.events("a2")] == ["event of a2"]
    assert [o["dtm_id"] for o in store.objects("a2")] == ["p-a2"]
    _populate(store, "a1")  # the id can be reused afterwards
    assert store.run_exists("a1")


def test_delete_unknown_run_is_a_noop(store):
    _populate(store, "a1")
    store.delete_run("ghost")
    assert store.run_exists("a1")


def test_delete_run_is_atomic(store):
    _populate(store, "a1")
    real = store._db

    class FailOnRunsDelete:
        def execute(self, sql, *args):
            if sql.startswith("DELETE FROM runs"):
                raise sqlite3.OperationalError("disk I/O error")
            return real.execute(sql, *args)

    store._db = FailOnRunsDelete()
    try:
        with pytest.raises(sqlite3.OperationalError):
            store.delete_run("a1")
    finally:
        store._db = real
    # rolled back: events and ledger are still there, and the store is usable
    assert store.run_exists("a1")
    assert len(store.events("a1")) == 1 and len(store.objects("a1")) == 1
    store.add_event("a1", "after rollback")


def test_upgrade_from_v1_database_adds_progress_column(tmp_path):
    path = tmp_path / "v1.db"
    with sqlite3.connect(path) as db:  # a data volume written by the v1 schema
        db.executescript(store_module.MIGRATIONS[0])
        db.execute("INSERT INTO runs (id, use_case, params, status, created_at, result) VALUES "
                   "('old', 'uc01', '{\"mode\": \"single\"}', 'completed', '2026-10-23T10:00:00+00:00', "
                   "'{\"certificate_total\": 1}')")
        db.execute("INSERT INTO run_events (run_id, ts, level, message) VALUES ('old', 'x', 'info', 'kept')")
        db.execute("PRAGMA user_version = 1")
    store = Store(path)
    assert user_version(path) == SCHEMA_VERSION >= 2
    run = store.get_run("old")
    assert run["progress"] is None and run["result"] == {"certificate_total": 1}
    assert store.events("old")[0]["message"] == "kept"
    store.update_run("old", progress={"label": "x", "done": 1})
    assert store.get_run("old")["progress"] == {"label": "x", "done": 1}
    Store(path)  # re-open: the ALTER must not run twice


def test_progress_roundtrip_and_clear(store):
    store.create_run("p", "uc01", {})
    assert store.get_run("p")["progress"] is None
    store.update_run("p", progress={"label": "Uploading", "started": 1.5, "total": 3, "done": None})
    assert store.get_run("p")["progress"] == {"label": "Uploading", "started": 1.5, "total": 3, "done": None}
    store.update_run("p", progress=None)
    assert store.get_run("p")["progress"] is None
    with sqlite3.connect(store_module.Path(store._db.execute("PRAGMA database_list").fetchone()[2])) as db:
        assert db.execute("SELECT progress FROM runs WHERE id = 'p'").fetchone()[0] is None  # NULL, not 'null'


def test_list_runs_skips_heavy_columns(store):
    store.create_run("a1", "uc01", {"mode": "batch"})
    store.update_run("a1", status="completed", result={"certificates": [{"x": 1}] * 100},
                     progress={"label": "x"}, cleanup_mode="full", cleanup_status="done")
    listed = store.list_runs()[0]
    assert listed["result"] is None and listed["progress"] is None
    assert (listed["status"], listed["cleanup_mode"], listed["cleanup_status"], listed["params"]) == (
        "completed", "full", "done", {"mode": "batch"})
    assert store.get_run("a1")["result"]["certificates"][0] == {"x": 1}  # still there for the run page


# --- v3: DTM connections ---------------------------------------------------------------------------

def _v2_database(path, settings: dict):
    with sqlite3.connect(path) as db:
        db.executescript(store_module.MIGRATIONS[0])
        db.execute(store_module.MIGRATIONS[1])
        for key, value in settings.items():
            db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
        db.execute("INSERT INTO runs (id, use_case, params, status, created_at) VALUES "
                   "('old', 'uc01', '{\"dtm_host\": \"one.digicert.com\"}', 'completed', '2026-10-23T10:00:00+00:00')")
        db.execute("PRAGMA user_version = 2")


V2_SETTINGS = {"dtm_host": "one.digicert.com", "dtm_account_id": "0a1b2c3d-0000-4000-8000-00000000a001",
               "dtm_api_key": "old-key", "other": "kept"}


def test_v3_moves_the_old_setting_into_a_default_connection(tmp_path):
    path = tmp_path / "v2.db"
    _v2_database(path, V2_SETTINGS)
    store = Store(path)
    assert user_version(path) == SCHEMA_VERSION >= 3
    (conn,) = store.connections()
    assert (conn["name"], conn["host"], conn["account_id"], conn["api_key"], conn["is_default"]) == (
        "Default", "one.digicert.com", "0a1b2c3d-0000-4000-8000-00000000a001", "old-key", 1)
    for key in ("dtm_host", "dtm_account_id", "dtm_api_key"):
        assert store.get_setting(key) is None
    assert store.get_setting("other") == "kept" and store.get_run("old")["status"] == "completed"
    Store(path)  # idempotent re-open
    assert len(store.connections()) == 1


def test_v3_without_old_settings_creates_no_connection(tmp_path):
    path = tmp_path / "v2.db"
    _v2_database(path, {"other": "kept"})
    store = Store(path)
    assert store.connections() == [] and store.get_setting("other") == "kept"


def test_v3_keeps_partial_old_settings(tmp_path):
    path = tmp_path / "v2.db"
    _v2_database(path, {"dtm_host": "one.digicert.com", "dtm_account_id": "x"})  # no key
    store = Store(path)
    assert store.connections() == []
    assert store.get_setting("dtm_host") == "one.digicert.com" and store.get_setting("dtm_account_id") == "x"


def test_connection_api(store):
    assert store.connection(None) is None and store.connections() == []
    first = store.save_connection(None, "US", "one.digicert.com", "a" * 8, "k1")
    second = store.save_connection(None, "NL", "eu.digicert.com", "b" * 8, "k2")
    assert {c["name"]: c["is_default"] for c in store.connections()} == {"US": 1, "NL": 0}
    assert [c["name"] for c in store.connections()] == ["NL", "US"]  # ordered by name
    assert store.connection(None)["id"] == first and store.connection(second)["name"] == "NL"
    assert store.connection_for("eu.digicert.com", "b" * 8)["id"] == second
    assert store.connection_for("eu.digicert.com", "a" * 8) is None
    store.save_connection(first, "US prod", "one.digicert.com", "a" * 8, "k1b")  # update keeps the default flag
    assert store.connection(None)["id"] == first and store.connection(first)["name"] == "US prod"
    assert store.connection(first)["api_key"] == "k1b"
    store.set_default_connection(second)
    assert [c["id"] for c in store.connections() if c["is_default"]] == [second]
    store.delete_connection(first)  # non-default: default unchanged
    assert store.connection(None)["id"] == second
    third = store.save_connection(None, "AU", "au.digicert.com", "c" * 8, "k3")
    store.delete_connection(second)  # default deleted → MIN(id) becomes default
    assert store.connection(None)["id"] == third and store.connection(third)["is_default"] == 1
    store.delete_connection(third)
    assert store.connections() == [] and store.connection(None) is None


@pytest.mark.parametrize("bad_id", [0, -1, 2 ** 63, 10 ** 30])
def test_connection_out_of_range_ids(store, bad_id):
    store.save_connection(None, "US", "h.example.com", "a", "k")
    assert store.connection(bad_id) is None


def test_connection_names_unique_case_insensitive_in_db(store):
    store.save_connection(None, "Prod", "h.example.com", "a", "k")
    with pytest.raises(sqlite3.IntegrityError):
        store.save_connection(None, "PROD", "h.example.com", "b", "k")
    assert len(store.connections()) == 1


def test_tx_rolls_back_and_later_writes_persist(store, tmp_path):
    store.save_connection(None, "US", "h.example.com", "a", "k")
    with pytest.raises(RuntimeError):
        with store._tx() as db:
            db.execute("UPDATE connections SET name = 'changed'")
            raise RuntimeError("boom")
    assert store.connections()[0]["name"] == "US"
    store.set_setting("after", "1")  # autocommit write after the rollback
    reopened = Store(store_module.Path(store._db.execute("PRAGMA database_list").fetchone()[2]))
    assert reopened.get_setting("after") == "1" and reopened.connections()[0]["name"] == "US"


def test_failed_delete_connection_leaves_no_open_transaction(store, monkeypatch):
    first = store.save_connection(None, "US", "h.example.com", "a", "k")
    real = store._db

    class Failing:
        def execute(self, sql, *args):
            if sql.startswith("UPDATE connections SET is_default = 1"):
                raise sqlite3.OperationalError("disk I/O error")
            return real.execute(sql, *args)

    store._db = Failing()
    try:
        with pytest.raises(sqlite3.OperationalError):
            store.delete_connection(first)
    finally:
        store._db = real
    assert store.connection(first) is not None  # the DELETE was rolled back
    store.set_setting("after", "1")
    assert not real.in_transaction
