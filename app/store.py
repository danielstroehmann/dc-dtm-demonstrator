"""SQLite persistence under DATA_DIR with ordered, idempotent schema migrations."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

# Each entry migrates the schema from version i to i+1. Never edit a released entry –
# append a new one instead, so older data volumes upgrade cleanly.
MIGRATIONS = [
    """
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE runs (
        id TEXT PRIMARY KEY,
        use_case TEXT NOT NULL,
        params TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        finished_at TEXT,
        result TEXT,
        error TEXT,
        cleanup_mode TEXT,
        cleanup_status TEXT
    );
    CREATE TABLE run_objects (
        run_id TEXT NOT NULL REFERENCES runs(id),
        kind TEXT NOT NULL,
        dtm_id TEXT NOT NULL,
        name TEXT NOT NULL,
        removed INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (run_id, kind, dtm_id)
    );
    CREATE TABLE run_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(id),
        ts TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL
    );
    """,
]
SCHEMA_VERSION = len(MIGRATIONS)


class SchemaTooNewError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.Lock()
        self._migrate()

    def _migrate(self) -> None:
        current = self._db.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            # Never downgrade silently: a newer release wrote this data.
            raise SchemaTooNewError(
                f"data schema version {current} is newer than this release supports ({SCHEMA_VERSION})"
            )
        for version in range(current, SCHEMA_VERSION):
            with self._lock:
                self._db.execute("BEGIN")
                try:
                    for statement in filter(str.strip, MIGRATIONS[version].split(";")):
                        self._db.execute(statement)
                    self._db.execute(f"PRAGMA user_version = {version + 1}")
                    self._db.execute("COMMIT")
                except Exception:
                    self._db.execute("ROLLBACK")
                    raise

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    # settings
    def get_setting(self, key: str) -> str | None:
        row = self._exec("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        self._exec(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # runs
    def create_run(self, run_id: str, use_case: str, params: dict) -> None:
        self._exec(
            "INSERT INTO runs (id, use_case, params, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
            (run_id, use_case, json.dumps(params), now()),
        )

    def run_exists(self, run_id: str) -> bool:
        return self._exec("SELECT 1 FROM runs WHERE id = ?", (run_id,)).fetchone() is not None

    def get_run(self, run_id: str) -> dict | None:
        row = self._exec("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return _run(row) if row else None

    def list_runs(self) -> list[dict]:
        return [_run(r) for r in self._exec("SELECT * FROM runs ORDER BY created_at DESC").fetchall()]

    def update_run(self, run_id: str, **fields) -> None:
        for key in ("params", "result"):
            if key in fields and fields[key] is not None:
                fields[key] = json.dumps(fields[key])
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE runs SET {cols} WHERE id = ?", (*fields.values(), run_id))

    def mark_interrupted(self) -> None:
        """Background tasks die with the process; make that visible after a restart."""
        self._exec("UPDATE runs SET status = 'interrupted' WHERE status IN ('pending', 'running')")
        self._exec("UPDATE runs SET cleanup_status = 'interrupted' WHERE cleanup_status = 'running'")

    # ledger of DTM objects created by a run – the primary source for cleanup
    def add_object(self, run_id: str, kind: str, dtm_id: str, name: str) -> None:
        self._exec(
            "INSERT OR IGNORE INTO run_objects (run_id, kind, dtm_id, name) VALUES (?, ?, ?, ?)",
            (run_id, kind, dtm_id, name),
        )

    def objects(self, run_id: str, kind: str | None = None, include_removed: bool = False) -> list[dict]:
        sql, args = "SELECT * FROM run_objects WHERE run_id = ?", [run_id]
        if kind:
            sql += " AND kind = ?"
            args.append(kind)
        if not include_removed:
            sql += " AND removed = 0"
        return [dict(r) for r in self._exec(sql, tuple(args)).fetchall()]

    def mark_removed(self, run_id: str, kind: str, dtm_id: str) -> None:
        self._exec(
            "UPDATE run_objects SET removed = 1 WHERE run_id = ? AND kind = ? AND dtm_id = ?",
            (run_id, kind, dtm_id),
        )

    # event log shown live in the UI
    def add_event(self, run_id: str, message: str, level: str = "info") -> None:
        self._exec(
            "INSERT INTO run_events (run_id, ts, level, message) VALUES (?, ?, ?, ?)",
            (run_id, now(), level, message),
        )

    def events(self, run_id: str) -> list[dict]:
        return [
            dict(r)
            for r in self._exec("SELECT ts, level, message FROM run_events WHERE run_id = ? ORDER BY id", (run_id,))
        ]


def _run(row: sqlite3.Row) -> dict:
    run = dict(row)
    run["params"] = json.loads(run["params"])
    run["result"] = json.loads(run["result"]) if run["result"] else None
    return run
