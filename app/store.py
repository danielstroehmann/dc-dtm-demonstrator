"""SQLite persistence under DATA_DIR with ordered, idempotent schema migrations."""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Each entry migrates the schema from version i to i+1. Never edit a released entry –
# append a new one instead, so older data volumes upgrade cleanly.
# Statements are split on ';' – do not use ';' inside literals or trigger bodies.
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
    # v2: live progress of a running step (shown while waiting for DTM)
    "ALTER TABLE runs ADD COLUMN progress TEXT",
    # v3: several DTM connections; the single v1/v2 setting becomes the default connection
    """
    CREATE TABLE connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        host TEXT NOT NULL,
        account_id TEXT NOT NULL,
        api_key TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO connections (name, host, account_id, api_key, is_default)
        SELECT 'Default', h.value, a.value, k.value, 1
        FROM settings h, settings a, settings k
        WHERE h.key = 'dtm_host' AND a.key = 'dtm_account_id' AND k.key = 'dtm_api_key';
    DELETE FROM settings WHERE key IN ('dtm_host', 'dtm_account_id', 'dtm_api_key')
        AND EXISTS (SELECT 1 FROM connections)
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

    @contextmanager
    def _tx(self):
        """Explicit transaction: with isolation_level=None a failed, unclosed BEGIN would swallow every
        later autocommit write."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _exec(self, sql: str, args: tuple = ()) -> "_Result":
        with self._lock:
            return _Result(self._db.execute(sql, args))

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

    def update_setting(self, key: str, value: str) -> bool:
        """Changes an existing setting only – False if it does not exist (e.g. deleted meanwhile)."""
        return self._exec("UPDATE settings SET value = ? WHERE key = ?", (value, key)).rowcount == 1

    def delete_setting(self, key: str) -> bool:
        return self._exec("DELETE FROM settings WHERE key = ?", (key,)).rowcount == 1

    def set_setting_once(self, key: str, value: str) -> bool:
        """Sets a setting only if it does not exist yet – False if another request was first."""
        return self._exec("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)).rowcount == 1

    # DTM connections (several accounts/environments; one is the default)
    def connections(self) -> list[dict]:
        return [dict(r) for r in self._exec("SELECT * FROM connections ORDER BY name").fetchall()]

    def connection(self, connection_id: int | None) -> dict | None:
        if connection_id is not None and not 0 < connection_id < 2 ** 63:
            return None
        if connection_id is None:
            row = self._exec("SELECT * FROM connections ORDER BY is_default DESC, id LIMIT 1").fetchone()
        else:
            row = self._exec("SELECT * FROM connections WHERE id = ?", (connection_id,)).fetchone()
        return dict(row) if row else None

    def connection_for(self, host: str, account_id: str) -> dict | None:
        row = self._exec("SELECT * FROM connections WHERE host = ? AND account_id = ? ORDER BY is_default DESC, id",
                         (host, account_id)).fetchone()
        return dict(row) if row else None

    def save_connection(self, connection_id: int | None, name: str, host: str, account_id: str,
                        api_key: str) -> int:
        with self._lock:
            if connection_id is None:
                first = self._db.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 0
                cur = self._db.execute(
                    "INSERT INTO connections (name, host, account_id, api_key, is_default) VALUES (?, ?, ?, ?, ?)",
                    (name, host, account_id, api_key, int(first)))
                return cur.lastrowid
            self._db.execute("UPDATE connections SET name = ?, host = ?, account_id = ?, api_key = ? WHERE id = ?",
                             (name, host, account_id, api_key, connection_id))
            return connection_id

    def set_default_connection(self, connection_id: int) -> None:
        with self._tx() as db:
            db.execute("UPDATE connections SET is_default = (id = ?)", (connection_id,))

    def delete_connection(self, connection_id: int) -> None:
        with self._tx() as db:
            was_default = db.execute("SELECT is_default FROM connections WHERE id = ?", (connection_id,)).fetchone()
            db.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
            if was_default and was_default[0]:  # keep exactly one default while any connection exists
                db.execute("UPDATE connections SET is_default = 1 WHERE id = (SELECT MIN(id) FROM connections)")

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
        # The overview needs no results (they hold every issued certificate).
        return [_run(r) for r in self._exec(
            "SELECT id, use_case, params, status, created_at, finished_at, NULL AS result, error, cleanup_mode, "
            "cleanup_status, progress FROM runs ORDER BY created_at DESC").fetchall()]

    def update_run(self, run_id: str, **fields) -> None:
        for key in ("params", "result", "progress"):
            if key in fields and fields[key] is not None:
                fields[key] = json.dumps(fields[key])
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE runs SET {cols} WHERE id = ?", (*fields.values(), run_id))

    def delete_run(self, run_id: str) -> None:
        with self._tx() as db:
            for table in ("run_events", "run_objects"):
                db.execute(f"DELETE FROM {table} WHERE run_id = ?", (run_id,))
            db.execute("DELETE FROM runs WHERE id = ?", (run_id,))

    def claim_status(self, run_id: str, expected: str, new: str) -> bool:
        """Atomic status change – False if another request changed the status first."""
        return self._exec("UPDATE runs SET status = ? WHERE id = ? AND status = ?", (new, run_id, expected)).rowcount == 1

    def mark_interrupted(self) -> None:
        """Background tasks die with the process; make that visible after a restart."""
        self._exec("UPDATE runs SET status = 'interrupted' WHERE status IN ('pending', 'running', 'paused')")
        # An interrupted renewal leaves the device with its previous, still valid certificate.
        self._exec("UPDATE runs SET status = 'completed' WHERE status = 'renewing'")
        # Same for a device of an Advanced run that was enrolling or renewing
        self._exec("UPDATE runs SET result = json_remove(result, '$.busy') "
                   "WHERE result IS NOT NULL AND json_extract(result, '$.busy') IS NOT NULL")
        self._exec("UPDATE runs SET cleanup_status = 'interrupted' WHERE cleanup_status = 'running'")
        self._exec("UPDATE runs SET progress = NULL WHERE progress IS NOT NULL")  # nothing is in progress after a restart

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


class _Result:
    """A statement's rows, read while the lock is held: the connection is shared between threads (e.g.
    the test client next to the app's loop), and a cursor fetched after the lock is released can return
    another statement's row (seen in CI: a run without params)."""

    def __init__(self, cursor: sqlite3.Cursor):
        self.rows = cursor.fetchall() if cursor.description else []
        self.rowcount = cursor.rowcount

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list:
        return self.rows

    def __iter__(self):
        return iter(self.rows)


def _run(row: sqlite3.Row) -> dict:
    run = dict(row)
    run["params"] = json.loads(run["params"])
    run["result"] = json.loads(run["result"]) if run["result"] else None
    run["progress"] = json.loads(run["progress"]) if run.get("progress") else None
    return run
