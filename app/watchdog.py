"""Watchdog (v1.1.0): keeps the DTM account and the host clean when nobody does.

Rule 1: a run is fully rolled back 3 h after it started. Rule 2: without a login in the last 24 h every run is.
Rule 3: minion containers whose run is unknown or rolled back are removed. One task, one tick every 5 minutes:
local DB reads and one launcher call per tick – DTM is only called when a rollback is due, and then through the
same full rollback as the runs list's button (the run's own connection, one run at a time)."""

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from . import cleanup, minions
from .store import Store, active, now, rolled_back

TICK_S = 300
LIFETIME_S = 3 * 3600
QUARTER_S = LIFETIME_S // 4  # the runs list's clock fills in quarters
IDLE_S = 24 * 3600
RETRY_S, MAX_RETRY_S = 1800, 6 * 3600  # a failed automatic rollback waits, doubling – never a hot loop on DTM
LAST_LOGIN = "last_login"  # setting: the latest successful login (ISO, UTC)
REASONS = {"lifetime": "3 h lifetime", "idle": "no login for 24 h"}
log = logging.getLogger("demonstrator")


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%H:%M")


def lifetime(run: dict, at: float) -> dict | None:
    """The runs list's clock: quarter 0–3 of the lifetime passed and when the run is rolled back (HH:MM UTC)."""
    if rolled_back(run):
        return None
    started = _epoch(run["created_at"])
    return {"quarter": max(0, min(3, int((at - started) // QUARTER_S))), "due": _utc(started + LIFETIME_S)}


class Watchdog:
    def __init__(self, store: Store, client_for: Callable, runs_dir: Path, clock: Callable[[], float] = time.time,
                 sleep=asyncio.sleep):
        """client_for(run_id): a DTM client for the run's own connection (raises if it is gone)."""
        self.store, self.client_for, self.runs_dir = store, client_for, runs_dir
        self.clock, self.sleep = clock, sleep
        self.started = clock()  # no login recorded yet: idle counts from the app's start
        self.retry: dict[str, tuple[int, float]] = {}  # run ID → (failures, next attempt)

    async def run(self) -> None:
        while True:
            await self.sleep(TICK_S)
            try:
                await self.tick()
            except Exception:  # the next tick tries again; the app keeps running
                log.exception("watchdog tick failed")

    def due(self) -> list[tuple[str, str]]:
        """(run ID, reason) of every run to roll back now – busy runs are skipped later, with their result."""
        at = self.clock()
        last = self.store.get_setting(LAST_LOGIN)
        idle = at - (_epoch(last) if last else self.started) >= IDLE_S
        found = []
        for run in self.store.list_runs():
            if rolled_back(run) or run.get("cleanup_status") == "running":
                continue
            reason = "lifetime" if at - _epoch(run["created_at"]) >= LIFETIME_S else "idle" if idle else None
            if reason and self.retry.get(run["id"], (0, 0))[1] <= at:
                found.append((run["id"], reason))
        return found

    async def tick(self) -> None:
        for run_id, reason in self.due():
            run = self.store.get_run(run_id)
            if run and not active(run) and not rolled_back(run):  # a busy run rolls back once it is done
                await self.rollback(run_id, reason)
        await self.sweep()

    async def rollback(self, run_id: str, reason: str) -> None:
        why = REASONS[reason]
        log.info("run %s: automatic full rollback (%s)", run_id, why)
        try:
            client = self.client_for(run_id)
        except Exception as exc:  # the run's connection is gone – never fall back to another account
            self._failed(run_id, f"no DTM connection for its account ({getattr(exc, 'detail', type(exc).__name__)})")
            return
        self.store.add_event(run_id, f"Automatic full rollback – {why}")
        try:
            await cleanup.cleanup(self.store, client, run_id, "full", self.runs_dir / run_id)
        except Exception as exc:  # cleanup has marked the run failed and logged it in the timeline
            log.exception("run %s: automatic rollback failed", run_id)
            self._failed(run_id, type(exc).__name__)
            return
        finally:
            await client.aclose()
        if rolled_back(self.store.get_run(run_id) or {}):
            self.retry.pop(run_id, None)
            self.store.add_event(run_id, f"Rolled back automatically – {why}", "success")
            log.info("run %s rolled back automatically (%s)", run_id, why)
        else:
            self._failed(run_id, "the cleanup failed")

    def _failed(self, run_id: str, reason: str) -> None:
        failures = self.retry.get(run_id, (0, 0))[0] + 1
        at = self.clock() + min(RETRY_S * 2 ** (failures - 1), MAX_RETRY_S)
        self.retry[run_id] = (failures, at)
        log.warning("run %s: automatic rollback failed (%s) – next attempt at %s UTC", run_id, reason, _utc(at))
        if self.store.run_exists(run_id):
            self.store.add_event(run_id, f"Automatic rollback failed – next attempt at {_utc(at)} UTC", "error")

    async def sweep(self) -> None:
        """Rule 3: removes minions whose run is unknown (deleted) or rolled back – only labelled containers."""
        if not minions.LAUNCHER:  # no minion runtime here
            return
        try:
            labelled = await minions.labelled_runs()
        except minions.MinionError as exc:
            log.warning("watchdog: cannot list minions – %s", exc)
            return
        for run_id in labelled:
            run = self.store.get_run(run_id)
            if run and not rolled_back(run):
                continue
            try:
                removed = await minions.remove_run(run_id)
            except minions.MinionError as exc:
                log.warning("watchdog: cannot remove the minions of run %s – %s", run_id, exc)
                continue
            log.info("watchdog: removed %d dangling minion container(s) of run %s", removed, run_id)


def record_login(store: Store) -> None:
    store.set_setting(LAST_LOGIN, now())
