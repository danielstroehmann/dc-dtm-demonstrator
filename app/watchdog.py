"""Watchdog (v1.1.0): keeps the DTM account and the host clean when nobody does.

Rule 1: a run is fully rolled back 3 h after it started. Rule 2: without a login in the last 24 h every run is.
Rule 3: this install's minion containers whose run is unknown or rolled back are removed. One task, one tick every
5 minutes: local DB reads and one launcher call per tick – DTM is only called when a rollback is due, and then
through the same full rollback as the runs list's button (the run's own connection), at most one run per tick so
a backlog (after an update or downtime) reaches DTM gradually."""

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
# Rule 2 rarely decides: a session lasts 12 h (JWT), so anyone using the app logs in at least twice a day – it
# catches the demonstrator left alone, e.g. runs that are younger than 3 h when everybody leaves.
IDLE_S = 24 * 3600
RETRY_S, MAX_RETRY_S = 1800, 6 * 3600  # a failed automatic rollback waits, doubling – never a hot loop on DTM
MAX_FAILURES = 3  # then the run is parked (persisted, survives restarts): the presenter rolls it back by hand
LAST_LOGIN = "last_login"  # setting: the latest successful login (ISO, UTC)
REASONS = {"lifetime": "3 h lifetime", "idle": "no login for 24 h"}
log = logging.getLogger("demonstrator")


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%H:%M")


def parked(run: dict) -> bool:
    return bool((run.get("watchdog") or {}).get("parked"))


def lifetime(run: dict, at: float) -> dict | None:
    """The runs list's clock: quarter 0–3 of the lifetime passed and its tooltip."""
    if rolled_back(run):
        return None
    started = _epoch(run["created_at"])
    if parked(run):
        return {"quarter": None, "tip": "Automatic rollback stopped"}
    due = started + LIFETIME_S
    return {"quarter": max(0, min(3, int((at - started) // QUARTER_S))),
            "tip": f"Rolled back automatically at {_utc(due)} UTC" if at < due else "Automatic rollback pending"}


class Watchdog:
    def __init__(self, store: Store, client_for: Callable, runs_dir: Path, clock: Callable[[], float] = time.time,
                 sleep=asyncio.sleep):
        """client_for(run_id): a DTM client for the run's own connection (raises if it is gone)."""
        self.store, self.client_for, self.runs_dir = store, client_for, runs_dir
        self.clock, self.sleep = clock, sleep
        self.started = clock()  # no login recorded yet: idle counts from the app's start
        self.retry: dict[str, float] = {}  # run ID → next attempt after a failure
        self.unreachable: set[str] = set()  # runs without a connection to their account (logged once)

    async def run(self) -> None:
        while True:
            await self.sleep(TICK_S)
            try:
                await self.tick()
            except Exception:  # the next tick tries again; the app keeps running
                log.exception("watchdog tick failed")

    def due(self) -> list[tuple[str, str]]:
        """(run ID, reason) of every run to roll back now, oldest first – busy runs are skipped later."""
        at = self.clock()
        last = self.store.get_setting(LAST_LOGIN)
        idle = at - (_epoch(last) if last else self.started) >= IDLE_S
        found = []
        for run in reversed(self.store.list_runs()):
            if rolled_back(run) or run.get("cleanup_status") == "running" or parked(run):
                continue
            reason = "lifetime" if at - _epoch(run["created_at"]) >= LIFETIME_S else "idle" if idle else None
            if reason and self.retry.get(run["id"], 0) <= at:
                found.append((run["id"], reason))
        return found

    async def tick(self) -> None:
        due = self.due()
        if len(due) > 1:
            log.info("watchdog: %d runs due", len(due))
        for run_id, reason in due:
            run = self.store.get_run(run_id)
            if run and not active(run) and not rolled_back(run):  # a busy run rolls back once it is done
                if await self.rollback(run_id, reason):
                    break  # one rollback per tick reached DTM
        await self.sweep()

    async def rollback(self, run_id: str, reason: str) -> bool:
        """One automatic full rollback. False if it never reached DTM (the run's connection is gone)."""
        why = REASONS[reason]
        try:
            client = self.client_for(run_id)  # a local lookup – never falls back to another account
        except Exception as exc:
            if run_id not in self.unreachable:
                self.unreachable.add(run_id)
                log.warning("run %s: no automatic rollback – no DTM connection for its account (%s)",
                            run_id, getattr(exc, "detail", type(exc).__name__))
            return False
        self.unreachable.discard(run_id)
        log.info("run %s: automatic full rollback (%s)", run_id, why)
        self.store.add_event(run_id, f"Automatic full rollback – {why}")
        try:
            await cleanup.cleanup(self.store, client, run_id, "full", self.runs_dir / run_id)
        except asyncio.CancelledError:
            log.warning("run %s: the shutdown interrupted its automatic rollback", run_id)
            raise
        except Exception:  # cleanup has marked the run failed and logged it in the timeline
            log.exception("run %s: automatic rollback failed", run_id)
        finally:
            await client.aclose()
        if rolled_back(self.store.get_run(run_id) or {}):
            self.retry.pop(run_id, None)
            self.store.add_event(run_id, f"Rolled back automatically – {why}", "success")
            log.info("run %s rolled back automatically (%s)", run_id, why)
        else:
            self._failed(run_id)
        return True

    def _failed(self, run_id: str) -> None:
        run = self.store.get_run(run_id)
        if not run:
            return
        failures = (run["watchdog"] or {}).get("failed", 0) + 1
        self.store.update_run(run_id, watchdog={"failed": failures, "parked": failures >= MAX_FAILURES})
        if failures >= MAX_FAILURES:
            self.retry.pop(run_id, None)
            log.warning("run %s: automatic rollback stopped after %d failures", run_id, failures)
            self.store.add_event(run_id, f"Automatic rollback stopped after {failures} failures – roll back manually",
                                 "error")
            return
        at = self.clock() + min(RETRY_S * 2 ** (failures - 1), MAX_RETRY_S)
        self.retry[run_id] = at
        log.warning("run %s: automatic rollback failed – next attempt at %s UTC", run_id, _utc(at))
        self.store.add_event(run_id, f"Automatic rollback failed – next attempt at {_utc(at)} UTC", "error")

    async def sweep(self) -> None:
        """Rule 3: removes this install's minions whose run is unknown (deleted) or rolled back."""
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
            if run and removed:
                self.store.add_event(run_id, f"Removed {removed} leftover minion container(s) automatically")


def record_login(store: Store) -> None:
    store.set_setting(LAST_LOGIN, now())
