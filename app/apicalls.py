"""Records the DTM API calls a run made, so every use case can show "this is what the call looks like"."""

import time
from collections.abc import Awaitable

from .snippets import tokenize


class ApiCalls:
    def __init__(self):
        self.calls: list[dict] = []
        self.run_name: str | None = None  # set once known: recorded specs then say {RUN_NAME} instead

    async def timed(self, purpose: str, method: str, path: str, call: Awaitable, spec: dict | None = None,
                    phase: str = "recurring"):
        start = time.monotonic()
        outcome = "error"
        try:
            result = await call
            outcome = "ok"
            return result
        finally:
            self.add(purpose, method, path, time.monotonic() - start, outcome, spec=spec, phase=phase)

    def add(self, purpose: str, method: str, path: str, seconds: float | None, outcome: str = "ok",
            count: int = 1, spec: dict | None = None, phase: str = "recurring") -> None:
        """spec: what app/snippets.py needs to render the call as curl/wget/PowerShell.
        phase: 'setup' (once, e.g. the policy) or 'recurring' (repeated to order more certificates)."""
        if spec and self.run_name:
            spec = tokenize(spec, self.run_name)
        self.calls.append({"purpose": purpose, "method": method, "path": path, "seconds": None if seconds is None else round(seconds, 2),
                           "outcome": outcome, "count": count, "spec": spec, "phase": phase})
