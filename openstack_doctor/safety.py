"""Safety primitives so that running this tool is provably read-only.

This module:

* Installs a *runtime guard* on the openstacksdk session that allows only
  HTTP methods which cannot mutate state (``GET``/``HEAD``/``OPTIONS``).
  The single exception is ``POST`` to Keystone's token endpoint, which is
  the standard auth handshake and does not modify tenant resources.
* Provides a tiny token-bucket style rate limiter so we never burst
  hundreds of requests against a busy production cloud.
* Provides ``bounded_list`` to cap the number of items pulled from a
  paginated SDK generator.
* Provides ``service_available`` so checks can be skipped cleanly when an
  optional service (Octavia, Heat, Cinder, ...) is simply not deployed.
* Provides ``snapshot`` to record raw API responses for offline analysis.
* Provides ``redact`` for masking sensitive values in reports/logs.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Any

from openstack.connection import Connection

# ---------------------------------------------------------------------------
# Read-only guard
# ---------------------------------------------------------------------------

SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
AUTH_POST_PATTERNS = (
    "/auth/tokens",
    "/v3/auth/tokens",
    "/v2.0/tokens",
)


class WriteAttemptBlocked(PermissionError):
    """Raised when something tries to mutate state through the SDK."""


class BudgetExceeded(RuntimeError):
    """Raised when the global request count or wall-clock budget is exhausted."""


class CircuitOpen(RuntimeError):
    """Raised when too many consecutive failures occurred and we stop calling."""


class DryRunBlocked(RuntimeError):
    """Raised in dry-run mode whenever a real HTTP call would have happened."""


@dataclass
class GuardStats:
    allowed: int = 0
    blocked: int = 0
    blocked_calls: list[tuple[str, str]] = field(default_factory=list)


_GUARD_INSTALLED_ATTR = "_openstack_doctor_guard_installed"


def install_readonly_guard(conn: Connection, stats: GuardStats | None = None) -> GuardStats:
    """Wrap ``conn.session.request`` so that only safe HTTP methods pass.

    Must be called *after* the initial authentication so we don't block
    the very POST that fetches our token. Re-auth POSTs to ``/auth/tokens``
    are explicitly allowed.

    Idempotent: re-installing on the same session is a no-op so wrapper
    chains never double-stack and double-count.
    """
    stats = stats or GuardStats()
    session = conn.session
    if getattr(session, _GUARD_INSTALLED_ATTR, False):
        return stats
    original = session.request

    def guarded(url, method, *args, **kwargs):  # noqa: ANN001,ANN201
        m = (method or "GET").upper()
        url_str = str(url)
        if m in SAFE_HTTP_METHODS:
            stats.allowed += 1
            return original(url, method, *args, **kwargs)
        if m == "POST" and any(p in url_str for p in AUTH_POST_PATTERNS):
            stats.allowed += 1
            return original(url, method, *args, **kwargs)
        stats.blocked += 1
        stats.blocked_calls.append((m, url_str))
        raise WriteAttemptBlocked(
            f"openstack-doctor refused to perform {m} {url_str}: "
            "this tool is strictly read-only."
        )

    session.request = guarded  # type: ignore[method-assign]
    setattr(session, _GUARD_INSTALLED_ATTR, True)
    return stats


# ---------------------------------------------------------------------------
# Rate limiting / pagination caps
# ---------------------------------------------------------------------------


class RateLimiter:
    """Very small thread-safe per-process rate limiter (requests / second)."""

    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


_RATE_LIMITER_INSTALLED_ATTR = "_openstack_doctor_rate_installed"


def install_rate_limiter(conn: Connection, rps: float) -> RateLimiter | None:
    """Insert a rate limiter in front of every HTTP request.

    Idempotent across re-installs on the same session.
    """
    if not rps or rps <= 0:
        return None
    session = conn.session
    if getattr(session, _RATE_LIMITER_INSTALLED_ATTR, False):
        return None
    limiter = RateLimiter(rps)
    original = session.request

    def throttled(url, method, *args, **kwargs):  # noqa: ANN001,ANN201
        limiter.wait()
        return original(url, method, *args, **kwargs)

    session.request = throttled  # type: ignore[method-assign]
    setattr(session, _RATE_LIMITER_INSTALLED_ATTR, True)
    return limiter


# ---------------------------------------------------------------------------
# Global request / wall-clock budget + circuit breaker
# ---------------------------------------------------------------------------


@dataclass
class Budget:
    """Hard caps that even runaway code cannot blow past."""

    max_requests: int = 0  # 0 = unlimited
    deadline_seconds: float = 0.0  # 0 = unlimited
    consecutive_failure_limit: int = 5
    started: float = field(default_factory=time.monotonic)
    used: int = 0
    failures: int = 0
    tripped: bool = False
    last_error: str | None = None

    def check(self) -> None:
        if self.tripped:
            raise CircuitOpen(
                f"Circuit open after {self.failures} consecutive failures "
                f"(last: {self.last_error})"
            )
        if self.max_requests and self.used >= self.max_requests:
            raise BudgetExceeded(
                f"max_requests={self.max_requests} reached - "
                "openstack-doctor refused to send more API calls."
            )
        if self.deadline_seconds and (time.monotonic() - self.started) >= self.deadline_seconds:
            raise BudgetExceeded(
                f"deadline_seconds={self.deadline_seconds} reached - "
                "openstack-doctor refused to send more API calls."
            )

    def record_success(self) -> None:
        self.used += 1
        self.failures = 0

    def record_failure(self, exc: BaseException) -> None:
        self.used += 1
        self.failures += 1
        self.last_error = f"{type(exc).__name__}: {exc}"
        if self.failures >= self.consecutive_failure_limit:
            self.tripped = True


_BUDGET_INSTALLED_ATTR = "_openstack_doctor_budget_installed"


def install_budget(conn: Connection, budget: Budget) -> Budget:
    """Wrap ``session.request`` to enforce a global budget + circuit breaker.

    Idempotent across re-installs on the same session.
    """
    session = conn.session
    if getattr(session, _BUDGET_INSTALLED_ATTR, False):
        return budget
    original = session.request

    def budgeted(url, method, *args, **kwargs):  # noqa: ANN001,ANN201
        budget.check()
        try:
            resp = original(url, method, *args, **kwargs)
        except DryRunBlocked:
            # Dry-run interception is not a real failure of the cloud, so
            # do not count it toward the circuit breaker.
            raise
        except Exception as exc:
            budget.record_failure(exc)
            raise
        budget.record_success()
        return resp

    session.request = budgeted  # type: ignore[method-assign]
    setattr(session, _BUDGET_INSTALLED_ATTR, True)
    return budget


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


@dataclass
class DryRunRecord:
    method: str
    url: str


@dataclass
class DryRunRecorder:
    records: list[DryRunRecord] = field(default_factory=list)


_DRY_RUN_INSTALLED_ATTR = "_openstack_doctor_dryrun_installed"


def install_dry_run(conn: Connection, recorder: DryRunRecorder) -> DryRunRecorder:
    """Insert a dry-run interceptor that records the attempt and raises.

    IMPORTANT: this must be installed *before* the readonly guard / budget /
    rate-limiter so it sits at the *bottom* of the wrapper chain. The chain
    then becomes::

        session.request -> guard -> budget -> rate_limiter -> dry_run -> (raise)

    This way an SDK call still flows through the safety wrappers (counters
    increment, write attempts are caught and reported as
    ``WriteAttemptBlocked`` instead of silently turning into a dry-run
    record) and only blocks at the very last step before any HTTP egress.

    Idempotent across re-installs on the same session.
    """
    session = conn.session
    if getattr(session, _DRY_RUN_INSTALLED_ATTR, False):
        return recorder

    def fake(url, method, *args, **kwargs):  # noqa: ANN001,ANN201
        m = str(method or "GET").upper()
        url_str = str(url)
        recorder.records.append(DryRunRecord(method=m, url=url_str))
        raise DryRunBlocked(f"DRY-RUN: would have sent {m} {url_str}")

    session.request = fake  # type: ignore[method-assign]
    setattr(session, _DRY_RUN_INSTALLED_ATTR, True)
    return recorder


# Absolute fallback when the caller passes ``None`` or 0 ("unlimited"). We
# still cap the iteration so a 50k-server cloud never blows up our memory or
# our request budget. Tunable but conservative.
ABSOLUTE_MAX_ITEMS = 5000


def bounded_list(it: Iterable[Any], max_items: int | None) -> list[Any]:
    """Materialise a generator with an upper bound.

    ``None`` or 0 falls back to :data:`ABSOLUTE_MAX_ITEMS` rather than truly
    unlimited iteration. A truly unlimited list against a busy cloud is an
    operational footgun.
    """
    if max_items is None or max_items <= 0:
        return list(islice(it, ABSOLUTE_MAX_ITEMS))
    return list(islice(it, max_items))


# ---------------------------------------------------------------------------
# Service catalog detection
# ---------------------------------------------------------------------------


def service_available(conn: Connection, service_type: str) -> bool:
    """Return True if the cloud actually exposes ``service_type``.

    We try the catalog (cheap, cached in the session) first. If the
    interface lookup raises, we treat the service as unavailable.
    """
    try:
        endpoint = conn.session.get_endpoint(service_type=service_type)
        return bool(endpoint)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Snapshot / capture mode
# ---------------------------------------------------------------------------


class Snapshot:
    """Persist arbitrary inspection payloads to disk for offline analysis."""

    def __init__(self, root: Path | None) -> None:
        self.root = root
        # ``failures`` accumulates (key, exception_repr) pairs so the caller
        # can surface them in the report instead of silently losing them.
        self.failures: list[tuple[str, str]] = []
        if self.root:
            self.root.mkdir(parents=True, exist_ok=True)

    def save(self, key: str, payload: Any) -> None:
        if not self.root:
            return
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", key)[:120]
        path = self.root / f"{safe}.json"
        try:
            path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as exc:
            self.failures.append((key, f"{type(exc).__name__}: {exc}"))


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


_IPV4 = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_TOKEN_KEYS = re.compile(r"(?i)(token|password|secret|api[_-]?key)")


def redact_ipv4(value: str) -> str:
    return _IPV4.sub("x.x.x.x", value)


def redact_dict(d: Any, redact_ips: bool = False) -> Any:
    """Recursively redact sensitive values in a dict/list structure."""
    if isinstance(d, dict):
        out: dict[str, Any] = {}
        for k, v in d.items():
            if isinstance(k, str) and _TOKEN_KEYS.search(k):
                out[k] = "***REDACTED***"
            else:
                out[k] = redact_dict(v, redact_ips=redact_ips)
        return out
    if isinstance(d, list):
        return [redact_dict(x, redact_ips=redact_ips) for x in d]
    if isinstance(d, str) and redact_ips:
        return redact_ipv4(d)
    return d


