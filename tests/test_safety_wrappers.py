"""Regression tests for the wrapper chain installed by ``auth.connect``.

These guard the most safety-critical invariant in the project:

* In dry-run mode, the readonly-guard / budget / rate-limiter still
  observe each attempted call (counters update correctly).
* No call ever reaches the real transport in dry-run mode.
* A write attempt is blocked by the readonly guard *before* dry-run gets
  a chance to record it (so dry-run can never silently swallow a write
  that would have hit the cloud if dry-run were off).
* DryRunBlocked is not counted as a budget failure (it must not trip the
  circuit breaker spuriously).
* Re-installing any wrapper on the same session is a no-op (idempotent).

If any of these break, the README's "blocked_writes==0 means no bug"
contract no longer holds and we should fail loudly here in CI before
anyone runs the tool against a production cloud.
"""

from __future__ import annotations

import pytest

from openstack_doctor.safety import (
    Budget,
    DryRunBlocked,
    DryRunRecorder,
    WriteAttemptBlocked,
    install_budget,
    install_dry_run,
    install_rate_limiter,
    install_readonly_guard,
)


def _install_full_chain(conn, *, dry_run: bool):
    """Mirror the install order used by ``auth.connect``.

    Order matters: dry_run must be installed *first* so the safety
    wrappers (rate_limiter, budget, readonly_guard) end up on top of it
    in the call chain.
    """
    recorder = None
    if dry_run:
        recorder = DryRunRecorder()
        install_dry_run(conn, recorder)
    install_rate_limiter(conn, 1000.0)  # high rps so wait() is effectively a no-op
    budget = Budget(max_requests=10, deadline_seconds=0)
    install_budget(conn, budget)
    guard = install_readonly_guard(conn)
    return recorder, budget, guard


def test_dry_run_safe_get_increments_guard_and_does_not_hit_transport(fake_conn):
    recorder, budget, guard = _install_full_chain(fake_conn, dry_run=True)

    with pytest.raises(DryRunBlocked):
        fake_conn.session.request("https://x/y", "GET")

    assert fake_conn.session.calls == []
    assert len(recorder.records) == 1
    assert recorder.records[0].method == "GET"
    assert guard.allowed == 1
    assert guard.blocked == 0
    assert budget.used == 0, "DryRunBlocked must not be counted toward budget"
    assert budget.failures == 0, "DryRunBlocked must not trip the circuit breaker"


def test_dry_run_write_attempt_is_blocked_by_guard_not_recorded_by_dryrun(fake_conn):
    recorder, _budget, guard = _install_full_chain(fake_conn, dry_run=True)

    with pytest.raises(WriteAttemptBlocked):
        fake_conn.session.request("https://x/servers", "POST")

    assert guard.blocked == 1
    assert recorder.records == [], (
        "dry_run must never record a write that the readonly guard would "
        "have blocked anyway -- otherwise the safety contract leaks."
    )
    assert fake_conn.session.calls == []


def test_dry_run_auth_post_is_allowed_through_guard(fake_conn):
    recorder, _budget, guard = _install_full_chain(fake_conn, dry_run=True)

    with pytest.raises(DryRunBlocked):
        fake_conn.session.request("https://keystone/v3/auth/tokens", "POST")

    assert guard.allowed == 1
    assert guard.blocked == 0
    assert len(recorder.records) == 1


def test_non_dry_run_safe_get_reaches_transport_and_increments_counters(fake_conn):
    _r, budget, guard = _install_full_chain(fake_conn, dry_run=False)

    assert fake_conn.session.request("https://x/y", "GET") == "ok"
    assert fake_conn.session.calls == [("GET", "https://x/y")]
    assert guard.allowed == 1
    assert budget.used == 1
    assert budget.failures == 0


def test_non_dry_run_write_blocked_does_not_count_toward_budget(fake_conn):
    _r, budget, guard = _install_full_chain(fake_conn, dry_run=False)

    with pytest.raises(WriteAttemptBlocked):
        fake_conn.session.request("https://x/y", "DELETE")

    assert guard.blocked == 1
    assert budget.used == 0, (
        "A blocked write never hit the wire, so it must not consume budget."
    )
    assert fake_conn.session.calls == []


def test_circuit_breaker_trips_on_consecutive_real_failures(fake_conn):
    # No dry_run; make the real transport always raise so the budget wrapper
    # records failures.
    def boom(*_a, **_kw):
        raise RuntimeError("upstream 5xx")

    fake_conn.session.request = boom  # type: ignore[assignment]
    install_rate_limiter(fake_conn, 1000.0)
    budget = Budget(max_requests=100, deadline_seconds=0, consecutive_failure_limit=3)
    install_budget(fake_conn, budget)
    install_readonly_guard(fake_conn)

    for _ in range(3):
        with pytest.raises(RuntimeError):
            fake_conn.session.request("https://x/y", "GET")

    assert budget.tripped is True
    # Subsequent calls are short-circuited by the circuit breaker.
    from openstack_doctor.safety import CircuitOpen

    with pytest.raises(CircuitOpen):
        fake_conn.session.request("https://x/y", "GET")


def test_install_wrappers_are_idempotent(fake_conn):
    g1 = install_readonly_guard(fake_conn)
    g2 = install_readonly_guard(fake_conn)
    fake_conn.session.request("https://x/y", "GET")
    # The second install was a no-op, so only the first stats object is
    # actually wired in.
    assert g1.allowed == 1
    assert g2.allowed == 0

    install_rate_limiter(fake_conn, 1000.0)
    install_rate_limiter(fake_conn, 1000.0)  # must not double-wrap

    b1 = Budget(max_requests=5, deadline_seconds=0)
    install_budget(fake_conn, b1)
    b2 = Budget(max_requests=5, deadline_seconds=0)
    install_budget(fake_conn, b2)
    fake_conn.session.request("https://x/y", "GET")
    assert b1.used == 1
    assert b2.used == 0, "second install_budget must not wire in a second wrapper"
