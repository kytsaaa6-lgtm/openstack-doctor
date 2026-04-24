"""Shared fixtures for openstack-doctor tests.

Tests in this suite never talk to a real OpenStack cloud. We exercise the
safety primitives, CLI helpers, and report rendering against in-memory
fakes that are good enough to verify the contracts we care about
(read-only enforcement, dry-run interception, wrapper-chain ordering,
shell-token whitelisting, markdown escaping, etc.).
"""

from __future__ import annotations

import pytest


class FakeSession:
    """Minimal stand-in for keystoneauth1's ``Session.request``.

    Records every call that reaches the "real transport" layer so tests
    can assert that dry-run / readonly-guard wrappers prevent leakage.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(self, url, method, *args, **kwargs):  # noqa: D401, ANN001
        self.calls.append((str(method).upper(), str(url)))
        return "ok"


class FakeConn:
    """Minimal stand-in for ``openstack.connection.Connection``."""

    def __init__(self) -> None:
        self.session = FakeSession()


@pytest.fixture
def fake_conn() -> FakeConn:
    return FakeConn()
