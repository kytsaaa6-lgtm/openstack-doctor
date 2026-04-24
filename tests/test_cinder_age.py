"""Tests for the cinder check's "stuck-after-N-seconds" gating."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from openstack_doctor.checks import cinder


def test_age_seconds_uses_updated_at_first():
    now = datetime.now(timezone.utc)
    v = SimpleNamespace(
        updated_at=(now - timedelta(seconds=30)).isoformat(),
        created_at=(now - timedelta(seconds=10000)).isoformat(),
    )
    age = cinder._age_seconds(v)
    assert age is not None
    assert 25 <= age <= 60


def test_age_seconds_falls_back_to_created_at():
    now = datetime.now(timezone.utc)
    v = SimpleNamespace(
        updated_at=None,
        created_at=(now - timedelta(seconds=120)).isoformat(),
    )
    age = cinder._age_seconds(v)
    assert age is not None
    assert 100 <= age <= 200


def test_age_seconds_handles_trailing_z_and_missing_timestamps():
    now = datetime.now(timezone.utc)
    v_z = SimpleNamespace(
        updated_at=now.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        created_at=None,
    )
    assert cinder._age_seconds(v_z) is not None

    v_none = SimpleNamespace(updated_at=None, created_at=None)
    assert cinder._age_seconds(v_none) is None

    v_garbage = SimpleNamespace(updated_at="not a date", created_at=None)
    assert cinder._age_seconds(v_garbage) is None


def test_stuck_threshold_is_conservative():
    # Sanity-check the hard-coded threshold so a future "let's lower it"
    # change has to update this test deliberately.
    assert cinder.STUCK_AFTER_SECONDS >= 120
