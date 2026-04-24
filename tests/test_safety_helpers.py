"""Tests for stand-alone helpers in ``openstack_doctor.safety``."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

from openstack_doctor.safety import (
    ABSOLUTE_MAX_ITEMS,
    Snapshot,
    bounded_list,
    redact_dict,
    redact_ipv4,
)


def test_bounded_list_caps_unlimited_request():
    out = bounded_list((i for i in itertools.count()), None)
    assert len(out) == ABSOLUTE_MAX_ITEMS

    out_zero = bounded_list((i for i in itertools.count()), 0)
    assert len(out_zero) == ABSOLUTE_MAX_ITEMS


def test_bounded_list_respects_explicit_max():
    assert bounded_list(iter(range(10)), 3) == [0, 1, 2]
    assert bounded_list(iter(range(2)), 100) == [0, 1]


def test_redact_ipv4_replaces_addresses():
    assert redact_ipv4("connect 10.0.0.1:6443 failed") == "connect x.x.x.x:6443 failed"
    assert redact_ipv4("no ip here") == "no ip here"


def test_redact_dict_masks_secret_keys_and_optionally_ips():
    payload = {
        "token": "abc123",
        "nested": {"password": "p", "host": "10.1.2.3"},
        "list": [{"api_key": "k"}, "10.4.5.6"],
        "ok": "value",
    }
    out = redact_dict(payload, redact_ips=True)
    assert out["token"] == "***REDACTED***"
    assert out["nested"]["password"] == "***REDACTED***"
    assert out["nested"]["host"] == "x.x.x.x"
    assert out["list"][0]["api_key"] == "***REDACTED***"
    assert out["list"][1] == "x.x.x.x"
    assert out["ok"] == "value"


def test_snapshot_records_failures_instead_of_swallowing(tmp_path: Path):
    snap = Snapshot(tmp_path)
    # A non-serialisable object triggers json.dumps (which uses default=str
    # so most things succeed). Use an object whose __str__ also raises to
    # force a failure path.
    class Boom:
        def __str__(self) -> str:
            raise RuntimeError("nope")

    snap.save("good", {"hello": "world"})
    snap.save("bad", Boom())

    assert (tmp_path / "good.json").exists()
    saved = json.loads((tmp_path / "good.json").read_text())
    assert saved == {"hello": "world"}

    assert len(snap.failures) == 1
    failed_key, failed_msg = snap.failures[0]
    assert failed_key == "bad"
    assert "RuntimeError" in failed_msg


def test_snapshot_no_root_is_noop(tmp_path: Path):
    snap = Snapshot(None)
    snap.save("x", {"y": 1})
    assert snap.failures == []
