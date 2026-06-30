"""Tests for the report diff feature (`openstack-doctor diff`)."""

from __future__ import annotations

import json
from pathlib import Path

from openstack_doctor.diff import (
    diff_reports,
    load_report,
    to_json,
    to_markdown,
)
from openstack_doctor.models import Severity


def _finding(check: str, severity: str, title: str, resource: str | None = None) -> dict:
    return {
        "check": check,
        "severity": severity,
        "title": title,
        "detail": "",
        "resource": resource,
        "suggestion": None,
        "evidence": {},
    }


def _report(cloud: str, worst: str, results: list[dict]) -> dict:
    return {
        "cloud": cloud,
        "worst_severity": worst,
        "started_at": "2026-06-30T00:00:00+00:00",
        "finished_at": "2026-06-30T00:01:00+00:00",
        "context": {},
        "results": results,
    }


def _check(name: str, worst: str, findings: list[dict]) -> dict:
    return {
        "name": name,
        "worst_severity": worst,
        "duration_ms": 1,
        "error": None,
        "findings": findings,
    }


def test_added_finding_detected():
    old = _report("c", "ok", [_check("nova", "ok", [])])
    new = _report(
        "c", "critical", [_check("nova", "critical", [_finding("nova", "critical", "vm stuck", "vm-1")])]
    )
    d = diff_reports(old, new)
    added = [f for f in d.findings if f.status == "added"]
    assert len(added) == 1
    assert added[0].new_severity == Severity.CRITICAL
    assert d.overall_direction == "regressed"


def test_resolved_finding_detected():
    old = _report(
        "c", "error", [_check("cinder", "error", [_finding("cinder", "error", "vol error", "v-1")])]
    )
    new = _report("c", "ok", [_check("cinder", "ok", [])])
    d = diff_reports(old, new)
    resolved = [f for f in d.findings if f.status == "resolved"]
    assert len(resolved) == 1
    assert resolved[0].old_severity == Severity.ERROR
    assert d.overall_direction == "improved"


def test_severity_change_matched_as_changed_not_pair():
    """Same finding (check+title+resource) with new severity => one 'changed'."""
    old = _report(
        "c", "warn", [_check("neutron", "warn", [_finding("neutron", "warn", "port down", "p-1")])]
    )
    new = _report(
        "c",
        "critical",
        [_check("neutron", "critical", [_finding("neutron", "critical", "port down", "p-1")])],
    )
    d = diff_reports(old, new)
    assert [f.status for f in d.findings] == ["changed"]
    fd = d.findings[0]
    assert fd.old_severity == Severity.WARN
    assert fd.new_severity == Severity.CRITICAL
    assert fd.worsened is True


def test_unchanged_finding_not_listed():
    same = _finding("nova", "warn", "hyp down", "h-1")
    old = _report("c", "warn", [_check("nova", "warn", [same])])
    new = _report("c", "warn", [_check("nova", "warn", [dict(same)])])
    d = diff_reports(old, new)
    assert d.findings == []
    nova = next(c for c in d.checks if c.name == "nova")
    assert nova.unchanged == 1
    assert nova.has_changes is False


def test_check_appeared_and_disappeared():
    old = _report("c", "ok", [_check("nova", "ok", [])])
    new = _report(
        "c", "warn", [_check("nova", "ok", []), _check("octavia", "warn", [_finding("octavia", "warn", "lb", "l-1")])]
    )
    d = diff_reports(old, new)
    octavia = next(c for c in d.checks if c.name == "octavia")
    assert octavia.direction == "appeared"


def test_has_regression_threshold():
    old = _report("c", "ok", [_check("nova", "ok", [])])
    new = _report(
        "c",
        "warn",
        [_check("nova", "warn", [_finding("nova", "warn", "minor", "m-1")])],
    )
    d = diff_reports(old, new)
    # A new warn-level finding is a regression at warn, but not at error.
    assert d.has_regression(Severity.WARN) is True
    assert d.has_regression(Severity.ERROR) is False


def test_has_regression_ignores_resolved():
    old = _report(
        "c", "critical", [_check("nova", "critical", [_finding("nova", "critical", "boom", "b-1")])]
    )
    new = _report("c", "ok", [_check("nova", "ok", [])])
    d = diff_reports(old, new)
    assert d.has_regression(Severity.WARN) is False


def test_load_report_rejects_non_report(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    try:
        load_report(bad)
    except ValueError as exc:
        assert "리포트가 아닙니다" in str(exc)
    else:
        raise AssertionError("expected ValueError for non-report json")


def test_roundtrip_json_then_diff(tmp_path: Path):
    old = _report("c", "ok", [_check("nova", "ok", [])])
    new = _report(
        "c", "critical", [_check("nova", "critical", [_finding("nova", "critical", "vm stuck", "vm-1")])]
    )
    op = tmp_path / "old.json"
    npth = tmp_path / "new.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    npth.write_text(json.dumps(new), encoding="utf-8")
    d = diff_reports(load_report(op), load_report(npth))
    assert d.overall_direction == "regressed"


def test_to_markdown_and_json_outputs(tmp_path: Path):
    old = _report(
        "cloud-x",
        "warn",
        [_check("neutron", "warn", [_finding("neutron", "warn", "port down", "p-1")])],
    )
    new = _report(
        "cloud-x",
        "critical",
        [
            _check(
                "neutron",
                "critical",
                [
                    _finding("neutron", "critical", "port down", "p-1"),
                    _finding("neutron", "error", "fip exhausted", "ext-net"),
                ],
            )
        ],
    )
    d = diff_reports(old, new)

    md = tmp_path / "diff.md"
    to_markdown(d, md)
    text = md.read_text(encoding="utf-8")
    assert "OpenStack Doctor Diff" in text
    assert "REGRESSED" in text
    assert "New problems (added)" in text
    assert "Severity changed" in text
    assert "warn -> critical" in text

    js = tmp_path / "diff.json"
    to_json(d, js)
    payload = json.loads(js.read_text(encoding="utf-8"))
    assert payload["overall_direction"] == "regressed"
    assert payload["new"]["worst_severity"] == "critical"
    statuses = {f["status"] for f in payload["findings"]}
    assert {"added", "changed"} <= statuses


def test_markdown_redacts_ip_in_resource(tmp_path: Path):
    old = _report("c", "ok", [_check("nodes", "ok", [])])
    new = _report(
        "c",
        "error",
        [_check("nodes", "error", [_finding("nodes", "error", "disk full", "10.0.0.7")])],
    )
    d = diff_reports(old, new)
    md = tmp_path / "diff.md"
    to_markdown(d, md, redact_ips=True)
    text = md.read_text(encoding="utf-8")
    assert "10.0.0.7" not in text
    assert "x.x.x.x" in text
