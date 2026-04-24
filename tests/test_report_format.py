"""Tests for report rendering, especially markdown escaping correctness."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from openstack_doctor.models import (
    CheckResult,
    DiagnosisReport,
    Finding,
    Severity,
)
from openstack_doctor.report import _fence, to_json, to_markdown


def test_fence_escapes_inner_triple_backtick():
    text = "before ``` middle ``` after"
    out = _fence(text)
    # The fence used must be longer than any backtick run inside text.
    fence = out[0]
    assert fence == "````"
    assert out[-1] == "````"
    assert text in out


def test_fence_default_three_backticks_when_safe():
    out = _fence("plain text", "json")
    assert out[0] == "```json"
    assert out[-1] == "```"


def _sample_report() -> DiagnosisReport:
    rep = DiagnosisReport(cloud="test")
    rep.context = {
        "tool_version": "9.9.9",
        "scalar": "value",
        "list": [1, 2, 3],
        "nested": {"k": "v"},
    }
    res = CheckResult(name="dummy")
    res.findings.append(
        Finding(
            check="dummy",
            severity=Severity.WARN,
            title="something with ``` inside",
            detail="line1\nline2 ``` ends here",
            resource="r-1",
            suggestion="check it",
            evidence={"sample": [1, 2]},
        )
    )
    rep.results.append(res)
    rep.finished_at = datetime.now(timezone.utc)
    return rep


def test_to_markdown_escapes_inner_backticks_and_renders(tmp_path: Path):
    rep = _sample_report()
    out = tmp_path / "r.md"
    to_markdown(rep, out)
    text = out.read_text(encoding="utf-8")
    assert "# OpenStack Doctor Report" in text
    # detail had ``` inside; the surrounding fence must be longer.
    assert "````" in text


def test_to_markdown_renders_dict_context_as_fenced_json(tmp_path: Path):
    rep = _sample_report()
    out = tmp_path / "r.md"
    to_markdown(rep, out)
    text = out.read_text(encoding="utf-8")
    assert "```json" in text
    assert "\"k\": \"v\"" in text


def test_to_json_redacts_when_requested(tmp_path: Path):
    rep = _sample_report()
    rep.results[0].findings.append(
        Finding(
            check="dummy",
            severity=Severity.INFO,
            title="ip leak test",
            detail="see 10.0.0.5 here",
            evidence={"password": "topsecret", "host": "10.0.0.6"},
        )
    )
    out = tmp_path / "r.json"
    to_json(rep, out, redact_ips=True)
    text = out.read_text(encoding="utf-8")
    assert "topsecret" not in text
    assert "10.0.0.5" not in text
    assert "10.0.0.6" not in text
    assert "x.x.x.x" in text
