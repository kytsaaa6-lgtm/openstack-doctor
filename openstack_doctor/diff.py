"""Compare two diagnosis reports to answer "언제부터 망가졌나".

Loads two JSON reports previously produced by :func:`report.to_json` and
computes the delta between them: per-check severity transitions plus the set
of findings that were added, resolved, or changed severity.

This module performs **no** OpenStack calls. It only reads local JSON files,
so it is always safe to run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import SEVERITY_ORDER, Severity
from .safety import redact_ipv4

_SEV_BY_STR = {s.value: s for s in Severity}


def _sev(value: str | None) -> Severity:
    return _SEV_BY_STR.get((value or "ok").lower(), Severity.OK)


def load_report(path: Path) -> dict[str, Any]:
    """Load a report JSON file produced by ``openstack-doctor diagnose --json``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "results" not in data:
        raise ValueError(
            f"{path} 는 openstack-doctor JSON 리포트가 아닙니다 "
            "(--json 으로 저장된 파일을 지정하세요)."
        )
    return data


def _finding_key(f: dict) -> tuple[str, str, str | None]:
    """Stable identity for a finding across two runs.

    Severity is intentionally excluded so that the *same* finding whose
    severity moved (e.g. warn -> critical) is matched and reported as
    ``changed`` rather than as a resolved+added pair.
    """
    return (f.get("check") or "", f.get("title") or "", f.get("resource"))


@dataclass
class FindingDelta:
    status: str  # added | resolved | changed
    check: str
    title: str
    resource: str | None
    old_severity: Severity | None
    new_severity: Severity | None

    @property
    def worsened(self) -> bool:
        o = SEVERITY_ORDER[self.old_severity] if self.old_severity else -1
        n = SEVERITY_ORDER[self.new_severity] if self.new_severity else -1
        return n > o

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "check": self.check,
            "title": self.title,
            "resource": self.resource,
            "old_severity": self.old_severity.value if self.old_severity else None,
            "new_severity": self.new_severity.value if self.new_severity else None,
            "worsened": self.worsened,
        }


@dataclass
class CheckDelta:
    name: str
    old_severity: Severity | None  # None => check absent in baseline
    new_severity: Severity | None  # None => check absent in current
    added: int = 0
    resolved: int = 0
    changed: int = 0
    unchanged: int = 0

    @property
    def direction(self) -> str:
        """One of: regressed | improved | same | appeared | disappeared."""
        if self.old_severity is None and self.new_severity is not None:
            return "appeared"
        if self.new_severity is None and self.old_severity is not None:
            return "disappeared"
        if self.old_severity is None or self.new_severity is None:
            return "same"
        o = SEVERITY_ORDER[self.old_severity]
        n = SEVERITY_ORDER[self.new_severity]
        if n > o:
            return "regressed"
        if n < o:
            return "improved"
        return "same"

    @property
    def has_changes(self) -> bool:
        return (
            self.added > 0
            or self.resolved > 0
            or self.changed > 0
            or self.direction not in ("same",)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "old_severity": self.old_severity.value if self.old_severity else None,
            "new_severity": self.new_severity.value if self.new_severity else None,
            "direction": self.direction,
            "added": self.added,
            "resolved": self.resolved,
            "changed": self.changed,
            "unchanged": self.unchanged,
        }


@dataclass
class ReportDiff:
    old_label: str
    new_label: str
    old_time: str | None
    new_time: str | None
    old_worst: Severity
    new_worst: Severity
    checks: list[CheckDelta] = field(default_factory=list)
    findings: list[FindingDelta] = field(default_factory=list)

    @property
    def overall_direction(self) -> str:
        o = SEVERITY_ORDER[self.old_worst]
        n = SEVERITY_ORDER[self.new_worst]
        if n > o:
            return "regressed"
        if n < o:
            return "improved"
        return "same"

    def has_regression(self, threshold: Severity) -> bool:
        """True if anything newly broke at or above ``threshold``.

        Used for CI gating (``--fail-on-regression``). A regression is an
        *added* finding at/above the threshold, or an existing finding whose
        severity *worsened* to at/above the threshold.
        """
        th = SEVERITY_ORDER[threshold]
        for fd in self.findings:
            if fd.new_severity is None:
                continue
            n = SEVERITY_ORDER[fd.new_severity]
            if n < th:
                continue
            if fd.status == "added":
                return True
            if fd.status == "changed" and fd.worsened:
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "old": {
                "label": self.old_label,
                "time": self.old_time,
                "worst_severity": self.old_worst.value,
            },
            "new": {
                "label": self.new_label,
                "time": self.new_time,
                "worst_severity": self.new_worst.value,
            },
            "overall_direction": self.overall_direction,
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings],
        }


def diff_reports(old: dict[str, Any], new: dict[str, Any]) -> ReportDiff:
    """Compute the delta from ``old`` (baseline) to ``new`` (current)."""
    old_results = {r.get("name", ""): r for r in old.get("results", [])}
    new_results = {r.get("name", ""): r for r in new.get("results", [])}
    # Preserve order: baseline order first, then any new-only checks.
    names = list(dict.fromkeys([*old_results, *new_results]))

    checks: list[CheckDelta] = []
    findings: list[FindingDelta] = []

    for name in names:
        o = old_results.get(name)
        n = new_results.get(name)
        o_find = {_finding_key(f): f for f in (o or {}).get("findings", [])}
        n_find = {_finding_key(f): f for f in (n or {}).get("findings", [])}

        delta = CheckDelta(
            name=name,
            old_severity=_sev(o.get("worst_severity")) if o else None,
            new_severity=_sev(n.get("worst_severity")) if n else None,
        )

        for key in dict.fromkeys([*o_find, *n_find]):
            of = o_find.get(key)
            nf = n_find.get(key)
            check, title, resource = key
            if of and nf:
                os_, ns_ = _sev(of.get("severity")), _sev(nf.get("severity"))
                if os_ != ns_:
                    delta.changed += 1
                    findings.append(
                        FindingDelta("changed", check, title, resource, os_, ns_)
                    )
                else:
                    delta.unchanged += 1
            elif nf:
                delta.added += 1
                findings.append(
                    FindingDelta("added", check, title, resource, None, _sev(nf.get("severity")))
                )
            elif of:
                delta.resolved += 1
                findings.append(
                    FindingDelta("resolved", check, title, resource, _sev(of.get("severity")), None)
                )

        checks.append(delta)

    return ReportDiff(
        old_label=str(old.get("cloud", "baseline")),
        new_label=str(new.get("cloud", "current")),
        old_time=old.get("finished_at") or old.get("started_at"),
        new_time=new.get("finished_at") or new.get("started_at"),
        old_worst=_sev(old.get("worst_severity")),
        new_worst=_sev(new.get("worst_severity")),
        checks=checks,
        findings=findings,
    )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_DIRECTION_TAG = {
    "regressed": "[REGRESSED]",
    "improved": "[IMPROVED]",
    "same": "[=]",
    "appeared": "[NEW CHECK]",
    "disappeared": "[GONE]",
}

_DIRECTION_STYLE = {
    "regressed": "bold red",
    "improved": "green",
    "same": "dim",
    "appeared": "yellow",
    "disappeared": "cyan",
}

_STATUS_TAG = {
    "added": "[+ NEW]",
    "resolved": "[- FIXED]",
    "changed": "[~ CHANGED]",
}

_SEV_STYLE = {
    Severity.OK: "green",
    Severity.INFO: "cyan",
    Severity.WARN: "yellow",
    Severity.ERROR: "red",
    Severity.CRITICAL: "bold red",
}


def _sev_label(s: Severity | None) -> str:
    return s.value if s else "-"


def _sev_style(s: Severity | None) -> str:
    if s is None:
        return "dim"
    return _SEV_STYLE[s]


def _order(s: Severity | None) -> int:
    return SEVERITY_ORDER[s] if s else -1


def _sorted_findings(findings: list[FindingDelta]) -> list[FindingDelta]:
    """Most alarming first: added > changed > resolved, then by severity."""
    status_rank = {"added": 0, "changed": 1, "resolved": 2}

    def sev_for_sort(f: FindingDelta) -> int:
        ref = f.new_severity or f.old_severity
        return -_order(ref)

    return sorted(
        findings,
        key=lambda f: (status_rank.get(f.status, 9), sev_for_sort(f), f.check, f.title),
    )


def to_console(diff: ReportDiff, console: Any = None, redact_ips: bool = False) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = console or Console()

    def _r(s: str | None) -> str:
        if not s:
            return ""
        return redact_ipv4(s) if redact_ips else s

    direction = diff.overall_direction
    style = _DIRECTION_STYLE[direction]
    header = (
        f"[{style}]{_DIRECTION_TAG[direction]}[/]  "
        f"baseline=[bold]{diff.old_worst.value}[/]  ->  current=[bold]{diff.new_worst.value}[/]\n"
        f"{diff.old_label}  ({diff.old_time})\n{diff.new_label}  ({diff.new_time})"
    )
    console.print(Panel.fit(header, title="OpenStack Doctor Diff"))

    changed_checks = [c for c in diff.checks if c.has_changes]
    if changed_checks:
        table = Table(title="변경된 체크")
        table.add_column("Check")
        table.add_column("Baseline")
        table.add_column("Current")
        table.add_column("Δ")
        table.add_column("+")
        table.add_column("-")
        table.add_column("~")
        for c in changed_checks:
            table.add_row(
                c.name,
                _sev_label(c.old_severity),
                _sev_label(c.new_severity),
                f"[{_DIRECTION_STYLE[c.direction]}]{c.direction}[/]",
                str(c.added),
                str(c.resolved),
                str(c.changed),
            )
        console.print(table)
    else:
        console.print("[green]변경된 체크 없음 - 두 리포트가 동일합니다.[/green]")

    for fd in _sorted_findings(diff.findings):
        tag = _STATUS_TAG[fd.status]
        if fd.status == "changed":
            trans = (
                f"[{_sev_style(fd.old_severity)}]{_sev_label(fd.old_severity)}[/]"
                f" -> [{_sev_style(fd.new_severity)}]{_sev_label(fd.new_severity)}[/]"
            )
        elif fd.status == "added":
            trans = f"[{_sev_style(fd.new_severity)}]{_sev_label(fd.new_severity)}[/]"
        else:
            trans = f"was [{_sev_style(fd.old_severity)}]{_sev_label(fd.old_severity)}[/]"
        res = f" ({_r(fd.resource)})" if fd.resource else ""
        console.print(f"{tag} {trans}  [bold]{fd.check}[/bold] / {_r(fd.title)}{res}")


def to_markdown(diff: ReportDiff, path: Path, redact_ips: bool = False) -> None:
    def _r(s: str | None) -> str:
        if not s:
            return ""
        return redact_ipv4(s) if redact_ips else s

    lines: list[str] = []
    lines.append(f"# OpenStack Doctor Diff - `{diff.old_label}` -> `{diff.new_label}`")
    lines.append("")
    lines.append(f"- overall: **{diff.overall_direction.upper()}**")
    lines.append(f"- baseline: `{diff.old_worst.value}`  ({diff.old_time})")
    lines.append(f"- current: `{diff.new_worst.value}`  ({diff.new_time})")
    lines.append("")

    changed_checks = [c for c in diff.checks if c.has_changes]
    lines.append("## Severity transitions")
    lines.append("")
    if changed_checks:
        lines.append("| Check | Baseline | Current | Δ | +new | -fixed | ~changed |")
        lines.append("|---|---|---|---|---|---|---|")
        for c in changed_checks:
            lines.append(
                f"| {c.name} | {_sev_label(c.old_severity)} | {_sev_label(c.new_severity)} "
                f"| {c.direction} | {c.added} | {c.resolved} | {c.changed} |"
            )
    else:
        lines.append("_변경 없음 - 두 리포트가 동일합니다._")
    lines.append("")

    sections = [
        ("added", "## New problems (added)"),
        ("changed", "## Severity changed"),
        ("resolved", "## Fixed (resolved)"),
    ]
    by_status: dict[str, list[FindingDelta]] = {"added": [], "changed": [], "resolved": []}
    for fd in _sorted_findings(diff.findings):
        by_status[fd.status].append(fd)

    for status, heading in sections:
        items = by_status[status]
        if not items:
            continue
        lines.append(heading)
        lines.append("")
        for fd in items:
            res = f" (`{_r(fd.resource)}`)" if fd.resource else ""
            if status == "changed":
                trans = f"{_sev_label(fd.old_severity)} -> {_sev_label(fd.new_severity)}"
            elif status == "added":
                trans = _sev_label(fd.new_severity)
            else:
                trans = f"was {_sev_label(fd.old_severity)}"
            lines.append(f"- **[{trans}]** `{fd.check}` / {_r(fd.title)}{res}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def to_json(diff: ReportDiff, path: Path) -> None:
    path.write_text(
        json.dumps(diff.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
