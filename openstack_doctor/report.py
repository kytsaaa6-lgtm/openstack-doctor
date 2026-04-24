"""Render diagnosis reports as Markdown / JSON / Rich console output."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import DiagnosisReport, Severity
from .safety import redact_dict, redact_ipv4

SEVERITY_STYLE = {
    Severity.OK: "green",
    Severity.INFO: "cyan",
    Severity.WARN: "yellow",
    Severity.ERROR: "red",
    Severity.CRITICAL: "bold red",
}

SEVERITY_EMOJI = {
    Severity.OK: "[OK]",
    Severity.INFO: "[INFO]",
    Severity.WARN: "[WARN]",
    Severity.ERROR: "[ERROR]",
    Severity.CRITICAL: "[CRITICAL]",
}


def to_console(
    report: DiagnosisReport,
    console: Console | None = None,
    redact_ips: bool = False,
) -> None:
    console = console or Console()

    header = (
        f"cloud=[bold]{report.cloud}[/bold]  "
        f"worst=[{SEVERITY_STYLE[report.worst_severity]}]{report.worst_severity.value}[/]  "
        f"checks={len(report.results)}"
    )
    console.print(Panel.fit(header, title="OpenStack Doctor 리포트"))

    table = Table(title="요약", show_lines=False)
    table.add_column("Check")
    table.add_column("Worst")
    table.add_column("# Findings")
    table.add_column("Time")
    for r in report.results:
        sev = r.worst_severity
        table.add_row(
            r.name,
            f"[{SEVERITY_STYLE[sev]}]{sev.value}[/]",
            str(len(r.findings)),
            f"{r.duration_ms} ms",
        )
    console.print(table)

    def _maybe(s: str) -> str:
        return redact_ipv4(s) if (redact_ips and s) else s

    for r in report.results:
        if not r.findings and not r.error:
            continue
        console.print(f"\n[bold]== {r.name} ==[/bold]")
        if r.error:
            console.print(f"[red]error:[/red] {_maybe(r.error)}")
        for f in r.findings:
            sev_tag = f"[{SEVERITY_STYLE[f.severity]}]{SEVERITY_EMOJI[f.severity]}[/]"
            console.print(f"{sev_tag} [bold]{f.title}[/bold]")
            if f.resource:
                console.print(f"   resource: {_maybe(f.resource)}")
            if f.detail:
                for line in _maybe(f.detail).splitlines()[:30]:
                    console.print(f"   {line}")
            if f.suggestion:
                console.print(f"   [cyan]힌트:[/cyan] {f.suggestion}")


def _maybe_redact(payload: dict, redact_ips: bool) -> dict:
    return redact_dict(payload, redact_ips=redact_ips)


def to_json(report: DiagnosisReport, path: Path, redact_ips: bool = False) -> None:
    payload = _maybe_redact(report.to_dict(), redact_ips)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _fence(text: str, lang: str = "") -> list[str]:
    """Wrap ``text`` in a markdown code fence that won't be broken by inner ```.

    Picks a fence longer than any backtick run found in ``text`` so logs
    that legitimately contain triple-backticks (journalctl output, etc.)
    can never escape the block.
    """
    longest = 0
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{lang}", text, fence]


def to_markdown(report: DiagnosisReport, path: Path, redact_ips: bool = False) -> None:
    lines: list[str] = []
    lines.append(f"# OpenStack Doctor Report - `{report.cloud}`")
    lines.append("")
    lines.append(f"- worst severity: **{report.worst_severity.value}**")
    lines.append(f"- started: {report.started_at.isoformat()}")
    if report.finished_at:
        lines.append(f"- finished: {report.finished_at.isoformat()}")
    if report.context:
        lines.append("- context:")
        for k, v in report.context.items():
            # dict/list values do not render well inside an inline-backtick
            # span (and may contain backticks themselves). Render them as a
            # nested fenced JSON block instead.
            if isinstance(v, (dict, list)):
                lines.append(f"  - `{k}`:")
                lines.extend(
                    "    " + ln
                    for ln in _fence(json.dumps(v, indent=2, ensure_ascii=False, default=str), "json")
                )
            else:
                lines.append(f"  - `{k}`: `{v}`")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Check | Worst | Findings | Time |")
    lines.append("|---|---|---|---|")
    for r in report.results:
        lines.append(
            f"| {r.name} | {r.worst_severity.value} | {len(r.findings)} | {r.duration_ms} ms |"
        )
    lines.append("")

    for r in report.results:
        lines.append(f"## {r.name}")
        if r.error:
            err = redact_ipv4(r.error) if redact_ips else r.error
            lines.append(f"> ERROR: `{err}`")
        if not r.findings:
            lines.append("- (no findings)")
            lines.append("")
            continue
        for f in r.findings:
            lines.append(f"### {SEVERITY_EMOJI[f.severity]} {f.title}")
            if f.resource:
                lines.append(f"- resource: `{f.resource}`")
            detail = f.detail
            if redact_ips and detail:
                detail = redact_ipv4(detail)
            if detail:
                lines.append("")
                lines.extend(_fence(detail))
            if f.suggestion:
                lines.append(f"- 힌트: {f.suggestion}")
            if f.evidence:
                ev = redact_dict(f.evidence, redact_ips=redact_ips)
                lines.append("- evidence:")
                lines.extend(
                    _fence(json.dumps(ev, indent=2, ensure_ascii=False, default=str), "json")
                )
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
