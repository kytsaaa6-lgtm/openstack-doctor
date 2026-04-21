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


def to_console(report: DiagnosisReport, console: Console | None = None) -> None:
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

    for r in report.results:
        if not r.findings and not r.error:
            continue
        console.print(f"\n[bold]== {r.name} ==[/bold]")
        if r.error:
            console.print(f"[red]error:[/red] {r.error}")
        for f in r.findings:
            sev_tag = f"[{SEVERITY_STYLE[f.severity]}]{SEVERITY_EMOJI[f.severity]}[/]"
            console.print(f"{sev_tag} [bold]{f.title}[/bold]")
            if f.resource:
                console.print(f"   resource: {f.resource}")
            if f.detail:
                for line in f.detail.splitlines()[:30]:
                    console.print(f"   {line}")
            if f.suggestion:
                console.print(f"   [cyan]힌트:[/cyan] {f.suggestion}")


def _maybe_redact(payload: dict, redact_ips: bool) -> dict:
    return redact_dict(payload, redact_ips=redact_ips)


def to_json(report: DiagnosisReport, path: Path, redact_ips: bool = False) -> None:
    payload = _maybe_redact(report.to_dict(), redact_ips)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


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
            lines.append(f"> ERROR: `{r.error}`")
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
                lines.append("```")
                lines.append(detail)
                lines.append("```")
            if f.suggestion:
                lines.append(f"- 힌트: {f.suggestion}")
            if f.evidence:
                ev = redact_dict(f.evidence, redact_ips=redact_ips)
                lines.append("- evidence:")
                lines.append("```json")
                lines.append(json.dumps(ev, indent=2, ensure_ascii=False, default=str))
                lines.append("```")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
