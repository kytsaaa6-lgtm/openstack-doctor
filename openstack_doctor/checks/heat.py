"""Heat (orchestration) checks - relevant only when the installer uses Heat."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed

FAILED = {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED", "ROLLBACK_FAILED"}
INPROG = {"CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "DELETE_IN_PROGRESS"}


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("heat", True):
        return skip_unavailable("heat", "Heat(Orchestration)")

    conn = handle.conn
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")

    with timed("heat") as result:
        try:
            stacks = bounded_list(conn.orchestration.stacks(), max_items)
        except Exception as exc:
            result.findings.append(
                Finding(
                    check="heat",
                    severity=Severity.INFO,
                    title="Heat 호출 실패 - 미설치/권한 문제 가능",
                    detail=str(exc),
                )
            )
            return result

        if name_prefix:
            stacks = [s for s in stacks if (s.name or "").startswith(name_prefix)]

        for s in stacks:
            status = (s.status or "").upper()
            if status in FAILED:
                result.findings.append(
                    Finding(
                        check="heat",
                        severity=Severity.ERROR,
                        title=f"Heat 스택 실패: {s.name}",
                        detail=f"{s.action}/{status} - {s.status_reason}",
                        resource=s.id,
                        suggestion="`openstack stack failures list <stack>` 으로 실패 리소스를 확인하세요.",
                    )
                )
            elif status in INPROG:
                result.findings.append(
                    Finding(
                        check="heat",
                        severity=Severity.WARN,
                        title=f"Heat 스택 진행중: {s.name}",
                        detail=f"{s.action}/{status}",
                        resource=s.id,
                    )
                )
    return result
