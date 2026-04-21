"""Cinder (block storage) checks."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("cinder", True):
        return skip_unavailable("cinder", "Cinder(Block Storage)")

    conn = handle.conn
    max_items = ctx.get("max_items")

    with timed("cinder") as result:
        volumes = bounded_list(conn.block_storage.volumes(details=True), max_items)
        bad = [v for v in volumes if (v.status or "").lower() in {"error", "error_deleting", "error_extending"}]
        attaching = [v for v in volumes if (v.status or "").lower() in {"attaching", "detaching", "creating"}]

        result.findings.append(
            Finding(
                check="cinder",
                severity=Severity.INFO,
                title="볼륨 수집",
                detail=f"전체 {len(volumes)}개 / error {len(bad)}개 / 진행중 {len(attaching)}개",
            )
        )

        for v in bad:
            result.findings.append(
                Finding(
                    check="cinder",
                    severity=Severity.ERROR,
                    title=f"볼륨 ERROR: {v.name or v.id[:8]}",
                    detail=f"status={v.status}, size={v.size}GB",
                    resource=v.id,
                    suggestion="cinder-volume / cinder-scheduler 로그와 백엔드(예: Ceph) 상태를 확인하세요.",
                )
            )

        for v in attaching:
            result.findings.append(
                Finding(
                    check="cinder",
                    severity=Severity.WARN,
                    title=f"볼륨 진행중 고착 의심: {v.name or v.id[:8]}",
                    detail=f"status={v.status}",
                    resource=v.id,
                )
            )

        try:
            services = bounded_list(conn.block_storage.services(), max_items)
        except Exception:
            services = []
        for svc in services:
            if getattr(svc, "state", "up") != "up":
                result.findings.append(
                    Finding(
                        check="cinder",
                        severity=Severity.ERROR,
                        title=f"Cinder 서비스 down: {svc.binary}@{svc.host}",
                        detail=f"state={svc.state}",
                    )
                )
    return result
