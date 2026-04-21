"""Quota / capacity checks - very common silent failure for kubespray."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ._util import timed


def _ratio(used: int | None, limit: int | None) -> float | None:
    if used is None or limit is None or limit <= 0:
        return None
    return used / limit


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    threshold = float(ctx.get("quota_warn_ratio", 0.85))
    conn = handle.conn

    with timed("quota") as result:
        project_id = conn.current_project.id if conn.current_project else None
        if not project_id:
            result.findings.append(
                Finding(
                    check="quota",
                    severity=Severity.WARN,
                    title="현재 프로젝트를 알 수 없어 쿼터 점검 생략",
                )
            )
            return result

        if handle.services.get("nova", True):
            try:
                cq = conn.compute.get_quota_set(project_id, usage=True)
            except Exception as exc:
                cq = None
                result.findings.append(
                    Finding(
                        check="quota",
                        severity=Severity.INFO,
                        title="Compute 쿼터 조회 실패",
                        detail=str(exc),
                    )
                )

            if cq is not None:
                for key in ("instances", "cores", "ram"):
                    used = (cq.usage or {}).get(key) if hasattr(cq, "usage") else None
                    limit = getattr(cq, key, None)
                    r = _ratio(used, limit)
                    if r is not None and r >= threshold:
                        sev = Severity.ERROR if r >= 1.0 else Severity.WARN
                        result.findings.append(
                            Finding(
                                check="quota",
                                severity=sev,
                                title=f"Compute {key} 쿼터 임박/초과",
                                detail=f"{used}/{limit} ({r*100:.0f}%)",
                                suggestion="kubespray 가 새 노드 생성에 실패할 수 있습니다. 쿼터 증설을 검토하세요.",
                            )
                        )

        if handle.services.get("neutron", True):
            try:
                nq = conn.network.get_quota(project_id, details=True)
            except Exception:
                nq = None
            if nq is not None:
                for key in (
                    "ports",
                    "routers",
                    "networks",
                    "subnets",
                    "floatingips",
                    "security_group_rules",
                ):
                    attr = getattr(nq, key, None)
                    if isinstance(attr, dict):
                        used = attr.get("used")
                        limit = attr.get("limit")
                        r = _ratio(used, limit)
                        if r is not None and r >= threshold:
                            sev = Severity.ERROR if r >= 1.0 else Severity.WARN
                            result.findings.append(
                                Finding(
                                    check="quota",
                                    severity=sev,
                                    title=f"Network {key} 쿼터 임박/초과",
                                    detail=f"{used}/{limit} ({r*100:.0f}%)",
                                )
                            )
    return result
