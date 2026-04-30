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

        # Octavia LB/Listener/Pool/Member 쿼터 체크
        if handle.services.get("octavia", True):
            try:
                oq = conn.load_balancer.get_quota(project_id)
            except Exception as exc:
                oq = None
                result.findings.append(
                    Finding(
                        check="quota",
                        severity=Severity.INFO,
                        title="Octavia 쿼터 조회 실패",
                        detail=str(exc),
                        suggestion="admin 권한이 없거나 Octavia 가 미설치 상태일 수 있습니다.",
                    )
                )

            if oq is not None:
                # Octavia quota 객체: load_balancer, listener, pool, member, healthmonitor
                octavia_keys = {
                    "load_balancer": "load_balancer",
                    "listener": "listener",
                    "pool": "pool",
                    "member": "member",
                    "health_monitor": "health_monitor",
                }
                for attr_name, display_name in octavia_keys.items():
                    limit = getattr(oq, attr_name, None)
                    # -1 means unlimited
                    if limit is None or limit == -1:
                        continue
                    # Octavia quota API does not return "used" in the same payload.
                    # We estimate used from the inventory when available.
                    used: int | None = None
                    if attr_name == "load_balancer" and handle.inventory is not None:
                        try:
                            lbs = handle.inventory.load_balancers(ctx.get("max_items"))
                            used = len(lbs)
                        except Exception:
                            pass

                    r = _ratio(used, limit) if used is not None else None
                    if r is not None and r >= threshold:
                        sev = Severity.ERROR if r >= 1.0 else Severity.WARN
                        result.findings.append(
                            Finding(
                                check="quota",
                                severity=sev,
                                title=f"Octavia {display_name} 쿼터 임박/초과",
                                detail=f"{used}/{limit} ({r*100:.0f}%)",
                                suggestion=(
                                    "Octavia LB 쿼터를 증설하거나 미사용 리소스를 정리하세요. "
                                    "`openstack loadbalancer quota show` 로 현황 확인."
                                ),
                            )
                        )
                    elif limit == 0:
                        result.findings.append(
                            Finding(
                                check="quota",
                                severity=Severity.ERROR,
                                title=f"Octavia {display_name} 쿼터 0 (생성 불가)",
                                detail=f"quota={limit}",
                                suggestion=(
                                    f"`openstack loadbalancer quota set --{display_name.replace('_', '-')} N "
                                    f"<project_id>` 로 쿼터를 할당하세요."
                                ),
                            )
                        )
    return result
