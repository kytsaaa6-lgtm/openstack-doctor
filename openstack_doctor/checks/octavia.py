"""Octavia (load balancer) checks - critical for the kube-apiserver LB."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed

PENDING_OPS = {"PENDING_CREATE", "PENDING_UPDATE", "PENDING_DELETE"}


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("octavia", True):
        return skip_unavailable("octavia", "Octavia(Load Balancer)")

    conn = handle.conn
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")

    with timed("octavia") as result:
        try:
            lbs = bounded_list(conn.load_balancer.load_balancers(), max_items)
        except Exception as exc:
            result.findings.append(
                Finding(
                    check="octavia",
                    severity=Severity.INFO,
                    title="Octavia 호출 실패 - 미설치/권한 문제 가능",
                    detail=str(exc),
                )
            )
            return result

        target = (
            [lb for lb in lbs if (lb.name or "").startswith(name_prefix)]
            if name_prefix
            else lbs
        )

        result.findings.append(
            Finding(
                check="octavia",
                severity=Severity.INFO,
                title="LB 수집",
                detail=f"전체 {len(lbs)}개"
                + (f" / prefix='{name_prefix}' 매칭 {len(target)}개" if name_prefix else ""),
            )
        )

        for lb in target:
            ps = (lb.provisioning_status or "").upper()
            os_ = (lb.operating_status or "").upper()

            if ps == "ERROR":
                result.findings.append(
                    Finding(
                        check="octavia",
                        severity=Severity.CRITICAL,
                        title=f"LB ERROR: {lb.name}",
                        resource=lb.id,
                        suggestion=(
                            "octavia-worker / octavia-housekeeping 로그와 amphora "
                            "인스턴스 상태(BUILD/ERROR)를 확인하세요."
                        ),
                        evidence={"vip": lb.vip_address, "provider": lb.provider},
                    )
                )
            elif ps in PENDING_OPS:
                result.findings.append(
                    Finding(
                        check="octavia",
                        severity=Severity.WARN,
                        title=f"LB 진행중 고착 의심: {lb.name}",
                        detail=f"provisioning_status={ps}",
                        resource=lb.id,
                        suggestion=(
                            "octavia-worker 가 살아있는지, amphora 인스턴스가 BUILD "
                            "상태에서 멈춰있지 않은지(Nova 점검 결과 참고) 확인하세요."
                        ),
                    )
                )
            elif os_ and os_ != "ONLINE":
                result.findings.append(
                    Finding(
                        check="octavia",
                        severity=Severity.WARN,
                        title=f"LB operating_status 비정상: {lb.name}",
                        detail=f"operating_status={os_}",
                        resource=lb.id,
                    )
                )

            try:
                pools = bounded_list(conn.load_balancer.pools(loadbalancer_id=lb.id), max_items)
            except Exception:
                pools = []
            for pool in pools:
                try:
                    members = bounded_list(conn.load_balancer.members(pool), max_items)
                except Exception:
                    members = []
                bad_members = [
                    m for m in members
                    if (m.operating_status or "").upper() not in {"ONLINE", "NO_MONITOR"}
                ]
                if bad_members:
                    result.findings.append(
                        Finding(
                            check="octavia",
                            severity=Severity.WARN,
                            title=f"LB 멤버 비정상: {lb.name}/{pool.name}",
                            detail=f"비정상 멤버 {len(bad_members)}/{len(members)}",
                            resource=pool.id,
                            evidence={
                                "members": [
                                    {"address": m.address, "status": m.operating_status}
                                    for m in bad_members[:10]
                                ]
                            },
                            suggestion=(
                                "백엔드 포트(예: 6443) 가 보안그룹에서 amphora 측 IP/CIDR 로 "
                                "허용되는지, kube-apiserver 가 listening 인지 확인하세요."
                            ),
                        )
                    )
    return result
