"""Octavia (load balancer) checks - critical for the kube-apiserver LB."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed

PENDING_OPS = {"PENDING_CREATE", "PENDING_UPDATE", "PENDING_DELETE"}
AMPHORA_ERROR_STATUSES = {"ERROR", "DELETED"}
AMPHORA_DEGRADED_STATUSES = {"PENDING_CREATE", "PENDING_DELETE", "BOOTING", "ALLOCATED"}

# Operating statuses that we treat as healthy enough not to warn about.
# DRAINING and NO_MONITOR are not-OFFLINE-not-ERROR signals that legitimately
# show up during normal cluster lifecycle. DEGRADED *is* a real warning so
# it's intentionally absent.
HEALTHY_MEMBER_STATUSES = {"ONLINE", "NO_MONITOR", "DRAINING"}


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("octavia", True):
        return skip_unavailable("octavia", "Octavia(Load Balancer)")

    conn = handle.conn
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")

    with timed("octavia") as result:
        # Octavia provider/worker 서비스 가용 여부 확인
        try:
            providers = bounded_list(conn.load_balancer.providers(), max_items)
        except Exception:
            providers = []
        if not providers:
            result.findings.append(
                Finding(
                    check="octavia",
                    severity=Severity.WARN,
                    title="Octavia provider 조회 실패 또는 미설정",
                    detail="load balancer provider 목록을 가져올 수 없습니다.",
                    suggestion=(
                        "octavia-api 서비스가 정상 동작하는지, "
                        "octavia-worker / octavia-housekeeping 이 살아있는지 확인하세요."
                    ),
                )
            )
        else:
            result.findings.append(
                Finding(
                    check="octavia",
                    severity=Severity.INFO,
                    title="Octavia provider 확인",
                    detail=f"등록된 provider: {[p.name for p in providers]}",
                )
            )

        # Amphora 상태 점검 (admin-only API; 권한 부족 시 graceful skip)
        try:
            amphorae = bounded_list(conn.load_balancer.amphorae(), max_items)
            error_amp = [
                a for a in amphorae
                if (getattr(a, "status", "") or "").upper() in AMPHORA_ERROR_STATUSES
            ]
            degraded_amp = [
                a for a in amphorae
                if (getattr(a, "status", "") or "").upper() in AMPHORA_DEGRADED_STATUSES
            ]
            result.findings.append(
                Finding(
                    check="octavia",
                    severity=Severity.INFO,
                    title="Amphora 수집",
                    detail=(
                        f"전체 {len(amphorae)}개 / ERROR {len(error_amp)}개 "
                        f"/ 진행중 {len(degraded_amp)}개"
                    ),
                )
            )
            for a in error_amp[:20]:
                result.findings.append(
                    Finding(
                        check="octavia",
                        severity=Severity.CRITICAL,
                        title=f"Amphora ERROR: {a.id[:8]}",
                        detail=(
                            f"status={getattr(a, 'status', '?')}, "
                            f"lb_id={getattr(a, 'loadbalancer_id', '?')}"
                        ),
                        resource=getattr(a, "compute_id", None),
                        suggestion=(
                            "해당 amphora Nova 인스턴스가 ERROR 상태인지 확인하세요. "
                            "octavia-housekeeping 이 자동 교체를 시도해야 하며, "
                            "교체가 막혀 있다면 Nova/Glance 쪽 오류를 함께 확인하세요."
                        ),
                    )
                )
            for a in degraded_amp[:10]:
                result.findings.append(
                    Finding(
                        check="octavia",
                        severity=Severity.WARN,
                        title=f"Amphora 진행중 고착 의심: {a.id[:8]}",
                        detail=(
                            f"status={getattr(a, 'status', '?')}, "
                            f"lb_id={getattr(a, 'loadbalancer_id', '?')}"
                        ),
                        suggestion=(
                            "Nova 인스턴스 상태(BUILD 고착)와 octavia-worker 로그를 확인하세요."
                        ),
                    )
                )
        except Exception as amp_exc:
            result.findings.append(
                Finding(
                    check="octavia",
                    severity=Severity.INFO,
                    title="Amphora 조회 불가 (권한 부족 가능)",
                    detail=str(amp_exc),
                    suggestion="admin 권한이 없으면 amphora 엔드포인트는 403 을 반환합니다.",
                )
            )

        if handle.inventory is not None:
            lbs = handle.inventory.load_balancers(max_items)
        else:
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
                    if (m.operating_status or "").upper() not in HEALTHY_MEMBER_STATUSES
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
