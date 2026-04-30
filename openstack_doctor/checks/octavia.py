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


def _check_amphora_image(conn, tag: str, max_items) -> list[Finding]:
    """Octavia 가 amphora 인스턴스를 부팅할 때 사용하는 Glance 이미지를 확인합니다.

    Octavia 기본 설정(octavia.conf [controller_worker] amp_image_tag) 이
    'amphora' 이므로, 해당 태그로 먼저 조회합니다. 사용자가 다른 태그를 쓴다면
    ctx 의 amphora_image_tag 를 통해 오버라이드할 수 있습니다.
    """
    findings: list[Finding] = []
    try:
        images = bounded_list(conn.image.images(tag=tag), max_items)
    except Exception as exc:
        findings.append(
            Finding(
                check="octavia",
                severity=Severity.WARN,
                title=f"Amphora 이미지 조회 실패 (tag={tag})",
                detail=str(exc),
                suggestion="Glance 서비스가 정상인지, 권한이 충분한지 확인하세요.",
            )
        )
        return findings

    if not images:
        findings.append(
            Finding(
                check="octavia",
                severity=Severity.CRITICAL,
                title=f"Amphora 이미지 없음 (tag={tag})",
                detail=(
                    f"Glance 에서 tag='{tag}' 인 이미지를 찾을 수 없습니다. "
                    "신규 LB 생성 시 Octavia 가 amphora 를 부팅하지 못합니다."
                ),
                suggestion=(
                    "Octavia amphora 이미지를 Glance 에 업로드하고 "
                    f"`openstack image set --tag {tag} <image_id>` 로 태그를 붙이세요. "
                    "또는 octavia.conf 의 amp_image_tag 설정과 일치시키세요."
                ),
            )
        )
        return findings

    active = [img for img in images if (img.status or "").lower() == "active"]
    inactive = [img for img in images if (img.status or "").lower() != "active"]

    findings.append(
        Finding(
            check="octavia",
            severity=Severity.INFO,
            title=f"Amphora 이미지 확인 (tag={tag})",
            detail=(
                f"전체 {len(images)}개 / ACTIVE {len(active)}개 / 비활성 {len(inactive)}개"
            ),
            evidence={
                "images": [
                    {
                        "id": img.id,
                        "name": img.name,
                        "status": img.status,
                        "size_mb": round((img.size or 0) / 1024 / 1024, 1),
                        "updated_at": getattr(img, "updated_at", None),
                    }
                    for img in images[:5]
                ]
            },
        )
    )

    if not active:
        findings.append(
            Finding(
                check="octavia",
                severity=Severity.CRITICAL,
                title=f"Amphora 이미지 전부 비활성 (tag={tag})",
                detail=f"비활성 상태: {[img.status for img in inactive[:5]]}",
                suggestion=(
                    "`openstack image set --activate <image_id>` 로 이미지를 활성화하거나 "
                    "올바른 이미지를 재업로드하세요."
                ),
            )
        )
    elif len(active) > 1:
        # 복수 ACTIVE 이미지는 허용하지만, 어느 것을 Octavia 가 선택할지 불명확
        findings.append(
            Finding(
                check="octavia",
                severity=Severity.WARN,
                title=f"Amphora 이미지 복수 존재 (tag={tag})",
                detail=f"ACTIVE {len(active)}개 - Octavia 가 최신 이미지를 선택하지만 예상치 못한 버전이 사용될 수 있습니다.",
                suggestion=(
                    "오래된 amphora 이미지의 태그를 제거하거나 비활성화해서 "
                    "1개만 남기는 것을 권장합니다."
                ),
            )
        )

    return findings


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

        # Octavia amphora Glance 이미지 가용성 체크
        # Glance 서비스가 없으면 건너뜀
        if handle.services.get("glance", True):
            amp_image_tag = ctx.get("amphora_image_tag", "amphora")
            result.findings.extend(_check_amphora_image(conn, amp_image_tag, max_items))

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
