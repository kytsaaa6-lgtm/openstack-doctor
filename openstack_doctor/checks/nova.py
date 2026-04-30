"""Nova (compute) checks - the most common stuck point for kubespray.

When an instance is stuck or errored we additionally pull
``server actions`` to surface *which* operation is the culprit. Nova
exposes this via ``GET /servers/{id}/os-instance-actions`` so it stays
strictly read-only.
"""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed

STUCK_STATUSES = {"BUILD", "REBUILD", "RESIZE", "MIGRATING", "REBOOT", "HARD_REBOOT"}
ERROR_STATUSES = {"ERROR"}

# Cap the number of additional ``os-instance-actions`` lookups we issue per
# run. Each ERROR/STUCK instance triggers one extra request, which can blow
# the API budget on a large failed cluster. The first N are usually enough
# to identify the root cause.
MAX_ACTION_LOOKUPS = 10


def _name_filter(servers, prefix: str | None):
    if not prefix:
        return list(servers)
    return [s for s in servers if (s.name or "").startswith(prefix)]


def _last_failed_action(conn, server_id: str) -> dict | None:
    try:
        actions = list(conn.compute.server_actions(server_id))
    except Exception:
        return None
    failed = [a for a in actions if (getattr(a, "message", None) or "").strip()]
    if not failed:
        return None
    last = failed[-1]
    return {
        "action": getattr(last, "action", None),
        "message": getattr(last, "message", None),
        "start_time": str(getattr(last, "start_time", "")),
    }


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("nova", True):
        return skip_unavailable("nova", "Nova(Compute)")

    conn = handle.conn
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")
    snapshot = ctx.get("snapshot")

    with timed("nova") as result:
        if handle.inventory is not None:
            servers = handle.inventory.servers(max_items)
        else:
            servers = bounded_list(conn.compute.servers(details=True), max_items)
        target = _name_filter(servers, name_prefix)
        action_lookups = 0

        if snapshot:
            snapshot.save(
                "nova_servers",
                [
                    {
                        "id": s.id,
                        "name": s.name,
                        "status": s.status,
                        "task_state": s.task_state,
                        "vm_state": getattr(s, "vm_state", None),
                        "host": getattr(s, "compute_host", None),
                        "image": getattr(s, "image", None),
                        "flavor": getattr(s, "flavor", None),
                        "fault": getattr(s, "fault", None),
                    }
                    for s in target
                ],
            )

        result.findings.append(
            Finding(
                check="nova",
                severity=Severity.INFO,
                title="인스턴스 수집",
                detail=(
                    f"전체 {len(servers)}개"
                    + (f" / prefix='{name_prefix}' 매칭 {len(target)}개" if name_prefix else "")
                ),
            )
        )

        for s in target:
            status = (s.status or "").upper()
            evidence = {
                "status": status,
                "task_state": s.task_state,
                "vm_state": getattr(s, "vm_state", None),
            }
            if status in ERROR_STATUSES:
                fault = (getattr(s, "fault", None) or {}).get("message")
                last_action = None
                if action_lookups < MAX_ACTION_LOOKUPS:
                    last_action = _last_failed_action(conn, s.id)
                    action_lookups += 1
                if last_action:
                    evidence["last_failed_action"] = last_action
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.CRITICAL,
                        title=f"인스턴스 ERROR: {s.name}",
                        detail=fault or "fault 메시지 없음",
                        resource=s.id,
                        suggestion=(
                            "위 last_failed_action 의 message 가 결정적 단서입니다. "
                            "보통 No valid host / image download / port binding / "
                            "block_device_mapping 중 하나입니다."
                        ),
                        evidence=evidence,
                    )
                )
            elif status in STUCK_STATUSES and s.task_state:
                if action_lookups < MAX_ACTION_LOOKUPS:
                    evidence["last_failed_action"] = _last_failed_action(conn, s.id)
                    action_lookups += 1
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.WARN,
                        title=f"인스턴스 진행중 고착 의심: {s.name}",
                        detail=f"status={status}, task_state={s.task_state}",
                        resource=s.id,
                        evidence=evidence,
                        suggestion=(
                            "task_state 가 networking/spawning/scheduling 인지에 따라 "
                            "Neutron / Glance / Nova-scheduler 를 차례로 의심하세요."
                        ),
                    )
                )

        try:
            hypervisors = bounded_list(conn.compute.hypervisors(details=True), max_items)
        except Exception:
            hypervisors = []

        free_vcpus_total = 0
        free_ram_mb_total = 0
        for h in hypervisors:
            state = getattr(h, "state", None)
            status = getattr(h, "status", None)
            if state and state != "up":
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.ERROR,
                        title=f"하이퍼바이저 다운: {h.name}",
                        detail=f"state={state}, status={status}",
                        resource=h.id,
                        suggestion="해당 컴퓨트 노드의 nova-compute 서비스와 메시지 큐 연결을 확인하세요.",
                    )
                )
            else:
                free_vcpus_total += (getattr(h, "vcpus", 0) or 0) - (getattr(h, "vcpus_used", 0) or 0)
                free_ram_mb_total += getattr(h, "free_ram_mb", 0) or 0

        required_vcpus = ctx.get("required_vcpus")
        required_ram_mb = ctx.get("required_ram_mb")
        if hypervisors:
            result.findings.append(
                Finding(
                    check="nova",
                    severity=Severity.INFO,
                    title="하이퍼바이저 가용 자원",
                    detail=f"여유 vCPU {free_vcpus_total}개 / 여유 RAM {free_ram_mb_total}MB (활성 하이퍼바이저 합산)",
                )
            )
            if required_vcpus is not None and free_vcpus_total < int(required_vcpus):
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.ERROR,
                        title="하이퍼바이저 vCPU 부족",
                        detail=f"여유 {free_vcpus_total}개 < 요구 {required_vcpus}개",
                        suggestion=(
                            "컴퓨트 노드 추가 또는 프로젝트 쿼터 증설이 필요합니다. "
                            "또는 CPU overcommit 비율(cpu_allocation_ratio)을 확인하세요."
                        ),
                    )
                )
            if required_ram_mb is not None and free_ram_mb_total < int(required_ram_mb):
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.ERROR,
                        title="하이퍼바이저 RAM 부족",
                        detail=f"여유 {free_ram_mb_total}MB < 요구 {required_ram_mb}MB",
                        suggestion=(
                            "컴퓨트 노드 추가 또는 프로젝트 쿼터 증설이 필요합니다. "
                            "또는 RAM overcommit 비율(ram_allocation_ratio)을 확인하세요."
                        ),
                    )
                )

        try:
            services = bounded_list(conn.compute.services(), max_items)
        except Exception:
            services = []
        for svc in services:
            if getattr(svc, "state", "up") != "up":
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.ERROR,
                        title=f"Nova 서비스 down: {svc.binary}@{svc.host}",
                        detail=f"state={svc.state}, status={svc.status}",
                        suggestion=(
                            f"{svc.host} 에서 `systemctl status {svc.binary}` / "
                            f"`journalctl -u {svc.binary} -n 200` 확인."
                        ),
                    )
                )

        # AZ 가용성 체크
        availability_zone = ctx.get("availability_zone")
        try:
            azs = bounded_list(conn.compute.availability_zones(), max_items)
        except Exception:
            azs = []
        if azs:
            available_az_names = {
                az.name for az in azs if getattr(az, "state", {}).get("available", True)
            }
            unavailable_azs = [
                az for az in azs if not getattr(az, "state", {}).get("available", True)
            ]
            for az in unavailable_azs:
                result.findings.append(
                    Finding(
                        check="nova",
                        severity=Severity.ERROR,
                        title=f"AZ 사용 불가: {az.name}",
                        detail="available=False",
                        suggestion=(
                            "해당 AZ 에 속한 nova-compute 서비스 상태와 "
                            "nova-conductor 로그를 확인하세요."
                        ),
                    )
                )
            if availability_zone:
                if availability_zone not in available_az_names:
                    all_az_names = {az.name for az in azs}
                    sev = Severity.ERROR if availability_zone not in all_az_names else Severity.CRITICAL
                    result.findings.append(
                        Finding(
                            check="nova",
                            severity=sev,
                            title=f"지정 AZ 없음 또는 사용 불가: {availability_zone}",
                            detail=f"가용 AZ 목록: {sorted(available_az_names)}",
                            suggestion=(
                                f"config 의 availability_zone='{availability_zone}' 이 "
                                "실제 클라우드에 존재하고 available=True 인지 확인하세요."
                            ),
                        )
                    )
                else:
                    result.findings.append(
                        Finding(
                            check="nova",
                            severity=Severity.INFO,
                            title=f"지정 AZ 정상 확인: {availability_zone}",
                            detail="available=True",
                        )
                    )
    return result
