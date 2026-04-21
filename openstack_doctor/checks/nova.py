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
        servers = bounded_list(conn.compute.servers(details=True), max_items)
        target = _name_filter(servers, name_prefix)

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
                last_action = _last_failed_action(conn, s.id)
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
                evidence["last_failed_action"] = _last_failed_action(conn, s.id)
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
    return result
