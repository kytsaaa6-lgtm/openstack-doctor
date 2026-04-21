"""Neutron (network) checks."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("neutron", True):
        return skip_unavailable("neutron", "Neutron(Network)")

    conn = handle.conn
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")

    with timed("neutron") as result:
        ports = bounded_list(conn.network.ports(), max_items)
        down_ports = [p for p in ports if (p.status or "").upper() == "DOWN"]
        result.findings.append(
            Finding(
                check="neutron",
                severity=Severity.INFO,
                title="포트 수집",
                detail=f"전체 {len(ports)}개 / DOWN {len(down_ports)}개",
            )
        )

        for p in down_ports[:50]:
            device_owner = p.device_owner or ""
            if device_owner.startswith("compute:"):
                result.findings.append(
                    Finding(
                        check="neutron",
                        severity=Severity.ERROR,
                        title=f"인스턴스 포트 DOWN: {p.name or p.id[:8]}",
                        detail=f"device_owner={device_owner}, network={p.network_id}",
                        resource=p.id,
                        suggestion=(
                            "해당 컴퓨트 노드의 OVS/L2 에이전트 상태와 "
                            "포트 binding(host_id, vif_type) 을 확인하세요."
                        ),
                    )
                )

        try:
            agents = bounded_list(conn.network.agents(), max_items)
        except Exception:
            agents = []
        for a in agents:
            if not a.is_alive:
                result.findings.append(
                    Finding(
                        check="neutron",
                        severity=Severity.ERROR,
                        title=f"Neutron 에이전트 dead: {a.binary}@{a.host}",
                        resource=a.id,
                        suggestion=(
                            f"{a.host} 에서 `systemctl status {a.binary}` / "
                            f"`journalctl -u {a.binary} -n 200` 확인."
                        ),
                    )
                )

        try:
            routers = bounded_list(conn.network.routers(), max_items)
        except Exception:
            routers = []
        for r in routers:
            if name_prefix and not (r.name or "").startswith(name_prefix):
                continue
            if r.status and r.status != "ACTIVE":
                result.findings.append(
                    Finding(
                        check="neutron",
                        severity=Severity.WARN,
                        title=f"라우터 상태 비정상: {r.name}",
                        detail=f"status={r.status}",
                        resource=r.id,
                    )
                )

        try:
            fips = bounded_list(conn.network.ips(), max_items)
        except Exception:
            fips = []
        for f in fips:
            if f.status and f.status not in {"ACTIVE", "DOWN"}:
                result.findings.append(
                    Finding(
                        check="neutron",
                        severity=Severity.WARN,
                        title=f"Floating IP 상태 비정상: {f.floating_ip_address}",
                        detail=f"status={f.status}",
                        resource=f.id,
                    )
                )
    return result
