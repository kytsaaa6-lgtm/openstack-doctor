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

        # External network 가용성 체크
        external_network_name = ctx.get("external_network")
        try:
            ext_networks = bounded_list(conn.network.networks(is_router_external=True), max_items)
        except Exception:
            ext_networks = []

        if not ext_networks:
            result.findings.append(
                Finding(
                    check="neutron",
                    severity=Severity.ERROR,
                    title="External network 없음",
                    detail="router:external=True 인 네트워크가 하나도 없습니다.",
                    suggestion=(
                        "Floating IP 할당 및 라우터 게이트웨이 설정에 필요한 "
                        "external network 가 없습니다. Neutron 관리자에게 문의하세요."
                    ),
                )
            )
        else:
            if external_network_name:
                matched = [n for n in ext_networks if n.name == external_network_name]
                if not matched:
                    result.findings.append(
                        Finding(
                            check="neutron",
                            severity=Severity.ERROR,
                            title=f"지정 External network 없음: {external_network_name}",
                            detail=f"가용 external 네트워크: {[n.name for n in ext_networks]}",
                            suggestion=(
                                f"config 의 external_network='{external_network_name}' 이 "
                                "실제 클라우드에 존재하는지 확인하세요."
                            ),
                        )
                    )
                else:
                    net = matched[0]
                    net_status = getattr(net, "status", "ACTIVE") or "ACTIVE"
                    sev = Severity.ERROR if net_status != "ACTIVE" else Severity.INFO
                    result.findings.append(
                        Finding(
                            check="neutron",
                            severity=sev,
                            title=f"External network 확인: {external_network_name}",
                            detail=f"status={net_status}",
                            resource=net.id,
                        )
                    )
            else:
                result.findings.append(
                    Finding(
                        check="neutron",
                        severity=Severity.INFO,
                        title="External network 목록",
                        detail=f"{len(ext_networks)}개 확인: {[n.name for n in ext_networks[:5]]}",
                    )
                )

        # FIP 풀 여유 체크: quota.floatingips - 현재 할당 수
        project_id = conn.current_project.id if conn.current_project else None
        if project_id:
            try:
                nq = conn.network.get_quota(project_id, details=True)
                fip_attr = getattr(nq, "floatingips", None)
                if isinstance(fip_attr, dict):
                    fip_limit = fip_attr.get("limit", -1)
                    fip_used = fip_attr.get("used", 0)
                    fip_free = fip_limit - fip_used if fip_limit >= 0 else None
                    if fip_free is not None:
                        min_fips = ctx.get("min_free_fips", 1)
                        sev = Severity.ERROR if fip_free < int(min_fips) else Severity.INFO
                        result.findings.append(
                            Finding(
                                check="neutron",
                                severity=sev,
                                title="Floating IP 풀 여유",
                                detail=f"할당 가능 {fip_free}개 (사용 {fip_used}/{fip_limit})",
                                suggestion=(
                                    "여유 FIP 가 부족합니다. 미사용 FIP 를 반납하거나 "
                                    "쿼터를 증설하세요."
                                ) if sev == Severity.ERROR else None,
                            )
                        )
            except Exception:
                pass
    return result
