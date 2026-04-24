"""Scenario diagnostics for an OpenStack-hosted Kubernetes cluster.

Note: kubespray itself runs as a Kubernetes Job, so its Ansible output
is not visible from outside. This module only joins evidence that is
*visible from the OpenStack side* and that experience says correlates
strongly with stuck cluster provisioning:

* fewer cluster instances than expected (Terraform/Heat phase failed),
* instances with no addresses (Neutron port/DHCP failure),
* k8s API LB has no listener on the expected port (Octavia phase
  incomplete),
* expected SG name not present.

Disable entirely with ``--skip-readiness`` if you only want raw service
checks.
"""

from __future__ import annotations

from .auth import CloudHandle
from .checks._util import timed
from .models import CheckResult, Finding, Severity
from .safety import bounded_list


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    name_prefix = ctx.get("name_prefix")
    expected_count = ctx.get("expected_node_count")
    api_port = int(ctx.get("api_port", 6443))
    max_items = ctx.get("max_items")

    with timed("cluster_readiness") as result:
        if not name_prefix and not expected_count:
            result.findings.append(
                Finding(
                    check="cluster_readiness",
                    severity=Severity.INFO,
                    title="cluster_readiness 점검 생략",
                    detail="--name-prefix 또는 --expected-nodes 가 없으면 의미가 없어 건너뜁니다.",
                )
            )
            return result

        if not handle.services.get("nova", True):
            result.findings.append(
                Finding(
                    check="cluster_readiness",
                    severity=Severity.INFO,
                    title="Nova 미설치 - cluster_readiness 점검 불가",
                )
            )
            return result

        if handle.inventory is not None:
            servers = handle.inventory.servers(max_items)
        else:
            servers = bounded_list(handle.conn.compute.servers(details=True), max_items)
        if name_prefix:
            servers = [s for s in servers if (s.name or "").startswith(name_prefix)]

        if expected_count is not None and len(servers) < int(expected_count):
            result.findings.append(
                Finding(
                    check="cluster_readiness",
                    severity=Severity.ERROR,
                    title="기대 노드 수 미달",
                    detail=f"expected={expected_count}, found={len(servers)}",
                    suggestion=(
                        "Terraform/Heat 단계에서 인스턴스 생성이 멈췄을 가능성이 높습니다. "
                        "Nova 와 quota 점검 결과를 우선 확인하세요."
                    ),
                )
            )

        for s in [s for s in servers if not s.addresses]:
            result.findings.append(
                Finding(
                    check="cluster_readiness",
                    severity=Severity.ERROR,
                    title=f"인스턴스에 IP 없음: {s.name}",
                    resource=s.id,
                    suggestion="Neutron 포트 생성 / DHCP 단계 실패 가능성. 보안그룹·서브넷·DHCP 에이전트를 확인하세요.",
                )
            )

        if handle.services.get("octavia", False):
            if handle.inventory is not None:
                lbs = handle.inventory.load_balancers(max_items)
            else:
                try:
                    lbs = bounded_list(handle.conn.load_balancer.load_balancers(), max_items)
                except Exception:
                    lbs = []
            # If we have a name_prefix, trust it: LBs from other clusters
            # that happen to have "api"/"k8s" in their name should NOT be
            # mistaken for ours. Only fall back to the heuristic when no
            # prefix is provided at all.
            if name_prefix:
                api_lbs = [lb for lb in lbs if (lb.name or "").startswith(name_prefix)]
            else:
                api_lbs = [
                    lb for lb in lbs
                    if "api" in (lb.name or "").lower()
                    or "k8s" in (lb.name or "").lower()
                ]
            for lb in api_lbs:
                try:
                    listeners = bounded_list(
                        handle.conn.load_balancer.listeners(loadbalancer_id=lb.id),
                        max_items,
                    )
                except Exception:
                    listeners = []
                ports = {ln.protocol_port for ln in listeners}
                if api_port not in ports:
                    result.findings.append(
                        Finding(
                            check="cluster_readiness",
                            severity=Severity.WARN,
                            title=f"k8s API 포트 리스너 없음 의심: {lb.name}",
                            detail=f"리스너 포트들: {sorted(ports)}",
                            resource=lb.id,
                            suggestion=(
                                f"kubespray 가 k8s API LB 를 만들었는지 ({api_port}/TCP), "
                                "또는 kube_apiserver_loadbalancer 설정을 확인하세요."
                            ),
                        )
                    )

        if handle.services.get("neutron", True) and name_prefix:
            if handle.inventory is not None:
                sgs = handle.inventory.security_groups(max_items)
            else:
                try:
                    sgs = bounded_list(handle.conn.network.security_groups(), max_items)
                except Exception:
                    sgs = []
            sg_for_cluster = [g for g in sgs if name_prefix in (g.name or "")]
            if not sg_for_cluster:
                result.findings.append(
                    Finding(
                        check="cluster_readiness",
                        severity=Severity.INFO,
                        title="클러스터 전용 보안그룹을 찾지 못함",
                        detail=f"prefix='{name_prefix}' 매칭되는 보안그룹 없음.",
                        suggestion="기본 SG 만 사용하는 환경이면 정상. security_groups 체크 결과를 참고하세요.",
                    )
                )

    return result
