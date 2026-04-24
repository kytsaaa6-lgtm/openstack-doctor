"""Audit security groups for ports kubespray / k8s commonly need.

Checks the security groups *attached to current cluster instances* (or
all SGs if no name prefix is provided) and reports any of these required
ingress ports that are not allowed:

* 22/tcp        - SSH for ansible/kubespray
* 6443/tcp      - kube-apiserver
* 2379-2380/tcp - etcd peer/client
* 10250/tcp     - kubelet
* 10257/tcp     - kube-controller-manager (HTTPS)
* 10259/tcp     - kube-scheduler (HTTPS)
* 179/tcp       - Calico BGP
* 4789/udp      - Flannel/Calico VXLAN
* 8472/udp      - Flannel VXLAN (Linux default)
* 51820/udp     - Wireguard (Calico encryption)

A missing port is reported as WARN, not ERROR, because the user may use
a non-default CNI / topology.
"""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed

REQUIRED = [
    ("tcp", 22, 22, "SSH (ansible/kubespray)"),
    ("tcp", 6443, 6443, "kube-apiserver"),
    ("tcp", 2379, 2380, "etcd"),
    ("tcp", 10250, 10250, "kubelet"),
    ("tcp", 10257, 10257, "kube-controller-manager"),
    ("tcp", 10259, 10259, "kube-scheduler"),
    ("tcp", 179, 179, "Calico BGP"),
    ("udp", 4789, 4789, "Calico/Flannel VXLAN"),
    ("udp", 8472, 8472, "Flannel VXLAN"),
    ("udp", 51820, 51820, "Wireguard"),
]


def _rule_matches(rule, proto: str, port_min: int, port_max: int) -> bool:
    if rule.direction != "ingress":
        return False
    if rule.ethertype not in (None, "IPv4"):
        return False
    rp = (rule.protocol or "").lower()
    if rp and rp != proto:
        return False
    rmin = rule.port_range_min
    rmax = rule.port_range_max
    if rmin is None and rmax is None:
        return True
    if rmin is None or rmax is None:
        return False
    return rmin <= port_min and rmax >= port_max


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("neutron", True):
        return skip_unavailable("security_groups", "Neutron(Security Groups)")

    conn = handle.conn
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")
    skip_audit = bool(ctx.get("skip_sg_audit", False))

    with timed("security_groups") as result:
        if skip_audit:
            result.findings.append(
                Finding(
                    check="security_groups",
                    severity=Severity.INFO,
                    title="보안그룹 audit 가 비활성화됨 (skip_sg_audit=true)",
                )
            )
            return result

        if handle.inventory is not None:
            sgs = handle.inventory.security_groups(max_items)
        else:
            sgs = bounded_list(conn.network.security_groups(), max_items)
        if not sgs:
            result.findings.append(
                Finding(
                    check="security_groups",
                    severity=Severity.INFO,
                    title="조회 가능한 보안그룹이 없습니다",
                )
            )
            return result

        target_sgs = sgs
        if name_prefix:
            if handle.inventory is not None:
                servers = handle.inventory.servers(max_items)
            else:
                try:
                    servers = bounded_list(conn.compute.servers(details=True), max_items)
                except Exception:
                    servers = []
            cluster_servers = [s for s in servers if (s.name or "").startswith(name_prefix)]
            sg_names: set[str] = set()
            for s in cluster_servers:
                for g in (getattr(s, "security_groups", None) or []):
                    if isinstance(g, dict) and g.get("name"):
                        sg_names.add(g["name"])
                    elif hasattr(g, "name"):
                        sg_names.add(g.name)
            if sg_names:
                target_sgs = [g for g in sgs if g.name in sg_names]

        result.findings.append(
            Finding(
                check="security_groups",
                severity=Severity.INFO,
                title="보안그룹 수집",
                detail=f"전체 {len(sgs)}개 / 점검대상 {len(target_sgs)}개",
                evidence={"audited": [g.name for g in target_sgs]},
            )
        )

        for sg in target_sgs:
            try:
                rules = list(getattr(sg, "security_group_rules", None) or [])
                if not rules:
                    rules = list(conn.network.security_group_rules(security_group_id=sg.id))
            except Exception:
                rules = []

            class _R:
                def __init__(self, d):
                    if isinstance(d, dict):
                        self.direction = d.get("direction")
                        self.ethertype = d.get("ethertype")
                        self.protocol = d.get("protocol")
                        self.port_range_min = d.get("port_range_min")
                        self.port_range_max = d.get("port_range_max")
                    else:
                        self.direction = getattr(d, "direction", None)
                        self.ethertype = getattr(d, "ethertype", None)
                        self.protocol = getattr(d, "protocol", None)
                        self.port_range_min = getattr(d, "port_range_min", None)
                        self.port_range_max = getattr(d, "port_range_max", None)

            wrapped = [_R(r) for r in rules]

            missing: list[str] = []
            for proto, lo, hi, label in REQUIRED:
                if not any(_rule_matches(r, proto, lo, hi) for r in wrapped):
                    missing.append(f"{proto}/{lo}{'-'+str(hi) if hi != lo else ''} ({label})")

            if missing:
                result.findings.append(
                    Finding(
                        check="security_groups",
                        severity=Severity.WARN,
                        title=f"보안그룹 '{sg.name}' 에 k8s 권장 포트 누락",
                        detail="\n".join(f"- {m}" for m in missing),
                        resource=sg.id,
                        suggestion="해당 SG가 마스터/워커/etcd 노드에 동시에 붙는다면 누락 포트를 열어주세요.",
                    )
                )
    return result
