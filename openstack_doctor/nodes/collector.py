"""Remote log / status collection helpers.

Strictly read-only: only inspection commands (`systemctl is-active`,
`journalctl -n N`, `df`, `chronyc tracking`, etc.) are issued. The
remote host is never modified.

All remote commands for a single node go over a single reused SSH
session (and a single shared bastion connection), so a multi-node run
no longer pays a handshake per command.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..checks._util import timed
from ..models import CheckResult, Finding, Severity
from .ssh import RemoteError, SSHSession, SSHTarget, is_safe_shell_token, open_session

CONTROLLER_UNITS = [
    "nova-api",
    "nova-conductor",
    "nova-scheduler",
    "neutron-server",
    "cinder-api",
    "cinder-scheduler",
    "glance-api",
    "keystone",
    "octavia-api",
    "octavia-worker",
    "octavia-health-manager",
    "octavia-housekeeping",
    "rabbitmq-server",
    "mariadb",
    "mysql",
    "haproxy",
]

COMPUTE_UNITS = [
    "nova-compute",
    "neutron-openvswitch-agent",
    "neutron-linuxbridge-agent",
    "openvswitch-switch",
    "libvirtd",
]

K8S_UNITS = ["kubelet", "containerd", "docker"]


@dataclass
class NodeRole:
    name: str
    target: SSHTarget
    role: str  # controller | compute | k8s | custom
    units: list[str] | None = None


def _units_for(role: str) -> list[str]:
    role = role.lower()
    if role == "controller":
        return CONTROLLER_UNITS
    if role == "compute":
        return COMPUTE_UNITS
    if role == "k8s":
        return K8S_UNITS
    return []


def _safe_run(sess: SSHSession, cmd: str, timeout: int = 15) -> tuple[int, str, str] | None:
    try:
        return sess.run(cmd, timeout=timeout)
    except RemoteError:
        return None


def _validated_units(raw_units: list[str]) -> tuple[list[str], list[str]]:
    """Split units into (safe, rejected) by shell-token whitelist."""
    safe: list[str] = []
    rejected: list[str] = []
    for u in raw_units:
        u = (u or "").strip()
        if not u:
            continue
        if is_safe_shell_token(u):
            safe.append(u)
        else:
            rejected.append(u)
    return safe, rejected


def collect(node: NodeRole, journal_lines: int = 100) -> CheckResult:
    raw_units = node.units or _units_for(node.role)
    units, rejected = _validated_units(raw_units)
    name = f"node:{node.name}"
    with timed(name) as result:
        if rejected:
            result.findings.append(
                Finding(
                    check=name,
                    severity=Severity.WARN,
                    title=f"안전하지 않은 systemd 유닛 이름 무시 ({len(rejected)}개)",
                    detail=", ".join(rejected[:10]),
                    suggestion="유닛 이름은 [A-Za-z0-9_.@:+-]+ 만 허용됩니다. 셸 메타문자가 들어 있으면 거부됩니다.",
                )
            )

        try:
            sess_cm = open_session(node.target)
            sess = sess_cm.__enter__()
        except RemoteError as exc:
            result.findings.append(
                Finding(
                    check=name,
                    severity=Severity.ERROR,
                    title="SSH 접속 실패",
                    detail=str(exc),
                    suggestion="키/유저/네트워크/보안그룹/Bastion 설정 또는 known_hosts 를 확인하세요. 호스트키를 의도적으로 신뢰한다면 --insecure-ssh 또는 ssh.insecure_host_key=true 사용.",
                )
            )
            return result

        try:
            try:
                rc, out, err = sess.run("uptime; uname -a; df -h /", timeout=15)
            except RemoteError as exc:
                result.findings.append(
                    Finding(
                        check=name,
                        severity=Severity.ERROR,
                        title="원격 명령 실행 실패",
                        detail=str(exc),
                    )
                )
                return result

            if rc != 0:
                result.findings.append(
                    Finding(
                        check=name,
                        severity=Severity.WARN,
                        title=f"기본 명령 비정상 종료(rc={rc})",
                        detail=(err or out).strip()[:500],
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        check=name,
                        severity=Severity.OK,
                        title="SSH 접속 성공",
                        detail=out.strip()[:1000],
                    )
                )

            df = _safe_run(sess, "df -P / | tail -1 | awk '{print $5}'")
            if df:
                try:
                    pct = int(df[1].strip().rstrip("%") or 0)
                except ValueError:
                    pct = 0
                if pct >= 90:
                    result.findings.append(
                        Finding(
                            check=name,
                            severity=Severity.ERROR if pct >= 95 else Severity.WARN,
                            title=f"루트 디스크 사용률 {pct}%",
                            suggestion="컨트롤러는 디스크가 차면 mariadb/rabbit 부터 죽습니다.",
                        )
                    )

            ntp = _safe_run(
                sess,
                "chronyc tracking 2>/dev/null || timedatectl show --property=NTPSynchronized,LocalRTC --value 2>/dev/null",
            )
            if ntp:
                text = ntp[1]
                if "Leap status     : Normal" not in text and "yes" not in text.lower():
                    result.findings.append(
                        Finding(
                            check=name,
                            severity=Severity.WARN,
                            title="시계 동기화 의심",
                            detail=text.strip()[:1500],
                            suggestion="NTP 비동기화는 토큰/인증서 오류, etcd lease 만료 등을 유발합니다.",
                        )
                    )

            mtu = _safe_run(
                sess,
                "ip -o link show 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i==\"mtu\") print $(i+1)}'",
            )
            if mtu:
                distinct: set[int] = set()
                for line in mtu[1].splitlines():
                    try:
                        v = int(line.strip())
                    except ValueError:
                        continue
                    # ignore loopback's 65536; keep real interface MTUs.
                    if v not in (65536,):
                        distinct.add(v)
                if len(distinct) > 2:
                    result.findings.append(
                        Finding(
                            check=name,
                            severity=Severity.INFO,
                            title=f"인터페이스 MTU 다양함: {sorted(distinct)}",
                            detail="VXLAN 오버헤드(50B) 와 어긋나면 pod-to-pod 가 큰 패킷에서 깨집니다.",
                        )
                    )

            ct = _safe_run(
                sess,
                "cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null; "
                "cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null",
            )
            if ct:
                nums = [int(x) for x in ct[1].split() if x.isdigit()]
                if len(nums) == 2 and nums[1] > 0 and nums[0] / nums[1] >= 0.85:
                    result.findings.append(
                        Finding(
                            check=name,
                            severity=Severity.WARN,
                            title=f"conntrack 사용률 {nums[0]}/{nums[1]}",
                            suggestion="포화되면 새 연결이 즉시 drop 됩니다. nf_conntrack_max 증설 고려.",
                        )
                    )

            for unit in units:
                # unit was validated above; safe to splice into the command.
                check = _safe_run(sess, f"systemctl is-active {unit} 2>/dev/null || true", timeout=10)
                if not check:
                    continue
                state = check[1].strip()
                if state in {"", "unknown", "not-found", "inactive"}:
                    continue

                if state != "active":
                    journal = _safe_run(
                        sess,
                        f"journalctl -u {unit} -n {journal_lines} --no-pager 2>/dev/null | tail -n {journal_lines}",
                        timeout=20,
                    )
                    detail = (journal[1] if journal else "").strip()[-4000:]
                    result.findings.append(
                        Finding(
                            check=name,
                            severity=Severity.ERROR if state in {"failed", "activating"} else Severity.WARN,
                            title=f"{unit} 상태 비정상: {state}",
                            detail=detail,
                            suggestion=f"`journalctl -u {unit} -n 500 --no-pager` 로 상세 로그 확인.",
                        )
                    )
                else:
                    journal = _safe_run(
                        sess,
                        f"journalctl -u {unit} -n {journal_lines} --no-pager -p err 2>/dev/null",
                        timeout=20,
                    )
                    err_lines = [ln for ln in (journal[1] if journal else "").splitlines() if ln.strip()]
                    if len(err_lines) > 5:
                        result.findings.append(
                            Finding(
                                check=name,
                                severity=Severity.WARN,
                                title=f"{unit} 최근 ERROR 로그 다수 ({len(err_lines)}건)",
                                detail="\n".join(err_lines[-30:]),
                            )
                        )
        finally:
            sess_cm.__exit__(None, None, None)
    return result
