"""Cinder (block storage) checks."""

from __future__ import annotations

from datetime import datetime, timezone

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed

# A volume that has been "attaching"/"detaching"/"creating" for less than
# this many seconds is considered "in flight, give it a moment" rather than
# stuck. Tunable: kubespray's volume operations usually finish well under a
# minute, so 5 minutes is a generous floor before we cry wolf.
STUCK_AFTER_SECONDS = 300


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # OpenStack timestamps are ISO-8601 (often without trailing Z).
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _age_seconds(v) -> float | None:
    ts = _parse_ts(getattr(v, "updated_at", None)) or _parse_ts(getattr(v, "created_at", None))
    if ts is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - ts).total_seconds())


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("cinder", True):
        return skip_unavailable("cinder", "Cinder(Block Storage)")

    conn = handle.conn
    max_items = ctx.get("max_items")

    with timed("cinder") as result:
        volumes = bounded_list(conn.block_storage.volumes(details=True), max_items)
        bad = [v for v in volumes if (v.status or "").lower() in {"error", "error_deleting", "error_extending"}]
        in_flight = [v for v in volumes if (v.status or "").lower() in {"attaching", "detaching", "creating"}]

        result.findings.append(
            Finding(
                check="cinder",
                severity=Severity.INFO,
                title="볼륨 수집",
                detail=f"전체 {len(volumes)}개 / error {len(bad)}개 / 진행중 {len(in_flight)}개",
            )
        )

        for v in bad:
            result.findings.append(
                Finding(
                    check="cinder",
                    severity=Severity.ERROR,
                    title=f"볼륨 ERROR: {v.name or v.id[:8]}",
                    detail=f"status={v.status}, size={v.size}GB",
                    resource=v.id,
                    suggestion="cinder-volume / cinder-scheduler 로그와 백엔드(예: Ceph) 상태를 확인하세요.",
                )
            )

        for v in in_flight:
            age = _age_seconds(v)
            # Skip "just started" volume operations to avoid noisy WARNs.
            if age is not None and age < STUCK_AFTER_SECONDS:
                continue
            age_label = f"{int(age)}s" if age is not None else "unknown"
            result.findings.append(
                Finding(
                    check="cinder",
                    severity=Severity.WARN,
                    title=f"볼륨 진행중 고착 의심: {v.name or v.id[:8]}",
                    detail=f"status={v.status}, age={age_label}",
                    resource=v.id,
                    suggestion=(
                        f"{STUCK_AFTER_SECONDS}s 이상 {v.status} 상태입니다. "
                        "cinder-volume / nova-compute / 백엔드 (예: Ceph/iSCSI) 를 확인하세요."
                    ),
                )
            )

        try:
            services = bounded_list(conn.block_storage.services(), max_items)
        except Exception:
            services = []
        for svc in services:
            if getattr(svc, "state", "up") != "up":
                result.findings.append(
                    Finding(
                        check="cinder",
                        severity=Severity.ERROR,
                        title=f"Cinder 서비스 down: {svc.binary}@{svc.host}",
                        detail=f"state={svc.state}",
                    )
                )

        # Volume type 가용성 체크
        required_volume_type = ctx.get("volume_type")
        try:
            vtypes = bounded_list(conn.block_storage.types(), max_items)
        except Exception:
            vtypes = []

        if vtypes:
            vtype_names = [getattr(vt, "name", None) or getattr(vt, "id", "?") for vt in vtypes]
            result.findings.append(
                Finding(
                    check="cinder",
                    severity=Severity.INFO,
                    title="Volume type 목록",
                    detail=f"{len(vtypes)}개: {vtype_names[:10]}",
                )
            )
            if required_volume_type:
                matched = [vt for vt in vtypes if getattr(vt, "name", None) == required_volume_type]
                if not matched:
                    result.findings.append(
                        Finding(
                            check="cinder",
                            severity=Severity.ERROR,
                            title=f"지정 Volume type 없음: {required_volume_type}",
                            detail=f"가용 타입: {vtype_names[:10]}",
                            suggestion=(
                                f"config 의 volume_type='{required_volume_type}' 이 "
                                "이 클라우드에 존재하지 않습니다. "
                                "`openstack volume type list` 로 올바른 이름을 확인하세요."
                            ),
                        )
                    )
                else:
                    result.findings.append(
                        Finding(
                            check="cinder",
                            severity=Severity.INFO,
                            title=f"지정 Volume type 확인: {required_volume_type}",
                            detail="존재함",
                            resource=matched[0].id,
                        )
                    )
        elif required_volume_type:
            result.findings.append(
                Finding(
                    check="cinder",
                    severity=Severity.WARN,
                    title="Volume type 목록 조회 실패",
                    detail="volume type 리스트를 가져올 수 없어 지정 타입 확인 불가",
                )
            )
    return result
