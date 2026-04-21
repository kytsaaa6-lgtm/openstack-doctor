"""Flavor existence + capacity check.

A common kubespray failure mode is "Terraform/inventory references a
flavor that doesn't exist (or no longer exists) in the target cloud, so
all instance creates immediately ERROR with No valid host." This check
verifies flavors used by *existing* cluster instances and any flavors
listed in the config are present and usable.
"""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("nova", True):
        return skip_unavailable("flavors", "Nova(Compute)")

    conn = handle.conn
    expected = ctx.get("expected_flavors") or []
    name_prefix = ctx.get("name_prefix")
    max_items = ctx.get("max_items")

    with timed("flavors") as result:
        flavors = bounded_list(conn.compute.flavors(details=True), max_items)
        by_name = {f.name: f for f in flavors}
        by_id = {f.id: f for f in flavors}

        for fname in expected:
            if fname not in by_name:
                result.findings.append(
                    Finding(
                        check="flavors",
                        severity=Severity.ERROR,
                        title=f"필요한 flavor 없음: {fname}",
                        suggestion="kubespray inventory / Terraform 의 flavor 명을 확인하거나 admin 에게 등록 요청.",
                    )
                )

        try:
            servers = bounded_list(conn.compute.servers(details=True), max_items)
        except Exception:
            servers = []
        if name_prefix:
            servers = [s for s in servers if (s.name or "").startswith(name_prefix)]

        used: dict[str, int] = {}
        for s in servers:
            f = getattr(s, "flavor", None) or {}
            ref = f.get("original_name") or f.get("id") or f.get("name")
            if not ref:
                continue
            used[ref] = used.get(ref, 0) + 1

        for ref, count in used.items():
            if ref not in by_name and ref not in by_id:
                result.findings.append(
                    Finding(
                        check="flavors",
                        severity=Severity.WARN,
                        title=f"클러스터가 사용중인 flavor 가 카탈로그에 없음: {ref}",
                        detail=f"{count}개 인스턴스가 참조 중. 삭제됐거나 권한 밖입니다.",
                    )
                )

        result.findings.append(
            Finding(
                check="flavors",
                severity=Severity.INFO,
                title="flavor 수집 완료",
                detail=f"카탈로그 {len(flavors)}개 / 사용중 {len(used)}종",
                evidence={"used": used},
            )
        )
    return result
