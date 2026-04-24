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
        if handle.inventory is not None:
            flavors = handle.inventory.flavors(max_items)
        else:
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

        if handle.inventory is not None:
            servers = handle.inventory.servers(max_items)
        else:
            try:
                servers = bounded_list(conn.compute.servers(details=True), max_items)
            except Exception:
                servers = []
        if name_prefix:
            servers = [s for s in servers if (s.name or "").startswith(name_prefix)]

        # Resolve each instance's flavor reference to a canonical *name* when
        # possible, so the evidence is consistently human-readable instead of
        # mixing names and ids.
        used_by_name: dict[str, int] = {}
        unresolved: dict[str, int] = {}
        for s in servers:
            f = getattr(s, "flavor", None) or {}
            ref_name = f.get("original_name") or f.get("name")
            ref_id = f.get("id")
            resolved = None
            if ref_name and ref_name in by_name:
                resolved = ref_name
            elif ref_id and ref_id in by_id:
                resolved = by_id[ref_id].name or ref_id
            if resolved:
                used_by_name[resolved] = used_by_name.get(resolved, 0) + 1
            else:
                key = ref_name or ref_id or "<unknown>"
                unresolved[key] = unresolved.get(key, 0) + 1

        for ref, count in unresolved.items():
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
                detail=(
                    f"카탈로그 {len(flavors)}개 / 사용중 {len(used_by_name)}종"
                    + (f" / 미식별 {len(unresolved)}종" if unresolved else "")
                ),
                evidence={"used": used_by_name, "unresolved": unresolved} if unresolved else {"used": used_by_name},
            )
        )
    return result
