"""Keystone (identity) checks."""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import timed


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    conn = handle.conn
    with timed("keystone") as result:
        token = conn.session.get_token()
        if not token:
            result.findings.append(
                Finding(
                    check="keystone",
                    severity=Severity.CRITICAL,
                    title="토큰 발급 실패",
                    suggestion="auth_url / username / password / project 를 확인하세요.",
                )
            )
            return result

        max_items = ctx.get("max_items")
        # We require Keystone v3 (set in auth.connect via identity_api_version
        # default), whose proxy exposes services()/endpoints(). The proxy
        # type is unioned with v2 in the SDK stubs, hence the type: ignore.
        services = bounded_list(conn.identity.services(), max_items)  # type: ignore[union-attr]
        endpoints = bounded_list(conn.identity.endpoints(), max_items)  # type: ignore[union-attr]

        present = sorted({s.type for s in services if s.type})
        result.findings.append(
            Finding(
                check="keystone",
                severity=Severity.OK,
                title="인증 성공",
                detail=f"서비스 {len(services)}개 / 엔드포인트 {len(endpoints)}개",
                evidence={"service_types": present},
            )
        )

        recommended = {"compute", "network", "image"}
        missing = recommended - set(present)
        if missing:
            result.findings.append(
                Finding(
                    check="keystone",
                    severity=Severity.WARN,
                    title="권장 서비스 누락",
                    detail=f"누락된 서비스 타입: {sorted(missing)}",
                    suggestion="해당 서비스 카탈로그 등록 여부를 확인하세요. (선택 서비스라면 무시 가능)",
                )
            )
    return result
