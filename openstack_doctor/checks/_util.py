"""Shared helpers for check modules."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from ..models import CheckResult, Finding, Severity
from ..safety import BudgetExceeded, CircuitOpen, DryRunBlocked, WriteAttemptBlocked


@contextmanager
def timed(name: str) -> Iterator[CheckResult]:
    """Time a check and capture any unexpected exception as an ERROR finding."""
    result = CheckResult(name=name)
    start = time.perf_counter()
    try:
        yield result
    except WriteAttemptBlocked as exc:
        # Should never happen, but if it does we report it loudly because
        # it means a check tried to mutate the cloud.
        result.error = f"WriteAttemptBlocked: {exc}"
        result.findings.append(
            Finding(
                check=name,
                severity=Severity.CRITICAL,
                title="쓰기 시도가 차단되었습니다 (버그)",
                detail=str(exc),
                suggestion="이 도구는 read-only 입니다. 차단된 호출 정보를 이슈로 보고해 주세요.",
            )
        )
    except (BudgetExceeded, CircuitOpen) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.findings.append(
            Finding(
                check=name,
                severity=Severity.WARN,
                title="안전 예산 초과로 점검 중단",
                detail=str(exc),
                suggestion="--max-requests / --total-timeout / --rps 를 더 보수적으로 잡거나, 클라우드가 회복된 뒤 재실행하세요.",
            )
        )
        raise
    except DryRunBlocked as exc:
        result.findings.append(
            Finding(
                check=name,
                severity=Severity.INFO,
                title="DRY-RUN: 실제 API 호출 없이 끝남",
                detail=str(exc),
            )
        )
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
        result.findings.append(
            Finding(
                check=name,
                severity=Severity.WARN,
                title=f"{name} 점검 중 예외 발생",
                detail=str(exc),
                suggestion="네트워크/권한 문제이거나 해당 서비스가 미설치일 수 있습니다.",
            )
        )
    finally:
        result.duration_ms = int((time.perf_counter() - start) * 1000)


def skip_unavailable(name: str, service_label: str) -> CheckResult:
    """Build a result that says the optional service isn't available."""
    return CheckResult(
        name=name,
        findings=[
            Finding(
                check=name,
                severity=Severity.INFO,
                title=f"{service_label} 서비스가 설치/노출되어 있지 않습니다",
                detail="카탈로그에 엔드포인트가 없어 점검을 건너뜁니다.",
            )
        ],
    )
