"""Glance (image) checks.

Beyond presence/active state we also check a few image *properties* that
kubespray-built images commonly need (cloud-init enabled, supported
hypervisor type, sane disk format).
"""

from __future__ import annotations

from ..auth import CloudHandle
from ..models import CheckResult, Finding, Severity
from ..safety import bounded_list
from ._util import skip_unavailable, timed


def run(handle: CloudHandle, ctx: dict) -> CheckResult:
    if not handle.services.get("glance", True):
        return skip_unavailable("glance", "Glance(Image)")

    conn = handle.conn
    image_name = ctx.get("image_name")
    max_items = ctx.get("max_items")

    with timed("glance") as result:
        images = bounded_list(conn.image.images(), max_items)
        active = [i for i in images if (i.status or "").lower() == "active"]

        result.findings.append(
            Finding(
                check="glance",
                severity=Severity.INFO,
                title="이미지 수집",
                detail=f"전체 {len(images)}개 / active {len(active)}개",
            )
        )

        if not image_name:
            return result

        matched = [i for i in images if i.name == image_name]
        if not matched:
            result.findings.append(
                Finding(
                    check="glance",
                    severity=Severity.ERROR,
                    title=f"필요한 이미지 없음: {image_name}",
                    suggestion="kubespray inventory 의 image_name 값과 Glance 업로드 상태를 확인하세요.",
                )
            )
            return result

        for img in matched:
            if (img.status or "").lower() != "active":
                result.findings.append(
                    Finding(
                        check="glance",
                        severity=Severity.ERROR,
                        title=f"이미지 비활성: {image_name}",
                        detail=f"status={img.status}",
                        resource=img.id,
                    )
                )
                continue

            props = getattr(img, "properties", {}) or {}
            visibility = getattr(img, "visibility", None)
            if visibility == "private":
                result.findings.append(
                    Finding(
                        check="glance",
                        severity=Severity.INFO,
                        title=f"이미지가 private: {image_name}",
                        detail="현재 프로젝트에서 사용 가능한지 확인하세요.",
                        resource=img.id,
                    )
                )
            disk_format = getattr(img, "disk_format", None)
            if disk_format and disk_format not in {"qcow2", "raw"}:
                result.findings.append(
                    Finding(
                        check="glance",
                        severity=Severity.WARN,
                        title=f"비표준 disk_format: {disk_format}",
                        resource=img.id,
                    )
                )
            if isinstance(props, dict) and props.get("hw_disk_bus") == "scsi":
                result.findings.append(
                    Finding(
                        check="glance",
                        severity=Severity.INFO,
                        title="이미지가 SCSI 디스크 버스 사용",
                        detail="virtio-scsi 드라이버 미지원 OS 라면 부팅 실패할 수 있습니다.",
                        resource=img.id,
                    )
                )
    return result
