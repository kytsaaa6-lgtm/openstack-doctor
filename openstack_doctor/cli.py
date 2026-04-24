"""openstack-doctor CLI."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console

from . import __version__, auth, cluster_readiness
from .checks import REGISTRY, available_checks
from .models import SEVERITY_ORDER, DiagnosisReport, Severity
from .nodes.collector import NodeRole, collect
from .nodes.ssh import from_dict as ssh_from_dict
from .report import to_console, to_json, to_markdown
from .safety import BudgetExceeded, CircuitOpen, Snapshot

app = typer.Typer(
    add_completion=False,
    help=(
        "OpenStack 위에서 kubespray 로 쿠버네티스 클러스터를 만들 때 어디서 멈췄는지 "
        "진단합니다. 100% read-only 입니다."
    ),
    no_args_is_help=True,
)
console = Console()


SEVERITY_FROM_STR = {
    "ok": Severity.OK,
    "info": Severity.INFO,
    "warn": Severity.WARN,
    "error": Severity.ERROR,
    "critical": Severity.CRITICAL,
}


# Keys that the CLI populates explicitly. Anything in the YAML ``cluster:``
# block with one of these names must NOT overwrite the CLI-resolved value
# in ``_build_context``, otherwise yaml silently wins over an explicit CLI
# argument (the opposite of the documented precedence).
_RESERVED_CTX_KEYS = frozenset(
    {
        "name_prefix",
        "image_name",
        "api_port",
        "expected_node_count",
        "expected_nodes",
        "quota_warn_ratio",
        "expected_flavors",
        "max_items",
        "skip_sg_audit",
        "snapshot",
    }
)


def _build_context(
    *,
    name_prefix: str | None,
    image_name: str | None,
    api_port: int,
    expected_nodes: int | None,
    quota_warn_ratio: float,
    expected_flavors: list[str] | None,
    max_items: int | None,
    skip_sg_audit: bool,
    snapshot: Snapshot | None,
    extra: dict | None = None,
) -> dict:
    ctx: dict = {
        "name_prefix": name_prefix,
        "image_name": image_name,
        "api_port": api_port,
        "expected_node_count": expected_nodes,
        "quota_warn_ratio": quota_warn_ratio,
        "expected_flavors": expected_flavors or [],
        "max_items": max_items,
        "skip_sg_audit": skip_sg_audit,
        "snapshot": snapshot,
    }
    if extra:
        for k, v in extra.items():
            if k in _RESERVED_CTX_KEYS:
                # CLI/explicit values already merged above; do not let
                # the yaml block overwrite them.
                continue
            ctx[k] = v
    return ctx


@app.command()
def list_checks() -> None:
    """사용 가능한 진단 체크를 출력합니다."""
    for name in available_checks():
        console.print(f"- {name}")
    console.print("- cluster_readiness (시나리오 룰)")
    console.print("- (선택) node:<name>  -- SSH 정보가 있을 때만")


@app.command()
def diagnose(
    cloud: Annotated[str | None, typer.Option(help="clouds.yaml 의 cloud 이름")] = None,
    config: Annotated[Path | None, typer.Option(help="auth/노드/시나리오 정보를 담은 YAML")] = None,
    region: Annotated[str | None, typer.Option(help="OpenStack region")] = None,
    insecure: Annotated[bool, typer.Option(help="TLS 검증 비활성화")] = False,
    only: Annotated[str | None, typer.Option(help="콤마로 구분된 체크만 실행")] = None,
    skip: Annotated[str | None, typer.Option(help="콤마로 구분된 체크 제외")] = None,
    name_prefix: Annotated[str | None, typer.Option(help="대상 클러스터 리소스 이름 prefix")] = None,
    image_name: Annotated[str | None, typer.Option(help="kubespray 가 요구하는 Glance 이미지명")] = None,
    api_port: Annotated[int, typer.Option(help="k8s API 포트")] = 6443,
    expected_nodes: Annotated[int | None, typer.Option(help="기대 노드 수")] = None,
    expected_flavors: Annotated[
        str | None, typer.Option(help="콤마로 구분된 기대 flavor 명들")
    ] = None,
    quota_warn_ratio: Annotated[float, typer.Option(help="쿼터 경고 임계 (0~1)")] = 0.85,
    skip_readiness: Annotated[bool, typer.Option(help="cluster_readiness 시나리오 룰 끄기")] = False,
    skip_sg_audit: Annotated[bool, typer.Option(help="security_groups 권장 포트 audit 끄기")] = False,
    rps: Annotated[float, typer.Option(help="초당 요청 상한 (0=제한 없음)")] = 2.0,
    api_timeout: Annotated[float, typer.Option(help="API 호출당 타임아웃(초)")] = 30.0,
    max_items: Annotated[int, typer.Option(help="체크당 페이지네이션 상한 (0=무제한)")] = 500,
    max_requests: Annotated[int, typer.Option(help="실행 전체 API 호출 상한 (0=무제한)")] = 2000,
    total_timeout: Annotated[float, typer.Option(help="실행 전체 시간 상한(초, 0=무제한)")] = 600.0,
    consec_failure_limit: Annotated[int, typer.Option(help="연속 실패 N회 시 회로 차단")] = 5,
    polite: Annotated[
        bool,
        typer.Option(
            "--polite",
            help="운영 클라우드용 보수 프리셋: rps=1, max_items=200, max_requests=500, "
            "total_timeout=300, 권장 SG audit 끔, hypervisors 등 admin-only 점검 skip.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="인증 + 카탈로그 점검만 하고, 그 이후 실제 API 호출은 모두 차단/기록.",
        ),
    ] = False,
    snapshot_dir: Annotated[Path | None, typer.Option("--snapshot", help="원본 응답 저장 폴더")] = None,
    redact: Annotated[bool, typer.Option(help="리포트에서 IP 및 비밀값 마스킹")] = False,
    json_out: Annotated[Path | None, typer.Option("--json")] = None,
    md_out: Annotated[Path | None, typer.Option("--markdown")] = None,
    no_console: Annotated[bool, typer.Option(help="콘솔 출력 끄기")] = False,
    insecure_ssh: Annotated[
        bool,
        typer.Option(
            "--insecure-ssh",
            help="SSH 호스트키가 known_hosts 에 없어도 자동으로 신뢰 (MITM 위험, 명시적 opt-in).",
        ),
    ] = False,
    fail_on: Annotated[
        str, typer.Option(help="이 심각도 이상이면 비정상 종료")
    ] = "error",
) -> None:
    """OpenStack 진단을 수행합니다 (read-only)."""

    # Validate --fail-on up front so a typo doesn't waste a full diagnosis run
    # against a production cloud.
    if fail_on.lower() not in SEVERITY_FROM_STR:
        console.print(
            f"[red]오류:[/red] --fail-on='{fail_on}' 는 알 수 없는 값입니다. "
            f"허용값: {sorted(SEVERITY_FROM_STR)}"
        )
        raise typer.Exit(code=64)

    file_data: dict = {}
    extra_ctx: dict = {}
    nodes_cfg: list = []
    if config:
        file_data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
        kube_ctx = file_data.get("kubespray", {}) or file_data.get("cluster", {}) or {}
        if kube_ctx:
            extra_ctx.update(kube_ctx)
            name_prefix = name_prefix or kube_ctx.get("name_prefix")
            image_name = image_name or kube_ctx.get("image_name")
            # Only let yaml override api_port if the CLI value is the default.
            # Typer doesn't tell us "was this explicit?" so we use the default
            # sentinel: 6443. Users who explicitly pass --api-port 6443 will
            # still correctly take the CLI value because it equals the yaml.
            if "api_port" in kube_ctx and api_port == 6443:
                api_port = kube_ctx["api_port"]
            expected_nodes = expected_nodes or kube_ctx.get("expected_nodes")
            if not expected_flavors and kube_ctx.get("expected_flavors"):
                expected_flavors = ",".join(kube_ctx["expected_flavors"])
        nodes_cfg = file_data.get("nodes") or []

    if polite:
        rps = min(rps, 1.0)
        max_items = min(max_items, 200) if max_items > 0 else 200
        max_requests = min(max_requests, 500) if max_requests > 0 else 500
        total_timeout = min(total_timeout, 300.0) if total_timeout > 0 else 300.0
        skip_sg_audit = True
        # In polite mode, default-skip checks that may be admin-only and heavy
        admin_heavy = {"heat"}
        skip_set = set(x.strip() for x in (skip or "").split(",") if x.strip())
        skip = ",".join(sorted(skip_set | admin_heavy))

    ac = auth.AuthConfig(
        cloud=cloud,
        config_file=config,
        insecure=insecure,
        region=region,
        rps=rps,
        api_timeout=api_timeout,
        max_requests=max_requests,
        deadline_seconds=total_timeout,
        consecutive_failure_limit=consec_failure_limit,
        dry_run=dry_run,
    )
    handle = auth.connect(ac)

    if handle.preflight_latency_ms is not None and handle.preflight_latency_ms > 3000:
        console.log(
            f"[yellow]주의:[/yellow] preflight latency {handle.preflight_latency_ms}ms "
            "- 클라우드 응답이 느립니다. --polite 또는 더 낮은 --rps 사용을 권장합니다."
        )

    cloud_label = handle.cloud_label
    report = DiagnosisReport(cloud=cloud_label)
    report.context = {
        "tool_version": __version__,
        "name_prefix": name_prefix,
        "image_name": image_name,
        "api_port": api_port,
        "expected_nodes": expected_nodes,
        "rps": rps,
        "max_items": max_items,
        "redact": redact,
        "services_detected": handle.services,
    }

    snapshot = Snapshot(snapshot_dir) if snapshot_dir else None
    if snapshot:
        snapshot.save("services_detected", handle.services)

    selected = available_checks()
    if only:
        wanted = {x.strip() for x in only.split(",") if x.strip()}
        selected = [c for c in selected if c in wanted]
    if skip:
        unwanted = {x.strip() for x in skip.split(",") if x.strip()}
        selected = [c for c in selected if c not in unwanted]

    flv_list = (
        [x.strip() for x in expected_flavors.split(",") if x.strip()]
        if expected_flavors
        else None
    )

    ctx = _build_context(
        name_prefix=name_prefix,
        image_name=image_name,
        api_port=api_port,
        expected_nodes=expected_nodes,
        quota_warn_ratio=quota_warn_ratio,
        expected_flavors=flv_list,
        max_items=max_items if max_items > 0 else None,
        skip_sg_audit=skip_sg_audit,
        snapshot=snapshot,
        extra=extra_ctx,
    )

    aborted = False
    for name in selected:
        if aborted:
            break
        console.log(f"running check: {name}")
        try:
            report.results.append(REGISTRY[name](handle, ctx))
        except (BudgetExceeded, CircuitOpen) as exc:
            console.log(f"[red]안전 예산/회로 차단:[/red] {exc} - 남은 체크는 모두 중단합니다.")
            aborted = True

    if not skip_readiness and not aborted:
        console.log("running scenario: cluster_readiness")
        try:
            report.results.append(cluster_readiness.run(handle, ctx))
        except (BudgetExceeded, CircuitOpen) as exc:
            console.log(f"[red]안전 예산/회로 차단:[/red] {exc}")
            aborted = True

    if nodes_cfg:
        console.log(f"SSH 노드 수집 ({len(nodes_cfg)}개)")
        for n in nodes_cfg:
            try:
                ssh_dict = dict(n.get("ssh") or {})
            except Exception:
                console.log(f"[yellow]경고:[/yellow] node {n!r} 에 ssh 섹션이 없거나 잘못되어 건너뜁니다.")
                continue
            if insecure_ssh:
                ssh_dict.setdefault("insecure_host_key", True)
                if isinstance(ssh_dict.get("bastion"), dict):
                    ssh_dict["bastion"].setdefault("insecure_host_key", True)
            try:
                target = ssh_from_dict(ssh_dict)
            except ValueError as exc:
                console.log(f"[yellow]경고:[/yellow] node {n.get('name')!r} ssh 설정 오류: {exc}")
                continue
            node_name = n.get("name") or ssh_dict.get("host") or "unknown"
            node = NodeRole(
                name=str(node_name),
                target=target,
                role=n.get("role", "custom"),
                units=n.get("units"),
            )
            report.results.append(collect(node))
    else:
        console.log("SSH 정보 없음 - 노드 수집은 건너뜁니다.")

    report.finished_at = datetime.now(timezone.utc)
    report.context["safety"] = {
        "allowed_requests": handle.guard_stats.allowed,
        "blocked_writes": handle.guard_stats.blocked,
        "blocked_calls": handle.guard_stats.blocked_calls[:20],
        "budget_used": handle.budget.used,
        "budget_max_requests": handle.budget.max_requests,
        "budget_deadline_seconds": handle.budget.deadline_seconds,
        "circuit_tripped": handle.budget.tripped,
        "preflight_latency_ms": handle.preflight_latency_ms,
        "polite": polite,
        "dry_run": dry_run,
    }
    if handle.dry_run:
        report.context["dry_run_records"] = [
            {"method": r.method, "url": r.url}
            for r in handle.dry_run.records[:200]
        ]
    if aborted:
        report.context["aborted"] = True
    if snapshot is not None and snapshot.failures:
        report.context["snapshot_failures"] = snapshot.failures[:20]
        console.log(
            f"[yellow]주의:[/yellow] snapshot 저장 실패 {len(snapshot.failures)}건 - "
            "리포트의 context.snapshot_failures 를 확인하세요."
        )

    if not no_console:
        to_console(report, console, redact_ips=redact)
    if json_out:
        to_json(report, json_out, redact_ips=redact)
        console.log(f"JSON 리포트 저장: {json_out}")
    if md_out:
        to_markdown(report, md_out, redact_ips=redact)
        console.log(f"Markdown 리포트 저장: {md_out}")

    fail_threshold = SEVERITY_FROM_STR[fail_on.lower()]
    if SEVERITY_ORDER[report.worst_severity] >= SEVERITY_ORDER[fail_threshold]:
        raise typer.Exit(code=2)


@app.command()
def collect_node(
    host: Annotated[str, typer.Option(help="대상 호스트")],
    user: Annotated[str, typer.Option(help="SSH 유저")] = "root",
    port: Annotated[int, typer.Option(help="SSH 포트")] = 22,
    key: Annotated[Path | None, typer.Option(help="SSH 키 파일")] = None,
    role: Annotated[str, typer.Option(help="controller|compute|k8s|custom")] = "custom",
    units: Annotated[str | None, typer.Option(help="콤마로 구분된 systemd 유닛")] = None,
    bastion_host: Annotated[str | None, typer.Option(help="Bastion 호스트")] = None,
    bastion_user: Annotated[str | None, typer.Option()] = None,
    bastion_key: Annotated[Path | None, typer.Option()] = None,
    json_out: Annotated[Path | None, typer.Option("--json")] = None,
    redact: Annotated[bool, typer.Option(help="IP 마스킹")] = False,
    insecure_ssh: Annotated[
        bool,
        typer.Option(
            "--insecure-ssh",
            help="SSH 호스트키가 known_hosts 에 없어도 자동으로 신뢰 (MITM 위험, 명시적 opt-in).",
        ),
    ] = False,
) -> None:
    """단일 노드에 SSH 로 접속해 systemd/journal/MTU/NTP/conntrack 을 수집합니다."""
    bastion = None
    if bastion_host:
        bastion = {
            "host": bastion_host,
            "user": bastion_user or "root",
            "key_filename": str(bastion_key) if bastion_key else None,
            "insecure_host_key": insecure_ssh,
        }
    target = ssh_from_dict(
        {
            "host": host,
            "user": user,
            "port": port,
            "key_filename": str(key) if key else None,
            "bastion": bastion,
            "insecure_host_key": insecure_ssh,
        }
    )
    unit_list = [u.strip() for u in units.split(",")] if units else None
    node = NodeRole(name=host, target=target, role=role, units=unit_list)
    result = collect(node)

    report = DiagnosisReport(cloud=f"node:{host}")
    report.results.append(result)
    report.finished_at = datetime.now(timezone.utc)
    to_console(report, console, redact_ips=redact)
    if json_out:
        to_json(report, json_out, redact_ips=redact)


if __name__ == "__main__":
    app()
