"""OpenStack authentication and connection helpers.

Credential sources, in priority order:

1. ``--cloud <name>`` referencing an entry in ``clouds.yaml``.
2. ``OS_*`` environment variables (the standard openstackclient layout).
3. A YAML config file passed via ``--config`` whose ``auth:`` block
   mirrors the ``clouds.yaml`` schema.

The returned :class:`openstack.connection.Connection` is wrapped with a
read-only HTTP guard and an optional rate limiter so the tool cannot
mutate cloud state, no matter what an individual check tries to do.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import openstack
import yaml
from openstack.connection import Connection

from .safety import (
    Budget,
    DryRunRecorder,
    GuardStats,
    install_budget,
    install_dry_run,
    install_rate_limiter,
    install_readonly_guard,
    service_available,
)


@dataclass
class AuthConfig:
    cloud: str | None = None
    config_file: Path | None = None
    insecure: bool = False
    region: str | None = None
    rps: float = 2.0
    api_timeout: float = 30.0
    max_requests: int = 2000
    deadline_seconds: float = 600.0
    consecutive_failure_limit: int = 5
    dry_run: bool = False


@dataclass
class CloudHandle:
    """Bundle of a connection + safety stats + service availability map."""

    conn: Connection
    services: dict[str, bool] = field(default_factory=dict)
    guard_stats: GuardStats = field(default_factory=GuardStats)
    budget: Budget = field(default_factory=Budget)
    dry_run: DryRunRecorder | None = None
    preflight_latency_ms: int | None = None
    cloud_label: str = "(env)"


SERVICE_TYPES: dict[str, tuple[str, ...]] = {
    "keystone": ("identity",),
    "nova": ("compute",),
    "neutron": ("network",),
    "cinder": ("volumev3", "block-storage", "volumev2", "volume"),
    "glance": ("image",),
    "octavia": ("load-balancer",),
    "heat": ("orchestration",),
}


def _any_service_available(conn: Connection, service_types: tuple[str, ...]) -> bool:
    return any(service_available(conn, st) for st in service_types)


def _load_extra(auth: AuthConfig) -> dict[str, Any]:
    if not auth.config_file:
        return {}
    with open(auth.config_file, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def connect(auth: AuthConfig) -> CloudHandle:
    """Build an authenticated, *guarded*, rate-limited connection."""

    extra = _load_extra(auth)

    if extra.get("clouds"):
        os.environ["OS_CLIENT_CONFIG_FILE"] = str(auth.config_file)

    kwargs: dict[str, Any] = {}
    if auth.cloud:
        kwargs["cloud"] = auth.cloud
    elif "auth" in extra:
        kwargs["auth"] = extra["auth"]
        kwargs["region_name"] = extra.get("region_name") or auth.region
        kwargs["interface"] = extra.get("interface", "public")
        kwargs["identity_api_version"] = extra.get("identity_api_version", "3")
    else:
        if not any(k.startswith("OS_") for k in os.environ):
            raise RuntimeError(
                "OpenStack 인증 정보를 찾지 못했습니다. --cloud, --config, "
                "또는 OS_* 환경변수 중 하나를 제공해 주세요."
            )

    if auth.insecure:
        kwargs["verify"] = False
    if auth.region and "region_name" not in kwargs:
        kwargs["region_name"] = auth.region

    conn = openstack.connect(**kwargs)
    conn.authorize()

    try:
        conn.session.timeout = auth.api_timeout
    except Exception:
        pass

    # Disable openstacksdk's built-in retry-on-failure so we never amplify
    # load against a struggling cloud. Best effort across SDK versions.
    for attr in ("status_code_retries", "connect_retries", "max_retries"):
        try:
            setattr(conn.session, attr, 0)
        except Exception:
            pass
    try:
        conn.config.config["max_concurrency"] = 1
    except Exception:
        pass

    services = {
        name: _any_service_available(conn, types) for name, types in SERVICE_TYPES.items()
    }
    cloud_label = (
        auth.cloud
        or (extra.get("cloud") if isinstance(extra, dict) else None)
        or "(env)"
    )

    # Quick preflight: one HEAD/GET to identity to gauge cloud responsiveness.
    preflight_ms = None
    try:
        t0 = time.monotonic()
        conn.session.get_endpoint(service_type="identity")
        preflight_ms = int((time.monotonic() - t0) * 1000)
    except Exception:
        preflight_ms = None

    install_rate_limiter(conn, auth.rps)
    budget = Budget(
        max_requests=auth.max_requests,
        deadline_seconds=auth.deadline_seconds,
        consecutive_failure_limit=auth.consecutive_failure_limit,
    )
    install_budget(conn, budget)
    guard_stats = install_readonly_guard(conn)

    dry_run_rec = None
    if auth.dry_run:
        dry_run_rec = DryRunRecorder()
        install_dry_run(conn, dry_run_rec)

    return CloudHandle(
        conn=conn,
        services=services,
        guard_stats=guard_stats,
        budget=budget,
        dry_run=dry_run_rec,
        preflight_latency_ms=preflight_ms,
        cloud_label=cloud_label,
    )
