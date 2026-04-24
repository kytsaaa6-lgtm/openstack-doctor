"""Per-service diagnostic check modules."""

from __future__ import annotations

from collections.abc import Callable

from ..auth import CloudHandle
from ..models import CheckResult
from . import (
    cinder,
    flavors,
    glance,
    heat,
    keystone,
    neutron,
    nova,
    octavia,
    quota,
    security_groups,
)

CheckFunc = Callable[[CloudHandle, dict], CheckResult]


REGISTRY: dict[str, CheckFunc] = {
    "keystone": keystone.run,
    "nova": nova.run,
    "neutron": neutron.run,
    "cinder": cinder.run,
    "glance": glance.run,
    "octavia": octavia.run,
    "heat": heat.run,
    "quota": quota.run,
    "flavors": flavors.run,
    "security_groups": security_groups.run,
}


def available_checks() -> list[str]:
    return list(REGISTRY.keys())
