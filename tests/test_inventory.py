"""Tests for the per-run shared Inventory cache used by check modules."""

from __future__ import annotations

from openstack_doctor.auth import Inventory


class _Fake:
    """Tiny fake of openstack.connection.Connection.compute/network/load_balancer."""

    def __init__(self, server_pages, sg_pages, lb_pages, flavor_pages):
        self.server_calls = 0
        self.sg_calls = 0
        self.lb_calls = 0
        self.flavor_calls = 0

        outer = self

        class _Compute:
            def servers(self, details=True):  # noqa: ANN001
                outer.server_calls += 1
                yield from server_pages

            def flavors(self, details=True):  # noqa: ANN001
                outer.flavor_calls += 1
                yield from flavor_pages

        class _Network:
            def security_groups(self):
                outer.sg_calls += 1
                yield from sg_pages

        class _LB:
            def load_balancers(self):
                outer.lb_calls += 1
                yield from lb_pages

        self.compute = _Compute()
        self.network = _Network()
        self.load_balancer = _LB()


def test_inventory_caches_servers_across_calls():
    fake = _Fake(server_pages=[1, 2, 3], sg_pages=[], lb_pages=[], flavor_pages=[])
    inv = Inventory(fake)
    a = inv.servers(100)
    b = inv.servers(100)
    assert a == b == [1, 2, 3]
    assert fake.server_calls == 1, "second call must be served from cache"


def test_inventory_keys_by_max_items():
    fake = _Fake(server_pages=[1, 2, 3], sg_pages=[], lb_pages=[], flavor_pages=[])
    inv = Inventory(fake)
    inv.servers(2)
    inv.servers(3)
    assert fake.server_calls == 2, "different max_items produce distinct cache keys"


def test_inventory_swallows_fetch_failures_into_empty_list():
    class _Boom:
        compute = None
        network = None
        load_balancer = None

    inv = Inventory(_Boom())
    # Each accessor should fall back to [] when the underlying SDK attr is
    # missing instead of raising AttributeError to the caller.
    assert inv.servers(10) == []
    assert inv.security_groups(10) == []
    assert inv.load_balancers(10) == []
    assert inv.flavors(10) == []
