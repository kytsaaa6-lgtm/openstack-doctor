"""Tests for CLI-side helpers that decide context precedence and option parsing."""

from __future__ import annotations

from typer.testing import CliRunner

from openstack_doctor import __version__
from openstack_doctor.cli import _build_context, app


def test_build_context_cli_wins_over_yaml_for_reserved_keys():
    """Regression for the yaml-overrides-CLI bug we fixed."""
    ctx = _build_context(
        name_prefix="cli-prefix",
        image_name="cli-img",
        api_port=6443,
        expected_nodes=3,
        quota_warn_ratio=0.85,
        expected_flavors=["a"],
        max_items=500,
        skip_sg_audit=False,
        snapshot=None,
        extra={
            "name_prefix": "yaml-prefix",
            "image_name": "yaml-img",
            "api_port": 9999,
            "expected_node_count": 99,
            "extra_user_key": "kept",
        },
    )
    assert ctx["name_prefix"] == "cli-prefix"
    assert ctx["image_name"] == "cli-img"
    assert ctx["api_port"] == 6443
    assert ctx["expected_node_count"] == 3
    # Non-reserved yaml keys still flow through.
    assert ctx["extra_user_key"] == "kept"


def test_build_context_passes_through_when_no_extra():
    ctx = _build_context(
        name_prefix=None,
        image_name=None,
        api_port=6443,
        expected_nodes=None,
        quota_warn_ratio=0.85,
        expected_flavors=None,
        max_items=None,
        skip_sg_audit=True,
        snapshot=None,
    )
    assert ctx["expected_flavors"] == []
    assert ctx["skip_sg_audit"] is True
    assert ctx["max_items"] is None


def test_cli_help_loads():
    """A typer-level smoke test so a typo in option declarations fails CI."""
    runner = CliRunner()
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "diagnose" in res.stdout
    assert "collect-node" in res.stdout


def test_diagnose_validates_fail_on_before_running_any_check():
    """An invalid --fail-on must abort before any cloud connection is attempted."""
    runner = CliRunner()
    res = runner.invoke(app, ["diagnose", "--fail-on", "totally-bogus"])
    assert res.exit_code == 64, res.stdout
    assert "fail-on" in res.stdout.lower() or "fail_on" in res.stdout.lower()


def test_version_constant_is_string():
    assert isinstance(__version__, str)
    assert __version__
