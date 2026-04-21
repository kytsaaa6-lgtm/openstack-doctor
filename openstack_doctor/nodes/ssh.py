"""Thin wrapper over paramiko for read-only remote diagnosis."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

import paramiko


@dataclass
class SSHTarget:
    host: str
    user: str = "root"
    port: int = 22
    key_filename: str | None = None
    password: str | None = None
    bastion: "SSHTarget | None" = None
    connect_timeout: int = 10


class RemoteError(RuntimeError):
    pass


def _open_channel(target: SSHTarget) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    sock = None
    if target.bastion:
        bastion_client = _open_channel(target.bastion)
        transport = bastion_client.get_transport()
        if transport is None:
            raise RemoteError("Failed to open bastion transport")
        sock = transport.open_channel(
            "direct-tcpip",
            (target.host, target.port),
            ("127.0.0.1", 0),
        )

    try:
        client.connect(
            hostname=target.host,
            port=target.port,
            username=target.user,
            key_filename=target.key_filename,
            password=target.password,
            timeout=target.connect_timeout,
            banner_timeout=target.connect_timeout,
            auth_timeout=target.connect_timeout,
            sock=sock,
            look_for_keys=target.key_filename is None and target.password is None,
            allow_agent=True,
        )
    except (paramiko.SSHException, socket.error) as exc:
        raise RemoteError(f"SSH connect to {target.user}@{target.host}:{target.port} failed: {exc}") from exc
    return client


def run_command(target: SSHTarget, command: str, timeout: int = 30) -> tuple[int, str, str]:
    client = _open_channel(target)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        stdin.close()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        client.close()


def from_dict(d: dict) -> SSHTarget:
    bastion = None
    if d.get("bastion"):
        bastion = from_dict(d["bastion"])
    key = d.get("key_filename")
    if key:
        key = str(Path(key).expanduser())
    return SSHTarget(
        host=d["host"],
        user=d.get("user", "root"),
        port=int(d.get("port", 22)),
        key_filename=key,
        password=d.get("password"),
        bastion=bastion,
        connect_timeout=int(d.get("connect_timeout", 10)),
    )
