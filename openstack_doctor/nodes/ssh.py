"""Thin wrapper over paramiko for read-only remote diagnosis.

Design notes:

* One ``SSHClient`` per :class:`SSHTarget` per ``SSHSession`` lifetime; commands
  are issued via ``exec_command`` on the existing connection so we don't pay
  a TCP+SSH handshake per command. Bastion connections live on the same
  lifetime and are explicitly closed in ``__exit__``.
* Default host-key policy is *strict*: known_hosts must already trust the
  target. Pass ``insecure_host_key=True`` to fall back to ``AutoAddPolicy``
  (only for explicit opt-in by the user; the CLI gates this behind
  ``--insecure-ssh``). MITM-resistance > convenience for a tool that
  carries credentials into production.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
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
    bastion: SSHTarget | None = None
    connect_timeout: int = 10
    insecure_host_key: bool = False


class RemoteError(RuntimeError):
    pass


# Allow only conservative shell tokens for any value that is interpolated into
# a remote command line. Used to validate systemd unit names that arrive from
# user-supplied config.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.@:+-]+$")


def is_safe_shell_token(s: str) -> bool:
    """Return True iff ``s`` is safe to splice into a shell command literally."""
    return bool(s) and bool(_SAFE_TOKEN.match(s))


def _make_client(target: SSHTarget, sock=None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    # Strict by default: rely on the user's known_hosts. Only opt in to
    # auto-add when the caller explicitly accepts the MITM risk.
    try:
        client.load_system_host_keys()
    except Exception:
        pass
    if target.insecure_host_key:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

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
    except paramiko.BadHostKeyException as exc:
        raise RemoteError(
            f"SSH host key for {target.host} does not match known_hosts: {exc}. "
            "Update known_hosts or pass --insecure-ssh after verifying the host."
        ) from exc
    except paramiko.SSHException as exc:
        # A missing host key surfaces here under RejectPolicy.
        raise RemoteError(
            f"SSH connect to {target.user}@{target.host}:{target.port} failed: {exc}. "
            "If the host key is unknown, add it to known_hosts or pass --insecure-ssh."
        ) from exc
    except OSError as exc:
        raise RemoteError(
            f"SSH connect to {target.user}@{target.host}:{target.port} failed: {exc}"
        ) from exc
    return client


class SSHSession:
    """Reusable SSH session for a single :class:`SSHTarget`.

    Usage::

        with SSHSession(target) as sess:
            rc, out, err = sess.run("uptime")
            ...
    """

    def __init__(self, target: SSHTarget) -> None:
        self.target = target
        self._client: paramiko.SSHClient | None = None
        self._bastion_client: paramiko.SSHClient | None = None

    def open(self) -> SSHSession:
        if self._client is not None:
            return self
        sock = None
        if self.target.bastion is not None:
            self._bastion_client = _make_client(self.target.bastion)
            transport = self._bastion_client.get_transport()
            if transport is None:
                self.close()
                raise RemoteError("Failed to open bastion transport")
            try:
                sock = transport.open_channel(
                    "direct-tcpip",
                    (self.target.host, self.target.port),
                    ("127.0.0.1", 0),
                )
            except Exception as exc:
                self.close()
                raise RemoteError(f"Failed to open channel through bastion: {exc}") from exc
        try:
            self._client = _make_client(self.target, sock=sock)
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        if self._bastion_client is not None:
            try:
                self._bastion_client.close()
            except Exception:
                pass
            self._bastion_client = None

    def __enter__(self) -> SSHSession:
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def run(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        if self._client is None:
            self.open()
        assert self._client is not None
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        except (paramiko.SSHException, OSError) as exc:
            raise RemoteError(f"remote exec failed on {self.target.host}: {exc}") from exc


@contextmanager
def open_session(target: SSHTarget) -> Iterator[SSHSession]:
    """Context-managed SSH session that always closes its resources."""
    sess = SSHSession(target)
    try:
        sess.open()
        yield sess
    finally:
        sess.close()


def run_command(target: SSHTarget, command: str, timeout: int = 30) -> tuple[int, str, str]:
    """Backwards-compatible one-shot exec.

    Prefer :class:`SSHSession` / :func:`open_session` for multiple commands
    against the same host -- each call here pays a fresh handshake (and a
    fresh bastion handshake, if applicable).
    """
    with open_session(target) as sess:
        return sess.run(command, timeout=timeout)


def from_dict(d: dict) -> SSHTarget:
    if not isinstance(d, dict):
        raise ValueError("ssh target must be a mapping")
    if not d.get("host"):
        raise ValueError("ssh target requires a 'host' field")
    bastion = None
    if d.get("bastion"):
        bastion = from_dict(d["bastion"])
    key = d.get("key_filename")
    if key:
        key = str(Path(key).expanduser())
    return SSHTarget(
        host=str(d["host"]),
        user=str(d.get("user", "root")),
        port=int(d.get("port", 22)),
        key_filename=key,
        password=d.get("password"),
        bastion=bastion,
        connect_timeout=int(d.get("connect_timeout", 10)),
        insecure_host_key=bool(d.get("insecure_host_key", False)),
    )
