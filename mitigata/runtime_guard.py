"""CPython worker egress guard. This is not a sandbox for hostile native extensions."""

from __future__ import annotations

import contextvars
import socket
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass

from .scope import ScopeDenied


@dataclass(frozen=True)
class WorkerNetworkPolicy:
    broker_id: int
    denied: Callable[[str], None]


worker_network_policy: contextvars.ContextVar[WorkerNetworkPolicy | None] = contextvars.ContextVar(
    "worker_network_policy", default=None
)
connection_permit: contextvars.ContextVar[tuple | None] = contextvars.ContextVar(
    "connection_permit", default=None
)
tool_launch_permit: contextvars.ContextVar[tuple | None] = contextvars.ContextVar(
    "tool_launch_permit", default=None
)
_installed = False
_install_lock = threading.Lock()


def _audit(event, args):
    policy = worker_network_policy.get()
    if policy is None:
        return
    reason = None
    if (
        event == "subprocess.Popen"
        and tool_launch_permit.get() is not None
        and tuple(args[1]) == tool_launch_permit.get()
    ):
        return
    if event in {
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.sendto",
        "socket.sendmsg",
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
    }:
        reason = f"Unregistered worker operation: {event}"
    elif event == "socket.__new__":
        _, family, kind, _ = args
        if family in {socket.AF_INET, socket.AF_INET6} and kind & 0xF != socket.SOCK_STREAM:
            reason = "Worker UDP/raw sockets are not supported"
    elif event == "socket.connect":
        sock, address = args
        if sock.family in {socket.AF_INET, socket.AF_INET6}:
            permit = connection_permit.get()
            if not permit or permit != (policy.broker_id, str(address[0]), int(address[1])):
                reason = "Worker connection bypassed the scope broker"
    if reason:
        policy.denied(reason)
        raise ScopeDenied(reason)


def install_worker_guard():
    global _installed
    with _install_lock:
        if not _installed:
            sys.addaudithook(_audit)
            _installed = True
