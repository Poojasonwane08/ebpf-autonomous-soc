"""Normalise raw Tetragon JSON events into one flat SOC event schema.

Raw input is the exact JSON that Tetragon writes with ``--export-filename``
(``process_exec``, ``process_exit``, ``process_kprobe``). The simulator emits
the same format, so live and simulated telemetry share one code path.

Normalised schema (all keys always present):
    id, ts, ts_epoch, host, type, exec_id, parent_exec_id, pid, uid,
    binary, args, cmdline, cwd, parent_binary, parent_pid,
    function, action, blocked,
    src_ip, src_port, dst_ip, dst_port, dst_host, dst_external,
    file_path, new_uid, ptrace_request, target_pid, memfd_name,
    mitre: [ {id, name, tactic, rule} ]
"""
from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone

from . import config
from .bus import Bus
from .mitre import MitreMapper, default_mapper

log = logging.getLogger("soc.normalizer")

PTRACE_REQUESTS = {0: "PTRACE_TRACEME", 1: "PTRACE_PEEKTEXT", 2: "PTRACE_PEEKDATA",
                   4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA", 7: "PTRACE_CONT",
                   12: "PTRACE_GETREGS", 13: "PTRACE_SETREGS", 16: "PTRACE_ATTACH",
                   17: "PTRACE_DETACH", 0x4206: "PTRACE_SEIZE"}

FILE_FUNCS = ("security_file_permission", "security_file_open", "fd_install",
              "security_mmap_file", "do_sys_open", "sys_openat")


def _strip_syscall(fn: str) -> str:
    for prefix in ("__x64_sys_", "__arm64_sys_", "__ia32_sys_", "sys_", "ksys_"):
        if fn.startswith(prefix):
            return fn[len(prefix):]
    return fn


def _parse_time(value) -> float:
    if not value:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).replace("Z", "+00:00")
    # Tetragon uses nanosecond precision; Python only parses microseconds.
    s = re.sub(r"(\.\d{1,6})\d*", r"\1", s, count=1)
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


class Normalizer:
    def __init__(self, mapper: MitreMapper | None = None, fleet: dict | None = None):
        self.mapper = mapper or default_mapper()
        fleet = fleet or config.load_fleet()
        self.ip_to_host = {h["ip"]: h["name"] for h in fleet.get("hosts", [])}
        self.internal = [ipaddress.ip_network(n) for n in fleet.get("internal_networks", [])]

    def is_external(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not any(addr in n for n in self.internal)

    def normalize(self, raw: dict) -> dict | None:
        kind = next((k for k in ("process_exec", "process_exit", "process_kprobe",
                                 "process_tracepoint") if k in raw), None)
        if kind is None:
            return None
        body = raw[kind] or {}
        proc = body.get("process") or {}
        parent = body.get("parent") or {}
        ts = _parse_time(raw.get("time"))
        binary = proc.get("binary", "")
        args = proc.get("arguments", "") or ""
        ev = {
            "id": uuid.uuid4().hex[:16],
            "ts": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
            "ts_epoch": ts,
            "host": raw.get("node_name", "unknown"),
            "type": kind,
            "exec_id": proc.get("exec_id"),
            "parent_exec_id": proc.get("parent_exec_id") or parent.get("exec_id"),
            "pid": proc.get("pid"),
            "uid": proc.get("uid"),
            "binary": binary,
            "args": args,
            "cmdline": f"{binary} {args}".strip(),
            "cwd": proc.get("cwd"),
            "parent_binary": parent.get("binary", ""),
            "parent_pid": parent.get("pid"),
            "function": None, "action": None, "blocked": False,
            "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None,
            "dst_host": None, "dst_external": None,
            "file_path": None, "new_uid": None, "ptrace_request": None,
            "target_pid": None, "memfd_name": None,
        }

        if kind == "process_kprobe":
            fn = body.get("function_name", "")
            short = _strip_syscall(fn)
            kargs = body.get("args") or []
            action = body.get("action", "")
            ev["function"] = fn
            ev["action"] = action
            ev["blocked"] = action in ("KPROBE_ACTION_SIGKILL", "KPROBE_ACTION_OVERRIDE")

            if short in ("tcp_connect", "tcp_v4_connect", "inet_csk_accept", "tcp_sendmsg"):
                sock = next((a.get("sock_arg") for a in kargs if "sock_arg" in a), {}) or {}
                ev["type"] = "network_blocked" if ev["blocked"] else "network_connect"
                ev["src_ip"], ev["src_port"] = sock.get("saddr"), sock.get("sport")
                ev["dst_ip"], ev["dst_port"] = sock.get("daddr"), sock.get("dport")
                ev["dst_host"] = self.ip_to_host.get(ev["dst_ip"])
                ev["dst_external"] = self.is_external(ev["dst_ip"])
            elif short == "commit_creds":
                cred = next((a.get("process_credentials_arg") for a in kargs
                             if "process_credentials_arg" in a), {}) or {}
                ev["type"] = "privilege_change"
                ev["new_uid"] = cred.get("euid", cred.get("uid"))
            elif short in ("setuid", "setreuid", "setresuid"):
                ev["type"] = "setuid"
                ev["new_uid"] = next((a.get("int_arg") for a in kargs if "int_arg" in a), None)
            elif short == "ptrace":
                ints = [a.get("int_arg", a.get("long_arg")) for a in kargs
                        if "int_arg" in a or "long_arg" in a]
                req = ints[0] if ints else None
                ev["type"] = "ptrace"
                ev["ptrace_request"] = PTRACE_REQUESTS.get(req, str(req))
                ev["target_pid"] = ints[1] if len(ints) > 1 else None
            elif short in ("memfd_create",):
                ev["type"] = "memfd_create"
                ev["memfd_name"] = next((a.get("string_arg") for a in kargs if "string_arg" in a), None)
            elif short in FILE_FUNCS or any("file_arg" in a for a in kargs):
                f = next((a.get("file_arg") for a in kargs if "file_arg" in a), {}) or {}
                ev["type"] = "file_access"
                ev["file_path"] = f.get("path") or next(
                    (a.get("string_arg") for a in kargs if "string_arg" in a), None)
            else:
                ev["type"] = f"kprobe:{short}"

        ev["mitre"] = self.mapper.map_event(ev)
        return ev


def run(bus: Bus) -> Normalizer:
    """Service: ebpf.raw -> soc.events"""
    norm = Normalizer()

    def handle(_topic, raw):
        ev = norm.normalize(raw)
        if ev:
            bus.publish(config.TOPIC_EVENTS, ev, key=ev["host"])

    bus.subscribe([config.TOPIC_RAW], handle, group="normalizer")
    log.info("normalizer running")
    return norm
