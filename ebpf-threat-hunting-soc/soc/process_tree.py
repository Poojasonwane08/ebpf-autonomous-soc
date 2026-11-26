"""Process execution trees rebuilt from disjoint kernel events.

Every eBPF event carries the Tetragon ``exec_id`` of the process and of its
parent. The store links them into per-host trees, attaches non-exec events
(network, file, ptrace, creds...) to the owning process, and answers the
questions the CEP engine needs: ancestors, descendants and the "attack root".
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

# Processes whose children are considered the start of a new "story".
# (a web shell's tree starts at the shell that php-fpm spawned, an SSH
#  session's tree starts at the shell that sshd spawned, and so on)
BOUNDARY_BINARIES = {
    "systemd", "init", "containerd-shim", "containerd-shim-runc-v2", "dockerd",
    "sshd", "cron", "crond", "nginx", "apache2", "httpd", "php-fpm", "php-fpm8.2",
    "gunicorn", "postgres", "kthreadd", "atd", "tetragon",
}

MAX_EVENTS_PER_NODE = 200
MAX_NODES = 60000


def basename(path: str | None) -> str:
    return (path or "").rstrip("/").rsplit("/", 1)[-1]


class ProcessTreeStore:
    def __init__(self) -> None:
        self.nodes: "OrderedDict[tuple[str, str], dict]" = OrderedDict()
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ ingest
    def _ensure(self, host: str, exec_id: str, **defaults) -> dict:
        key = (host, exec_id)
        node = self.nodes.get(key)
        if node is None:
            node = {"host": host, "exec_id": exec_id, "parent_exec_id": None, "pid": None,
                    "binary": "", "args": "", "uid": None, "start": None, "end": None,
                    "children": [], "events": [], "alerts": [], "techniques": [],
                    "status": "running", "placeholder": True}
            self.nodes[key] = node
        for k, v in defaults.items():
            if v is not None and (node.get(k) in (None, "") or node.get("placeholder")):
                node[k] = v
        return node

    def on_event(self, ev: dict) -> dict | None:
        host, exec_id = ev.get("host"), ev.get("exec_id")
        if not exec_id:
            return None
        with self.lock:
            if ev["type"] == "process_exec":
                node = self._ensure(host, exec_id)
                node.update(parent_exec_id=ev.get("parent_exec_id"), pid=ev.get("pid"),
                            binary=ev.get("binary", ""), args=ev.get("args", ""),
                            uid=ev.get("uid"), start=ev.get("ts_epoch"), placeholder=False,
                            cwd=ev.get("cwd"))
                pid_ = ev.get("parent_exec_id")
                if pid_:
                    parent = self._ensure(host, pid_, binary=ev.get("parent_binary"),
                                          pid=ev.get("parent_pid"))
                    if exec_id not in parent["children"]:
                        parent["children"].append(exec_id)
            else:
                node = self._ensure(host, exec_id, binary=ev.get("binary"), pid=ev.get("pid"),
                                    uid=ev.get("uid"))
                if node.get("parent_exec_id") is None and ev.get("parent_exec_id"):
                    node["parent_exec_id"] = ev["parent_exec_id"]
                    parent = self._ensure(host, ev["parent_exec_id"], binary=ev.get("parent_binary"))
                    if exec_id not in parent["children"]:
                        parent["children"].append(exec_id)
                if ev["type"] == "process_exit":
                    node["end"] = ev.get("ts_epoch")
                    if node["status"] == "running":
                        node["status"] = "exited"
                elif ev["type"] == "privilege_change" and ev.get("new_uid") is not None:
                    node["uid_after"] = ev["new_uid"]
            if len(node["events"]) < MAX_EVENTS_PER_NODE:
                node["events"].append(ev)
            for t in ev.get("mitre", []):
                if t["id"] not in node["techniques"]:
                    node["techniques"].append(t["id"])
            self._prune()
            return node

    def _prune(self) -> None:
        if len(self.nodes) <= MAX_NODES:
            return
        cutoff = time.time() - 900
        for key in list(self.nodes.keys())[: len(self.nodes) // 10]:
            n = self.nodes[key]
            if n["end"] and n["end"] < cutoff and not n["alerts"]:
                del self.nodes[key]

    # ----------------------------------------------------------------- queries
    def get(self, host: str, exec_id: str) -> dict | None:
        return self.nodes.get((host, exec_id))

    def ancestors(self, host: str, exec_id: str, limit: int = 64) -> list[dict]:
        out, seen = [], set()
        node = self.get(host, exec_id)
        while node and node.get("parent_exec_id") and len(out) < limit:
            pe = node["parent_exec_id"]
            if pe in seen:
                break
            seen.add(pe)
            node = self.get(host, pe)
            if node:
                out.append(node)
        return out

    def lineage_binaries(self, host: str, exec_id: str) -> list[str]:
        return [basename(n["binary"]) for n in self.ancestors(host, exec_id)]

    def attack_root(self, host: str, exec_id: str) -> str:
        """Highest ancestor below a boundary process (service daemon / init)."""
        with self.lock:
            node = self.get(host, exec_id)
            if node is None:
                return exec_id
            if basename(node["binary"]) in BOUNDARY_BINARIES:
                return exec_id
            root = node
            for anc in self.ancestors(host, exec_id):
                if basename(anc["binary"]) in BOUNDARY_BINARIES or anc.get("placeholder"):
                    break
                root = anc
            return root["exec_id"]

    def descendants(self, host: str, exec_id: str) -> list[dict]:
        out, stack, seen = [], [exec_id], set()
        while stack:
            eid = stack.pop()
            if eid in seen:
                continue
            seen.add(eid)
            node = self.get(host, eid)
            if node is None:
                continue
            out.append(node)
            stack.extend(node["children"])
        return out

    def subtree(self, host: str, exec_id: str, depth: int = 0) -> dict | None:
        node = self.get(host, exec_id)
        if node is None or depth > 40:
            return None
        return {
            "exec_id": node["exec_id"], "host": host, "pid": node["pid"],
            "binary": node["binary"], "args": node["args"], "uid": node["uid"],
            "uid_after": node.get("uid_after"), "status": node["status"],
            "start": node["start"], "alerts": list(node["alerts"]),
            "techniques": list(node["techniques"]),
            "children": [c for c in (self.subtree(host, ch, depth + 1) for ch in node["children"]) if c],
        }

    def set_status(self, host: str, exec_ids: list[str], status: str) -> None:
        with self.lock:
            for eid in exec_ids:
                n = self.get(host, eid)
                if n:
                    n["status"] = status
