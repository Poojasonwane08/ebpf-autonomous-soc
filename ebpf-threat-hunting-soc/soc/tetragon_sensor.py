"""LIVE mode sensor: real eBPF telemetry from Cilium Tetragon (Linux only).

* tails Tetragon's JSON export file (``--export-filename``) and publishes every
  event to ``ebpf.raw`` - the same topic the simulator uses
* keeps an exec_id -> pid map so SOAR actions can be executed on real PIDs
* ``LiveResponder`` executes SOAR actions on the host:
    freeze_process_tree  -> SIGSTOP every pid in the tree
    kill_process_tree    -> SIGKILL every pid in the tree
    isolate_host         -> nftables table dropping all traffic except the SOC IP
    block_ip             -> Tetragon TracingPolicy that SIGKILLs any process
                            calling tcp_connect() to that IP (in-kernel eBPF
                            enforcement), loaded with `tetra tracingpolicy add`
  LIVE_RESPONDER_DRY_RUN=true (default) only logs the commands it would run.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from . import config
from .bus import Bus

log = logging.getLogger("soc.tetragon")

BLOCK_POLICY = """apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: soc-block-{name}
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values:
        - "{ip}/32"
      matchActions:
      - action: Sigkill
"""


class LiveResponder:
    def __init__(self, dry_run: bool | None = None):
        self.dry_run = config.LIVE_RESPONDER_DRY_RUN if dry_run is None else dry_run
        self.procs: dict[str, dict] = {}      # exec_id -> {pid, parent_exec_id}
        self.lock = threading.Lock()

    def track(self, raw: dict):
        for kind in ("process_exec", "process_exit"):
            if kind in raw:
                p = raw[kind].get("process", {})
                with self.lock:
                    if kind == "process_exec":
                        self.procs[p.get("exec_id")] = {"pid": p.get("pid"),
                                                        "parent": p.get("parent_exec_id")}
                    else:
                        self.procs.pop(p.get("exec_id"), None)

    def tree_pids(self, root: str) -> list[int]:
        with self.lock:
            ids = {root}
            changed = True
            while changed:
                changed = False
                for eid, p in self.procs.items():
                    if p["parent"] in ids and eid not in ids:
                        ids.add(eid)
                        changed = True
            return [self.procs[e]["pid"] for e in ids if e in self.procs and self.procs[e]["pid"]]

    def _run(self, cmd: list[str], stdin: str | None = None) -> str:
        if self.dry_run:
            return "DRY-RUN: " + " ".join(cmd)
        out = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=10)
        return (out.stdout + out.stderr).strip() or "ok"

    def execute(self, action: dict) -> dict:
        t = action["type"]
        res = {"action_id": action["action_id"], "type": t, "host": action.get("host"),
               "status": "success", "ts": time.time()}
        try:
            if t in ("freeze_process_tree", "kill_process_tree"):
                pids = self.tree_pids(action.get("exec_id", ""))
                sig = signal.SIGSTOP if t.startswith("freeze") else signal.SIGKILL
                for pid in pids:
                    if self.dry_run:
                        continue
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        pass
                res["detail"] = f"{'DRY-RUN ' if self.dry_run else ''}{sig.name} -> pids {pids}"
                res["exec_ids"] = [action.get("exec_id")]
            elif t == "isolate_host":
                mgmt = config.load_fleet().get("soc_management_ip", "10.0.0.2")
                rules = (f"table inet soc_isolation {{ chain out {{ type filter hook output priority 0; "
                         f"policy drop; oif lo accept; ip daddr {mgmt} accept; }} "
                         f"chain in {{ type filter hook input priority 0; policy drop; iif lo accept; "
                         f"ip saddr {mgmt} accept; }} }}")
                res["detail"] = self._run(["nft", "-f", "-"], stdin=rules)
            elif t == "release_host":
                res["detail"] = self._run(["nft", "delete", "table", "inet", "soc_isolation"])
            elif t == "block_ip":
                ip = action["ip"]
                path = Path("/tmp") / f"soc-block-{ip.replace('.', '-')}.yaml"
                path.write_text(BLOCK_POLICY.format(name=ip.replace(".", "-"), ip=ip))
                res["detail"] = self._run(["tetra", "--server-address",
                                           os.environ.get("TETRA_SERVER", "localhost:54321"),
                                           "tracingpolicy", "add", str(path)])
            else:
                res["status"] = "ignored"
        except Exception as exc:
            res.update(status="failed", detail=str(exc))
        return res


def follow(path: str):
    """Yield new lines appended to a file (like `tail -F`), surviving rotation."""
    while not os.path.exists(path):
        log.info("waiting for Tetragon export file %s", path)
        time.sleep(2)
    fh = open(path, "r", encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    while True:
        line = fh.readline()
        if line:
            yield line
            continue
        time.sleep(0.1)
        try:
            if os.stat(path).st_ino != inode:
                fh.close()
                fh = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
        except FileNotFoundError:
            pass


def run(bus: Bus) -> LiveResponder:
    responder = LiveResponder()

    def handle(_topic, msg):
        if msg.get("execute", True) and msg.get("type") in (
                "freeze_process_tree", "kill_process_tree", "isolate_host", "release_host", "block_ip"):
            res = responder.execute(msg)
            bus.publish(config.TOPIC_ACTION_RESULTS, {"kind": "action_result", **res})

    bus.subscribe([config.TOPIC_ACTIONS], handle, group="sensor-tetragon")

    def pump():
        for line in follow(config.TETRAGON_EXPORT_FILE):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            responder.track(raw)
            bus.publish(config.TOPIC_RAW, raw, key=raw.get("node_name"))

    threading.Thread(target=pump, daemon=True, name="tetragon-tail").start()
    log.info("live Tetragon sensor tailing %s (responder dry_run=%s)",
             config.TETRAGON_EXPORT_FILE, responder.dry_run)
    return responder
