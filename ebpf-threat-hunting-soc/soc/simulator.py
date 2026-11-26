"""eBPF telemetry simulator for a fleet of Linux servers.

Produces the *exact* JSON shape Tetragon exports (process_exec, process_exit,
process_kprobe with sock/file/cred/int args) so the rest of the pipeline is
identical in simulated and live mode. Also:

* generates benign background activity (cron, health checks, admin SSH
  sessions from the bastion, backups, package updates, app -> db traffic)
* plays adversary-emulation scenarios (scenarios/*.yml), Caldera-style
* enforces SOAR response actions it receives (freeze / kill process trees,
  isolate hosts, block IPs) so that a contained attack *really* stops: later
  scenario steps that depend on a frozen process or an isolated network fail,
  and blocked connections show up as Tetragon SIGKILL enforcement events.
"""
from __future__ import annotations

import base64
import itertools
import logging
import random
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .bus import Bus

log = logging.getLogger("soc.simulator")


def _now_iso(ts: float | None = None) -> str:
    ts = ts or host_clock()
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


_virtual_clock: list[float | None] = [None]


def host_clock() -> float:
    """Wall clock, or a virtual clock while generating offline baselines."""
    return _virtual_clock[0] if _virtual_clock[0] is not None else time.time()


class SimProcess:
    __slots__ = ("host", "exec_id", "pid", "binary", "args", "uid", "cwd", "parent",
                 "start", "state", "scenario")

    def __init__(self, host, exec_id, pid, binary, args, uid, cwd, parent, scenario=None):
        self.host, self.exec_id, self.pid = host, exec_id, pid
        self.binary, self.args, self.uid, self.cwd = binary, args, uid, cwd
        self.parent: SimProcess | None = parent
        self.start = host_clock()
        self.state = "running"          # running | exited | frozen | killed
        self.scenario = scenario

    def to_json(self) -> dict:
        return {
            "exec_id": self.exec_id, "pid": self.pid, "tid": self.pid, "uid": self.uid,
            "auid": 4294967295 if self.uid == 0 else self.uid, "cwd": self.cwd,
            "binary": self.binary, "arguments": self.args, "flags": "execve clone",
            "start_time": _now_iso(self.start),
            "parent_exec_id": self.parent.exec_id if self.parent else None,
        }

    def lineage(self):
        p = self
        while p:
            yield p
            p = p.parent


class SimHost:
    def __init__(self, spec: dict, sim: "FleetSimulator"):
        self.name, self.ip, self.role = spec["name"], spec["ip"], spec.get("role", "")
        self.sim = sim
        self.pids = itertools.count(random.randint(900, 1500))
        self.procs: dict[str, SimProcess] = {}
        self.isolated = False
        self.ktime = itertools.count(1)
        self.init = self.spawn(None, "/usr/lib/systemd/systemd", "--system", 0, "/", pid=1)
        self.daemons: dict[str, SimProcess] = {
            "systemd": self.init,
            "sshd": self.spawn(self.init, "/usr/sbin/sshd", "-D", 0, "/"),
            "cron": self.spawn(self.init, "/usr/sbin/cron", "-f", 0, "/"),
        }
        svc = {"nginx": ("/usr/sbin/nginx", "-g daemon off;", 0, "/"),
               "php-fpm": ("/usr/sbin/php-fpm8.2", "--nodaemonize", 33, "/var/www/html"),
               "gunicorn": ("/usr/local/bin/gunicorn", "api:app -w 4 -b 0.0.0.0:8000", 1001, "/srv/api"),
               "postgres": ("/usr/lib/postgresql/16/bin/postgres", "-D /var/lib/postgresql/16/main",
                            999, "/var/lib/postgresql")}
        for s in spec.get("services", []):
            if s in svc:
                b, a, u, c = svc[s]
                self.daemons[s] = self.spawn(self.init, b, a, u, c)

    def spawn(self, parent, binary, args, uid, cwd, pid=None, scenario=None) -> SimProcess:
        pid = pid or next(self.pids)
        raw_id = f"{self.name}:{next(self.ktime) * 1000003}:{pid}"
        exec_id = base64.b64encode(raw_id.encode()).decode()
        p = SimProcess(self.name, exec_id, pid, binary, args, uid, cwd, parent, scenario)
        self.procs[exec_id] = p
        self.sim.emit({"process_exec": {"process": p.to_json(),
                                        "parent": parent.to_json() if parent else {}},
                       "node_name": self.name, "time": _now_iso(host_clock())})
        return p

    def exit(self, p: SimProcess, status=0, signal=""):
        if p.state in ("exited", "killed"):
            return
        p.state = "killed" if signal else "exited"
        self.sim.emit({"process_exit": {"process": p.to_json(),
                                        "parent": p.parent.to_json() if p.parent else {},
                                        "signal": signal, "status": status},
                       "node_name": self.name, "time": _now_iso(host_clock())})
        if not signal:
            self.procs.pop(p.exec_id, None)

    def kprobe(self, p: SimProcess, function: str, args: list, action="KPROBE_ACTION_POST",
               policy="soc-default"):
        self.sim.emit({"process_kprobe": {"process": p.to_json(),
                                          "parent": p.parent.to_json() if p.parent else {},
                                          "function_name": function, "args": args,
                                          "action": action, "policy_name": policy},
                       "node_name": self.name, "time": _now_iso(host_clock())})

    def connect(self, p: SimProcess, dst_ip: str, dport: int) -> bool:
        """Returns False when the connection was blocked by an enforcement policy."""
        sock = {"family": "AF_INET", "type": "SOCK_STREAM", "protocol": "IPPROTO_TCP",
                "saddr": self.ip, "daddr": dst_ip, "sport": random.randint(32768, 60999),
                "dport": dport}
        blocked = (self.isolated and dst_ip not in (self.sim.mgmt_ip, "127.0.0.1")) \
            or dst_ip in self.sim.blocked_ips
        dst_host = self.sim.ip_to_host.get(dst_ip)
        if dst_host and self.sim.hosts[dst_host].isolated:
            blocked = True
        if blocked:
            self.kprobe(p, "tcp_connect", [{"sock_arg": sock}], action="KPROBE_ACTION_SIGKILL",
                        policy="soc-isolation" if self.isolated or dst_host else "soc-block-ip")
            self.exit(p, status=137, signal="SIGKILL")   # Tetragon Sigkill enforcement
            return False
        self.kprobe(p, "tcp_connect", [{"sock_arg": sock}], policy="soc-network")
        return True

    def file(self, p: SimProcess, path: str, mask=4):
        self.kprobe(p, "security_file_permission",
                    [{"file_arg": {"path": path}}, {"int_arg": mask}], policy="soc-sensitive-files")


class FleetSimulator:
    def __init__(self, bus: Bus | None, fleet: dict | None = None, seed: int | None = None):
        self.bus = bus
        self.fleet = fleet or config.load_fleet()
        self.rng = random.Random(seed)
        self.mgmt_ip = self.fleet.get("soc_management_ip", "10.0.0.2")
        self.ip_to_host = {h["ip"]: h["name"] for h in self.fleet["hosts"]}
        self.blocked_ips: set[str] = set()
        self.buffer: list[dict] | None = None      # used for offline baseline generation
        self.lock = threading.RLock()
        self.hosts: dict[str, SimHost] = {}
        self.scenario_runs: dict[str, dict] = {}
        self._stop = threading.Event()
        self._build_hosts()

    def _build_hosts(self):
        self.hosts = {h["name"]: SimHost(h, self) for h in self.fleet["hosts"]}

    # ------------------------------------------------------------------ output
    def emit(self, raw: dict):
        if self.buffer is not None:
            self.buffer.append(raw)
        elif self.bus:
            self.bus.publish(config.TOPIC_RAW, raw, key=raw.get("node_name"))

    # -------------------------------------------------------------- benign
    def benign_activity(self):
        r = self.rng
        name = r.choice(list(self.hosts))
        h = self.hosts[name]
        kind = r.choices(["cron", "health", "monitor", "app_db", "admin", "backup", "apt", "logrotate"],
                         weights=[18, 25, 18, 20, 6, 4, 2, 7])[0]
        with self.lock:
            if kind == "cron":
                sh = h.spawn(h.daemons["cron"], "/bin/sh", "-c run-parts --report /etc/cron.hourly", 0, "/")
                c = h.spawn(sh, "/usr/bin/run-parts", "--report /etc/cron.hourly", 0, "/")
                h.exit(c), h.exit(sh)
            elif kind == "health":
                c = h.spawn(h.init, "/usr/bin/curl", "-fsS http://127.0.0.1/healthz", 0, "/")
                h.connect(c, "127.0.0.1", 80)
                h.exit(c)
            elif kind == "monitor":
                agent = h.spawn(h.init, "/usr/bin/python3", "/opt/monitor/agent.py --once", 0, "/opt/monitor")
                for b, a in r.sample([("/usr/bin/df", "-h"), ("/usr/bin/free", "-m"),
                                      ("/usr/bin/uptime", ""), ("/usr/bin/ps", "aux --sort=-%cpu")], 2):
                    c = h.spawn(agent, b, a, 0, "/opt/monitor")
                    h.exit(c)
                h.connect(agent, self.mgmt_ip, 9100)
                h.exit(agent)
            elif kind == "app_db" and "gunicorn" in h.daemons:
                w = h.spawn(h.daemons["gunicorn"], "/usr/bin/python3", "-m api.worker --job sync", 1001, "/srv/api")
                h.connect(w, "10.0.3.31", 5432)
                h.exit(w)
            elif kind == "backup" and "postgres" in h.daemons:
                sh = h.spawn(h.daemons["cron"], "/bin/sh", "-c /usr/local/bin/pg-backup.sh", 999, "/var/lib/postgresql")
                d = h.spawn(sh, "/usr/lib/postgresql/16/bin/pg_dump", "-Fc appdb -f /backup/appdb.dump", 999, "/var/lib/postgresql")
                h.exit(d), h.exit(sh)
            elif kind == "apt":
                a = h.spawn(h.init, "/usr/bin/apt-get", "update -qq", 0, "/")
                h.connect(a, "91.189.91.83", 80)
                h.exit(a)
            elif kind == "logrotate":
                lr = h.spawn(h.daemons["cron"], "/usr/sbin/logrotate", "/etc/logrotate.conf", 0, "/")
                h.file(lr, "/var/log/syslog", 2)
                h.exit(lr)
            elif kind == "admin":
                self._admin_session(r)

    def _admin_session(self, r):
        bastion = self.hosts.get("bastion-01")
        targets = [n for n in self.hosts if n != "bastion-01"]
        if not bastion or not targets:
            return
        dst = self.hosts[r.choice(targets)]
        shell = bastion.spawn(bastion.daemons["sshd"], "/bin/bash", "-l", 1000, "/home/admin")
        ssh = bastion.spawn(shell, "/usr/bin/ssh", f"admin@{dst.name}", 1000, "/home/admin")
        bastion.file(ssh, "/home/admin/.ssh/id_ed25519")
        if bastion.connect(ssh, dst.ip, 22):
            rs = dst.spawn(dst.daemons["sshd"], "/bin/bash", "-l", 1000, "/home/admin")
            for b, a in r.sample([("/usr/bin/systemctl", "status nginx"), ("/usr/bin/df", "-h"),
                                  ("/usr/bin/tail", "-n 50 /var/log/syslog"), ("/usr/bin/ls", "-la"),
                                  ("/usr/bin/uptime", "")], 3):
                c = dst.spawn(rs, b, a, 1000, "/home/admin")
                dst.exit(c)
            dst.exit(rs)
        bastion.exit(ssh), bastion.exit(shell)

    def generate_baseline(self, n_activities: int = 3000) -> list[dict]:
        """Offline benign telemetry for training the anomaly model."""
        with self.lock:
            self.buffer = []
            saved_hosts = self.hosts
            _virtual_clock[0] = time.time() - n_activities * 0.2
            try:
                self._build_hosts()             # fresh daemons go into the buffer too
                for _ in range(n_activities):
                    _virtual_clock[0] += self.rng.uniform(0.05, 0.25)   # ~BACKGROUND_EPS pacing
                    self.benign_activity()
            finally:
                _virtual_clock[0] = None
            out, self.buffer = self.buffer, None
            self.hosts = saved_hosts
        return out

    def run_background(self, eps: float):
        """Loop emitting roughly `eps` raw events per second until stopped."""
        if eps <= 0:
            return
        per_activity = 3.0                      # avg raw events per benign activity
        delay = per_activity / eps
        while not self._stop.is_set():
            self.benign_activity()
            time.sleep(delay * self.rng.uniform(0.5, 1.5))

    # ------------------------------------------------------------ scenarios
    def run_scenario(self, scenario: dict, speed: float | None = None, run_id: str | None = None,
                     progress=None) -> dict:
        speed = speed or config.SCENARIO_SPEED
        run_id = run_id or f"RUN-{int(time.time())}"
        refs: dict[str, SimProcess] = {}
        status = {"run_id": run_id, "scenario": scenario["name"], "title": scenario.get("title", ""),
                  "started": time.time(), "finished": None, "steps": []}
        self.scenario_runs[run_id] = status
        for i, step in enumerate(scenario["steps"]):
            time.sleep(step.get("delay", 1.0) / speed)
            if self._stop.is_set():
                break
            with self.lock:
                result, detail = self._play_step(step, refs, run_id)
            status["steps"].append({"n": i + 1, "id": step.get("id"), "name": step.get("name", step["action"]),
                                    "host": step["host"], "technique": step.get("technique"),
                                    "result": result, "detail": detail, "ts": time.time()})
            if progress:
                progress(status)
        status["finished"] = time.time()
        if progress:
            progress(status)
        return status

    def _resolve(self, ref: str | None, host: SimHost, refs: dict) -> SimProcess | None:
        if ref is None:
            return None
        if ref.startswith("@"):
            return host.daemons.get(ref[1:])
        return refs.get(ref)

    def _play_step(self, step: dict, refs: dict, run_id: str) -> tuple[str, str]:
        host = self.hosts[step["host"]]
        act = step["action"]
        actor_ref = step.get("parent") if act == "exec" else step.get("proc")
        actor = self._resolve(actor_ref, host, refs)
        if actor_ref and actor is None:
            return "prevented", f"dependency '{actor_ref}' does not exist (earlier step was stopped)"
        if actor is not None:
            for p in actor.lineage():
                if p.state in ("frozen", "killed"):
                    return "prevented", f"process tree {p.binary} (pid {p.pid}) is {p.state} by SOAR"

        if act == "exec":
            p = host.spawn(actor, step["binary"], step.get("args", ""), step.get("uid", actor.uid if actor else 0),
                           step.get("cwd", actor.cwd if actor else "/"), scenario=run_id)
            if step.get("id"):
                refs[step["id"]] = p
            if step.get("exit"):
                host.exit(p)
            return "executed", f"{p.binary} {p.args}".strip()
        if act == "file":
            host.file(actor, step["path"], step.get("mask", 4))
            return "executed", f"read {step['path']}"
        if act == "connect":
            ip = step.get("dst_ip") or self.hosts[step["dst_host"]].ip
            ok = host.connect(actor, ip, int(step["dport"]))
            return ("executed", f"connected to {ip}:{step['dport']}") if ok else \
                   ("blocked", f"connection to {ip}:{step['dport']} killed by eBPF enforcement")
        if act == "memfd":
            host.kprobe(actor, "__x64_sys_memfd_create",
                        [{"string_arg": step.get("name", "")}, {"int_arg": 1}], policy="soc-fileless")
            return "executed", f"memfd_create('{step.get('name', '')}')"
        if act == "ptrace":
            target = self._resolve(step["target"], host, refs)
            tpid = target.pid if target else 0
            for req in step.get("requests", [16, 4, 4, 17]):
                host.kprobe(actor, "__x64_sys_ptrace", [{"int_arg": req}, {"int_arg": tpid}],
                            policy="soc-injection")
            return "executed", f"ptrace into pid {tpid} ({target.binary if target else '?'})"
        if act == "privesc":
            host.kprobe(actor, "commit_creds", [{"process_credentials_arg": {
                "uid": 0, "gid": 0, "euid": 0, "egid": 0, "suid": 0, "sgid": 0, "fsuid": 0, "fsgid": 0}}],
                policy="soc-privileges")
            actor.uid = 0
            return "executed", f"{actor.binary} credentials changed to uid 0"
        if act == "ssh_pivot":
            dst = self.hosts[step["dst_host"]]
            ok = host.connect(actor, dst.ip, 22)
            if not ok:
                return "blocked", f"SSH to {dst.name} killed by eBPF network isolation"
            sess = dst.spawn(dst.daemons["sshd"], "/bin/bash", "-i", step.get("uid", 1000),
                             step.get("cwd", "/home/deploy"), scenario=run_id)
            if step.get("id"):
                refs[step["id"]] = sess
            return "executed", f"SSH session opened on {dst.name}"
        raise ValueError(f"unknown scenario action {act}")

    # -------------------------------------------------------------- response
    def apply_action(self, action: dict) -> dict:
        """Execute a SOAR action against the simulated fleet."""
        t = action["type"]
        res = {"action_id": action["action_id"], "type": t, "host": action.get("host"),
               "status": "success", "detail": "", "ts": time.time()}
        with self.lock:
            host = self.hosts.get(action.get("host") or "")
            if t in ("freeze_process_tree", "kill_process_tree"):
                if not host:
                    return res | {"status": "failed", "detail": "unknown host"}
                root = host.procs.get(action.get("exec_id"))
                if not root:
                    return res | {"status": "noop", "detail": "process already gone"}
                tree = [p for p in host.procs.values() if any(a is root for a in p.lineage())]
                affected = []
                for p in tree:
                    if p.state != "running":
                        continue
                    if t == "kill_process_tree":
                        host.exit(p, status=137, signal="SIGKILL")
                    else:
                        p.state = "frozen"
                    affected.append(p)
                verb = "SIGKILL" if t == "kill_process_tree" else "SIGSTOP (cgroup freeze)"
                res["detail"] = (f"{verb} sent to {len(affected)} running process(es) in the tree rooted "
                                 f"at {root.binary} pid {root.pid}")
                res["exec_ids"] = [p.exec_id for p in affected]
            elif t == "isolate_host":
                if not host:
                    return res | {"status": "failed", "detail": "unknown host"}
                host.isolated = True
                res["detail"] = (f"{host.name} isolated: eBPF policy SIGKILLs every tcp_connect except "
                                 f"management {self.mgmt_ip}")
            elif t == "release_host":
                if host:
                    host.isolated = False
                    for p in host.procs.values():
                        if p.state == "frozen":
                            p.state = "running"
                res["detail"] = f"{action.get('host')} released from isolation"
            elif t == "block_ip":
                self.blocked_ips.add(action["ip"])
                res["detail"] = f"{action['ip']} added to eBPF blocklist (fleet-wide)"
            else:
                res["status"] = "ignored"
        return res

    def reset(self):
        with self.lock:
            self.blocked_ips.clear()
            for h in self.hosts.values():
                h.isolated = False
                for eid, p in list(h.procs.items()):
                    if p.scenario:
                        h.procs.pop(eid, None)
                    elif p.state == "frozen":
                        p.state = "running"

    def stop(self):
        self._stop.set()


def load_scenarios() -> dict[str, dict]:
    out = {}
    for path in sorted(Path(config.SCENARIO_DIR).glob("*.yml")):
        data = config.load_yaml(path)
        out[data["name"]] = data
    return out


def run(bus: Bus, eps: float | None = None) -> FleetSimulator:
    """Service: simulated eBPF sensor fleet."""
    sim = FleetSimulator(bus)
    scenarios = load_scenarios()

    def progress(status):
        bus.publish(config.TOPIC_ACTION_RESULTS, {"kind": "scenario_progress", **status})

    def handle(topic, msg):
        if topic == config.TOPIC_ACTIONS:
            if msg.get("type") in ("freeze_process_tree", "kill_process_tree", "isolate_host",
                                   "release_host", "block_ip") and msg.get("execute", True):
                res = sim.apply_action(msg)
                bus.publish(config.TOPIC_ACTION_RESULTS, {"kind": "action_result", **res})
        elif topic == config.TOPIC_CONTROL:
            cmd = msg.get("cmd")
            if cmd == "run_scenario":
                sc = scenarios.get(msg.get("scenario"))
                if sc:
                    threading.Thread(target=sim.run_scenario,
                                     kwargs={"scenario": sc, "speed": msg.get("speed"),
                                             "run_id": msg.get("run_id"), "progress": progress},
                                     daemon=True).start()
            elif cmd == "reset":
                sim.reset()

    bus.subscribe([config.TOPIC_ACTIONS, config.TOPIC_CONTROL], handle, group="sensor-sim")
    threading.Thread(target=sim.run_background, args=(eps if eps is not None else config.BACKGROUND_EPS,),
                     daemon=True, name="background").start()
    log.info("simulated sensor fleet running: %s", ", ".join(sim.hosts))
    return sim
