"""Complex Event Processing (CEP) engine.

Consumes normalised events and:
  1. rebuilds process execution trees (process_tree.py)
  2. runs Sigma rules, behavioural sequence detectors and the anomaly model
  3. correlates SSH connections with sshd-spawned sessions on the target host
     to autonomously trace lateral movement across the fleet
  4. groups alerts into incidents (one incident = one attack story, which may
     span several hosts once lateral movement is detected)
"""
from __future__ import annotations

import itertools
import logging
import threading
import time
import uuid
from collections import deque

from . import config
from .anomaly import AnomalyModel, BehaviourDetector
from .bus import Bus
from .mitre import MitreMapper, default_mapper
from .process_tree import ProcessTreeStore, basename
from .sigma import LEVELS, SigmaEngine

log = logging.getLogger("soc.detector")

SEV_SCORE = {"informational": 1, "low": 5, "medium": 20, "high": 50, "critical": 90}
INCIDENT_WINDOW = 900          # seconds an open incident keeps absorbing alerts on a host
LATERAL_WINDOW = 20            # seconds between ssh connect and the remote session


class LateralMovementCorrelator:
    """Joins `tcp_connect(dst:22)` on host A with `sshd -> shell` on host B."""

    def __init__(self, trees: ProcessTreeStore, admin_sources: list[str]):
        self.trees = trees
        self.admin_sources = set(admin_sources)
        self.pending_connects: deque = deque(maxlen=5000)
        self.pending_sessions: deque = deque(maxlen=5000)

    def on_event(self, ev: dict) -> list[dict]:
        now = ev["ts_epoch"]
        edges = []
        if ev["type"] == "network_connect" and ev.get("dst_port") == 22 and ev.get("dst_host"):
            conn = {"ts": now, "src_host": ev["host"], "src_exec": ev["exec_id"],
                    "dst_host": ev["dst_host"], "src_binary": ev["binary"]}
            match = self._take(self.pending_sessions, lambda s: s["host"] == conn["dst_host"]
                               and abs(s["ts"] - now) < LATERAL_WINDOW)
            if match:
                edges.append(self._edge(conn, match))
            else:
                self.pending_connects.append(conn)
        elif ev["type"] == "process_exec" and basename(ev.get("parent_binary")) == "sshd" \
                and basename(ev.get("binary")) in ("bash", "sh", "zsh", "dash"):
            sess = {"ts": now, "host": ev["host"], "exec_id": ev["exec_id"], "uid": ev.get("uid")}
            match = self._take(self.pending_connects, lambda c: c["dst_host"] == sess["host"]
                               and abs(c["ts"] - now) < LATERAL_WINDOW)
            if match:
                edges.append(self._edge(match, sess))
            else:
                self.pending_sessions.append(sess)
        return edges

    @staticmethod
    def _take(dq: deque, pred):
        for item in dq:
            if pred(item):
                dq.remove(item)
                return item
        return None

    def _edge(self, conn: dict, sess: dict) -> dict:
        return {"src_host": conn["src_host"], "src_exec": conn["src_exec"],
                "dst_host": sess["host"], "dst_exec": sess["exec_id"], "ts": sess["ts"],
                "uid": sess.get("uid"), "legit_admin": conn["src_host"] in self.admin_sources}


class DetectionEngine:
    def __init__(self, bus: Bus | None = None, mapper: MitreMapper | None = None,
                 fleet: dict | None = None):
        self.bus = bus
        self.mapper = mapper or default_mapper()
        fleet = fleet or config.load_fleet()
        self.trees = ProcessTreeStore()
        self.sigma = SigmaEngine()
        self.behaviour = BehaviourDetector(self.trees)
        self.anomaly = AnomalyModel(self.trees)
        self.lateral = LateralMovementCorrelator(self.trees, fleet.get("admin_sources", []))
        self.incidents: dict[str, dict] = {}
        self.root_to_incident: dict[tuple[str, str], str] = {}
        self.alert_keys: set = set()
        self._seq = itertools.count(1)
        self.lock = threading.RLock()
        self.stats = {"events": 0, "alerts": 0, "start": time.time()}

    # --------------------------------------------------------------- training
    def train_baseline(self, baseline_events: list[dict]) -> None:
        tmp = ProcessTreeStore()
        saved, self.anomaly.trees = self.anomaly.trees, tmp
        for e in baseline_events:
            tmp.on_event(e)
        self.anomaly.fit(baseline_events)
        self.anomaly.trees = saved

    def reset(self) -> None:
        with self.lock:
            self.trees.nodes.clear()
            self.incidents.clear()
            self.root_to_incident.clear()
            self.alert_keys.clear()
            self.lateral.pending_connects.clear()
            self.lateral.pending_sessions.clear()
            self._seq = itertools.count(1)

    # ------------------------------------------------------------------- core
    def process(self, ev: dict) -> list[dict]:
        """Run the full CEP pipeline on one event; returns new alerts."""
        with self.lock:
            self.stats["events"] += 1
            self.trees.on_event(ev)
            candidates = []
            for rule in self.sigma.evaluate(ev):
                candidates.append({"rule_id": rule.id, "title": rule.title, "severity": rule.level,
                                   "technique_ids": rule.techniques, "description": rule.description,
                                   "source": "sigma", "rule_file": rule.source})
            candidates += self.behaviour.evaluate(ev)
            candidates += self.anomaly.score(ev)

            alerts = []
            for edge in self.lateral.on_event(ev):
                alerts += self._handle_edge(edge, ev)

            for c in candidates:
                key = (c["rule_id"], ev["host"], ev.get("exec_id"))
                if key in self.alert_keys:
                    continue
                self.alert_keys.add(key)
                alerts.append(self._make_alert(c, ev))
            return alerts

    def _make_alert(self, c: dict, ev: dict, root: tuple[str, str] | None = None,
                    incident_id: str | None = None) -> dict:
        rule_t = list(c["technique_ids"])
        ev_t = [t["id"] for t in ev.get("mitre", [])]
        confirmed = [t for t in rule_t if t in ev_t]
        # a rule tagged with several techniques is attributed only to the ones the kernel
        # event actually confirms (keeps the heatmap honest); otherwise use rule + event tags
        tech_ids = confirmed if confirmed else list(dict.fromkeys(rule_t + ev_t))
        host = ev["host"]
        root = root or (host, self.trees.attack_root(host, ev["exec_id"]))
        alert = {
            "id": "ALR-" + uuid.uuid4().hex[:10],
            "ts": ev["ts"], "ts_epoch": ev["ts_epoch"], "detected_at": time.time(),
            "host": host, "rule_id": c["rule_id"], "title": c["title"],
            "source": c["source"], "severity": c["severity"],
            "score": SEV_SCORE.get(c["severity"], 10),
            "description": c.get("description", ""),
            "techniques": [self.mapper.describe(t) for t in tech_ids],
            "exec_id": ev.get("exec_id"), "pid": ev.get("pid"), "uid": ev.get("uid"),
            "binary": ev.get("binary"), "cmdline": ev.get("cmdline"),
            "event_type": ev["type"], "event_id": ev["id"],
            "dst_ip": ev.get("dst_ip"), "dst_port": ev.get("dst_port"),
            "file_path": ev.get("file_path"),
            "root_exec_id": root[1], "root_host": root[0],
            "anomaly_score": c.get("anomaly_score"),
        }
        node = self.trees.get(host, ev.get("exec_id"))
        if node is not None:
            node["alerts"].append(alert["id"])
        alert["incident_id"] = self._assign_incident(alert, root, incident_id)
        self.stats["alerts"] += 1
        return alert

    # ------------------------------------------------------- lateral movement
    def _handle_edge(self, edge: dict, ev: dict) -> list[dict]:
        src_root = (edge["src_host"], self.trees.attack_root(edge["src_host"], edge["src_exec"]))
        dst_root = (edge["dst_host"], self.trees.attack_root(edge["dst_host"], edge["dst_exec"]))
        src_inc = self.root_to_incident.get(src_root)
        if edge["legit_admin"] and not src_inc:
            return []                              # normal admin session from the bastion
        c = {"rule_id": "CORR-LATERAL-SSH",
             "title": f"Lateral movement via SSH: {edge['src_host']} -> {edge['dst_host']}",
             "severity": "critical", "technique_ids": ["T1021.004"], "source": "correlation",
             "description": (f"Process {edge['src_exec']} on {edge['src_host']} opened SSH to "
                             f"{edge['dst_host']} and sshd spawned session {edge['dst_exec']} "
                             f"(uid {edge.get('uid')}) - process trees linked across hosts.")}
        # the alert lives on the destination session, inside the source's incident
        alert = self._make_alert(c, ev if ev["host"] == edge["dst_host"] else
                                 self._session_event(edge), root=dst_root, incident_id=src_inc)
        inc = self.incidents[alert["incident_id"]]
        self.root_to_incident[src_root] = inc["id"]
        if src_root not in [tuple(r) for r in inc["roots"]]:
            inc["roots"].append(list(src_root))
        if edge["src_host"] not in inc["hosts"]:
            inc["hosts"].append(edge["src_host"])
        inc["lateral_edges"].append(edge)
        self._publish_incident(inc)
        return [alert]

    def _session_event(self, edge):
        node = self.trees.get(edge["dst_host"], edge["dst_exec"]) or {}
        return {"host": edge["dst_host"], "exec_id": edge["dst_exec"], "ts_epoch": edge["ts"],
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(edge["ts"])) + "+00:00",
                "pid": node.get("pid"), "uid": node.get("uid"), "binary": node.get("binary"),
                "cmdline": node.get("binary"), "type": "process_exec", "id": "corr", "mitre": []}

    # -------------------------------------------------------------- incidents
    def _assign_incident(self, alert: dict, root: tuple[str, str], forced: str | None) -> str:
        inc_id = forced or self.root_to_incident.get(root)
        if inc_id is None:
            # join an open incident on the same host if it is recent
            for inc in sorted(self.incidents.values(), key=lambda i: -i["last_ts"]):
                if alert["host"] in inc["hosts"] and inc["status"] == "open" \
                        and alert["ts_epoch"] - inc["last_ts"] < INCIDENT_WINDOW \
                        and LEVELS.get(alert["severity"], 0) >= 2:
                    inc_id = inc["id"]
                    break
        if inc_id is None:
            if LEVELS.get(alert["severity"], 0) < 2:
                # low-severity noise does not open an incident on its own
                return None
            inc_id = f"INC-{next(self._seq):04d}"
            root_node = self.trees.get(*root) or {}
            self.incidents[inc_id] = {
                "id": inc_id, "status": "open", "title": alert["title"], "severity": alert["severity"],
                "score": 0, "hosts": [], "roots": [], "alerts": [], "techniques": [], "tactics": [],
                "lateral_edges": [], "created": time.time(),
                "first_event_ts": root_node.get("start") or alert["ts_epoch"],
                "first_alert_ts": alert["ts_epoch"], "first_detected_at": alert["detected_at"],
                "last_ts": alert["ts_epoch"],
            }
        inc = self.incidents[inc_id]
        self.root_to_incident[root] = inc_id
        if list(root) not in inc["roots"]:
            inc["roots"].append(list(root))
        if alert["host"] not in inc["hosts"]:
            inc["hosts"].append(alert["host"])
        inc["alerts"].append(alert["id"])
        inc["score"] += alert["score"]
        inc["last_ts"] = max(inc["last_ts"], alert["ts_epoch"])
        if LEVELS.get(alert["severity"], 0) > LEVELS.get(inc["severity"], 0):
            inc["severity"] = alert["severity"]
            inc["title"] = alert["title"]
        for t in alert["techniques"]:
            if t["id"] not in inc["techniques"]:
                inc["techniques"].append(t["id"])
            if t["tactic"] not in inc["tactics"]:
                inc["tactics"].append(t["tactic"])
        self._publish_incident(inc)
        return inc_id

    def _publish_incident(self, inc: dict) -> None:
        if self.bus:
            self.bus.publish(config.TOPIC_INCIDENTS, dict(inc), key=inc["id"])


def run(bus: Bus, baseline: list[dict] | None = None) -> DetectionEngine:
    """Service: soc.events -> soc.alerts + soc.incidents"""
    engine = DetectionEngine(bus)
    if baseline:
        engine.train_baseline(baseline)

    def handle(topic, msg):
        if topic == config.TOPIC_CONTROL:
            if msg.get("cmd") == "reset":
                engine.reset()
            return
        for alert in engine.process(msg):
            bus.publish(config.TOPIC_ALERTS, alert, key=alert["host"])

    bus.subscribe([config.TOPIC_EVENTS, config.TOPIC_CONTROL], handle, group="detector")
    log.info("detection engine running with %d sigma rules", len(engine.sigma.rules))
    return engine
