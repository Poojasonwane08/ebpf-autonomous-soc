"""SOC investigation dashboard: state aggregation + REST API + web UI.

The dashboard service consumes every SOC topic, keeps an investigation-ready
view (process trees, alerts, incidents, response actions, MITRE heatmap,
fleet status, KPIs), runs evidence collection, and serves the single-page UI
in soc/web/.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import Counter, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, forensics
from .bus import Bus
from .mitre import default_mapper
from .process_tree import ProcessTreeStore
from .sigma import SigmaEngine
from .soar import CONTAINMENT, load_playbooks

log = logging.getLogger("soc.dashboard")
WEB_DIR = Path(__file__).parent / "web"


class SocState:
    def __init__(self, bus: Bus | None = None):
        self.bus = bus
        self.lock = threading.RLock()
        self.mapper = default_mapper()
        self.fleet = config.load_fleet()
        self.mode = config.RESPONSE_MODE
        self.reset()

    def reset(self):
        with getattr(self, "lock", threading.RLock()):
            self.trees = ProcessTreeStore()
            self.recent = deque(maxlen=300)
            self.total_events = 0
            self.by_type = Counter()
            self.eps_window = deque()
            self.alerts: list[dict] = []
            self.incidents: dict[str, dict] = {}
            self.actions: dict[str, dict] = {}
            self.results: dict[str, dict] = {}
            self.runs: dict[str, dict] = {}
            self.rule_hits = Counter()
            self.technique_hits = Counter()
            self.blocked_ips: set[str] = set()
            self.evidence: dict[str, str] = {}
            self.hosts = {h["name"]: {"name": h["name"], "ip": h["ip"], "role": h.get("role", ""),
                                      "isolated": False, "events": 0, "alerts": 0, "last_seen": None,
                                      "frozen": 0, "killed": 0}
                          for h in self.fleet["hosts"]}

    # ------------------------------------------------------------- consumers
    def on_message(self, topic: str, msg: dict):
        with self.lock:
            if topic == config.TOPIC_EVENTS:
                self._on_event(msg)
            elif topic == config.TOPIC_ALERTS:
                self.alerts.append(msg)
                if len(self.alerts) > 3000:
                    self.alerts = self.alerts[-3000:]
                self.rule_hits[(msg["rule_id"], msg["title"], msg["severity"], msg["source"])] += 1
                for t in msg["techniques"]:
                    self.technique_hits[t["id"]] += 1
                h = self.hosts.get(msg["host"])
                if h:
                    h["alerts"] += 1
                node = self.trees.get(msg["host"], msg.get("exec_id"))
                if node is not None and msg["id"] not in node["alerts"]:
                    node["alerts"].append(msg["id"])
            elif topic == config.TOPIC_INCIDENTS:
                prev = self.incidents.get(msg["id"], {})
                msg["status"] = prev.get("status", msg.get("status", "open"))
                for k in ("contained_ts", "contained_by"):
                    if k in prev:
                        msg[k] = prev[k]
                self.incidents[msg["id"]] = msg
            elif topic == config.TOPIC_ACTIONS:
                self.actions[msg["action_id"]] = {**self.actions.get(msg["action_id"], {}), **msg}
                if msg["type"] == "collect_evidence":
                    threading.Thread(target=self._collect_evidence, args=(msg,), daemon=True).start()
            elif topic == config.TOPIC_ACTION_RESULTS:
                if msg.get("kind") == "scenario_progress":
                    self.runs[msg["run_id"]] = msg
                else:
                    self._on_result(msg)
            elif topic == config.TOPIC_CONTROL:
                if msg.get("cmd") == "set_mode":
                    self.mode = msg["mode"]

    def _on_event(self, ev: dict):
        self.total_events += 1
        self.by_type[ev["type"]] += 1
        now = time.time()
        self.eps_window.append(now)
        while self.eps_window and now - self.eps_window[0] > 10:
            self.eps_window.popleft()
        self.trees.on_event(ev)
        h = self.hosts.setdefault(ev["host"], {"name": ev["host"], "ip": ev.get("src_ip") or "?",
                                               "role": "discovered", "isolated": False, "events": 0,
                                               "alerts": 0, "last_seen": None, "frozen": 0, "killed": 0})
        h["events"] += 1
        h["last_seen"] = ev["ts_epoch"]
        self.recent.append({k: ev.get(k) for k in ("ts_epoch", "host", "type", "pid", "uid", "cmdline",
                                                    "dst_ip", "dst_port", "file_path", "new_uid",
                                                    "ptrace_request", "memfd_name", "action")}
                           | {"mitre": [t["id"] for t in ev.get("mitre", [])]})

    def _on_result(self, res: dict):
        aid = res["action_id"]
        self.results[aid] = res
        act = self.actions.get(aid)
        if not act:
            return
        act["state"] = res.get("status", "done")
        act["completed_at"] = res.get("ts")
        if act.get("issued_at") and res.get("ts"):
            act["latency_ms"] = round((res["ts"] - act["issued_at"]) * 1000, 1)
        if act.get("alert_event_ts") and res.get("ts"):
            act["kernel_to_response_ms"] = round((res["ts"] - act["alert_event_ts"]) * 1000, 1)
        host = self.hosts.get(act.get("host") or "")
        t = act["type"]
        if res.get("status") == "success":
            if t == "isolate_host" and host:
                host["isolated"] = True
            elif t == "release_host" and host:
                host["isolated"] = False
                host["frozen"] = 0
            elif t == "block_ip":
                self.blocked_ips.add(act.get("ip"))
            elif t in ("freeze_process_tree", "kill_process_tree") and host:
                ids = res.get("exec_ids", [])
                host["frozen" if t.startswith("freeze") else "killed"] += len(ids)
                self.trees.set_status(act["host"], ids, "frozen" if t.startswith("freeze") else "killed")
            if t in ("freeze_process_tree", "kill_process_tree", "isolate_host"):
                inc = self.incidents.get(act.get("incident_id") or "")
                if inc and inc.get("status") != "contained":
                    inc["status"] = "contained"
                    inc["contained_ts"] = res["ts"]
                    inc["contained_by"] = act["playbook"]

    # -------------------------------------------------------------- evidence
    def incident_bundle(self, inc_id: str) -> dict:
        with self.lock:
            inc = self.incidents.get(inc_id)
            if not inc:
                raise KeyError(inc_id)
            return forensics.build_timeline(inc, self.trees, list(self.alerts),
                                            list(self.actions.values()), dict(self.results))

    def _collect_evidence(self, action: dict):
        time.sleep(1.5)              # let in-flight telemetry for the incident arrive
        status, detail = "success", ""
        try:
            bundle = self.incident_bundle(action.get("incident_id") or "")
            path = forensics.write_bundle(bundle)
            self.evidence[bundle["incident"]["id"]] = str(path)
            detail = f"{len(bundle['timeline'])} timeline entries written to {path}"
        except KeyError:
            status, detail = "noop", "no incident attached to alert"
        except Exception as exc:          # pragma: no cover
            status, detail = "failed", str(exc)
        if self.bus:
            self.bus.publish(config.TOPIC_ACTION_RESULTS, {"kind": "action_result",
                             "action_id": action["action_id"], "type": "collect_evidence",
                             "status": status, "detail": detail, "ts": time.time()})

    # --------------------------------------------------------------- metrics
    def incident_metrics(self, inc: dict) -> dict:
        acts = [a for a in self.actions.values() if a.get("incident_id") == inc["id"]]
        contain = [a for a in acts if a["type"] in CONTAINMENT and a.get("state") == "success"]
        m = {"mttd_ms": None, "time_to_contain_ms": None, "kernel_to_response_ms": None,
             "actions": len(acts)}
        if inc.get("first_detected_at") and inc.get("first_event_ts"):
            m["mttd_ms"] = round(max(0.0, inc["first_detected_at"] - inc["first_event_ts"]) * 1000, 1)
        if inc.get("contained_ts") and inc.get("first_event_ts"):
            m["time_to_contain_ms"] = round((inc["contained_ts"] - inc["first_event_ts"]) * 1000, 1)
        lat = [a["kernel_to_response_ms"] for a in contain if a.get("kernel_to_response_ms") is not None]
        if lat:
            m["kernel_to_response_ms"] = min(lat)
        return m

    def heatmap(self) -> list[dict]:
        cols = []
        for tactic in self.mapper.tactic_order:
            techs = [{"id": tid, "name": t["name"], "count": self.technique_hits.get(tid, 0)}
                     for tid, t in self.mapper.techniques.items() if t["tactic"] == tactic]
            cols.append({"tactic": tactic, "techniques": techs})
        return cols

    def snapshot(self) -> dict:
        with self.lock:
            incs = []
            for inc in sorted(self.incidents.values(), key=lambda i: i["id"], reverse=True):
                incs.append(inc | {"metrics": self.incident_metrics(inc)})
            contain_lat = [a["kernel_to_response_ms"] for a in self.actions.values()
                           if a["type"] in CONTAINMENT and a.get("kernel_to_response_ms") is not None]
            return {
                "mode": self.mode,
                "kpi": {
                    "events_total": self.total_events,
                    "eps": round(len(self.eps_window) / 10.0, 1),
                    "alerts": len(self.alerts),
                    "critical": sum(1 for a in self.alerts if a["severity"] == "critical"),
                    "incidents_open": sum(1 for i in self.incidents.values() if i["status"] == "open"),
                    "incidents_contained": sum(1 for i in self.incidents.values() if i["status"] == "contained"),
                    "hosts_isolated": sum(1 for h in self.hosts.values() if h["isolated"]),
                    "blocked_ips": len(self.blocked_ips),
                    "blocked_connections": self.by_type.get("network_blocked", 0),
                    "avg_response_ms": round(sum(contain_lat) / len(contain_lat), 1) if contain_lat else None,
                    "processes_tracked": len(self.trees.nodes),
                },
                "event_types": dict(self.by_type),
                "hosts": list(self.hosts.values()),
                "heatmap": self.heatmap(),
                "alerts": self.alerts[-150:][::-1],
                "incidents": incs,
                "actions": sorted(self.actions.values(), key=lambda a: a["issued_at"], reverse=True)[:150],
                "recent_events": list(self.recent)[-80:][::-1],
                "runs": sorted(self.runs.values(), key=lambda r: r["started"], reverse=True)[:5],
                "blocked_ips": sorted(i for i in self.blocked_ips if i),
            }


# ======================================================================= API
class SimRequest(BaseModel):
    scenario: str
    speed: float | None = None


class ModeRequest(BaseModel):
    mode: str


def create_app(bus: Bus, state: SocState) -> FastAPI:
    from . import report
    from .simulator import load_scenarios

    app = FastAPI(title="eBPF Autonomous Threat Hunting SOC", version="1.0.0")
    scenarios = load_scenarios()

    @app.get("/")
    def index():
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/state")
    def get_state():
        return state.snapshot()

    @app.get("/api/scenarios")
    def get_scenarios():
        return [{"name": s["name"], "title": s.get("title", ""), "description": s.get("description", ""),
                 "steps": len(s["steps"])} for s in scenarios.values()]

    @app.get("/api/playbooks")
    def get_playbooks():
        return load_playbooks()

    @app.get("/api/rules")
    def get_rules():
        hits = Counter()
        for (rid, _t, _s, _src), n in state.rule_hits.items():
            hits[rid] += n
        return [{"id": r.id, "title": r.title, "level": r.level, "techniques": r.techniques,
                 "file": r.source, "hits": hits.get(r.id, 0)} for r in SigmaEngine().rules]

    @app.get("/api/incidents/{inc_id}")
    def get_incident(inc_id: str):
        try:
            bundle = state.incident_bundle(inc_id)
        except KeyError:
            raise HTTPException(404, "incident not found")
        bundle["metrics"] = state.incident_metrics(bundle["incident"])
        bundle["evidence_path"] = state.evidence.get(inc_id)
        return bundle

    @app.get("/api/incidents/{inc_id}/timeline.md", response_class=PlainTextResponse)
    def get_timeline_md(inc_id: str):
        try:
            return forensics.to_markdown(state.incident_bundle(inc_id))
        except KeyError:
            raise HTTPException(404, "incident not found")

    @app.post("/api/simulate")
    def simulate(req: SimRequest):
        if req.scenario not in scenarios:
            raise HTTPException(404, "unknown scenario")
        run_id = f"RUN-{uuid.uuid4().hex[:6]}"
        bus.publish(config.TOPIC_CONTROL, {"cmd": "run_scenario", "scenario": req.scenario,
                                           "speed": req.speed, "run_id": run_id})
        return {"run_id": run_id}

    @app.post("/api/mode")
    def set_mode(req: ModeRequest):
        if req.mode not in ("autonomous", "monitor"):
            raise HTTPException(400, "mode must be autonomous or monitor")
        state.mode = req.mode
        bus.publish(config.TOPIC_CONTROL, {"cmd": "set_mode", "mode": req.mode})
        return {"mode": req.mode}

    @app.post("/api/actions/{action_id}/approve")
    def approve(action_id: str):
        act = state.actions.get(action_id)
        if not act:
            raise HTTPException(404, "action not found")
        if act.get("state") not in ("awaiting_approval", "recommended"):
            raise HTTPException(409, f"action is {act.get('state')}")
        msg = {**act, "execute": True, "state": "issued", "approved_at": time.time(),
               "issued_at": time.time(), "alert_event_ts": None}
        bus.publish(config.TOPIC_ACTIONS, msg, key=msg.get("host"))
        return {"approved": action_id}

    @app.post("/api/hosts/{host}/release")
    def release(host: str):
        msg = {"action_id": "ACT-" + uuid.uuid4().hex[:8], "type": "release_host", "host": host,
               "playbook": "analyst", "playbook_name": "Manual release", "incident_id": None,
               "alert_id": None, "alert_title": "analyst action", "severity": "info",
               "issued_at": time.time(), "execute": True, "state": "issued", "mode": state.mode}
        bus.publish(config.TOPIC_ACTIONS, msg, key=host)
        return {"released": host}

    @app.post("/api/reset")
    def reset():
        bus.publish(config.TOPIC_CONTROL, {"cmd": "reset"})
        state.reset()
        return {"reset": True}

    @app.get("/api/report", response_class=PlainTextResponse)
    def get_report():
        return report.generate(state)

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app


def run(bus: Bus) -> SocState:
    """Service: consume all topics into the dashboard state (API served separately)."""
    state = SocState(bus)
    bus.subscribe([config.TOPIC_EVENTS, config.TOPIC_ALERTS, config.TOPIC_INCIDENTS,
                   config.TOPIC_ACTIONS, config.TOPIC_ACTION_RESULTS, config.TOPIC_CONTROL],
                  state.on_message, group="dashboard")
    return state
