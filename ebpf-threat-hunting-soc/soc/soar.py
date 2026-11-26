"""SOAR - Security Orchestration, Automation and Response.

Playbooks (playbooks/*.yml) are matched against every alert. Matching
playbooks expand into concrete response actions which are published on
``soc.actions``; the eBPF sensors (simulated or live) execute them and report
back on ``soc.action_results``.

Response modes
  autonomous : containment actions execute immediately (default)
  monitor    : containment actions are only *recommended*; evidence collection
               and notifications still run

Action types
  freeze_process_tree  SIGSTOP the attack tree (keeps memory for forensics)
  kill_process_tree    SIGKILL the attack tree
  isolate_host         eBPF network isolation (only SOC management IP allowed)
  block_ip             add IPs to the eBPF tcp_connect blocklist (fleet-wide)
  collect_evidence     build the forensic timeline bundle for the incident
  notify               POST to a webhook (n8n / Slack / Teams) if configured
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
import urllib.request
import uuid
from pathlib import Path

from . import config
from .bus import Bus
from .sigma import LEVELS

log = logging.getLogger("soc.soar")

CONTAINMENT = {"freeze_process_tree", "kill_process_tree", "isolate_host", "block_ip"}
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def load_playbooks(directory: Path | None = None) -> list[dict]:
    out = []
    for path in sorted(Path(directory or config.PLAYBOOK_DIR).glob("*.yml")):
        pb = config.load_yaml(path)
        if pb.get("enabled", True):
            pb["file"] = path.name
            out.append(pb)
    return out


def _external(ip: str, internal_nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in n for n in internal_nets) and not addr.is_private and not addr.is_loopback \
        or ip.startswith(("203.0.113.", "198.51.100.", "192.0.2."))  # RFC5737 test ranges = "internet"


class SoarEngine:
    def __init__(self, bus: Bus | None, mode: str | None = None, fleet: dict | None = None):
        self.bus = bus
        self.mode = mode or config.RESPONSE_MODE
        self.playbooks = load_playbooks()
        fleet = fleet or config.load_fleet()
        self.internal = [ipaddress.ip_network(n) for n in fleet.get("internal_networks", [])]
        self.incidents: dict[str, dict] = {}
        self.iocs: dict[str, set] = {}
        self.done: dict = {}
        self.actions: dict[str, dict] = {}
        self.lock = threading.RLock()

    def reset(self):
        with self.lock:
            self.incidents.clear()
            self.iocs.clear()
            self.done.clear()
            self.actions.clear()

    # ----------------------------------------------------------- matching
    def matches(self, pb: dict, alert: dict) -> bool:
        trig = pb.get("trigger", {})
        if LEVELS.get(alert["severity"], 0) < LEVELS.get(trig.get("min_severity", "informational"), 0):
            return False
        if trig.get("sources") and alert["source"] not in trig["sources"]:
            return False
        techs = {t["id"] for t in alert.get("techniques", [])}
        if trig.get("techniques_any") and not techs.intersection(trig["techniques_any"]):
            return False
        if trig.get("incident_hosts_gte"):
            inc = self.incidents.get(alert.get("incident_id") or "", {})
            if len(inc.get("hosts", [])) < trig["incident_hosts_gte"]:
                return False
        return True

    def _targets(self, target: str | None, alert: dict) -> list[dict]:
        inc = self.incidents.get(alert.get("incident_id") or "", {})
        if target == "alert_host":
            return [{"host": alert["host"]}]
        if target == "incident_hosts":
            hosts = list(dict.fromkeys(inc.get("hosts", []) + [alert["host"]]))
            return [{"host": h} for h in hosts]
        if target == "attack_root":
            return [{"host": alert["root_host"], "exec_id": alert["root_exec_id"]}]
        if target == "alert_process":
            return [{"host": alert["host"], "exec_id": alert["exec_id"]}]
        if target == "incident_roots":
            roots = [tuple(r) for r in inc.get("roots", [])] + [(alert["root_host"], alert["root_exec_id"])]
            return [{"host": h, "exec_id": e} for h, e in dict.fromkeys(roots)]
        if target == "incident_external_ips":
            key = alert.get("incident_id") or alert["id"]
            return [{"ip": ip} for ip in sorted(self.iocs.get(key, set()))]
        return [{}]

    def _collect_iocs(self, alert: dict):
        key = alert.get("incident_id") or alert["id"]
        found = set(IP_RE.findall(alert.get("cmdline") or ""))
        if alert.get("dst_ip"):
            found.add(alert["dst_ip"])
        ext = {ip for ip in found if _external(ip, self.internal)}
        self.iocs.setdefault(key, set()).update(ext)

    # ------------------------------------------------------------- handling
    def on_alert(self, alert: dict) -> list[dict]:
        issued = []
        with self.lock:
            self._collect_iocs(alert)
            for pb in self.playbooks:
                if not self.matches(pb, alert):
                    continue
                for spec in pb["actions"]:
                    for tgt in self._targets(spec.get("target"), alert):
                        scope = alert.get("incident_id") or alert["id"]
                        tkey = tgt.get("exec_id") or tgt.get("ip") or tgt.get("host") or ""
                        dkey = (scope, spec["type"], tkey) if spec["type"] in CONTAINMENT \
                            else (scope, pb["id"], spec["type"], tkey)
                        will_execute = spec["type"] not in CONTAINMENT or (
                            self.mode == "autonomous" and not spec.get("approval"))
                        # skip duplicates - unless an earlier proposal is now being auto-executed
                        if dkey in self.done and (self.done[dkey] or not will_execute):
                            continue
                        self.done[dkey] = will_execute
                        issued.append(self._issue(pb, spec, tgt, alert))
        return issued

    def _issue(self, pb: dict, spec: dict, tgt: dict, alert: dict) -> dict:
        t = spec["type"]
        approval = bool(spec.get("approval"))
        if t in CONTAINMENT:
            execute = self.mode == "autonomous" and not approval
            state = "issued" if execute else ("awaiting_approval" if approval and self.mode == "autonomous"
                                              else "recommended")
        else:
            execute, state = True, "issued"
        action = {
            "action_id": "ACT-" + uuid.uuid4().hex[:8], "type": t, "playbook": pb["id"],
            "playbook_name": pb["name"], "incident_id": alert.get("incident_id"),
            "alert_id": alert["id"], "alert_title": alert["title"], "severity": alert["severity"],
            "issued_at": time.time(), "alert_detected_at": alert.get("detected_at"),
            "alert_event_ts": alert.get("ts_epoch"), "execute": execute, "state": state,
            "mode": self.mode, "channel": spec.get("channel"), **tgt,
        }
        self.actions[action["action_id"]] = action
        if self.bus:
            self.bus.publish(config.TOPIC_ACTIONS, action, key=action.get("host"))
        if t == "notify":
            threading.Thread(target=self._notify, args=(action, alert), daemon=True).start()
        log.info("[%s] %s %s -> %s (%s)", pb["id"], state, t,
                 tgt.get("host") or tgt.get("ip"), alert["title"])
        return action

    def _notify(self, action: dict, alert: dict):
        detail, status = "no webhook configured (set SOAR_WEBHOOK_URL for n8n/Slack)", "success"
        if config.SOAR_WEBHOOK_URL:
            body = json.dumps({"text": f"[{alert['severity'].upper()}] {alert['title']} on {alert['host']}",
                               "alert": alert, "action": action}, default=str).encode()
            req = urllib.request.Request(config.SOAR_WEBHOOK_URL, data=body,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    detail = f"webhook HTTP {resp.status}"
            except Exception as exc:
                status, detail = "failed", f"webhook error: {exc}"
        if self.bus:
            self.bus.publish(config.TOPIC_ACTION_RESULTS, {
                "kind": "action_result", "action_id": action["action_id"], "type": "notify",
                "status": status, "detail": detail, "ts": time.time()})


def run(bus: Bus) -> SoarEngine:
    """Service: soc.alerts + soc.incidents -> soc.actions"""
    soar = SoarEngine(bus)

    def handle(topic, msg):
        if topic == config.TOPIC_INCIDENTS:
            with soar.lock:
                soar.incidents[msg["id"]] = msg
        elif topic == config.TOPIC_ALERTS:
            soar.on_alert(msg)
        elif topic == config.TOPIC_CONTROL:
            if msg.get("cmd") == "set_mode" and msg.get("mode") in ("autonomous", "monitor"):
                soar.mode = msg["mode"]
                log.info("response mode -> %s", soar.mode)
            elif msg.get("cmd") == "reset":
                soar.reset()

    bus.subscribe([config.TOPIC_INCIDENTS, config.TOPIC_ALERTS, config.TOPIC_CONTROL], handle, group="soar")
    log.info("SOAR running with %d playbooks in %s mode", len(soar.playbooks), soar.mode)
    return soar
