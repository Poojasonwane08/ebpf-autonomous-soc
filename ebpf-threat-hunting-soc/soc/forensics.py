"""Automated evidence collection: forensic timeline of an incident.

For an incident the collector walks every attack root (on every host the
attacker touched), pulls the full descendant process tree, every kernel event
those processes generated, the alerts, the lateral-movement edges and the
response actions, and writes a bundle to evidence/<INCIDENT>/:

    timeline.json       machine-readable ordered timeline
    timeline.md         human-readable forensic timeline + IOCs
    process_trees.json  nested process trees per host
    iocs.json           IPs, files, binaries, command lines, hashes-to-collect
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import config

URL_RE = re.compile(r"(?:https?|stratum\+tcp)://[^\s'\"]+")
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _describe(ev: dict) -> str:
    t = ev["type"]
    if t == "process_exec":
        return f"EXEC   {ev['cmdline']}  (uid {ev.get('uid')}, parent {ev.get('parent_binary')})"
    if t == "process_exit":
        return f"EXIT   {ev['binary']}"
    if t == "network_connect":
        return f"CONNECT {ev.get('src_ip')} -> {ev.get('dst_ip')}:{ev.get('dst_port')} ({ev['binary']})"
    if t == "network_blocked":
        return f"BLOCKED connect -> {ev.get('dst_ip')}:{ev.get('dst_port')} [eBPF SIGKILL] ({ev['binary']})"
    if t == "file_access":
        return f"FILE   {ev.get('file_path')} read by {ev['binary']}"
    if t == "privilege_change":
        return f"CREDS  {ev['binary']} uid {ev.get('uid')} -> {ev.get('new_uid')} (commit_creds)"
    if t == "ptrace":
        return f"PTRACE {ev.get('ptrace_request')} target pid {ev.get('target_pid')} by {ev['binary']}"
    if t == "memfd_create":
        return f"MEMFD  memfd_create('{ev.get('memfd_name')}') by {ev['binary']}"
    return f"{t} {ev.get('binary')}"


def build_timeline(incident: dict, trees, alerts: list[dict], actions: list[dict],
                   results: dict) -> dict:
    entries, tree_out, procs = [], {}, []
    for host, root in incident.get("roots", []):
        tree_out.setdefault(host, []).append(trees.subtree(host, root))
        for node in trees.descendants(host, root):
            procs.append(node)
            for ev in node["events"]:
                entries.append({"ts": ev["ts_epoch"], "host": host, "kind": "telemetry",
                                "event_type": ev["type"], "pid": ev.get("pid"),
                                "text": _describe(ev),
                                "mitre": [t["id"] for t in ev.get("mitre", [])]})
    inc_alerts = [a for a in alerts if a.get("incident_id") == incident["id"]]
    for a in inc_alerts:
        entries.append({"ts": a["ts_epoch"], "host": a["host"], "kind": "alert",
                        "event_type": a["source"], "pid": a.get("pid"),
                        "text": f"ALERT [{a['severity'].upper()}] {a['title']}",
                        "mitre": [t["id"] for t in a["techniques"]]})
    for e in incident.get("lateral_edges", []):
        entries.append({"ts": e["ts"], "host": e["dst_host"], "kind": "lateral_movement",
                        "event_type": "ssh", "pid": None,
                        "text": f"LATERAL MOVEMENT {e['src_host']} -> {e['dst_host']} (SSH, uid {e.get('uid')})",
                        "mitre": ["T1021.004"]})
    for act in actions:
        if act.get("incident_id") != incident["id"]:
            continue
        res = results.get(act["action_id"], {})
        target = act.get("host") or act.get("ip") or ""
        entries.append({"ts": res.get("ts", act["issued_at"]), "host": act.get("host") or "*",
                        "kind": "response", "event_type": act["type"], "pid": None,
                        "text": f"RESPONSE {act['type']} {target} [{res.get('status', act['state'])}] "
                                f"{res.get('detail', '')} ({act['playbook']})".strip(),
                        "mitre": []})
    entries.sort(key=lambda e: e["ts"])

    iocs = {"external_ips": set(), "urls": set(), "files": set(), "binaries": set(),
            "command_lines": [], "users": set()}
    for n in procs:
        if n.get("placeholder"):
            continue
        cmd = f"{n['binary']} {n['args']}".strip()
        iocs["command_lines"].append(f"[{n['host']}] {cmd}")
        iocs["binaries"].add(n["binary"])
        iocs["users"].add(str(n.get("uid")))
        iocs["urls"].update(URL_RE.findall(cmd))
        for ev in n["events"]:
            if ev.get("file_path"):
                iocs["files"].add(ev["file_path"])
            if ev.get("dst_external") and ev.get("dst_ip"):
                iocs["external_ips"].add(ev["dst_ip"])
        for ip in IP_RE.findall(cmd):
            if not ip.startswith(("10.", "127.", "0.")):
                iocs["external_ips"].add(ip)
    iocs = {k: sorted(v) if isinstance(v, set) else v for k, v in iocs.items()}
    return {"incident": incident, "generated_at": _fmt(datetime.now(timezone.utc).timestamp()),
            "timeline": entries, "process_trees": tree_out, "iocs": iocs,
            "alert_count": len(inc_alerts)}


def to_markdown(bundle: dict) -> str:
    inc = bundle["incident"]
    lines = [f"# Forensic timeline - {inc['id']}", "",
             f"**Title:** {inc['title']}  ",
             f"**Severity:** {inc['severity']}  ",
             f"**Hosts:** {', '.join(inc['hosts'])}  ",
             f"**ATT&CK techniques:** {', '.join(inc['techniques'])}  ",
             f"**Generated:** {bundle['generated_at']}", ""]
    if inc.get("lateral_edges"):
        lines += ["## Lateral movement path", ""]
        for e in inc["lateral_edges"]:
            lines.append(f"- `{e['src_host']}` --SSH--> `{e['dst_host']}` at {_fmt(e['ts'])}")
        lines.append("")
    lines += ["## Timeline", "", "| Time (UTC) | Host | Kind | Event | ATT&CK |", "|---|---|---|---|---|"]
    for e in bundle["timeline"]:
        text = e["text"].replace("|", "\\|")
        lines.append(f"| {_fmt(e['ts'])} | {e['host']} | {e['kind']} | `{text}` | {', '.join(e['mitre'])} |")
    lines += ["", "## Indicators of compromise", ""]
    for k, v in bundle["iocs"].items():
        if not v:
            continue
        lines.append(f"**{k.replace('_', ' ').title()}**")
        lines += [f"- `{x}`" for x in v[:60]]
        lines.append("")
    return "\n".join(lines)


def write_bundle(bundle: dict, base: Path | None = None) -> Path:
    out = Path(base or config.EVIDENCE_DIR) / bundle["incident"]["id"]
    out.mkdir(parents=True, exist_ok=True)
    (out / "timeline.json").write_text(json.dumps(bundle["timeline"], indent=2, default=str), encoding="utf-8")
    (out / "process_trees.json").write_text(json.dumps(bundle["process_trees"], indent=2, default=str),
                                            encoding="utf-8")
    (out / "iocs.json").write_text(json.dumps(bundle["iocs"], indent=2), encoding="utf-8")
    (out / "timeline.md").write_text(to_markdown(bundle), encoding="utf-8")
    return out
