"""Threat-intelligence engineering report generator.

* ``generate(state)`` renders a markdown report from a live SocState
  (served at /api/report on the dashboard).
* ``python -m soc.report`` runs the whole pipeline in-process, plays every
  adversary scenario twice (monitor mode vs autonomous mode) and writes
  docs/THREAT_HUNTING_REPORT.md with measured detection and response numbers.
"""
from __future__ import annotations

import argparse
import logging
import statistics
import time
from datetime import datetime, timezone

from . import config
from .sigma import SigmaEngine
from .soar import CONTAINMENT, load_playbooks


def _ms(v):
    return "-" if v is None else f"{v:,.1f} ms"


def generate(state, title: str = "eBPF Autonomous Threat Hunting - Detection & Playbook Report",
             scenario_results: list[dict] | None = None) -> str:
    snap = state.snapshot()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = [f"# {title}", "", f"_Generated {now} by `soc.report`._", ""]
    k = snap["kpi"]
    L += ["## 1. Summary", "",
          "| Metric | Value |", "|---|---|",
          f"| Kernel events processed | {k['events_total']:,} |",
          f"| Alerts raised | {k['alerts']} ({k['critical']} critical) |",
          f"| Incidents (open / contained) | {k['incidents_open']} / {k['incidents_contained']} |",
          f"| Hosts isolated | {k['hosts_isolated']} |",
          f"| IPs blocked by eBPF policy | {k['blocked_ips']} |",
          f"| Mean kernel-event -> containment latency | {_ms(k['avg_response_ms'])} |", ""]

    if scenario_results:
        L += ["## 2. Adversary emulation results", "",
              "Each scenario was played twice: once with response **off** (monitor mode, shows the full "
              "kill chain and what the detections see) and once with **autonomous** SOAR response.", "",
              "| Scenario | Mode | Steps executed | Steps prevented/blocked | Alerts | Techniques detected | "
              "Time to contain |", "|---|---|---|---|---|---|---|"]
        for r in scenario_results:
            L.append(f"| {r['scenario']} | {r['mode']} | {r['executed']}/{r['total']} | {r['stopped']} | "
                     f"{r['alerts']} | {r['techniques']} | {_ms(r['time_to_contain_ms'])} |")
        L.append("")
        for r in scenario_results:
            if r["mode"] != "autonomous":
                continue
            L += [f"### {r['scenario']} - step-by-step (autonomous)", "",
                  "| # | Step | Host | ATT&CK | Result |", "|---|---|---|---|---|"]
            for s in r["steps"]:
                L.append(f"| {s['n']} | {s['name']} | {s['host']} | {s.get('technique') or ''} | "
                         f"**{s['result']}** |")
            L.append("")

    L += ["## 3. Incidents", "", "| Incident | Severity | Hosts | Techniques | Status | MTTD | "
          "Kernel->response | Dwell until contained |", "|---|---|---|---|---|---|---|---|"]
    for inc in snap["incidents"]:
        m = inc["metrics"]
        L.append(f"| {inc['id']} | {inc['severity']} | {', '.join(inc['hosts'])} | "
                 f"{', '.join(inc['techniques'][:8])} | {inc['status']} | {_ms(m['mttd_ms'])} | "
                 f"{_ms(m['kernel_to_response_ms'])} | {_ms(m['time_to_contain_ms'])} |")
    L.append("")

    L += ["## 4. Detection signatures", "",
          "### 4.1 Sigma rules (rules/sigma)", "", "| Rule | Level | ATT&CK | Hits |", "|---|---|---|---|"]
    hits = {}
    for (rid, _t, _s, _src), n in state.rule_hits.items():
        hits[rid] = hits.get(rid, 0) + n
    for r in SigmaEngine().rules:
        L.append(f"| {r.title} | {r.level} | {', '.join(r.techniques)} | {hits.get(r.id, 0)} |")
    other = [(key, n) for key, n in state.rule_hits.items() if key[3] != "sigma"]
    L += ["", "### 4.2 Behavioural, anomaly and correlation detections", "",
          "| Detector | Title | Severity | Hits |", "|---|---|---|---|"]
    for (rid, title_, sev, src), n in sorted(other, key=lambda x: -x[1]):
        L.append(f"| {src}:{rid} | {title_} | {sev} | {n} |")
    L.append("")

    L += ["## 5. MITRE ATT&CK coverage (alerts per technique)", "", "| Tactic | Technique | Alerts |",
          "|---|---|---|"]
    for col in snap["heatmap"]:
        for t in col["techniques"]:
            L.append(f"| {col['tactic']} | {t['id']} {t['name']} | {t['count'] or ''} |")
    L.append("")

    L += ["## 6. Playbook effectiveness", "", "| Playbook | Action | Issued | Succeeded | Recommended only | "
          "Avg kernel->response |", "|---|---|---|---|---|---|"]
    agg: dict = {}
    for a in state.actions.values():
        if not str(a.get("playbook", "")).startswith("PB-"):
            continue                      # manual / housekeeping actions
        key = (a["playbook"], a.get("playbook_name", ""), a["type"])
        d = agg.setdefault(key, {"n": 0, "ok": 0, "rec": 0, "lat": []})
        d["n"] += 1
        d["ok"] += a.get("state") == "success"
        d["rec"] += a.get("state") in ("recommended", "awaiting_approval")
        if a["type"] in CONTAINMENT and a.get("kernel_to_response_ms") is not None:
            d["lat"].append(a["kernel_to_response_ms"])
    for (pb, name, t), d in sorted(agg.items()):
        avg = statistics.mean(d["lat"]) if d["lat"] else None
        L.append(f"| {pb} {name} | {t} | {d['n']} | {d['ok']} | {d['rec']} | {_ms(avg)} |")
    L += ["", "Playbook definitions:", ""]
    for pb in load_playbooks():
        trig = pb["trigger"]
        L.append(f"- **{pb['id']} {pb['name']}** - trigger: techniques "
                 f"{trig.get('techniques_any', 'any')}, min severity {trig.get('min_severity')}; actions: "
                 + ", ".join(a["type"] + (" (approval)" if a.get("approval") else "") for a in pb["actions"]))
    L.append("")
    return "\n".join(L)


def _wait_run(state, run_id, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = state.runs.get(run_id)
        if r and r.get("finished"):
            return r
        time.sleep(0.2)
    raise TimeoutError(run_id)


def main():  # pragma: no cover - exercised manually / in CI artifact job
    from .run_all import start_pipeline
    from .simulator import load_scenarios

    ap = argparse.ArgumentParser(description="Run all scenarios and write the threat hunting report")
    ap.add_argument("--speed", type=float, default=4.0, help="scenario playback speed")
    ap.add_argument("--out", default=str(config.ROOT / "docs" / "THREAT_HUNTING_REPORT.md"))
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)

    bus, parts = start_pipeline(eps=40, serve=False)
    state, sim, soar = parts["state"], parts["sim"], parts["soar"]
    time.sleep(2)
    results = []
    for name in load_scenarios():
        for mode in ("monitor", "autonomous"):
            bus.publish(config.TOPIC_CONTROL, {"cmd": "set_mode", "mode": mode})
            time.sleep(0.3)
            before_alerts = len(state.alerts)
            before_incs = set(state.incidents)
            run_id = f"{name}-{mode}"
            bus.publish(config.TOPIC_CONTROL, {"cmd": "run_scenario", "scenario": name,
                                               "speed": args.speed, "run_id": run_id})
            run = _wait_run(state, run_id)
            time.sleep(2.5)
            new_alerts = state.alerts[before_alerts:]
            new_incs = [state.incidents[i] for i in state.incidents if i not in before_incs]
            ttc = [state.incident_metrics(i)["time_to_contain_ms"] for i in new_incs]
            ttc = [t for t in ttc if t is not None]
            techs = sorted({t["id"] for a in new_alerts for t in a["techniques"]})
            results.append({
                "scenario": name, "mode": mode, "steps": run["steps"], "total": len(run["steps"]),
                "executed": sum(s["result"] == "executed" for s in run["steps"]),
                "stopped": sum(s["result"] in ("prevented", "blocked") for s in run["steps"]),
                "alerts": len(new_alerts), "techniques": len(techs),
                "time_to_contain_ms": min(ttc) if ttc else None})
            # clean slate for the next run (keeps counters for the report)
            for h in list(state.hosts):
                bus.publish(config.TOPIC_ACTIONS, {"action_id": f"rel-{run_id}-{h}", "type": "release_host",
                                                   "host": h, "execute": True, "playbook": "report",
                                                   "issued_at": time.time(), "state": "issued"})
            sim.blocked_ips.clear()
            soar.done.clear()
            with parts["engine"].lock:          # close the incident so the next run opens a new one
                for inc in parts["engine"].incidents.values():
                    inc["status"] = "closed"
            time.sleep(1)
    md = generate(state, scenario_results=results)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"report written to {args.out}")
    for r in results:
        print(f"  {r['scenario']:<24} {r['mode']:<10} executed {r['executed']}/{r['total']}  "
              f"stopped {r['stopped']}  alerts {r['alerts']}  ttc {_ms(r['time_to_contain_ms'])}")


if __name__ == "__main__":
    main()
