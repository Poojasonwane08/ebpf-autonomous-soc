"""End-to-end smoke test against a running stack (used by CI after `docker compose up`).

    python scripts/e2e_docker_stack.py [http://localhost:8080]

Launches the APT scenario and asserts that the SOC detects the lateral movement
and autonomously contains the incident.
"""
import json
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"


def call(path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"},
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


for _ in range(90):
    try:
        s = call("/api/state")
        if s["kpi"]["events_total"] > 50:
            break
    except Exception:
        pass
    time.sleep(2)
else:
    sys.exit("dashboard never received telemetry")
print("telemetry flowing:", s["kpi"]["events_total"], "events")

call("/api/simulate", {"scenario": "apt_lateral_movement", "speed": 3})
for _ in range(60):
    time.sleep(2)
    s = call("/api/state")
    if any(i["status"] == "contained" for i in s["incidents"]) and s["kpi"]["hosts_isolated"] >= 2:
        break
else:
    print(json.dumps(s["kpi"], indent=2))
    sys.exit("incident was not contained")
titles = [a["title"] for a in s["alerts"]]
assert any("Lateral movement" in t for t in titles), titles
print("OK - lateral movement detected and contained:", s["kpi"])
