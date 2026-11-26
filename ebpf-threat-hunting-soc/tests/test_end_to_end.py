"""Full pipeline on the in-memory bus: sensor -> normalizer -> CEP -> SOAR -> sensor."""
import time

import pytest

from soc import config
from soc.run_all import start_pipeline


@pytest.fixture(scope="module")
def pipeline():
    bus, parts = start_pipeline(eps=10, serve=False)
    yield bus, parts
    parts["sim"].stop()
    bus.close()


def run(bus, state, scenario, mode):
    bus.publish(config.TOPIC_CONTROL, {"cmd": "set_mode", "mode": mode})
    time.sleep(0.3)
    run_id = f"{scenario}-{mode}"
    bus.publish(config.TOPIC_CONTROL, {"cmd": "run_scenario", "scenario": scenario, "speed": 20,
                                       "run_id": run_id})
    for _ in range(300):
        r = state.runs.get(run_id)
        if r and r.get("finished"):
            break
        time.sleep(0.1)
    time.sleep(2.0)      # evidence collection + results
    return state.runs[run_id]


def test_autonomous_response_stops_apt_at_lateral_movement(pipeline):
    bus, parts = pipeline
    state = parts["state"]
    r = run(bus, state, "apt_lateral_movement", "autonomous")
    results = {s["name"]: s["result"] for s in r["steps"]}
    assert results["SSH pivot web-01 -> app-01"] == "executed"
    assert results["Run local privilege-escalation exploit"] == "prevented"
    assert results["Exfiltrate over HTTPS"] == "prevented"
    assert any(h["isolated"] for h in state.hosts.values() if h["name"] in ("web-01", "app-01"))
    inc = next(i for i in state.incidents.values() if "app-01" in i["hosts"])
    assert inc["status"] == "contained"
    assert inc["id"] in state.evidence                     # forensic bundle written
    m = state.incident_metrics(inc)
    assert m["kernel_to_response_ms"] is not None and m["kernel_to_response_ms"] < 2000


def test_monitor_mode_only_recommends(pipeline):
    bus, parts = pipeline
    state = parts["state"]
    bus.publish(config.TOPIC_CONTROL, {"cmd": "reset"})
    state.reset()
    time.sleep(0.5)
    r = run(bus, state, "fileless_cryptominer", "monitor")
    assert all(s["result"] == "executed" for s in r["steps"])
    kills = [a for a in state.actions.values() if a["type"] == "kill_process_tree"]
    assert kills and all(a["state"] == "recommended" for a in kills)


def test_dashboard_api(pipeline):
    from fastapi.testclient import TestClient
    from soc.dashboard import create_app

    bus, parts = pipeline
    client = TestClient(create_app(bus, parts["state"]))
    s = client.get("/api/state").json()
    assert {"kpi", "heatmap", "hosts", "incidents"} <= set(s)
    assert len(s["heatmap"]) == 12
    assert len(client.get("/api/scenarios").json()) == 3
    assert client.get("/").status_code == 200
    for inc in s["incidents"]:
        b = client.get(f"/api/incidents/{inc['id']}").json()
        assert b["timeline"] and b["process_trees"]
        assert client.get(f"/api/incidents/{inc['id']}/timeline.md").status_code == 200
    assert "Detection signatures" in client.get("/api/report").text
