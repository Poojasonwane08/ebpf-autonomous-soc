from soc.detector import DetectionEngine
from soc.normalizer import Normalizer
from soc.simulator import FleetSimulator, load_scenarios


def replay(engine, sim, scenario_name):
    norm = Normalizer()
    sim.buffer = []
    refs = {}
    for step in load_scenarios()[scenario_name]["steps"]:
        sim._play_step(step, refs, "test")
    alerts = []
    for raw in sim.buffer:
        e = norm.normalize(raw)
        if e:
            alerts += engine.process(e)
    sim.buffer = None
    return alerts


def test_process_tree_lineage_and_attack_root():
    sim = FleetSimulator(None, seed=1)
    engine = DetectionEngine()
    replay(engine, sim, "apt_lateral_movement")
    nodes = [n for n in engine.trees.nodes.values() if n["binary"] == "/usr/bin/ssh" and n["host"] == "web-01"]
    assert nodes
    ssh = nodes[0]
    lineage = engine.trees.lineage_binaries("web-01", ssh["exec_id"])
    assert lineage[:3] == ["bash", "sh", "php-fpm8.2"]
    root = engine.trees.get("web-01", engine.trees.attack_root("web-01", ssh["exec_id"]))
    assert root["binary"] == "/bin/sh"          # the shell spawned by php-fpm


def test_lateral_movement_links_hosts_into_one_incident():
    engine = DetectionEngine()
    alerts = replay(engine, FleetSimulator(None, seed=2), "apt_lateral_movement")
    lateral = [a for a in alerts if a["rule_id"] == "CORR-LATERAL-SSH"]
    assert len(lateral) == 1 and lateral[0]["severity"] == "critical"
    inc = engine.incidents[lateral[0]["incident_id"]]
    assert set(inc["hosts"]) == {"web-01", "app-01"}
    assert inc["lateral_edges"][0]["src_host"] == "web-01"
    # every alert of the attack ends up in the same incident
    assert {a["incident_id"] for a in alerts if a["severity"] in ("high", "critical")} == {inc["id"]}


def test_behaviour_detectors_fire():
    engine = DetectionEngine()
    rules = {a["rule_id"] for a in replay(engine, FleetSimulator(None, seed=3), "apt_lateral_movement")}
    assert {"BHV-FILELESS", "BHV-INJECT", "BHV-PRIVESC"} <= rules


def test_admin_ssh_from_bastion_is_not_lateral_movement():
    engine = DetectionEngine()
    alerts = replay(engine, FleetSimulator(None, seed=4), "insider_privesc")
    assert not [a for a in alerts if a["rule_id"] == "CORR-LATERAL-SSH"]
    assert any(a["rule_id"] == "BHV-PRIVESC" for a in alerts)


def test_benign_baseline_produces_no_high_alerts():
    norm = Normalizer()
    engine = DetectionEngine()
    engine.train_baseline([e for e in (norm.normalize(r) for r in
                                       FleetSimulator(None, seed=7).generate_baseline(2000)) if e])
    alerts = []
    for raw in FleetSimulator(None, seed=11).generate_baseline(3000):
        e = norm.normalize(raw)
        if e:
            alerts += engine.process(e)
    assert not [a for a in alerts if a["severity"] in ("high", "critical")], alerts[:3]
    assert len(alerts) <= 3       # anomaly model false-positive budget


def test_anomaly_model_flags_unseen_behaviour():
    norm = Normalizer()
    engine = DetectionEngine()
    engine.train_baseline([e for e in (norm.normalize(r) for r in
                                       FleetSimulator(None, seed=7).generate_baseline(2000)) if e])
    alerts = replay(engine, FleetSimulator(None, seed=5), "fileless_cryptominer")
    assert any(a["source"] == "anomaly" for a in alerts)
