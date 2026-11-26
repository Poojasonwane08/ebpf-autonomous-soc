"""Throughput benchmark of the detection pipeline (single Python process, no Kafka).

    python scripts/benchmark.py --events 200000

Measures how many raw Tetragon events per second the normalizer + MITRE mapper +
CEP engine (process trees, 15 Sigma rules, behavioural detectors, IsolationForest,
lateral-movement correlation) can process on one CPU core. Scale horizontally by
adding engine containers to the Kafka consumer group (events are keyed by host).
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc.detector import DetectionEngine  # noqa: E402
from soc.normalizer import Normalizer  # noqa: E402
from soc.simulator import FleetSimulator  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=200000)
    args = ap.parse_args()

    norm = Normalizer()
    engine = DetectionEngine()
    engine.train_baseline([e for e in (norm.normalize(r) for r in
                                       FleetSimulator(None, seed=7).generate_baseline(2000)) if e])
    print("generating raw eBPF events...")
    sim = FleetSimulator(None, seed=1)
    raw = []
    while len(raw) < args.events:
        raw += sim.generate_baseline(5000)
    raw = raw[: args.events]

    t0 = time.perf_counter()
    normalized = [norm.normalize(r) for r in raw]
    t1 = time.perf_counter()
    alerts = 0
    for e in normalized:
        alerts += len(engine.process(e))
    t2 = time.perf_counter()
    n = len(raw)
    print(f"events            : {n:,}")
    print(f"normalize + MITRE : {n / (t1 - t0):>10,.0f} events/s")
    print(f"CEP detection     : {n / (t2 - t1):>10,.0f} events/s")
    print(f"end-to-end        : {n / (t2 - t0):>10,.0f} events/s per core")
    print(f"alerts on benign  : {alerts}")


if __name__ == "__main__":
    main()
