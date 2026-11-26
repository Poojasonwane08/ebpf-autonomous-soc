"""Container entrypoint: run one SOC service against Kafka.

    python -m soc.service sensor      # simulated fleet (SENSOR_MODE=simulate) or Tetragon tail (tetragon)
    python -m soc.service engine      # normalizer + CEP detection engine + SOAR
    python -m soc.service dashboard   # state + REST API + web UI on :8080
"""
from __future__ import annotations

import logging
import signal
import sys
import threading

from . import config, dashboard, detector, normalizer, simulator, soar
from .bus import create_bus


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)-14s %(levelname)-7s %(message)s")
    role = sys.argv[1] if len(sys.argv) > 1 else "all"
    bus = create_bus()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    if role == "sensor":
        if config.SENSOR_MODE == "tetragon":
            from . import tetragon_sensor
            tetragon_sensor.run(bus)
        else:
            simulator.run(bus)
    elif role == "engine":
        norm = normalizer.run(bus)
        baseline_sim = simulator.FleetSimulator(None, seed=7)
        baseline = None
        if config.SENSOR_MODE != "tetragon":     # live mode learns its baseline online
            baseline = [e for e in (norm.normalize(r) for r in baseline_sim.generate_baseline(3000)) if e]
        detector.run(bus, baseline=baseline)
        soar.run(bus)
    elif role == "dashboard":
        import uvicorn
        state = dashboard.run(bus)
        uvicorn.run(dashboard.create_app(bus, state), host=config.DASHBOARD_HOST,
                    port=config.DASHBOARD_PORT, log_level="warning")
        return
    else:
        raise SystemExit(f"unknown role {role!r} (sensor | engine | dashboard)")

    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    bus.close()


if __name__ == "__main__":
    main()
