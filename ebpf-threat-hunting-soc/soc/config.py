"""Central configuration. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --- Messaging ---------------------------------------------------------------
BUS = _env("SOC_BUS", "memory")                     # "memory" or "kafka"
KAFKA_BOOTSTRAP = _env("KAFKA_BOOTSTRAP", "localhost:9092")

TOPIC_RAW = "ebpf.raw"                # raw Tetragon JSON events from sensors
TOPIC_EVENTS = "soc.events"           # normalised + MITRE-tagged events
TOPIC_ALERTS = "soc.alerts"           # detections (Sigma / behavioural / anomaly / correlation)
TOPIC_INCIDENTS = "soc.incidents"     # incident lifecycle updates
TOPIC_ACTIONS = "soc.actions"         # SOAR response commands to sensors
TOPIC_ACTION_RESULTS = "soc.action_results"  # sensor acknowledgements
TOPIC_CONTROL = "soc.control"         # dashboard control plane (scenarios, mode, reset)

ALL_TOPICS = [TOPIC_RAW, TOPIC_EVENTS, TOPIC_ALERTS, TOPIC_INCIDENTS,
              TOPIC_ACTIONS, TOPIC_ACTION_RESULTS, TOPIC_CONTROL]

# --- Sensor ------------------------------------------------------------------
SENSOR_MODE = _env("SENSOR_MODE", "simulate")       # "simulate" or "tetragon"
TETRAGON_EXPORT_FILE = _env("TETRAGON_EXPORT_FILE", "/var/log/tetragon/tetragon.log")
BACKGROUND_EPS = float(_env("BACKGROUND_EPS", "25"))  # benign events / second (simulator)
SCENARIO_SPEED = float(_env("SCENARIO_SPEED", "1.0"))  # >1 = faster attack playback

# --- SOAR --------------------------------------------------------------------
RESPONSE_MODE = _env("RESPONSE_MODE", "autonomous")  # "autonomous" or "monitor"
SOAR_WEBHOOK_URL = _env("SOAR_WEBHOOK_URL", "")      # e.g. an n8n webhook
LIVE_RESPONDER_DRY_RUN = _env("LIVE_RESPONDER_DRY_RUN", "true").lower() != "false"

# --- Dashboard ---------------------------------------------------------------
DASHBOARD_HOST = _env("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(_env("DASHBOARD_PORT", "8080"))
EVIDENCE_DIR = Path(_env("EVIDENCE_DIR", str(ROOT / "evidence")))

# --- Paths -------------------------------------------------------------------
CONFIG_DIR = ROOT / "config"
SIGMA_DIR = ROOT / "rules" / "sigma"
PLAYBOOK_DIR = ROOT / "playbooks"
SCENARIO_DIR = ROOT / "scenarios"


def load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_fleet() -> dict:
    return load_yaml(CONFIG_DIR / "fleet.yml")
