"""Translate normalised kernel events into MITRE ATT&CK techniques using the
declarative schema in config/mitre_mapping.yml."""
from __future__ import annotations

import re
from functools import lru_cache

from . import config


def _check(value, op: str, expected) -> bool:
    if op == "equals":
        return value == expected
    if op == "ne":
        return value != expected
    if op == "in":
        return value in expected
    if value is None:
        return False
    if op == "gt":
        return value > expected
    if op == "lt":
        return value < expected
    s = str(value)
    if op == "startswith":
        return s.startswith(expected)
    if op == "endswith":
        return s.endswith(expected)
    if op == "contains":
        return expected in s
    if op == "regex":
        return re.search(expected, s) is not None
    raise ValueError(f"unknown operator {op}")


class MitreMapper:
    def __init__(self, mapping: dict | None = None):
        mapping = mapping or config.load_yaml(config.CONFIG_DIR / "mitre_mapping.yml")
        self.techniques: dict[str, dict] = mapping["techniques"]
        self.tactic_order: list[str] = mapping["tactic_order"]
        self.rules: list[dict] = mapping["rules"]

    def describe(self, tid: str) -> dict:
        t = self.techniques.get(tid, {"name": tid, "tactic": "Unknown"})
        return {"id": tid, "name": t["name"], "tactic": t["tactic"]}

    def map_event(self, ev: dict) -> list[dict]:
        found: dict[str, dict] = {}
        for rule in self.rules:
            ok = True
            for field, cond in rule["match"].items():
                value = ev.get(field)
                for op, expected in cond.items():
                    if not _check(value, op, expected):
                        ok = False
                        break
                if not ok:
                    break
            if ok and rule["technique"] not in found:
                found[rule["technique"]] = self.describe(rule["technique"]) | {"rule": rule["id"]}
        return list(found.values())


@lru_cache(maxsize=1)
def default_mapper() -> MitreMapper:
    return MitreMapper()
