"""A compact Sigma rule engine for the eBPF event stream.

Supports the commonly used subset of the Sigma specification:
  * logsource (product/category) -> mapped onto normalised event types
  * detection maps (AND) and lists of maps (OR), value lists (OR)
  * modifiers: contains, startswith, endswith, re, all, gt, lt
  * conditions: and / or / not / parentheses / "1 of sel*" / "all of sel*" /
    "1 of them" / "all of them"

Rules live in rules/sigma/*.yml and are standard Sigma YAML, so they can be
reused with other Sigma back-ends (pySigma) later.
"""
from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path

import yaml

from . import config

log = logging.getLogger("soc.sigma")

# Sigma field name -> normalised event key
FIELD_MAP = {
    "Image": "binary", "CommandLine": "cmdline", "ParentImage": "parent_binary",
    "Args": "args", "User": "uid", "Uid": "uid", "NewUid": "new_uid",
    "CurrentDirectory": "cwd", "Hostname": "host",
    "DestinationIp": "dst_ip", "DestinationPort": "dst_port",
    "DestinationHostname": "dst_host", "DestinationIsExternal": "dst_external",
    "SourceIp": "src_ip", "TargetFilename": "file_path", "EventType": "type",
    "Function": "function", "PtraceRequest": "ptrace_request", "MemfdName": "memfd_name",
}

CATEGORY_TYPES = {
    "process_creation": {"process_exec"},
    "network_connection": {"network_connect", "network_blocked"},
    "file_access": {"file_access"},
    "file_event": {"file_access"},
    "privilege_change": {"privilege_change", "setuid"},
    "process_access": {"ptrace"},
    "memfd": {"memfd_create"},
}

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _match_value(actual, expected, modifiers: list[str]) -> bool:
    if actual is None:
        return expected is None
    if "gt" in modifiers:
        return float(actual) > float(expected)
    if "lt" in modifiers:
        return float(actual) < float(expected)
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual == expected
    if isinstance(expected, (int, float)) and not modifiers:
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    a, e = str(actual), str(expected)
    if "re" in modifiers:
        return re.search(e, a) is not None
    a_l, e_l = a.lower(), e.lower()
    if "contains" in modifiers:
        return e_l in a_l
    if "startswith" in modifiers:
        return a_l.startswith(e_l)
    if "endswith" in modifiers:
        return a_l.endswith(e_l)
    if "*" in e or "?" in e:  # Sigma wildcards in plain values
        return fnmatch.fnmatch(a_l, e_l)
    return a_l == e_l


def _match_map(event: dict, selection: dict) -> bool:
    for key, expected in selection.items():
        field, *mods = key.split("|")
        actual = event.get(FIELD_MAP.get(field, field))
        values = expected if isinstance(expected, list) else [expected]
        if "all" in mods:
            ok = all(_match_value(actual, v, mods) for v in values)
        else:
            ok = any(_match_value(actual, v, mods) for v in values)
        if not ok:
            return False
    return True


def _match_selection(event: dict, selection) -> bool:
    if isinstance(selection, list):
        return any(_match_map(event, s) if isinstance(s, dict)
                   else _match_value(event.get("cmdline"), s, ["contains"]) for s in selection)
    return _match_map(event, selection)


class _Condition:
    """Tiny recursive-descent parser for Sigma condition strings."""

    TOKEN = re.compile(r"\(|\)|[\w*]+")

    def __init__(self, text: str, names: list[str]):
        self.tokens = self.TOKEN.findall(text)
        self.names = names
        self.pos = 0

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self):
        node = self._or()
        if self._peek() is not None:
            raise ValueError(f"unexpected token {self._peek()}")
        return node

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._take()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        tok = self._take()
        if tok == "(":
            node = self._or()
            if self._take() != ")":
                raise ValueError("missing )")
            return node
        if tok in ("1", "all") and self._peek() == "of":
            self._take()
            pattern = self._take()
            names = self.names if pattern == "them" else fnmatch.filter(self.names, pattern)
            return ("any" if tok == "1" else "all", names)
        return ("sel", tok)


def _eval(node, event, detection) -> bool:
    op = node[0]
    if op == "sel":
        return _match_selection(event, detection[node[1]])
    if op == "and":
        return _eval(node[1], event, detection) and _eval(node[2], event, detection)
    if op == "or":
        return _eval(node[1], event, detection) or _eval(node[2], event, detection)
    if op == "not":
        return not _eval(node[1], event, detection)
    if op == "any":
        return any(_match_selection(event, detection[n]) for n in node[1])
    if op == "all":
        return all(_match_selection(event, detection[n]) for n in node[1])
    raise ValueError(op)


class SigmaRule:
    def __init__(self, data: dict, source: str = ""):
        self.data = data
        self.id = data.get("id", source)
        self.title = data["title"]
        self.level = data.get("level", "medium")
        self.description = data.get("description", "")
        self.source = source
        self.tags = data.get("tags", [])
        self.techniques = sorted({
            t.split(".", 1)[1].upper() for t in self.tags
            if re.match(r"attack\.t\d{4}", t, re.I)})
        ls = data.get("logsource", {})
        self.event_types = CATEGORY_TYPES.get(ls.get("category"))  # None = any
        det = dict(data["detection"])
        cond = det.pop("condition")
        self.detection = det
        conditions = cond if isinstance(cond, list) else [cond]
        names = list(det.keys())
        self.conditions = [_Condition(c, names).parse() for c in conditions]

    def matches(self, event: dict) -> bool:
        if self.event_types and event.get("type") not in self.event_types:
            return False
        return any(_eval(c, event, self.detection) for c in self.conditions)


class SigmaEngine:
    def __init__(self, rule_dir: Path | None = None):
        self.rules: list[SigmaRule] = []
        rule_dir = rule_dir or config.SIGMA_DIR
        for path in sorted(Path(rule_dir).glob("*.yml")):
            try:
                with open(path, encoding="utf-8") as fh:
                    for doc in yaml.safe_load_all(fh):
                        if doc:
                            self.rules.append(SigmaRule(doc, path.name))
            except Exception as exc:
                log.error("failed to load sigma rule %s: %s", path, exc)
        log.info("loaded %d sigma rules", len(self.rules))

    def evaluate(self, event: dict) -> list[SigmaRule]:
        return [r for r in self.rules if r.matches(event)]
