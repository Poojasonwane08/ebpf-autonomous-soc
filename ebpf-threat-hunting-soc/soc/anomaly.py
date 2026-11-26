"""Behavioural analytics on the kernel event stream.

Two layers:

1. ``BehaviourDetector`` - deterministic, stateful sequence detectors for the
   three behaviours the project brief calls out:
     * fileless malware   (memfd_create -> exec from /proc/<pid>/fd or memfd)
     * memory injection   (ptrace ATTACH -> POKETEXT/POKEDATA on another pid)
     * privilege escalation (non-root process gains uid 0 outside sudo/su/login)

2. ``AnomalyModel`` - an unsupervised IsolationForest trained on a baseline of
   normal process executions (parent/child rarity, path, uid class, argument
   entropy, tree depth, spawn burst). Anything far outside the baseline raises
   a medium-severity "anomalous process behaviour" alert.
"""
from __future__ import annotations

import logging
import math
import re
import time
from collections import Counter, defaultdict, deque

from .process_tree import BOUNDARY_BINARIES, ProcessTreeStore, basename

log = logging.getLogger("soc.anomaly")

LEGIT_ESCALATORS = {"sudo", "su", "sshd", "login", "cron", "crond", "systemd", "polkitd",
                    "pkexec-legit", "newgrp", "unix_chkpwd", "runuser", "doas"}
WRITABLE_EXEC = re.compile(r"^(/tmp/|/var/tmp/|/dev/shm/|/proc/|memfd:|/run/user/)")
WRITABLE_ARGS = re.compile(r"(/tmp/|/var/tmp/|/dev/shm/|/proc/self/|memfd)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# 1. Deterministic behaviour sequences
# ---------------------------------------------------------------------------
class BehaviourDetector:
    def __init__(self, trees: ProcessTreeStore):
        self.trees = trees
        self.memfd = {}                       # (host, pid) -> ts of memfd_create
        self.ptrace_attach = {}               # (host, exec_id, target) -> ts

    def evaluate(self, ev: dict) -> list[dict]:
        out = []
        host, t = ev["host"], ev["type"]
        now = ev.get("ts_epoch", time.time())

        if t == "memfd_create":
            self.memfd[(host, ev.get("pid"))] = now
        elif t == "process_exec":
            b = ev.get("binary") or ""
            if WRITABLE_EXEC.match(b) or b.startswith("/proc/"):
                # same pid (fexecve replaces image) or child of the memfd creator
                for pid in (ev.get("pid"), ev.get("parent_pid")):
                    ts = self.memfd.get((host, pid))
                    if ts and now - ts < 60:
                        out.append(_alert("BHV-FILELESS", "Fileless execution chain: memfd_create -> exec from memory",
                                          "critical", ["T1620"],
                                          f"{b} executed from an anonymous memory file "
                                          f"{now - ts:.1f}s after memfd_create()"))
                        break
        elif t == "ptrace":
            req = ev.get("ptrace_request")
            key = (host, ev.get("exec_id"), ev.get("target_pid"))
            if req in ("PTRACE_ATTACH", "PTRACE_SEIZE"):
                self.ptrace_attach[key] = now
            elif req in ("PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_SETREGS"):
                ts = self.ptrace_attach.get(key)
                if ts and now - ts < 120:
                    out.append(_alert("BHV-INJECT", "Process memory injection: ptrace attach + write",
                                      "critical", ["T1055.008"],
                                      f"{ev.get('binary')} attached to pid {ev.get('target_pid')} "
                                      f"and wrote to its memory ({req})"))
        elif t in ("privilege_change", "setuid"):
            if ev.get("new_uid") == 0 and (ev.get("uid") or 0) != 0:
                lineage = [basename(ev.get("binary"))] + self.trees.lineage_binaries(host, ev["exec_id"])
                if not LEGIT_ESCALATORS.intersection(lineage[:1]) and not (
                        set(lineage[:3]) & {"sudo", "su", "pkexec-legit"}):
                    out.append(_alert("BHV-PRIVESC", "Privilege escalation to root outside approved paths",
                                      "critical", ["T1068"],
                                      f"uid {ev.get('uid')} -> 0 in {ev.get('binary')} "
                                      f"(lineage: {' <- '.join(lineage[:6])})"))
        return out


# ---------------------------------------------------------------------------
# 2. Unsupervised anomaly model
# ---------------------------------------------------------------------------
class AnomalyModel:
    FEATURES = ["pair_rarity", "binary_rarity", "writable_binary", "writable_args", "uid_class",
                "args_len", "args_entropy", "depth", "spawn_burst"]

    def __init__(self, trees: ProcessTreeStore, threshold: float | None = None,
                 learning_events: int = 2000):
        self.trees = trees
        self.threshold = threshold
        self.learning_events = learning_events
        self.pair_counts: Counter = Counter()
        self.binary_counts: Counter = Counter()
        self.total_pairs = 0
        self.model = None
        self._buffer: list[list[float]] = []
        self._spawn = defaultdict(deque)       # (host, parent_exec) -> deque[ts]
        self.trained_on = 0

    def _features(self, ev: dict) -> list[float]:
        pair = (basename(ev.get("parent_binary")), basename(ev.get("binary")))
        cnt = self.pair_counts.get(pair, 0)
        rarity = -math.log((cnt + 1) / (self.total_pairs + 2))
        bcnt = self.binary_counts.get(basename(ev.get("binary")), 0)
        brarity = -math.log((bcnt + 1) / (self.total_pairs + 2))
        b = ev.get("binary") or ""
        uid = ev.get("uid")
        uid_class = 0 if uid == 0 else (1 if uid is not None and uid < 1000 else 2)
        args = ev.get("args") or ""
        depth = len(self.trees.ancestors(ev["host"], ev["exec_id"]))
        key = (ev["host"], ev.get("parent_exec_id"))
        dq = self._spawn[key]
        now = ev.get("ts_epoch", time.time())
        dq.append(now)
        while dq and now - dq[0] > 30:
            dq.popleft()
        return [rarity, brarity, 1.0 if WRITABLE_EXEC.match(b) else 0.0,
                1.0 if WRITABLE_ARGS.search(args) else 0.0, float(uid_class),
                math.log1p(len(args)), shannon_entropy(args), float(depth), float(len(dq))]

    def _learn_pair(self, ev):
        self.pair_counts[(basename(ev.get("parent_binary")), basename(ev.get("binary")))] += 1
        self.binary_counts[basename(ev.get("binary"))] += 1
        self.total_pairs += 1

    def fit(self, baseline_events: list[dict]) -> None:
        """Train on a list of known-good process_exec events (already inserted
        in a ProcessTreeStore so depth can be computed)."""
        # service daemons started at boot are not "behaviour" - keep them out of the model
        execs = [e for e in baseline_events if e["type"] == "process_exec"
                 and basename(e.get("binary")) not in BOUNDARY_BINARIES]
        for e in execs:
            self._learn_pair(e)
        X = [self._features(e) for e in execs]
        self._spawn.clear()
        self._train(X)

    def _train(self, X):
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:  # pragma: no cover - sklearn missing: rarity-only mode
            log.warning("scikit-learn not installed - anomaly model uses rarity scoring only")
            self.model = "rarity"
            self.trained_on = len(X)
            return
        if len(X) < 50:
            return
        self.model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        self.model.fit(X)
        self.trained_on = len(X)
        if self.threshold is None:
            # calibrate: alert below the 5% quantile of scores on the (benign) training set
            scores = sorted(self.model.decision_function(X))
            self.threshold = float(scores[max(0, int(len(scores) * 0.05) - 1)]) - 0.005
        log.info("anomaly model trained on %d process executions", len(X))

    def score(self, ev: dict) -> list[dict]:
        if ev["type"] != "process_exec" or basename(ev.get("binary")) in BOUNDARY_BINARIES:
            return []
        feats = self._features(ev)
        if self.model is None:              # online learning period (live mode)
            self._learn_pair(ev)
            self._buffer.append(feats)
            if len(self._buffer) >= self.learning_events:
                self._train(self._buffer)
                self._buffer = []
            return []
        unseen_pair = self.pair_counts.get(
            (basename(ev.get("parent_binary")), basename(ev.get("binary"))), 0) == 0
        novel = self.binary_counts.get(basename(ev.get("binary")), 0) == 0 or feats[2] or feats[3]
        if not (unseen_pair and novel):
            return []            # cheap gate first: model inference only for novel behaviour
        if self.model == "rarity":
            s = -feats[0] / 12.0
            if self.threshold is None:
                self.threshold = -0.6
        else:
            s = float(self.model.decision_function([feats])[0])
        if s < self.threshold:
            names = dict(zip(self.FEATURES, (round(f, 2) for f in feats)))
            return [_alert("ANOM-PROC", "Anomalous process behaviour (IsolationForest)", "medium", [],
                           f"score={s:.3f} (threshold {self.threshold:.3f}); never-seen parent/child pair "
                           f"{basename(ev.get('parent_binary'))} -> {basename(ev.get('binary'))}; "
                           f"features={names}", score=s)]
        return []


def _alert(rule_id, title, severity, techniques, description, score=None):
    return {"rule_id": rule_id, "title": title, "severity": severity,
            "technique_ids": techniques, "description": description,
            "source": "anomaly" if rule_id.startswith("ANOM") else "behaviour",
            "anomaly_score": score}
