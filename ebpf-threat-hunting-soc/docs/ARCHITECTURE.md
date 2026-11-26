# Architecture

## Services

| Service | Module | Container | Role |
|---|---|---|---|
| Sensor (simulated) | `soc/simulator.py` | `soc-sensor` | 5 virtual Linux hosts emitting Tetragon-format eBPF events, plays adversary scenarios, enforces response actions |
| Sensor (live) | `soc/tetragon_sensor.py` | `soc-sensor` + `soc-tetragon` | Tails real Tetragon JSON, executes actions on the host |
| Normalizer | `soc/normalizer.py` + `soc/mitre.py` | `soc-engine` | Raw event → normalised schema + ATT&CK tags |
| CEP / detection | `soc/detector.py`, `process_tree.py`, `sigma.py`, `anomaly.py` | `soc-engine` | Process trees, detections, lateral movement correlation, incidents |
| SOAR | `soc/soar.py` | `soc-engine` | Playbooks → response actions |
| Dashboard | `soc/dashboard.py`, `forensics.py`, `report.py`, `web/` | `soc-dashboard` | State, REST API, UI, evidence, report |
| Broker | Apache Kafka 3.8 (KRaft) | `soc-kafka` | Streaming backbone |

All services talk only through the bus (`soc/bus.py`). The same code runs on Kafka (Docker) or on an
in-memory bus (one Python process, `python -m soc.run_all`).

## Kafka topics

| Topic | Producer → Consumer | Content |
|---|---|---|
| `ebpf.raw` | sensors → normalizer | raw Tetragon JSON (keyed by host) |
| `soc.events` | normalizer → CEP, dashboard | normalised + ATT&CK-tagged events |
| `soc.alerts` | CEP → SOAR, dashboard | detections |
| `soc.incidents` | CEP → SOAR, dashboard | incident create/update (hosts, roots, lateral edges, techniques) |
| `soc.actions` | SOAR / analyst → sensors, dashboard | response commands |
| `soc.action_results` | sensors / SOAR / dashboard → dashboard | action outcome + scenario progress |
| `soc.control` | dashboard → all | run scenario, response mode, reset |

Events are keyed by host, so all events of one host land in the same partition (ordering per host is
preserved). Scaling the engine = more `engine` containers in the `detector` consumer group (3 partitions
by default; raise `KAFKA_NUM_PARTITIONS` for more).

## Normalised event schema

```
id, ts, ts_epoch, host, type, exec_id, parent_exec_id, pid, uid, binary, args, cmdline, cwd,
parent_binary, parent_pid, function, action, blocked, src_ip, src_port, dst_ip, dst_port,
dst_host, dst_external, file_path, new_uid, ptrace_request, target_pid, memfd_name,
mitre: [{id, name, tactic, rule}]
```

`type` ∈ `process_exec, process_exit, network_connect, network_blocked, file_access,
privilege_change, setuid, ptrace, memfd_create`.

| Tetragon raw event | Normalised type |
|---|---|
| `process_exec` | `process_exec` |
| `process_exit` | `process_exit` |
| `process_kprobe` `tcp_connect` (POST) | `network_connect` |
| `process_kprobe` `tcp_connect` (SIGKILL action) | `network_blocked` |
| `process_kprobe` `commit_creds` | `privilege_change` |
| `process_kprobe` `__x64_sys_setuid` | `setuid` |
| `process_kprobe` `__x64_sys_ptrace` | `ptrace` |
| `process_kprobe` `__x64_sys_memfd_create` | `memfd_create` |
| `process_kprobe` `security_file_permission` | `file_access` |

## CEP engine

For every event (`DetectionEngine.process`):

1. **Process tree** — `ProcessTreeStore.on_event` links `exec_id` ↔ `parent_exec_id` (creating
   placeholders for parents seen later) and attaches every non-exec event to its process.
2. **Attack root** — walk up the ancestors until a *boundary* process (systemd, sshd, cron, nginx,
   php-fpm, gunicorn, postgres…). The highest non-boundary ancestor is the root of the "story"; e.g. the
   `/bin/sh` a web shell made php-fpm spawn.
3. **Detections** — Sigma rules, behavioural sequence detectors and the IsolationForest model.
4. **Lateral movement** — `LateralMovementCorrelator` keeps a window of SSH connects and of
   `sshd → shell` sessions; a match within 20 s creates an edge `src_host → dst_host`. If the source process
   belongs to an incident (or the source is not an approved admin host) a critical correlation alert is
   raised **inside the source's incident**, and the destination session's tree is added to that incident.
   Admin SSH from `bastion-01` (config `admin_sources`) is not flagged.
5. **Incidents** — alerts are grouped by attack root; a new medium+ alert on a host with a recent open
   incident joins it; low-severity alerts never open incidents on their own.

## SOAR

`playbooks/*.yml` — trigger (techniques, severity, source) + action list with targets:
`alert_host`, `incident_hosts`, `attack_root`, `incident_roots`, `alert_process`, `incident_external_ips`.

- Containment actions (`freeze_process_tree`, `kill_process_tree`, `isolate_host`, `block_ip`) are executed only
  in **autonomous** mode, otherwise *recommended*; `approval: true` makes them wait for an analyst click.
- Each containment target is executed once per incident (deduplication across playbooks).
- External IPs are harvested from alert command lines / connections into the incident IOC set.
- `notify` POSTs to `SOAR_WEBHOOK_URL` (e.g. an **n8n** webhook node → Slack/Teams/Jira).

## Response enforcement

| Action | Simulator | Live (Linux) |
|---|---|---|
| freeze_process_tree | processes marked frozen; later steps that need them fail | `SIGSTOP` to every PID in the tree |
| kill_process_tree | `process_exit` with `SIGKILL` | `SIGKILL` to every PID in the tree |
| isolate_host | every `tcp_connect` except the SOC IP → `KPROBE_ACTION_SIGKILL` | nftables table dropping everything except the SOC IP |
| block_ip | connects to the IP → `KPROBE_ACTION_SIGKILL` | Tetragon TracingPolicy `tcp_connect` + `DAddr` + `Sigkill` (in-kernel) |

## Metrics

- **MTTD** — first alert detection time − start of the attack root process.
- **Kernel → response** — action completion − timestamp of the kernel event that triggered it.
- **Dwell until contained** — first successful freeze/kill/isolate − start of the attack root.
