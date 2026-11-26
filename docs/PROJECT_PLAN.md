# Project 3: eBPF-Powered Autonomous Threat Hunting SOC

**Organization:** Zaalima Development Pvt. Ltd. (Enterprise-Level Project, Cyber Security)
**Team size:** 5 members
**Submission:** first week of November 2026
**Repository:** `ebpf-autonomous-soc`

---

## 1. Problem Statement

Design a next-generation Security Operations Center (SOC) framework that uses extended Berkeley Packet Filter (eBPF) for deep, low-overhead kernel-level telemetry. The system must:

1. Autonomously trace lateral movement.
2. Map complex behaviors to the MITRE ATT&CK framework.
3. Execute automated, dynamic network isolation.

## 2. Objectives

- Capture kernel-level syscalls, file executions and socket connections from Linux hosts using eBPF (Falco / Tetragon).
- Stream and normalize telemetry through Apache Kafka.
- Correlate events into process execution trees and detect anomalies (fileless malware, memory injection, privilege escalation).
- Detect threats with Sigma rules tailored to the eBPF event stream.
- Respond automatically through SOAR playbooks (n8n): kill or freeze process trees, block malicious IPs.
- Visualize telemetry and MITRE coverage on a dashboard (Grafana / Kibana).
- Validate with simulated adversarial activity and measure response times.

## 3. Architecture

```
Linux hosts (eBPF: Falco / Tetragon)
        |
        v
  Kafka: raw-ebpf-events
        |
        v
  Normalizer -> Kafka: normalized-events
        |
        v
  Python CEP engine (process trees, ATT&CK tagging, anomaly detection, Sigma rules)
        |
        v
  Alerts -> n8n SOAR -> response on host (kill process / block IP)
        |
        v
  Grafana / Kibana dashboard + forensic timeline + final report
```

## 4. Tools and Technologies

| Area | Tools |
|---|---|
| eBPF telemetry | Falco (primary), Tetragon (enforcement, optional) |
| Streaming | Apache Kafka (Docker) |
| Correlation and detection | Python, Sigma rules, MITRE ATT&CK |
| SOAR | n8n (Cortex as an alternative) |
| Dashboard | Grafana (or Elasticsearch/Kibana) |
| Adversary simulation | Caldera, manual attacks from a Kali VM |
| Lab | VirtualBox, Ubuntu 24.04, Kali Linux |
| Collaboration | GitHub (private repo, branches, pull requests) |

## 5. Deliverables

1. eBPF telemetry dashboard with live MITRE ATT&CK mapping.
2. Autonomous SOAR playbooks that isolate simulated adversaries.
3. Final threat hunting architecture and forensic report.
4. **Final report: "eBPF Autonomous Threat Hunting & Playbook Report"** covering architecture diagram, ATT&CK mapping table, Sigma rules, playbook descriptions, response-time results, and screenshots.

## 6. Mandatory Protocol (from Zaalima)

- Every team must keep a GitHub repository.
- **Commit daily** for every week of the project. Commit history is the strict metric for productivity tracking; without consistent daily commits the evaluation will not be processed.
- Use professional commit messages, logical branch management and standard collaborative workflows.

## 7. Team Roles and Task Distribution

| Member | Name | Role |
|---|---|---|
| Member 1 | Pooja Sonwane | Sensor and data pipeline lead (eBPF + Kafka) and reports and repo owner  |
| Member 2 |Pranil Kumar | MITRE mapping and detection rules and Correlation engine (Python) |
| Member 3 | (name) |SOAR and automated response and  Dashboard, attack simulation|

### Member 1: Sensor and Data Pipeline Lead
**Folders:** `sensor/`, `pipeline/`

- Build the VirtualBox lab (Ubuntu VM for the sensor; extra hosts if RAM allows).
- Install and configure Falco (optionally Tetragon) to capture syscalls, file executions and socket connections.
- Write custom Falco rules (exec from /tmp, reverse shell, sensitive file reads).
- Deploy Kafka (Docker) with topics `raw-ebpf-events` and `normalized-events`.
- Write the shipper and normalizer that publish clean JSON events.
- Publish the shared event schema in `docs/event-schema.md` within the first two days.

**Done when:** events flow Falco -> `raw-ebpf-events` -> normalizer -> `normalized-events`, and teammates can consume them.

### Member 2: MITRE Mapping and Detection Rules
**Folders:** `detection/`, `docs/attack-mapping.csv`

- Design the mapping table: event/syscall -> ATT&CK tactic -> technique ID.
- Write at least 5 Sigma rules for the eBPF event stream.
- Cover: privilege escalation, suspicious shell spawn, memory injection, fileless execution, SSH lateral movement.
- Provide test cases (sample events) for each rule.

**Done when:** each rule fires on its simulated attack and each alert carries the right technique ID.

### Member 3: Correlation Engine (Python)
**Folder:** `correlation/`

- Consume `normalized-events` from Kafka.
- Build parent -> child process execution trees and socket mapping.
- Tag events with ATT&CK techniques using Member 2's mapping.
- Implement rule-based anomaly detection (unusual parent-child pairs, unexpected root processes, fileless execution indicators).
- Publish alerts to the SOAR layer (webhook or Kafka topic `alerts`).

**Done when:** a multi-step attack produces one correlated alert with its process tree.

### Member 4: SOAR and Automated Response
**Folder:** `soar/`

- Install n8n and connect it to the alert source.
- Build playbooks: alert -> kill/freeze the process tree, block the attacker IP (nftables/iptables), optional Tetragon enforcement policy.
- Write the evidence collection script that builds a forensic timeline of lateral movement.
- Log every automated action with timestamps.

**Done when:** a simulated attack is isolated automatically and the forensic timeline is generated.

### Member 5: Dashboard, Simulation, Reports and GitHub
**Folders:** `dashboard/`, `simulation/`, `docs/`

- Own the repo: README, branch protection, pull request reviews, daily commit tracking.
- Build the Grafana/Kibana dashboard: live events, alert counts, MITRE heatmap.
- Run attack simulations (Caldera or scripted attacks from Kali) and record **time from attack to isolation**.
- Collect screenshots and notes from all members weekly.
- Write the final report and architecture diagram.

**Done when:** dashboard is live, response times are recorded, and the final report is complete.

## 8. Timeline (compressed to the deadline)

| Dates | Goal |
|---|---|
| Oct 27-28 | Repo set up, everyone has a lab VM and git access, event schema agreed |
| Oct 29-30 | Falco -> Kafka working; ATT&CK mapping draft; Python consumer; n8n installed |
| Oct 31-Nov 1 | Process trees, Sigma rules and anomaly detection working. **Mid-review.** |
| Nov 1-2 | Integration: alert -> n8n -> response; dashboard showing live data |
| Nov 3 | Run simulations, record response times, take screenshots |
| Nov 4 | Final report, repo cleanup, final review |
| Nov 5 | Buffer and submission |

## 9. Review Checklists

**Mid-project review**
- [ ] eBPF probes capturing telemetry with low CPU overhead
- [ ] Process execution trees and socket mapping operational
- [ ] Initial behavioral anomaly detection running

**Final review**
- [ ] eBPF telemetry dashboard and ATT&CK mapping live
- [ ] SOAR playbooks isolate adversarial simulations
- [ ] Final architecture and forensic report delivered

## 10. Shared Interfaces

- **Event schema:** `docs/event-schema.md` (owned by Member 1; announce any change to the team first).
- **ATT&CK mapping:** `docs/attack-mapping.csv` (owned by Member 2, used by Member 3).
- **Alert format:** JSON with `timestamp`, `host`, `rule`, `technique_id`, `severity`, `process_tree`, `src_ip`, `dst_ip` (owned by Member 3, consumed by Member 4 and 5).

## 11. Git Workflow

```bash
git checkout main && git pull
git checkout -b feat/<area>-<what>
# work
git add . && git commit -m "feat(area): short description"
git push -u origin feat/<area>-<what>
# open a Pull Request, get one review, merge
```

- Commit prefixes: `feat:`, `fix:`, `docs:`, `chore:`.
- One member commits at least once every day, even small commits (config, rules, docs).
- Never commit passwords, API keys, SSH private keys or large log dumps.

## 12. Scope Decisions and Risks

| Item | Decision |
|---|---|
| Event volume | Demonstrate with thousands of events; scale discussed in the report |
| Anomaly detection | Rule-based plus simple statistical baseline instead of trained ML |
| SOAR | n8n instead of Cortex |
| Dashboard | Grafana (lighter than Kibana for limited RAM) |
| Lab hardware | Limited RAM; run Falco and Kafka on one VM if needed |
| Integration risk | Agree on the event schema in the first two days |

## 13. Daily Sync

A 10-minute sync every day to unblock each other. Members 2, 3 and 4 send notes and screenshots to Member 5 weekly so the report is not a last-minute rush.
