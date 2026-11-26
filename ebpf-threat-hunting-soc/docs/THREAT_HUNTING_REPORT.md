# eBPF Autonomous Threat Hunting - Detection & Playbook Report

_Generated 2026-11-26 05:22 UTC by `soc.report`._

## 1. Summary

| Metric | Value |
|---|---|
| Kernel events processed | 2,527 |
| Alerts raised | 95 (18 critical) |
| Incidents (open / contained) | 3 / 3 |
| Hosts isolated | 0 |
| IPs blocked by eBPF policy | 2 |
| Mean kernel-event -> containment latency | 5.5 ms |

## 2. Adversary emulation results

Each scenario was played twice: once with response **off** (monitor mode, shows the full kill chain and what the detections see) and once with **autonomous** SOAR response.

| Scenario | Mode | Steps executed | Steps prevented/blocked | Alerts | Techniques detected | Time to contain |
|---|---|---|---|---|---|---|
| apt_lateral_movement | monitor | 28/28 | 0 | 37 | 15 | - |
| apt_lateral_movement | autonomous | 11/28 | 17 | 16 | 7 | 2,279.9 ms |
| fileless_cryptominer | monitor | 10/10 | 0 | 13 | 7 | - |
| fileless_cryptominer | autonomous | 6/10 | 4 | 11 | 5 | 986.6 ms |
| insider_privesc | monitor | 13/13 | 0 | 13 | 6 | - |
| insider_privesc | autonomous | 6/13 | 7 | 5 | 2 | 826.8 ms |

### apt_lateral_movement - step-by-step (autonomous)

| # | Step | Host | ATT&CK | Result |
|---|---|---|---|---|
| 1 | Web shell spawns /bin/sh | web-01 | T1505.003 | **executed** |
| 2 | whoami | web-01 | T1033 | **executed** |
| 3 | id | web-01 | T1033 | **executed** |
| 4 | uname -a | web-01 | T1082 | **executed** |
| 5 | cat /etc/passwd | web-01 | T1087.001 | **executed** |
| 6 | Download stager to /tmp | web-01 | T1105 | **executed** |
| 7 | Stager C2 connection | web-01 |  | **blocked** |
| 8 | Run stager | web-01 | T1059.004 | **executed** |
| 9 | Steal deploy SSH key | web-01 |  | **executed** |
| 10 | Read private key (kernel file hook) | web-01 | T1552.004 | **executed** |
| 11 | ssh deploy@app-01 | web-01 |  | **executed** |
| 12 | SSH pivot web-01 -> app-01 | web-01 | T1021.004 | **executed** |
| 13 | hostname | app-01 | T1082 | **prevented** |
| 14 | Download exploit | app-01 | T1105 | **prevented** |
| 15 | Exploit download connection | app-01 |  | **prevented** |
| 16 | Run local privilege-escalation exploit | app-01 |  | **prevented** |
| 17 | Kernel creds -> uid 0 | app-01 | T1068 | **prevented** |
| 18 | Root shell | app-01 |  | **prevented** |
| 19 | Python memfd loader | app-01 |  | **prevented** |
| 20 | kworker | app-01 | T1620 | **prevented** |
| 21 | Execute implant from memory | app-01 | T1620 | **prevented** |
| 22 | Inject into gunicorn via ptrace | app-01 | T1055.008 | **prevented** |
| 23 | Cron persistence | app-01 | T1053.003 | **prevented** |
| 24 | Archive secrets | app-01 | T1560.001 | **prevented** |
| 25 | Read /etc/shadow | app-01 | T1003.008 | **prevented** |
| 26 | Exfiltrate over HTTPS | app-01 | T1048 | **prevented** |
| 27 | Exfil connection | app-01 |  | **prevented** |
| 28 | Wipe auth log | app-01 | T1070.002 | **prevented** |

### fileless_cryptominer - step-by-step (autonomous)

| # | Step | Host | ATT&CK | Result |
|---|---|---|---|---|
| 1 | RCE spawns shell | web-02 | T1505.003 | **executed** |
| 2 | Download loader to /dev/shm | web-02 | T1105 | **executed** |
| 3 | Loader download connection | web-02 |  | **blocked** |
| 4 | Run loader | web-02 |  | **executed** |
| 5 | Python memfd loader | web-02 |  | **executed** |
| 6 | kswapd0 | web-02 | T1620 | **executed** |
| 7 | XMRig executed from memory | web-02 | T1496 | **executed** |
| 8 | Mining pool connection :3333 | web-02 | T1571 | **prevented** |
| 9 | Cron persistence | web-02 | T1053.003 | **prevented** |
| 10 | Second pool connection attempt | web-02 | T1571 | **prevented** |

### insider_privesc - step-by-step (autonomous)

| # | Step | Host | ATT&CK | Result |
|---|---|---|---|---|
| 1 | Login on bastion | bastion-01 |  | **executed** |
| 2 | ssh dbadmin@db-01 | bastion-01 |  | **executed** |
| 3 | Admin SSH session (legit path) | bastion-01 |  | **executed** |
| 4 | id | db-01 | T1033 | **executed** |
| 5 | pkexec exploit (CVE-2021-4034) | db-01 |  | **executed** |
| 6 | Kernel creds -> uid 0 | db-01 | T1068 | **executed** |
| 7 | Root shell | db-01 |  | **prevented** |
| 8 | Dump /etc/shadow | db-01 |  | **prevented** |
| 9 | Read /etc/shadow | db-01 | T1003.008 | **prevented** |
| 10 | Injector | db-01 |  | **prevented** |
| 11 | ptrace into postgres | db-01 | T1055.008 | **prevented** |
| 12 | Cron persistence | db-01 | T1053.003 | **prevented** |
| 13 | Clear logs + history | db-01 | T1070.002 | **prevented** |

## 3. Incidents

| Incident | Severity | Hosts | Techniques | Status | MTTD | Kernel->response | Dwell until contained |
|---|---|---|---|---|---|---|---|
| INC-0006 | critical | db-01 | T1033, T1068 | contained | 387.6 ms | 1.3 ms | 826.8 ms |
| INC-0005 | critical | db-01 | T1033, T1068, T1003.008, T1055.008, T1053.003, T1070.002 | open | 391.7 ms | - | - |
| INC-0004 | critical | web-02 | T1505.003, T1059.004, T1105, T1620, T1496 | contained | 12.4 ms | 10.5 ms | 986.6 ms |
| INC-0003 | critical | web-02 | T1505.003, T1059.004, T1105, T1620, T1496, T1053.003, T1571 | open | 11.4 ms | - | - |
| INC-0002 | critical | web-01, app-01 | T1505.003, T1033, T1082, T1087.001, T1105, T1552.004, T1021.004 | contained | 0.8 ms | 1.7 ms | 2,279.9 ms |
| INC-0001 | critical | web-01, app-01 | T1505.003, T1033, T1082, T1087.001, T1105, T1552.004, T1021.004, T1068 | open | 0.7 ms | - | - |

## 4. Detection signatures

### 4.1 Sigma rules (rules/sigma)

| Rule | Level | ATT&CK | Hits |
|---|---|---|---|
| Cron Persistence by Non-Root User or Web Account | medium | T1053.003 | 2 |
| Cryptominer Execution or Mining Pool Connection | high | T1496, T1571 | 3 |
| Data Exfiltration via HTTP Upload Tools | high | T1048 | 1 |
| Fileless Execution from memfd / /proc/self/fd / /dev/shm | critical | T1620 | 3 |
| Download of Payload to Temp / Pipe-to-Shell | high | T1105 | 5 |
| Linux System Discovery Commands | low | T1033, T1082, T1087.001 | 11 |
| Linux Log or History Tampering | high | T1070.002 | 2 |
| memfd_create Syscall from Scripting / Download Process | high | T1620 | 3 |
| Ptrace Process Injection | critical | T1055.008 | 2 |
| Reverse Shell Command Line | critical | T1059.004 | 0 |
| Access to /etc/shadow (Credential Dumping) | high | T1003.008 | 2 |
| Outbound SSH from a Non-Admin Server | high | T1021.004 | 2 |
| SSH Private Key Read by Non-SSH Process | high | T1552.004 | 2 |
| Unexpected Privilege Escalation to Root (commit_creds) | critical | T1068 | 3 |
| Web Server Process Spawns a Shell (Web Shell) | high | T1190, T1505.003 | 4 |

### 4.2 Behavioural, anomaly and correlation detections

| Detector | Title | Severity | Hits |
|---|---|---|---|
| anomaly:ANOM-PROC | Anomalous process behaviour (IsolationForest) | medium | 40 |
| behaviour:BHV-PRIVESC | Privilege escalation to root outside approved paths | critical | 3 |
| behaviour:BHV-FILELESS | Fileless execution chain: memfd_create -> exec from memory | critical | 3 |
| correlation:CORR-LATERAL-SSH | Lateral movement via SSH: web-01 -> app-01 | critical | 2 |
| behaviour:BHV-INJECT | Process memory injection: ptrace attach + write | critical | 2 |

## 5. MITRE ATT&CK coverage (alerts per technique)

| Tactic | Technique | Alerts |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing Application |  |
| Execution | T1059.004 Command and Scripting Interpreter: Unix Shell | 2 |
| Persistence | T1505.003 Server Software Component: Web Shell | 6 |
| Persistence | T1053.003 Scheduled Task/Job: Cron | 3 |
| Privilege Escalation | T1068 Exploitation for Privilege Escalation | 6 |
| Privilege Escalation | T1548.001 Abuse Elevation Control: Setuid and Setgid |  |
| Defense Evasion | T1620 Reflective Code Loading (fileless / memfd) | 12 |
| Defense Evasion | T1055.008 Process Injection: Ptrace System Calls | 4 |
| Defense Evasion | T1070.002 Indicator Removal: Clear Linux Logs | 3 |
| Credential Access | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow | 2 |
| Credential Access | T1552.004 Unsecured Credentials: Private Keys | 2 |
| Discovery | T1033 System Owner/User Discovery | 12 |
| Discovery | T1082 System Information Discovery | 6 |
| Discovery | T1087.001 Account Discovery: Local Account | 4 |
| Discovery | T1018 Remote System Discovery |  |
| Lateral Movement | T1021.004 Remote Services: SSH | 4 |
| Collection | T1560.001 Archive Collected Data: Archive via Utility | 1 |
| Command and Control | T1105 Ingress Tool Transfer | 10 |
| Command and Control | T1571 Non-Standard Port | 1 |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol | 2 |
| Impact | T1496 Resource Hijacking (cryptomining) | 4 |

## 6. Playbook effectiveness

| Playbook | Action | Issued | Succeeded | Recommended only | Avg kernel->response |
|---|---|---|---|---|---|
| PB-01 Contain lateral movement | collect_evidence | 2 | 2 | 0 | - |
| PB-01 Contain lateral movement | freeze_process_tree | 3 | 2 | 1 | 1.7 ms |
| PB-01 Contain lateral movement | isolate_host | 4 | 2 | 2 | 1.7 ms |
| PB-01 Contain lateral movement | notify | 2 | 2 | 0 | - |
| PB-02 Kill fileless malware / process injection | collect_evidence | 4 | 4 | 0 | - |
| PB-02 Kill fileless malware / process injection | kill_process_tree | 4 | 1 | 3 | 10.5 ms |
| PB-02 Kill fileless malware / process injection | notify | 4 | 4 | 0 | - |
| PB-03 Freeze privilege escalation and isolate host | collect_evidence | 3 | 3 | 0 | - |
| PB-03 Freeze privilege escalation and isolate host | freeze_process_tree | 2 | 1 | 1 | 1.3 ms |
| PB-03 Freeze privilege escalation and isolate host | isolate_host | 2 | 1 | 1 | 1.3 ms |
| PB-03 Freeze privilege escalation and isolate host | notify | 3 | 3 | 0 | - |
| PB-04 Block C2 / mining / exfiltration destinations | block_ip | 4 | 2 | 2 | 14.7 ms |
| PB-04 Block C2 / mining / exfiltration destinations | notify | 4 | 4 | 0 | - |
| PB-05 High-severity triage (analyst approval) | collect_evidence | 6 | 6 | 0 | - |
| PB-05 High-severity triage (analyst approval) | freeze_process_tree | 4 | 0 | 4 | - |
| PB-05 High-severity triage (analyst approval) | notify | 6 | 6 | 0 | - |

Playbook definitions:

- **PB-01 Contain lateral movement** - trigger: techniques ['T1021.004'], min severity critical; actions: isolate_host, freeze_process_tree, collect_evidence, notify
- **PB-02 Kill fileless malware / process injection** - trigger: techniques ['T1620', 'T1055.008'], min severity critical; actions: kill_process_tree, block_ip, collect_evidence, notify
- **PB-03 Freeze privilege escalation and isolate host** - trigger: techniques ['T1068', 'T1548.001'], min severity critical; actions: freeze_process_tree, isolate_host, collect_evidence, notify
- **PB-04 Block C2 / mining / exfiltration destinations** - trigger: techniques ['T1048', 'T1571', 'T1496', 'T1105'], min severity high; actions: block_ip, notify
- **PB-05 High-severity triage (analyst approval)** - trigger: techniques any, min severity high; actions: collect_evidence, freeze_process_tree (approval), notify
