# Running the project on Windows 10 / 11 — step by step

There are two ways to run it. **Option B (Python only)** is the quickest. **Option A (Docker)** runs the
real architecture with Apache Kafka and separate containers, and is what you should show in a review.

---

## Part 1 — Install the tools (one time)

### 1.1 Git
1. Download from https://git-scm.com/download/win and install with the default options.
2. Open **PowerShell** (Start menu → type `PowerShell`) and check: `git --version`

### 1.2 Python 3.11 or 3.12 (needed for Option B and for tests)
1. Download from https://www.python.org/downloads/windows/
2. On the first installer screen **tick "Add python.exe to PATH"**, then *Install Now*.
3. Close and reopen PowerShell, then check: `python --version`
   - If Windows opens the Microsoft Store instead, go to *Settings → Apps → Advanced app settings →
     App execution aliases* and turn **off** the two `python.exe` / `python3.exe` aliases.

### 1.3 Docker Desktop (needed for Option A)
1. Download from https://www.docker.com/products/docker-desktop/ and install.
2. Keep **"Use WSL 2 instead of Hyper-V"** ticked. Restart Windows if asked.
3. If Docker asks you to update WSL, open PowerShell **as Administrator** and run `wsl --update`.
4. Start Docker Desktop and wait until the whale icon says *Docker Desktop is running*.
5. Check in PowerShell: `docker compose version`
6. Recommended: Docker Desktop → *Settings → Resources* → at least **4 GB memory**.

---

## Part 2 — Get the code

```powershell
cd $HOME\Documents
git clone https://github.com/<your-username>/ebpf-threat-hunting-soc.git
cd ebpf-threat-hunting-soc
```
(Or download the ZIP from GitHub → *Code → Download ZIP*, extract it and `cd` into the folder.)

---

## Part 3A — Run with Docker + Kafka (full stack)

```powershell
docker compose up --build
```

- The first run downloads Kafka and Python images and builds the project (3–5 minutes).
- You will see logs from `soc-kafka`, `soc-engine`, `soc-sensor`, `soc-dashboard`.
- When you see `detection engine running` and `simulated sensor fleet running`, open
  **http://localhost:8080** in your browser.

Useful commands (in a second PowerShell window, same folder):

| What | Command |
|---|---|
| Run in background | `docker compose up --build -d` |
| See logs | `docker compose logs -f engine` |
| Status of containers | `docker compose ps` |
| Stop everything | `docker compose down` |
| Rebuild after code change | `docker compose up --build` |

Shortcut: double-click `scripts\windows\run-docker.bat`.

## Part 3B — Run with Python only (no Docker)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m soc.run_all
```
Open **http://localhost:8080**. Stop with `Ctrl+C`.

- If `activate` is blocked with *"running scripts is disabled"*, either run
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use **Command Prompt** with
  `.venv\Scripts\activate.bat`.
- Shortcut: double-click `scripts\windows\run-local.bat` (creates the venv, installs, starts, opens the browser).

---

## Part 4 — Demonstrate it

1. Leave it running for ~20 seconds: the *kernel events/sec* counter rises, the live telemetry panel fills
   with benign activity, and there are **no alerts** (no false positives on normal behaviour).
2. Top bar → choose **APT: web shell → credential theft → SSH lateral movement…** → **▶ Launch attack simulation**.
3. Watch the **Adversary emulation** panel: each attack step appears as it runs. After the SSH pivot:
   - the **Attack graph** draws a red arrow `web-01 → app-01`,
   - both hosts turn **ISOLATED** in the Fleet panel,
   - **SOAR response actions** show `isolate_host`, `freeze_process_tree`, `block_ip` with their latency,
   - all later steps (privilege escalation, fileless implant, exfiltration) show **PREVENTED**.
4. Click the incident in **Incidents** → process trees across both hosts, forensic timeline, IOCs, and
   *Download forensic timeline (.md)*. The same bundle is saved under `evidence\INC-0001\`.
5. Click **Reset**, then **Monitor only**, and launch again: nothing is blocked and the full kill chain lights
   up the **MITRE ATT&CK heatmap**. Actions show as *recommended*; you can click **Approve** to run one manually.
6. Try the other two scenarios (*fileless cryptominer*, *insider privilege escalation*).
7. Click **Report** to open the generated detection and playbook report.
8. Use **Release host** on an isolated host to bring it back online.

---

## Part 5 — Run the tests

```powershell
.venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest
python scripts\benchmark.py
python -m soc.report      # regenerates docs\THREAT_HUNTING_REPORT.md
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `port is already allocated` / port 8080 in use | Change the left side of `"8080:8080"` in `docker-compose.yml` (e.g. `"8090:8080"`), or for Option B run `python -m soc.run_all --port 8090`. |
| Kafka container restarts / engine says *waiting for Kafka* | Normal for the first 20–40 s. If it keeps failing, give Docker more memory (Settings → Resources). |
| `docker: command not found` | Docker Desktop is not running or PowerShell was opened before installing it — restart PowerShell. |
| WSL 2 errors on Docker start | PowerShell as Administrator: `wsl --install` then `wsl --update`, reboot. Make sure virtualization is enabled in BIOS. |
| `pip install` fails building `confluent-kafka` | Use Python 3.11 or 3.12 (wheels are pre-built). On Python 3.13+ use Option A. |
| Dashboard loads but nothing moves | Check the terminal for errors; for Docker run `docker compose logs sensor engine`. |
| Antivirus flags the scenario files | They only contain *text* describing simulated attacks (no real malware). Allow the project folder if needed. |
