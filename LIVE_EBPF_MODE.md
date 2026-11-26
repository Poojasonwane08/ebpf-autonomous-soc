# Live eBPF mode (real kernel telemetry with Cilium Tetragon)

Live mode replaces the simulator with **Tetragon**, an eBPF agent that hooks the Linux kernel. It needs a
**Linux kernel ≥ 5.10 with BTF** (`ls /sys/kernel/btf/vmlinux` must exist). Ubuntu 22.04/24.04 works out of
the box.

> Windows users: run it in an **Ubuntu VM** (VirtualBox/VMware/Hyper-V) or a cloud VM. WSL 2 can work when
> its kernel exposes `/sys/kernel/btf/vmlinux`, but this is not guaranteed — a VM is the reliable option.

## Start

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
git clone https://github.com/<your-username>/ebpf-threat-hunting-soc.git
cd ebpf-threat-hunting-soc
sudo docker compose -f docker-compose.yml -f docker-compose.live.yml up --build
```

Open `http://<vm-ip>:8080`. The fleet panel shows the VM (discovered from Tetragon's `node_name`).

What runs:
- `soc-tetragon` — Tetragon with the policies in `deploy/tetragon/policies/`:
  `tcp_connect`, `commit_creds`, `sys_setuid`, `sys_memfd_create`, `sys_ptrace`,
  `security_file_permission` (shadow, sudoers, SSH keys, cron).
- `soc-sensor` (live image) — tails `/var/log/tetragon/tetragon.log` into Kafka and executes SOAR actions.
- The engine learns its anomaly baseline from the first 2 000 real executions.

## Generate real detections (safe, on your own test VM)

The dashboard's *Launch attack simulation* button drives the simulator only; in live mode generate activity on
the host itself:

```bash
# discovery commands run by a service account (alerts: Linux system discovery)
sudo -u www-data sh -c 'whoami; id; uname -a; cat /etc/passwd > /dev/null'
# credential access (alerts: Access to /etc/shadow)
sudo cat /etc/shadow > /dev/null
# fileless execution from memory (alerts: memfd_create + fileless exec)
python3 -c "import os; fd=os.memfd_create('x'); os.write(fd, open('/bin/true','rb').read()); os.execv(f'/proc/self/fd/{fd}', ['x'])"
# outbound SSH (alerts: outbound SSH from non-admin server)
ssh -o ConnectTimeout=2 nobody@127.0.0.1 true
# cron persistence (alerts: cron persistence)
crontab -l
```

For a full adversary emulation, install **MITRE Caldera** on another machine, deploy its `sandcat` agent on
the VM and run the *Discovery* / *Credential Access* adversary profiles — the abilities are executed as real
processes and flow through the same pipeline.

## Response actions in live mode

Remediation defaults to **dry-run**: actions are logged in the dashboard with the exact command that
would run. To enforce for real (only on a disposable test VM):

```bash
LIVE_RESPONDER_DRY_RUN=false sudo -E docker compose -f docker-compose.yml -f docker-compose.live.yml up -d
```

| Action | Live implementation |
|---|---|
| freeze_process_tree | `SIGSTOP` to every PID descending from the attack root |
| kill_process_tree | `SIGKILL` to every PID descending from the attack root |
| isolate_host | nftables table `inet soc_isolation` – drop all traffic except the SOC management IP (`config/fleet.yml`) |
| release_host | delete that nftables table |
| block_ip | writes a TracingPolicy (`tcp_connect` + `DAddr` selector + `Sigkill`) and loads it with `tetra tracingpolicy add` — the kernel kills any process that connects to the IP |

⚠️ `isolate_host` cuts the VM's network (except the management IP). Set `soc_management_ip` in
`config/fleet.yml` to the IP you connect from before enabling real enforcement.

## Running Tetragon without Docker

```bash
# install Tetragon from the release tarball (see https://tetragon.io/docs/installation/package/)
sudo tetragon --export-filename /var/log/tetragon/tetragon.log \
              --tracing-policy-dir $(pwd)/deploy/tetragon/policies &
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
sudo -E env "PATH=$PATH" SENSOR_MODE=tetragon TETRAGON_EXPORT_FILE=/var/log/tetragon/tetragon.log \
     python3 -m soc.run_all
```
(`sudo` is needed to read Tetragon's log and, with dry-run off, to send signals / change nftables.)
