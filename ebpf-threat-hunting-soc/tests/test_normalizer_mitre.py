from soc.normalizer import Normalizer

PROC = {"exec_id": "aaa", "pid": 4242, "uid": 33, "cwd": "/var/www", "binary": "/bin/sh",
        "arguments": "-c id", "parent_exec_id": "ppp"}
PARENT = {"exec_id": "ppp", "pid": 100, "uid": 33, "binary": "/usr/sbin/php-fpm8.2", "arguments": ""}


def test_process_exec_and_webshell_mapping():
    ev = Normalizer().normalize({"process_exec": {"process": PROC, "parent": PARENT},
                                 "node_name": "web-01", "time": "2026-01-01T10:00:00.123456789Z"})
    assert ev["type"] == "process_exec" and ev["host"] == "web-01"
    assert ev["cmdline"] == "/bin/sh -c id"
    ids = {t["id"] for t in ev["mitre"]}
    assert {"T1505.003", "T1059.004"} <= ids


def test_tcp_connect_internal_ssh_is_lateral():
    raw = {"process_kprobe": {"process": PROC, "parent": PARENT, "function_name": "tcp_connect",
                              "args": [{"sock_arg": {"saddr": "10.0.1.11", "daddr": "10.0.2.21",
                                                     "sport": 40000, "dport": 22}}],
                              "action": "KPROBE_ACTION_POST"}, "node_name": "web-01"}
    ev = Normalizer().normalize(raw)
    assert ev["type"] == "network_connect" and ev["dst_host"] == "app-01" and ev["dst_external"] is False
    assert "T1021.004" in {t["id"] for t in ev["mitre"]}


def test_sigkill_enforcement_becomes_network_blocked():
    raw = {"process_kprobe": {"process": PROC, "function_name": "tcp_connect",
                              "args": [{"sock_arg": {"daddr": "203.0.113.9", "dport": 4444}}],
                              "action": "KPROBE_ACTION_SIGKILL"}, "node_name": "web-01"}
    ev = Normalizer().normalize(raw)
    assert ev["type"] == "network_blocked" and ev["blocked"] and ev["dst_external"]


def test_commit_creds_ptrace_memfd_file():
    n = Normalizer()
    base = {"process": PROC, "parent": PARENT}
    creds = n.normalize({"process_kprobe": {**base, "function_name": "commit_creds",
                         "args": [{"process_credentials_arg": {"uid": 0, "euid": 0}}]}, "node_name": "h"})
    assert creds["type"] == "privilege_change" and creds["new_uid"] == 0
    assert "T1068" in {t["id"] for t in creds["mitre"]}
    pt = n.normalize({"process_kprobe": {**base, "function_name": "__x64_sys_ptrace",
                      "args": [{"int_arg": 16}, {"int_arg": 77}]}, "node_name": "h"})
    assert pt["ptrace_request"] == "PTRACE_ATTACH" and pt["target_pid"] == 77
    mf = n.normalize({"process_kprobe": {**base, "function_name": "__x64_sys_memfd_create",
                      "args": [{"string_arg": "x"}, {"int_arg": 1}]}, "node_name": "h"})
    assert mf["type"] == "memfd_create" and "T1620" in {t["id"] for t in mf["mitre"]}
    fa = n.normalize({"process_kprobe": {**base, "function_name": "security_file_permission",
                      "args": [{"file_arg": {"path": "/etc/shadow"}}, {"int_arg": 4}]}, "node_name": "h"})
    assert fa["type"] == "file_access" and "T1003.008" in {t["id"] for t in fa["mitre"]}


def test_unknown_event_ignored():
    assert Normalizer().normalize({"process_loader": {}}) is None
