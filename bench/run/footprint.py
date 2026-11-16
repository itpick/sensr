#!/usr/bin/env python3
"""Boot timing + idle footprint of one router variant.

usage: footprint.py KIND [--boots 5] [--idle-boots 1] [--idle-wait 300]
Each boot starts from a fresh qcow2 overlay of the prepared image (so every
boot is identical), with client+server already running.
  t_forward  virsh start -> first client->server ping answered through the router
  t_ssh      virsh start -> SSH accepts our key
  t_api      virsh start -> management API answers 200 (OPNsense API, VyOS
             HTTPS API, NixOS: the Rust prototype's /api/health; OpenBSD: n/a)
  serial_*   host arrival time of console milestones (first byte, kernel, login)
After --idle-wait seconds of idle (first --idle-boots boots): memory, process
counts, management-stack RSS, disk usage.
"""
import argparse
import json
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request

import lab
from console import Console

OS_OF = {"opn": "freebsd", "opnL": "freebsd", "obsd": "openbsd", "nixr": "linux", "vyos": "linux", "vyosL": "linux"}
SSH_OF = {"vyos": "vyos", "vyosL": "vyos"}
KERNEL_RX = {"freebsd": r"Copyright \(c\) 1992-\d+ The FreeBSD Project", "openbsd": r"Copyright \(c\) 1982, 1986",
             "linux": r"Linux version \d"}
LOGIN_RX = r"login: ?$"


def api_ok(kind):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if kind.startswith("opn"):
            k = json.load(open(os.environ.get("OPN_KEYFILE", f"{lab.BENCH}/keys/opn-apikey.json")))
            import base64
            req = urllib.request.Request("https://192.168.1.1/api/core/firmware/status")
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{k['key']}:{k['secret']}".encode()).decode())
        elif kind.startswith("vyos"):
            k = json.load(open(f"{lab.BENCH}/keys/vyos-apikey.json"))["key"]
            body = json.dumps({"op": "showConfig", "path": ["system", "host-name"]})
            data = urllib.parse.urlencode({"data": body, "key": k}).encode()
            req = urllib.request.Request("https://192.168.1.1/retrieve", data=data)
        elif kind == "nixr":
            req = urllib.request.Request("http://192.168.1.1:8080/api/health")
        else:
            return None
        with urllib.request.urlopen(req, context=ctx, timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def boot_once(kind):
    lab.stop_routers()
    dom, port = lab.router_domain(kind, fresh=True)
    res = {}
    host = SSH_OF.get(kind, "router")
    # client pings continuously; we timestamp answers on arrival at the host
    p = subprocess.Popen(["ssh", "-F", lab.SSHCFG, "client", "ping -i 0.05 -W 0.05 10.99.0.10"],
                         stdout=subprocess.PIPE, text=True, bufsize=1)
    first = {}

    def reader():
        for line in p.stdout:
            if "bytes from" in line and "fwd" not in first:
                first["fwd"] = time.time()
    threading.Thread(target=reader, daemon=True).start()
    time.sleep(1.0)
    first.clear()
    t0 = time.time()
    lab.virsh("start", dom)
    con = Console(port, f"{lab.BENCH}/work/boot-{kind}.log")
    deadline = t0 + 600
    t_ssh = t_api = None
    want_api = api_ok(kind) is not None
    while time.time() < deadline:
        if t_ssh is None:
            r = subprocess.run(f"ssh -F {lab.SSHCFG} -o ControlMaster=no -o ConnectTimeout=1 {host} true",
                               shell=True, capture_output=True)
            if r.returncode == 0:
                t_ssh = time.time()
        if want_api and t_api is None and api_ok(kind):
            t_api = time.time()
        if t_ssh and (t_api or not want_api) and "fwd" in first:
            break
        time.sleep(0.2)
    p.terminate()
    os_kind = OS_OF[kind]
    lines = list(con.lines)
    def first_line(rx):
        for t, l in lines:
            if re.search(rx, l):
                return t - t0
        return None
    res.update({
        "t_forward_s": (first["fwd"] - t0) if "fwd" in first else None,
        "t_ssh_s": (t_ssh - t0) if t_ssh else None,
        "t_api_s": (t_api - t0) if t_api else None,
        "serial_first_s": (lines[0][0] - t0) if lines else None,
        "serial_kernel_s": first_line(KERNEL_RX[os_kind]),
        "serial_login_s": (con.time_of(r"login: ") - t0) if con.time_of(r"login: ") else None,
    })
    res["_console"] = con
    return dom, res


def idle_stats(kind):
    os_kind = OS_OF[kind]
    host = SSH_OF.get(kind, "router")
    pre = "sudo " if host == "vyos" else ""
    r = {}
    if os_kind == "linux":
        mi = dict((l.split(":")[0], int(l.split()[1])) for l in lab.ssh(host, "cat /proc/meminfo").splitlines())
        r["mem_total_mib"] = mi["MemTotal"] / 1024
        r["mem_used_mib"] = (mi["MemTotal"] - mi["MemAvailable"]) / 1024
        r["mem_free_mib"] = mi["MemFree"] / 1024
        ps = lab.ssh(host, "ps -e -o pid=,ppid=,rss=,comm=")
        rows = [x for x in (l.split(None, 3) for l in ps.splitlines()) if len(x) >= 3 and x[2].isdigit()]
        user = [x for x in rows if x[1] != "2" and x[0] != "2"]
        r["procs_total"] = len(rows)
        r["procs_user"] = len(user)
        r["rss_user_mib"] = sum(int(x[2]) for x in user) / 1024
        r["disk_used_mib"] = int(lab.ssh(host, "df -k / | tail -1").split()[2]) / 1024
        if kind.startswith("vyos"):
            # VyOS root is a squashfs overlay; count the installed image size instead
            r["disk_used_mib"] = int(lab.ssh(host, "sudo du -sk /usr/lib/live/mount/persistence/boot 2>/dev/null | cut -f1 || echo 0").strip() or 0) / 1024
    else:
        ps = lab.ssh(host, "ps -ax -o pid= -o ppid= -o rss= -o command=")  # FreeBSD: "pid=,ppid=" would make the rest a header
        rows = [x for x in (l.split(None, 3) for l in ps.splitlines()) if len(x) >= 3 and x[2].isdigit()]
        # kernel threads: FreeBSD shows "[name]", OpenBSD "(name)"; both have ppid 0
        iskern = lambda x: len(x) > 3 and (x[3].startswith("[") or (x[3].startswith("(") and x[1] == "0"))
        user = [x for x in rows if not iskern(x)]
        r["procs_total"] = len(rows)
        r["procs_user"] = len(user)
        r["rss_user_mib"] = sum(int(x[2]) for x in user) / 1024
        # all local disk partitions (OpenBSD's auto layout splits /, /usr, /var, ...)
        r["disk_used_mib"] = int(lab.ssh(host, "df -kl | awk 'NR>1 && $1 ~ /^\\/dev/ {s+=$3} END {print s}'").strip()) / 1024
        if os_kind == "freebsd":
            s = lab.ssh(host, "sysctl -n hw.physmem hw.pagesize vm.stats.vm.v_free_count vm.stats.vm.v_inactive_count vm.stats.vm.v_laundry_count").split()
            phys, pg, free, inact, laund = map(int, s)
            r["mem_total_mib"] = phys / 2**20
            r["mem_free_mib"] = free * pg / 2**20
            r["mem_used_mib"] = (phys - (free + inact + laund) * pg) / 2**20
        else:
            out = lab.ssh(host, "vmstat -s")
            g = lambda k: int(re.search(rf"(\d+) {k}", out).group(1))
            pg = g("bytes per page")
            r["mem_total_mib"] = g("pages managed") * pg / 2**20
            r["mem_free_mib"] = g("pages free") * pg / 2**20
            r["mem_used_mib"] = (g("pages managed") - g("pages free") - g("pages inactive")) * pg / 2**20
    r["mgmt"] = mgmt_rss(kind, rows, os_kind)
    return r


MGMT = {
    "opn": r"lighttpd|php|configd|python",
    "vyos": r"vyos-|python|uvicorn|nginx|vyconf",
    "nixr": r"sensr-proto",
}


def mgmt_rss(kind, rows, os_kind):
    rx = MGMT.get(kind.rstrip("L"))
    if not rx:
        return None
    out = {}
    for x in rows:
        if len(x) > 3 and re.search(rx, x[3]) and not x[3].startswith("["):
            toks = [t.rsplit("/", 1)[-1] for t in x[3].split()[:3]]
            # name python processes by their script (configd.py, vyos-configd, ...)
            name = next((t for t in toks[1:] if not t.startswith("-")), toks[0]) if toks[0].startswith("python") else toks[0]
            name = name[:40]
            out[name] = out.get(name, 0) + int(x[2]) / 1024
    return {"total_mib": sum(out.values()), "by_process": out}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind")
    ap.add_argument("--boots", type=int, default=5)
    ap.add_argument("--idle-boots", type=int, default=1)
    ap.add_argument("--idle-wait", type=int, default=300)
    ap.add_argument("--out", default=f"{lab.BENCH}/results/footprint.jsonl")
    a = ap.parse_args()
    for b in range(a.boots):
        hl = lab.host_load()
        dom, res = boot_once(a.kind)
        con = res.pop("_console")
        rec = {"router": a.kind, "boot": b, "ts": time.time(), **res, "host_loadavg1": hl["loadavg"][0]}
        if b < a.idle_boots:
            time.sleep(max(0, a.idle_wait - (time.time() - rec["ts"]) ))
            rec["idle"] = idle_stats(a.kind)
        con.close()
        lab.append_jsonl(a.out, rec)
        print(json.dumps(rec), flush=True)
    lab.stop_routers()


if __name__ == "__main__":
    main()
