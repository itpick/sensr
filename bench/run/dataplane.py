#!/usr/bin/env python3
"""Data-plane benchmark through the running router (client LAN -> server WAN, NAT).

usage: dataplane.py ROUTER_KIND LABEL [--reps 5] [--tests a,b,...] [--os linux|freebsd|openbsd]
Writes one JSON line per (test, rep) to results/dataplane.jsonl.

Per test the router CPU is measured three ways:
  guest_busy_pct   busy share of the router's own CPU counters (Linux /proc/stat,
                   BSD kern.cp_time) over the test window, 100 = both vCPUs busy
  host_vcpu_pct    host view: libvirt cpu.time delta minus KVM halt-polling, per 2 vCPUs
  vhost_pct        host CPU burnt by the router's vhost-net workers (per 1 CPU)
"""
import argparse
import json
import re
import statistics
import subprocess
import threading
import time

import lab

SERVER = "10.99.0.10"
HOST = "router"  # ssh alias of the router (VyOS logs in as vyos)


def guest_cpu(os_kind):
    if os_kind == "linux":
        f = lab.ssh(HOST, "head -1 /proc/stat").split()[1:]
        v = list(map(int, f))
        idle = v[3] + v[4]
        return sum(v[:8]), idle
    out = lab.ssh(HOST, "sysctl -n kern.cp_time")
    v = list(map(int, re.findall(r"\d+", out)))
    # FreeBSD/OpenBSD: user nice sys [spin] intr idle  (idle is last)
    return sum(v), v[-1]


def host_cpu(dom):
    out = lab.sh(f"virsh domstats {dom} --cpu-total")
    d = dict(l.strip().split("=", 1) for l in out.splitlines() if "=" in l)
    poll = int(d.get("cpu.haltpoll.success.time", 0)) + int(d.get("cpu.haltpoll.fail.time", 0))
    return int(d["cpu.time"]), poll


class CpuWindow:
    def __init__(self, dom, os_kind):
        self.dom, self.os = dom, os_kind

    def __enter__(self):
        self.t0 = time.time()
        self.g0 = guest_cpu(self.os)
        self.h0 = host_cpu(self.dom)
        self.v0 = lab.vhost_cpu_ticks(self.dom)
        return self

    def __exit__(self, *a):
        dt = time.time() - self.t0
        g1, h1, v1 = guest_cpu(self.os), host_cpu(self.dom), lab.vhost_cpu_ticks(self.dom)
        tot, idle = g1[0] - self.g0[0], g1[1] - self.g0[1]
        self.guest_busy_pct = 100.0 * (tot - idle) / tot if tot else None
        busy_ns = (h1[0] - self.h0[0]) - (h1[1] - self.h0[1])
        self.host_vcpu_pct = 100.0 * busy_ns / (dt * 1e9 * 2)
        self.vhost_pct = 100.0 * (v1 - self.v0) / 100 / dt  # CLK_TCK=100


def iperf(args, timeout=60):
    out = lab.ssh("client", f"iperf3 -c {SERVER} --json {args}", timeout=timeout)
    return json.loads(out)


def t_tcp(streams, reverse):
    def run():
        j = iperf(f"-t 10 -O 1 -P {streams}" + (" -R" if reverse else ""))
        e = j["end"]
        return {"gbps": e["sum_received"]["bits_per_second"] / 1e9,
                "retrans": e["sum_sent"].get("retransmits")}
    return run


def t_udp(size):
    def run():
        j = iperf(f"-u -b 0 -l {size} -t 10 -P 4")
        s = j["end"]["sum"]
        recv_pkts = s["packets"] - s["lost_packets"]
        return {"sent_pps": s["packets"] / s["seconds"], "recv_pps": recv_pkts / s["seconds"],
                "loss_pct": s["lost_percent"], "recv_mbps": recv_pkts * size * 8 / s["seconds"] / 1e6}
    return run


def parse_ping(out):
    rtts = [float(x) for x in re.findall(r"time=([\d.]+) ms", out)]
    m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    sent, recv = int(m.group(1)), int(m.group(2))
    rtts.sort()
    pct = lambda p: rtts[min(len(rtts) - 1, int(p * len(rtts)))] if rtts else None
    return {"rtt_p50_ms": pct(0.5), "rtt_p99_ms": pct(0.99), "rtt_avg_ms": statistics.mean(rtts) if rtts else None,
            "rtt_max_ms": rtts[-1] if rtts else None, "loss_pct": 100.0 * (sent - recv) / sent}


def t_ping():
    return parse_ping(lab.ssh("client", f"ping -i 0.01 -c 1000 -W 1 {SERVER}"))


def t_ping_load():
    res = {}
    def load():
        res["iperf"] = iperf("-t 16 -P 8", timeout=60)
    th = threading.Thread(target=load)
    th.start()
    time.sleep(2)
    r = parse_ping(lab.ssh("client", f"ping -i 0.01 -c 1000 -W 1 {SERVER}"))
    th.join()
    r["load_gbps"] = res["iperf"]["end"]["sum_received"]["bits_per_second"] / 1e9
    return r


def t_cps():
    out = lab.ssh("client", f"wrk -t 3 -c 48 -d 10s -H 'Connection: close' http://{SERVER}/")
    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1))
    errs = re.search(r"Socket errors: (.*)", out)
    return {"conn_per_s": rps, "socket_errors": errs.group(1) if errs else ""}


PKTGEN = r"""
set -e
modprobe pktgen
PG=/proc/net/pktgen
for t in 0 1; do echo rem_device_all > $PG/kpktgend_$t; done
for t in 0 1; do
  echo "add_device enp1s0@$t" > $PG/kpktgend_$t
  D=$PG/enp1s0@$t
  echo "queue_map_min $t" > $D; echo "queue_map_max $t" > $D
  echo "count 0" > $D; echo "clone_skb 1000" > $D; echo "burst 32" > $D; echo "pkt_size {size}" > $D; echo "delay 0" > $D
  echo "dst 10.99.0.10" > $D; echo "dst_mac 52:54:00:5b:01:01" > $D
  echo "src_min 192.168.1.100" > $D; echo "src_max 192.168.1.100" > $D
  echo "udp_src_min $((20000 + t * 128))" > $D; echo "udp_src_max $((20000 + t * 128 + 127))" > $D
  echo "udp_dst_min 9" > $D; echo "udp_dst_max 9" > $D
done
echo start > $PG/pgctrl &
sleep {secs}
echo stop > $PG/pgctrl
wait
for t in 0 1; do grep -o "[0-9]*pps" $PG/enp1s0@$t; grep -o "sofar: [0-9]*" $PG/enp1s0@$t; done
"""


def t_pktgen(size):
    """Kernel pktgen on the client (2 threads, 256 UDP flows) -> router -> server.
    Measures what the router forwards (server NIC rx), not what iperf3 can send."""
    def run():
        rx = "cat /sys/class/net/enp1s0/statistics/rx_packets"
        r0 = int(lab.ssh("server", rx))
        t0 = time.time()
        out = lab.ssh("client", PKTGEN.format(size=size - 4, secs=10), timeout=60)
        dt = time.time() - t0
        time.sleep(1)
        r1 = int(lab.ssh("server", rx))
        sent = sum(int(x) for x in re.findall(r"sofar: (\d+)", out))
        return {"sent_kpps": sent / 10 / 1000, "recv_kpps": (r1 - r0) / 10 / 1000,
                "loss_pct": 100.0 * (1 - (r1 - r0) / sent) if sent else None}
    return run


TESTS = {
    "tcp1_up": t_tcp(1, False), "tcp1_down": t_tcp(1, True),
    "tcp8_up": t_tcp(8, False), "tcp8_down": t_tcp(8, True),
    "udp64": t_udp(64), "udp512": t_udp(512),
    "ping": t_ping, "ping_load": t_ping_load, "cps": t_cps,
    "pktgen64": t_pktgen(64), "pktgen512": t_pktgen(512),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind")
    ap.add_argument("label")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--tests", default=",".join(TESTS))
    ap.add_argument("--os", default="linux")
    ap.add_argument("--out", default=f"{lab.BENCH}/results/dataplane.jsonl")
    a = ap.parse_args()
    global HOST
    HOST = "vyos" if a.kind.startswith("vyos") else "router"
    dom = lab.dom_of(a.kind)
    for rep in range(a.reps):
        for name in a.tests.split(","):
            hl = lab.host_load()
            r0 = hl["rocky_cpu_ns"]
            t0 = time.time()
            with CpuWindow(dom, a.os) as cw:
                try:
                    m = TESTS[name]()
                except Exception as e:  # record failures as results, not silence
                    m = {"error": str(e)[-300:]}
            dt = time.time() - t0
            rocky = lab.dom_cpu_ns("rocky-rel")
            rec = {"router": a.kind, "label": a.label, "test": name, "rep": rep, "ts": t0, **m,
                   "guest_busy_pct": cw.guest_busy_pct, "host_vcpu_pct": cw.host_vcpu_pct,
                   "vhost_pct": cw.vhost_pct, "host_loadavg1": hl["loadavg"][0],
                   "rocky_cpu_pct": (100.0 * (rocky - r0) / (dt * 1e9)) if (rocky and r0) else None}
            lab.append_jsonl(a.out, rec)
            print(json.dumps(rec), flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
