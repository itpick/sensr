#!/usr/bin/env python3
"""Diagnostics for the connection-rate results (not a benchmark):
  - pf routers: state counters around one 10 s wrk run (state-mismatch, inserts)
  - NixOS large vs VyOS large: how the 1,000-rule forward chain is compiled
Writes results/diag.jsonl and raw text to work/diag-*.txt."""
import json
import time

import lab
import run_x86

OUT = f"{lab.BENCH}/results/diag.jsonl"
WRK = "wrk -t 3 -c 48 -d 10s -H 'Connection: close' http://10.99.0.10/"


def pf_diag(kind, host="router"):
    run_x86.boot(kind, 1)
    before = lab.ssh(host, "pfctl -si; pfctl -sm; pfctl -st | head -30")
    w = lab.ssh("client", WRK)
    after = lab.ssh(host, "pfctl -si; pfctl -ss | wc -l")
    open(f"{lab.BENCH}/work/diag-{kind}.txt", "w").write(before + "\n---- wrk\n" + w + "\n---- after\n" + after)
    lab.append_jsonl(OUT, {"router": kind, "what": "pf_state_counters", "ts": time.time(),
                           "before": before, "wrk": w, "after": after})


def nft_diag(kind, host, cmd):
    run_x86.boot(kind, 1)
    if kind == "nixr":
        lab.ssh(host, "nft -f /etc/sensrbench/nft/large.nft")
    t = lab.ssh(host, cmd)
    w = lab.ssh("client", WRK)
    open(f"{lab.BENCH}/work/diag-{kind}.txt", "w").write(t + "\n---- wrk\n" + w)
    lab.append_jsonl(OUT, {"router": kind, "what": "forward_chain_head", "ts": time.time(), "chain": t[:6000], "wrk": w})


CONNLAT = r"""
for i in $(seq 200); do curl -s -o /dev/null -w '%{time_connect} %{time_total}\n' http://10.99.0.10/; done
"""


def conn_latency(kind, host="router"):
    """Sequential new connections (no concurrency): per-connection setup/total
    time through the router, plus wrk at 48 and 256 concurrent connections."""
    run_x86.boot(kind, 1)
    out = lab.ssh("client", CONNLAT)
    v = [tuple(map(float, l.split())) for l in out.split("\n") if l.strip()]
    tc = sorted(x[0] * 1000 for x in v)
    tt = sorted(x[1] * 1000 for x in v)
    res = {"router": kind, "what": "conn_latency", "ts": time.time(), "n": len(v),
           "connect_p50_ms": tc[len(tc) // 2], "connect_p99_ms": tc[int(len(tc) * 0.99) - 1],
           "total_p50_ms": tt[len(tt) // 2], "total_p99_ms": tt[int(len(tt) * 0.99) - 1]}
    for c in (48, 256):
        w = lab.ssh("client", f"wrk -t 3 -c {c} -d 10s -H 'Connection: close' http://10.99.0.10/")
        import re
        res[f"wrk_c{c}_rps"] = float(re.search(r"Requests/sec:\s+([\d.]+)", w).group(1))
        lat = re.search(r"Latency\s+(\S+)", w)
        res[f"wrk_c{c}_lat_avg"] = lat.group(1) if lat else None
        time.sleep(5)
    lab.append_jsonl(OUT, res)
    print(json.dumps(res), flush=True)


if __name__ == "__main__":
    import sys
    lab.endpoints(queues=2, fresh=False)
    if "connlat" in sys.argv:
        for k in ("opn", "obsd", "nixr", "vyos"):
            conn_latency(k, "vyos" if k == "vyos" else "router")
        lab.stop_routers()
        raise SystemExit
    pf_diag("obsd")
    pf_diag("opn")
    nft_diag("nixr", "router", "nft list chain inet filter forward | head -60; nft list chain inet filter forward | wc -l")
    nft_diag("vyosL", "vyos", "sudo nft list chain ip vyos_filter VYOS_FORWARD_filter | head -60; sudo nft list chain ip vyos_filter VYOS_FORWARD_filter | wc -l; sudo nft list tables")
    lab.stop_routers()
