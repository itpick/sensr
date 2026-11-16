#!/usr/bin/env python3
"""Reduce raw JSONL results to median / min-max tables (CSV + Markdown).

usage: summarize.py RESULTS_DIR OUT_DIR
"""
import collections
import csv
import json
import os
import statistics
import sys

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)


def load(name):
    p = os.path.join(src, name)
    if not os.path.exists(p):
        return []
    return [json.loads(l) for l in open(p) if l.strip()]


def agg(vals):
    vals = [v for v in vals if isinstance(v, (int, float))]
    if not vals:
        return None
    return {"median": statistics.median(vals), "min": min(vals), "max": max(vals), "n": len(vals)}


def fmt(a, digits=2):
    if not a:
        return "n/a"
    m = a["median"]
    if a["n"] == 1:
        return f"{m:.{digits}f}"
    return f"{m:.{digits}f} ({a['min']:.{digits}f}–{a['max']:.{digits}f})"


def table(rows, keys, metrics, out, digits=2):
    """rows grouped by keys; metrics list of (column, field)."""
    groups = collections.OrderedDict()
    for r in rows:
        if "error" in r and r["error"]:
            continue
        groups.setdefault(tuple(r.get(k) for k in keys), []).append(r)
    csv_rows, md = [], []
    hdr = list(keys) + [c for c, _ in metrics] + ["n"]
    md.append("| " + " | ".join(hdr) + " |")
    md.append("|" + "---|" * len(hdr))
    for g, rs in groups.items():
        line = [str(x) for x in g]
        crow = dict(zip(keys, g))
        n = 0
        for col, field in metrics:
            a = agg([r.get(field) for r in rs])
            line.append(fmt(a, digits))
            if a:
                crow[col + "_median"], crow[col + "_min"], crow[col + "_max"] = a["median"], a["min"], a["max"]
                n = max(n, a["n"])
        line.append(str(n))
        crow["n"] = n
        md.append("| " + " | ".join(line) + " |")
        csv_rows.append(crow)
    with open(os.path.join(dst, out + ".csv"), "w", newline="") as f:
        cols = sorted({k for r in csv_rows for k in r}, key=lambda k: (k not in keys, k))
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(csv_rows)
    with open(os.path.join(dst, out + ".md"), "w") as f:
        f.write("\n".join(md) + "\n")
    return "\n".join(md)


dp = load("dataplane.jsonl")
# first OpenBSD q=2 attempt lost its ssh control channel after one sample; it was rerun
dp = [r for r in dp if not (r["router"] == "obsd" and r["label"] == "as-shipped/q2" and r["ts"] < 1794815700)]
sections = []
for test, metrics in [
    ("tcp", [("Gbit/s", "gbps"), ("router guest busy %", "guest_busy_pct"), ("router host vCPU %", "host_vcpu_pct"), ("vhost %", "vhost_pct")]),
    ("udp", [("recv kpps", "recv_kpps"), ("sent kpps", "sent_kpps"), ("loss %", "loss_pct"), ("router host vCPU %", "host_vcpu_pct")]),
    ("ping", [("p50 ms", "rtt_p50_ms"), ("p99 ms", "rtt_p99_ms"), ("max ms", "rtt_max_ms"), ("loss %", "loss_pct")]),
    ("cps", [("conn/s", "conn_per_s"), ("router host vCPU %", "host_vcpu_pct")]),
]:
    rows = [r for r in dp if r["test"].startswith(test)]
    for r in rows:
        if "recv_pps" in r:
            r["recv_kpps"], r["sent_kpps"] = r["recv_pps"] / 1000, r["sent_pps"] / 1000
    sections.append(f"### {test}\n\n" + table(rows, ["test", "router", "label"], metrics, f"dataplane_{test}"))

# first-pass OpenBSD/NixOS footprint rows were redone (disk sum / API probe fixes)
fp = [r for r in load("footprint.jsonl") if r["router"] not in ("obsd", "nixr")]
fp += load("footprint-obsd-redo.jsonl") + load("footprint-nixr-redo.jsonl") + load("footprint-opn-idle.jsonl")
sections.append("### boot\n\n" + table(fp, ["router"], [("forwarding s", "t_forward_s"), ("ssh s", "t_ssh_s"),
                                                      ("mgmt API s", "t_api_s"), ("kernel msg s", "serial_kernel_s"),
                                                      ("login prompt s", "serial_login_s")], "boot", 1))
idle = []
for r in fp:
    if "idle" in r and r["idle"].get("procs_total"):  # first OPNsense pass: ps parse bug -> 0
        i = dict(r["idle"])
        i["router"] = r["router"]
        i["mgmt_mib"] = (i.get("mgmt") or {}).get("total_mib")
        idle.append(i)
sections.append("### idle\n\n" + table(idle, ["router"], [("mem used MiB", "mem_used_mib"), ("free MiB", "mem_free_mib"),
                                                        ("procs total", "procs_total"), ("procs user", "procs_user"),
                                                        ("user RSS MiB", "rss_user_mib"), ("mgmt RSS MiB", "mgmt_mib"),
                                                        ("disk used MiB", "disk_used_mib")], "idle", 0))
cp = load("controlplane.jsonl")
# first VyOS large load raced the boot-time commit and was not applied (attempt 2 is real)
cp = [r for r in cp if not (r["router"] == "vyosL" and r["part"] == "initial_load" and r.get("attempt") != 2)]
# VyOS commit is a diff: repeating the same group content is a no-op, keep the real change (rep 0)
cp = [r for r in cp if not (r["router"].startswith("vyos") and r["part"] == "table_mgmt" and r.get("rep", 0) > 0)]
for part, keys, metrics in [
    ("apply", ["router", "rules", "method", "proto"], [("total s", "total_s"), ("commit s", "commit_s"), ("add s", "add_s"), ("apply s", "apply_s")]),
    ("apply_api", ["router"], [("total s", "total_s")]),
    ("initial_load", ["router"], [("commit s", "commit_s"), ("total s", "total_s")]),
    ("table_raw", ["router", "size", "method"], [("seconds", "seconds")]),
    ("table_mgmt", ["router", "size", "method", "proto"], [("total s", "total_s"), ("commit s", "commit_s"), ("render s", "render_s"), ("apply s", "apply_s")]),
    ("api", ["router", "rules", "query", "proto"], [("p50 ms", "p50_ms"), ("p95 ms", "p95_ms"), ("RSS MiB", "rss_mib")]),
    ("gui", ["router", "page"], [("HTML KiB", "html_kib"), ("total KiB", "total_kib"), ("assets", "assets"), ("HTML s", "html_s"), ("HTML+assets s", "html_plus_assets_s")]),
    ("proto_full", ["router", "rules", "renderer", "proto"], [("render s", "render_s"), ("nft apply s", "apply_s"), ("JSON MiB", "json_mib"), ("RSS MiB", "rss_mib")]),
    ("nft_text_full", ["router", "rules"], [("seconds", "seconds")]),
    ("proto_rss", ["router", "rules", "proto"], [("RSS start MiB", "rss_mib_start"), ("RSS after MiB", "rss_mib_after_applies")]),
]:
    rows = [r for r in cp if r["part"] == part]
    for r in rows:
        if "html_bytes" in r:
            r["html_kib"], r["total_kib"] = r["html_bytes"] / 1024, r["total_bytes"] / 1024
        if "json_bytes" in r:
            r["json_mib"] = r["json_bytes"] / 2**20
    if rows:
        sections.append(f"### {part}\n\n" + table(rows, keys, metrics, f"cp_{part}", 3))
pi = load("pi5.jsonl")
if pi:
    boots = [r for r in pi if r.get("part") == "boot"]
    sections.append("### pi5 boot (TCG, relative only)\n\n" + table(boots, ["router"], [("forwarding s", "t_forward_s"), ("ssh s", "t_ssh_s"), ("mgmt API s", "t_api_s")], "pi5_boot", 1))
    pidle = []
    for r in boots:
        if "idle" in r:
            i = dict(r["idle"]); i["router"] = r["router"]; i["mgmt_mib"] = (i.get("mgmt") or {}).get("total_mib")
            pidle.append(i)
    sections.append("### pi5 idle\n\n" + table(pidle, ["router"], [("mem used MiB", "mem_used_mib"), ("procs total", "procs_total"), ("procs user", "procs_user"), ("user RSS MiB", "rss_user_mib"), ("mgmt RSS MiB", "mgmt_mib"), ("disk used MiB", "disk_used_mib")], "pi5_idle", 0))
    for part, keys, metrics in [
        ("apply", ["router", "rules", "method"], [("total s", "total_s"), ("add s", "add_s"), ("apply s", "apply_s")]),
        ("table_raw", ["router", "size", "method"], [("seconds", "seconds")]),
        ("table_mgmt", ["router", "size", "method"], [("total s", "total_s"), ("render s", "render_s"), ("apply s", "apply_s")]),
        ("api", ["router", "rules", "query"], [("p50 ms", "p50_ms"), ("p95 ms", "p95_ms")]),
        ("proto_full", ["router", "rules", "renderer"], [("render s", "render_s"), ("nft apply s", "apply_s"), ("RSS MiB", "rss_mib")]),
        ("initial_load", ["router", "size"], [("per-rule add ms", "per_rule_add_ms"), ("filter apply s", "filter_apply_s"), ("alias reconfigure s", "alias_reconfigure_s")]),
    ]:
        rows = [r for r in pi if r.get("part") == part]
        if rows:
            sections.append(f"### pi5 {part} (TCG, relative only)\n\n" + table(rows, keys, metrics, f"pi5_{part}", 3))
open(os.path.join(dst, "summary.md"), "w").write("\n\n".join(sections) + "\n")
print("\n\n".join(sections))
