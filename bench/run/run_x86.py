#!/usr/bin/env python3
"""Run the x86 track end to end (on nixtop). Stages: dataplane, footprint, control.

usage: run_x86.py [--stages dataplane,footprint,control] [--queues 1,2] [--only KIND,...]
Every router variant boots from a fresh overlay of its prepared image, then
settles 60 s before measuring. Endpoints (client/server) always use 2 queues
so they are not the bottleneck; the router's queue count is the variable.
"""
import argparse
import subprocess
import sys
import time

import lab

OS = {"opn": "freebsd", "opnL": "freebsd", "obsd": "openbsd", "nixr": "linux", "vyos": "linux", "vyosL": "linux"}
SSH = {"vyos": "vyos", "vyosL": "vyos"}
FULL = "tcp1_up,tcp1_down,tcp8_up,tcp8_down,udp64,udp512,ping,ping_load,cps"
SUB = "tcp1_up,tcp8_up,udp64,cps"


def setup_offload_opn():
    for i in ("vtnet0", "vtnet1"):
        lab.ssh("router", f"ifconfig {i} txcsum rxcsum tso lro")


def setup_offload_opn_boot_nolro():
    """As setup_offload_opn_boot but keep LRO off (checksum + TSO only)."""
    setup_offload_opn_boot(lro=False)


def setup_offload_opn_boot(lro=True):
    """Tuned OPNsense: untick the three 'Disable hardware * offload' boxes and
    override the shipped hw.vtnet.csum_disable=1 / lro_disable=1 loader
    tunables (loader.conf.local is not rewritten by OPNsense), then reboot."""
    lro_v = "0" if lro else "1"
    lro_sed = "-e '/disablelargereceiveoffloading/d' " if lro else ""
    lab.ssh("router", f"printf 'hw.vtnet.csum_disable=\"0\"\\nhw.vtnet.lro_disable=\"{lro_v}\"\\n' > /boot/loader.conf.local && "
            "sed -i '' -e '/disablechecksumoffloading/d' -e '/disablesegmentationoffloading/d' "
            f"{lro_sed}/conf/config.xml && rm -f /tmp/config.cache && "
            "daemon -f sh -c 'sleep 2; shutdown -r now'")
    time.sleep(20)
    import glob, os
    for f in glob.glob(f"{lab.BENCH}/keys/cm-router"):
        os.remove(f)
    lab.wait_ssh("router")
    time.sleep(60)
    print(lab.ssh("router", "ifconfig vtnet0 | grep options; sysctl hw.vtnet.csum_disable hw.vtnet.lro_disable"), flush=True)


def setup_obsd_large():
    g = f"{lab.SRC}/generated/pf"
    lab.sh(f"scp -F {lab.SSHCFG} -q {g}/large.conf router:/etc/pf.conf && scp -F {lab.SSHCFG} -q {g}/large-tables/*.txt router:/etc/pf/")
    lab.ssh("router", "pfctl -f /etc/pf.conf")


def nft(file):
    return lambda: lab.ssh("router", f"nft -f /etc/sensrbench/nft/{file}")


def nooffload():
    for i in ("lan0", "wan0"):
        lab.ssh("router", f"ethtool -K {i} gro off gso off tso off")


# (kind, label, setup, tests, queues where it runs)
VARIANTS = [
    ("opn", "as-shipped", None, FULL, (1, 2)),
    ("opn", "offload-on", setup_offload_opn, FULL, ()),  # runtime ifconfig: no effect, see below
    ("opn", "offload-boot", setup_offload_opn_boot, FULL, (1, 2)),
    ("opn", "offload-boot-nolro", setup_offload_opn_boot_nolro, FULL, (1,)),
    ("opnL", "large", None, SUB, (1,)),
    ("obsd", "as-shipped", None, FULL, (1, 2)),
    ("obsd", "large", setup_obsd_large, SUB, (1,)),
    ("nixr", "as-shipped", None, FULL, (1, 2)),
    ("nixr", "flowtable", nft("small-ft.nft"), FULL, (1, 2)),
    ("nixr", "no-gro-gso-tso", nooffload, FULL, (1,)),
    ("nixr", "large", nft("large.nft"), SUB, (1,)),
    ("nixr", "large-flowtable", nft("large-ft.nft"), SUB, (1,)),
    ("vyos", "as-shipped", None, FULL, (1, 2)),
    ("vyosL", "large", None, SUB, (1,)),
]


def boot(kind, queues):
    lab.stop_routers()
    dom, _ = lab.router_domain(kind, queues=queues, fresh=True)
    lab.virsh("start", dom)
    lab.wait_ssh(SSH.get(kind, "router"))
    time.sleep(60)
    return dom


def dataplane(queues, only, tests_override=None, labels=None):
    lab.endpoints(queues=2, fresh=False)
    for q in queues:
        for kind, label, setup, tests, qs in VARIANTS:
            if q not in qs or (only and kind not in only) or (labels and f"{kind}:{label}" not in labels):
                continue
            print(f"== dataplane {kind} {label} q={q}", flush=True)
            try:
                boot(kind, q)
                if setup:
                    setup()
                    time.sleep(5)
                info = lab.ssh(SSH.get(kind, "router"), "uname -a", check=False).strip()
                subprocess.run([sys.executable, "dataplane.py", kind, f"{label}/q{q}", "--os", OS[kind],
                                "--tests", tests_override or tests, "--reps", "5"], check=False)
                lab.append_jsonl(f"{lab.BENCH}/results/runs.jsonl", {"stage": "dataplane", "kind": kind,
                                 "label": label, "queues": q, "uname": info, "ts": time.time()})
            except Exception as e:
                print("ERROR", kind, label, q, e, flush=True)
    lab.stop_routers()


def footprint(only):
    lab.endpoints(queues=2, fresh=False)
    for kind, boots, idle in (("opn", 5, 2), ("opnL", 3, 1), ("obsd", 5, 2), ("nixr", 5, 2), ("vyos", 5, 2), ("vyosL", 3, 1)):
        if only and kind not in only:
            continue
        print(f"== footprint {kind}", flush=True)
        subprocess.run([sys.executable, "footprint.py", kind, "--boots", str(boots), "--idle-boots", str(idle)], check=False)


def control(only):
    lab.endpoints(queues=2, fresh=False)
    for kind, parts in (("opn", "apply,table,api,gui"), ("opnL", "apply,api,gui"), ("obsd", "apply,table"),
                        ("nixr", "table,proto,apply"), ("vyos", "apply,api,table"), ("vyosL", "apply,api")):
        if only and kind not in only:
            continue
        print(f"== control {kind}", flush=True)
        try:
            boot(kind, 1)
            if kind == "obsd":
                pass
            subprocess.run([sys.executable, "controlplane.py", kind, "--parts", parts, "--reps", "5"], check=False)
            if kind == "obsd":  # 1,000-rule pf.conf reload, same method
                setup_obsd_large()
                subprocess.run([sys.executable, "controlplane.py", "obsdL", "--parts", "apply", "--reps", "5"], check=False)
        except Exception as e:
            print("ERROR", kind, e, flush=True)
    lab.stop_routers()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stages", default="dataplane,footprint,control")
    ap.add_argument("--queues", default="1,2")
    ap.add_argument("--only", default="")
    ap.add_argument("--labels", default="", help="kind:label,... filter for the dataplane stages")
    a = ap.parse_args()
    only = set(filter(None, a.only.split(",")))
    st = a.stages.split(",")
    labels = set(filter(None, a.labels.split(",")))
    if "dataplane" in st:
        dataplane([int(x) for x in a.queues.split(",")], only, labels=labels)
    if "pktgen" in st:  # kernel pktgen small-packet pass (added after the first pass)
        dataplane([int(x) for x in a.queues.split(",")], only, tests_override="pktgen64,pktgen512", labels=labels)
    if "footprint" in st:
        footprint(only)
    if "control" in st:
        control(only)
