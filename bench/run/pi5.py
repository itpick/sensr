#!/usr/bin/env python3
"""Pi 5 shape, emulated: QEMU virt + cortex-a76 x4, 4 GiB, UEFI (edk2), TCG on
the x86 host — the opnsense-pi VM profile. The real Pi firmware/UEFI blobs and
RP1 hardware cannot run in QEMU, so this measures the OS images, not the board.
Footprint (image/installed size, idle RAM, process count) is valid; boot and
control-plane times are RELATIVE indicators only; no throughput numbers.

usage: pi5.py domain KIND DISK [--iso ISO]   define the aarch64 domain
       pi5.py prep-opn                       build the configured OPNsense aarch64 image
       pi5.py measure KIND                   footprint + control-plane (relative)
"""
import json
import os
import sys
import time

import lab
from console import Console

P = f"{lab.BENCH}/pi5"
# QEMU's own edk2 builds (same as opnsense-pi vm/run.sh): <qemu prefix>/share/qemu
_QSHARE = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(
    lab.sh("command -v qemu-system-aarch64").strip()))), "share", "qemu")
FW = f"{_QSHARE}/edk2-aarch64-code.fd"
# libvirtd's default emulator set on this host is x86-only: name the binary
EMU = os.path.realpath(lab.sh("command -v qemu-system-aarch64").strip())
VARS_SRC = f"{_QSHARE}/edk2-arm-vars.fd"
PORT = {"opn": 45601, "nixr": 45602, "obsd": 45603}


def domain_xml(name, disk, port, iso=None, fmt="qcow2"):
    vars_path = f"{P}/{name}-vars.fd"
    if not os.path.exists(vars_path):
        lab.sh(f"cp {VARS_SRC} {vars_path} && chmod u+w {vars_path} && setfacl -m u:qemu-libvirtd:rw {vars_path}")
    cd = ""
    if iso:
        cd = f"""<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{iso}'/>
      <target dev='sda' bus='scsi'/><readonly/><boot order='1'/></disk>
    <controller type='scsi' model='virtio-scsi'/>"""
    return f"""<domain type='qemu'>
  <name>{name}</name><memory unit='MiB'>4096</memory><vcpu>4</vcpu>
  <cputune><vcpupin vcpu='0' cpuset='2'/><vcpupin vcpu='1' cpuset='3'/><vcpupin vcpu='2' cpuset='10'/><vcpupin vcpu='3' cpuset='11'/><emulatorpin cpuset='0,8'/></cputune>
  <os><type arch='aarch64' machine='virt'>hvm</type>
    <loader readonly='yes' type='pflash'>{FW}</loader><nvram>{vars_path}</nvram></os>
  <cpu mode='custom' match='exact' check='none'><model fallback='forbid'>cortex-a76</model></cpu>
  <features><gic version='3'/></features>
  <devices>
    <emulator>{EMU}</emulator>
    {cd}
    <disk type='file' device='disk'><driver name='qemu' type='{fmt}'/><source file='{disk}'/><target dev='vda' bus='virtio'/><boot order='2'/></disk>
    <interface type='network'><source network='sensrbench-lan'/><mac address='52:54:00:5b:01:01'/><model type='virtio'/></interface>
    <interface type='network'><source network='sensrbench-wan'/><mac address='52:54:00:5b:01:02'/><model type='virtio'/></interface>
    <serial type='tcp'><source mode='bind' host='127.0.0.1' service='{port}'/><protocol type='raw'/></serial>
    <console type='tcp'><source mode='bind' host='127.0.0.1' service='{port}'/><protocol type='raw'/><target type='serial' port='0'/></console>
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
  </devices>
</domain>"""


def define(name, disk, port, iso=None):
    if lab.exists(name):
        if lab.running(name):
            lab.virsh("destroy", name)
        lab.virsh("undefine", name, "--nvram", check=False)
    # fresh UEFI variable store per definition (created after undefine removed the old one)
    p = f"{lab.BENCH}/work/{name}.xml"
    open(p, "w").write(domain_xml(name, disk, port, iso))
    lab.virsh("define", p)


IMG = {
    "opn": f"{P}/opn-aarch64-small.qcow2",
    "opnL": f"{P}/opn-aarch64-large.qcow2",
    "nixr": f"{P}/nixos-aarch64-router.qcow2",
}
OPN_KEY = f"{lab.BENCH}/keys/opn-aarch64-apikey.json"


def boot(kind, fresh=True):
    """Boot from a fresh overlay; return timings (host clock, TCG = relative only)."""
    base = IMG[kind]
    fam = kind.rstrip("L")
    dom = f"sensrbench-pi-{fam}"
    disk = f"{lab.BENCH}/work/pi-{kind}.qcow2"
    lab.overlay(base, disk, fresh=fresh)
    for d in lab.virsh("list", "--name").split():
        if d.startswith("sensrbench-") and d not in ("sensrbench-client", "sensrbench-server"):
            lab.virsh("destroy", d)
    import glob
    for f in glob.glob(f"{lab.BENCH}/keys/cm-*"):
        if "client" not in f and "server" not in f:
            os.remove(f)
    define(dom, disk, PORT[fam])
    import subprocess, threading
    p = subprocess.Popen(["ssh", "-F", lab.SSHCFG, "client", "ping -i 0.2 -W 0.2 10.99.0.10"],
                         stdout=subprocess.PIPE, text=True, bufsize=1)
    first = {}
    def reader():
        for line in p.stdout:
            if "bytes from" in line and "fwd" not in first:
                first["fwd"] = time.time()
    threading.Thread(target=reader, daemon=True).start()
    time.sleep(1)
    first.clear()
    t0 = time.time()
    lab.virsh("start", dom)
    con = Console(PORT[fam], f"{lab.BENCH}/work/pi-boot-{kind}.log")
    import footprint
    t_ssh = t_api = None
    while time.time() - t0 < 3600:
        if t_ssh is None and subprocess.run(f"ssh -F {lab.SSHCFG} -o ControlMaster=no -o ConnectTimeout=2 router true",
                                            shell=True, capture_output=True).returncode == 0:
            t_ssh = time.time()
        if t_api is None and footprint.api_ok("opn" if fam == "opn" else "nixr"):
            t_api = time.time()
        if t_ssh and t_api and "fwd" in first:
            break
        time.sleep(1)
    p.terminate()
    con.close()
    return dom, {"t_forward_s": (first["fwd"] - t0) if "fwd" in first else None,
                 "t_ssh_s": (t_ssh - t0) if t_ssh else None, "t_api_s": (t_api - t0) if t_api else None}


def measure(kind, boots=3):
    import controlplane as cp
    import footprint
    os.environ["OPN_KEYFILE"] = OPN_KEY
    out = f"{lab.BENCH}/results/pi5.jsonl"
    for b in range(boots):
        dom, r = boot(kind)
        rec = {"router": f"pi-{kind}", "part": "boot", "boot": b, "ts": time.time(), **r,
               "note": "TCG emulation on x86: relative indicator only"}
        if b == 0:
            time.sleep(300)
            rec["idle"] = footprint.idle_stats("opn" if kind.startswith("opn") else "nixr")
        lab.append_jsonl(out, rec)
        print(json.dumps(rec), flush=True)
    cp.OUT = out
    if kind.startswith("opn"):
        cp.opn_apply(f"pi-{kind}", 3)
        if kind == "opn":
            cp.opn_table(f"pi-{kind}", 3)
        cp.opn_api(f"pi-{kind}", 20)
    else:
        cp.nix_table(f"pi-{kind}", 3)
        cp.proto_full(f"pi-{kind}", 3)
        cp.proto_api(f"pi-{kind}", 3, 20)
    for d in lab.virsh("list", "--name").split():
        if d.startswith("sensrbench-pi-"):
            lab.virsh("destroy", d)


def prep_opn():
    """Factory aarch64 serial image -> bench baseline (same bootstrap + API load as x86)."""
    import subprocess
    os.environ["OPN_KEYFILE"] = OPN_KEY
    factory = f"{P}/dl/OPNsense-26.7-ufs-serial-vm-aarch64.qcow2"
    build = f"{lab.BENCH}/work/pi-opn-build.qcow2"
    lab.sh(f"setfacl -m u:qemu-libvirtd:rx {P} {P}/dl && setfacl -m u:qemu-libvirtd:r {factory}")
    lab.overlay(factory, build, fresh=True)
    define("sensrbench-pi-opn", build, PORT["opn"])
    lab.virsh("start", "sensrbench-pi-opn")
    # first boot runs the automatic interface assignment; any keypress would
    # turn it into the manual one, so stay silent until the login prompt.
    # One persistent console connection: on this aarch64 (PL011) console a
    # TCP reconnect gets no I/O, unlike x86.
    import base64
    import opnconsole as oc
    w = f"{lab.BENCH}/work"
    con = Console(PORT["opn"], f"{w}/pi-opn-firstboot.log")
    con.expect(r"login: $", 3600)
    oc.shell(con)
    out, rc = oc.run_capture(con, "b64encode -r /conf/config.xml x", timeout=600)
    open(f"{w}/pi-opn-default-config.xml", "wb").write(base64.b64decode("".join(out.split())))
    lab.sh(f"python3 {lab.SRC}/gen/opn_bootstrap.py {w}/pi-opn-default-config.xml {w}/pi-opn-boot-config.xml {lab.BENCH}/keys/id_bench.pub")
    oc.put(con, f"{w}/pi-opn-boot-config.xml", "/conf/config.xml")
    con.sendline("daemon -f sh -c 'sleep 2; shutdown -r now'")
    time.sleep(5)
    con.close()
    time.sleep(30)
    lab.wait_ssh("router", timeout=3600)
    key = lab.ssh("router", "cd /usr/local/opnsense/mvc/script && php -r 'require_once(\"load_phalcon.php\"); $a=new OPNsense\\Auth\\API(); echo json_encode($a->createKey(\"root\"));'")
    open(OPN_KEY, "w").write(key)
    os.chmod(OPN_KEY, 0o600)
    time.sleep(60)
    t = lab.sh("python3 opn_api.py load small", timeout=7200)
    lab.append_jsonl(f"{lab.BENCH}/results/pi5.jsonl", {"router": "pi-opn", "part": "initial_load", **json.loads(t)})
    print(t, flush=True)
    lab.ssh("router", "shutdown -p now", check=False)
    for _ in range(120):
        if not lab.running("sensrbench-pi-opn"):
            break
        time.sleep(2)
    lab.sh(f"qemu-img convert -O qcow2 {build} {IMG['opn']} && setfacl -m u:qemu-libvirtd:rw {IMG['opn']}")
    # large: same API path as x86 (1,000 rules + 10k alias), timed
    lab.overlay(IMG["opn"], build, fresh=True)
    define("sensrbench-pi-opn", build, PORT["opn"])
    lab.virsh("start", "sensrbench-pi-opn")
    lab.wait_ssh("router", timeout=3600)
    time.sleep(60)
    t = lab.sh("python3 opn_api.py load large", timeout=14400)
    lab.append_jsonl(f"{lab.BENCH}/results/pi5.jsonl", {"router": "pi-opnL", "part": "initial_load", **json.loads(t)})
    print(t, flush=True)
    lab.ssh("router", "shutdown -p now", check=False)
    for _ in range(120):
        if not lab.running("sensrbench-pi-opn"):
            break
        time.sleep(2)
    lab.sh(f"qemu-img convert -O qcow2 {build} {IMG['opnL']} && setfacl -m u:qemu-libvirtd:rw {IMG['opnL']} && rm {build}")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "prep-opn":
        prep_opn()
    if cmd == "measure":
        measure(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 3)
    if cmd == "domain":
        kind, disk = sys.argv[2], sys.argv[3]
        iso = sys.argv[5] if len(sys.argv) > 5 and sys.argv[4] == "--iso" else None
        define(f"sensrbench-pi-{kind}", disk, PORT[kind], iso)
