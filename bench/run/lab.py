"""Lab orchestration shared by all benchmark scripts (runs on nixtop).

Topology (isolated libvirt networks, no forwarding):
  client 192.168.1.100 --[sensrbench-lan]-- ROUTER --[sensrbench-wan]-- server 10.99.0.10
  router LAN 192.168.1.1 (NIC0, MAC ..:01:01), WAN 10.99.0.1 (NIC1, MAC ..:01:02)
  host has .254 on both bridges for management only.
CPU placement (host has 8 cores / 16 threads, SMT siblings n and n+8):
  router vCPU0,1 -> host 2,3   emulator+vhost -> 10,11
  client vCPU    -> 4,5,12     emulator+vhost -> 13
  server vCPU    -> 6,7,14     emulator+vhost -> 15
  host/orchestrator 0,1,8,9. The pre-existing rocky-rel VM floats (not ours).
"""
import json
import os
import subprocess
import time

BENCH = "/mnt/vms/sensr/bench"
SRC = f"{BENCH}/src"
os.environ["PATH"] = "/run/current-system/sw/bin:" + os.environ.get("PATH", "")
os.environ["LIBVIRT_DEFAULT_URI"] = "qemu:///system"
SSHCFG = f"{BENCH}/keys/ssh_config"

ROUTER_PIN = ("2,3", "10,11")
ROUTERS = {
    # kind: (base image, serial port); domain is sensrbench-<kind without size suffix>
    "opn": (f"{BENCH}/images/opnsense-26.7-bench-small.qcow2", 45501),
    "opnL": (f"{BENCH}/images/opnsense-26.7-bench-large.qcow2", 45501),
    "vyosL": (f"{BENCH}/vyos/vyos-router-large.qcow2", 45504),
    "nixr": (f"{BENCH}/images/nixos-router.qcow2", 45502),
    "obsd": (f"{BENCH}/openbsd/openbsd-8.0-router.qcow2", 45503),
    "vyos": (f"{BENCH}/vyos/vyos-router.qcow2", 45504),
}


def sh(cmd, check=True, capture=True, timeout=None):
    r = subprocess.run(cmd, shell=True, text=True, capture_output=capture, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(f"{cmd!r} failed rc={r.returncode}: {r.stderr[-800:]}")
    return r.stdout if capture else ""


def ssh(host, cmd, check=True, timeout=600):
    """Run cmd with /bin/sh on the guest, script on stdin: independent of the
    login shell (OPNsense root uses tcsh, VyOS vbash) and of quoting."""
    for attempt in range(4):
        r = subprocess.run(["ssh", "-F", SSHCFG, host, "sh -s"], input=cmd, text=True,
                           capture_output=True, timeout=timeout)
        # 255 = ssh transport error (e.g. connection reset under load): retry
        if r.returncode != 255:
            break
        time.sleep(1 + attempt)
    if check and r.returncode:
        raise RuntimeError(f"ssh {host} {cmd[:200]!r} failed rc={r.returncode}: {r.stderr[-800:]}")
    return r.stdout


def virsh(*args, check=True):
    return sh("virsh " + " ".join(args), check=check)


def exists(dom):
    return dom in virsh("list", "--all", "--name").split()


def running(dom):
    return dom in virsh("list", "--name").split()


def define(dom, disk, vcpus, mem, cpus, emu, serial, queues, nics):
    xml = sh(f"python3 {SRC}/libvirt/mkdomain.py {dom} {disk} {vcpus} {mem} {cpus} {emu} {serial} {queues} " + " ".join(nics))
    p = f"{BENCH}/work/{dom}.xml"
    open(p, "w").write(xml)
    if exists(dom):
        if running(dom):
            virsh("destroy", dom)
        virsh("undefine", dom)
    virsh("define", p)


def overlay(base, path, fresh=True):
    if fresh and os.path.exists(path):
        os.remove(path)
    if not os.path.exists(path):
        sh(f"qemu-img create -q -f qcow2 -F qcow2 -b {base} {path}")
        sh(f"setfacl -m u:qemu-libvirtd:rw {path}")


def endpoints(queues=1, fresh=False):
    """Client + server (NixOS endpoint image, role picked by MAC)."""
    base = f"{BENCH}/images/nixos-endpoint.qcow2"
    for role, mac, net, cpus, emu, port in (
        ("client", "52:54:00:5b:00:10", "sensrbench-lan", "4,5,12", "13", 45511),
        ("server", "52:54:00:5b:00:20", "sensrbench-wan", "6,7,14", "15", 45512),
    ):
        dom = f"sensrbench-{role}"
        if running(dom) and not fresh:
            continue
        disk = f"{BENCH}/work/{role}.qcow2"
        overlay(base, disk, fresh=True)
        define(dom, disk, 3, 2048, cpus, emu, port, queues, [f"{net}:{mac}"])
        virsh("start", dom)
    wait_ssh("client")
    wait_ssh("server")


def router_domain(kind, queues=1, fresh=True, disk=None):
    base, port = ROUTERS[kind]
    disk = disk or f"{BENCH}/work/router-{kind}.qcow2"
    if fresh:
        overlay(base, disk, fresh=True)
    dom = dom_of(kind)
    define(dom, disk, 2, 2048, ROUTER_PIN[0], ROUTER_PIN[1], port, queues,
           ["sensrbench-lan:52:54:00:5b:01:01", "sensrbench-wan:52:54:00:5b:01:02"])
    return dom, port


def dom_of(kind):
    return "sensrbench-" + kind.rstrip("L")


def stop_routers():
    import glob
    for f in glob.glob(f"{BENCH}/keys/cm-*"):
        os.remove(f)
    for k in ROUTERS:
        d = dom_of(k)
        if exists(d) and running(d):
            virsh("destroy", d)


def wait_ssh(host, timeout=600):
    t = time.time()
    while time.time() - t < timeout:
        r = subprocess.run(f"ssh -F {SSHCFG} -o ControlMaster=no {host} true", shell=True, capture_output=True)
        if r.returncode == 0:
            return time.time() - t
        time.sleep(1)
    raise TimeoutError(f"ssh {host}")


def host_load():
    """Host load + rocky-rel CPU (the VM we must not touch) for the run log."""
    la = open("/proc/loadavg").read().split()[:3]
    return {"loadavg": [float(x) for x in la], "rocky_cpu_ns": dom_cpu_ns("rocky-rel")}


def dom_cpu_ns(dom):
    out = sh(f"virsh domstats {dom} --cpu-total", check=False)
    for line in out.splitlines():
        if "cpu.time=" in line:
            return int(line.split("=")[1])
    return None


def qemu_pid(dom):
    try:
        return int(open(f"/run/libvirt/qemu/{dom}.pid").read().strip())
    except OSError:
        out = sh(f"pgrep -f 'guest={dom},'", check=False).split()
        return int(out[0]) if out else None


def vhost_cpu_ticks(dom):
    """Sum utime+stime (clock ticks) of the vhost worker threads of a domain."""
    pid = qemu_pid(dom)
    if not pid:
        return 0
    total = 0
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            comm = open(f"/proc/{p}/comm").read().strip()
            if comm == f"vhost-{pid}":
                f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
                total += int(f[11]) + int(f[12])
        except OSError:
            pass
    # newer kernels run vhost workers as threads of the qemu process
    try:
        for t in os.listdir(f"/proc/{pid}/task"):
            comm = open(f"/proc/{pid}/task/{t}/comm").read().strip()
            if comm.startswith("vhost-"):
                f = open(f"/proc/{pid}/task/{t}/stat").read().rsplit(")", 1)[1].split()
                total += int(f[11]) + int(f[12])
    except OSError:
        pass
    return total


def append_jsonl(path, rec):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")
