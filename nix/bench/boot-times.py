#!/usr/bin/env python3
"""Boot-time benchmark for sensr images, with the milestones and method of
docs/research/07 (and the vyos-pi pages):

  kernel  first kernel line on the router's serial console
  fwd     first ping from the LAN client to the WAN host answered through
          the router (NAT), probe every 50 ms
  ssh     SSH to the router's LAN address accepts the key
  api     sensr-api answers HTTP on the LAN address

All measured from the moment the router's QEMU starts, on a fresh qcow2
overlay each boot, with the endpoints already up. Milestones are
timestamped on arrival at the host (serial consoles over Unix sockets).

  boot-times.py --router IMG --endpoint IMG --key ID_ED25519 [--boots 5]
                [--label NAME] [--json OUT]

x86_64 with KVM. Networks are QEMU socket multicast segments on loopback,
so no root is needed.
"""
import argparse, json, os, random, re, selectors, shutil, socket, statistics, subprocess, sys, tempfile, time

OVMF = os.environ.get("OVMF_FD", "")
MILESTONES = ["kernel", "fwd", "ssh", "api"]


def qemu(name, disk, nics, serial, extra, firmware=False, mem=1024, cpus=2):
    cmd = ["qemu-system-x86_64", "-name", name, "-machine", "q35,accel=kvm", "-cpu", "host",
           "-smp", str(cpus), "-m", str(mem), "-display", "none",
           "-drive", f"file={disk},if=virtio,format=qcow2",
           "-chardev", f"socket,id=ser,path={serial},server=on,wait=on", "-serial", "chardev:ser"]
    if firmware:
        vars_ = disk + ".vars"
        shutil.copy(f"{OVMF}/OVMF_VARS.fd", vars_)
        os.chmod(vars_, 0o644)
        cmd += ["-drive", f"if=pflash,format=raw,readonly=on,file={OVMF}/OVMF_CODE.fd",
                "-drive", f"if=pflash,format=raw,file={vars_}"]
    for i, (mac, port) in enumerate(nics):
        cmd += ["-netdev", f"socket,id=n{i},mcast=230.0.0.1:{port},localaddr=127.0.0.1",
                "-device", f"virtio-net-pci,netdev=n{i},mac={mac}"]
    return subprocess.Popen(cmd + extra, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def connect(path, deadline=10):
    end = time.time() + deadline
    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
            s.setblocking(False)
            return s
        except OSError:
            if time.time() > end:
                raise
            time.sleep(0.01)


def overlay(base, path):
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, path], check=True)


def one_boot(a, work, n):
    wan, lan = random.randint(20000, 40000), random.randint(40001, 60000)
    procs, socks, logs = [], {}, {}
    sel = selectors.DefaultSelector()

    def start(name, base, nics, firmware, extra=()):
        disk = f"{work}/{name}.qcow2"
        overlay(base, disk)
        ser = f"{work}/{name}.sock"
        p = qemu(name, disk, nics, ser, list(extra), firmware=firmware, mem=1024 if name == "router" else 512)
        procs.append(p)
        s = connect(ser)
        socks[name] = s
        logs[name] = open(f"{work}/boot{n}-{name}.log", "wb")
        sel.register(s, selectors.EVENT_READ, name)
        return s

    buf = {"client": b"", "router": b"", "wanhost": b""}
    seen = {}
    t0 = None

    def pump(timeout):
        for key, _ in sel.select(timeout):
            name = key.data
            try:
                data = key.fileobj.recv(65536)
            except BlockingIOError:
                continue
            if not data:
                sel.unregister(key.fileobj)
                continue
            now = time.monotonic()
            logs[name].write(data)
            buf[name] += data
            text = buf[name].decode(errors="replace")
            if name == "router" and "kernel" not in seen and re.search(r"Linux version", text):
                seen["kernel"] = now
            for m in re.findall(r"SENSRBENCH (\w+)", text):
                seen.setdefault(f"{name}:{m}", now)
            # keep the tail only
            buf[name] = buf[name][-4096:]

    try:
        start("wanhost", a.endpoint, [("52:54:00:5e:00:20", wan)], False)
        start("client", a.endpoint, [("52:54:00:5e:00:10", lan)], False,
              ["-fw_cfg", f"name=opt/sensrbench/key,file={a.key}"])
        end = time.monotonic() + 120
        while "client:ready" not in seen and time.monotonic() < end:
            pump(0.05)
        if "client:ready" not in seen:
            raise RuntimeError("endpoints did not come up")
        time.sleep(2)  # wanhost's networkd and DHCP server settle
        t0 = time.monotonic()
        start("router", a.router, [("52:54:00:5e:00:01", wan), ("52:54:00:5e:00:02", lan)], True)
        end = t0 + a.timeout
        while time.monotonic() < end and not all(
                (m == "kernel" and "kernel" in seen) or f"client:{m}" in seen for m in MILESTONES):
            pump(0.05)
        res = {}
        for m in MILESTONES:
            k = "kernel" if m == "kernel" else f"client:{m}"
            res[m] = round(seen[k] - t0, 2) if k in seen else None
        return res
    finally:
        for p in procs:
            p.kill()
        for p in procs:
            p.wait()
        for f in logs.values():
            f.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--router", required=True)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--boots", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--label", default="sensr")
    ap.add_argument("--json")
    ap.add_argument("--work", default=tempfile.mkdtemp(prefix="sensrbench-"))
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    runs = []
    for n in range(1, a.boots + 1):
        r = one_boot(a, a.work, n)
        print(f"{a.label} boot {n}: " + "  ".join(f"{m}={r[m]}" for m in MILESTONES), flush=True)
        runs.append(r)
    med = {}
    for m in MILESTONES:
        vals = [r[m] for r in runs if r[m] is not None]
        med[m] = {"median": statistics.median(vals) if vals else None,
                  "min": min(vals) if vals else None, "max": max(vals) if vals else None,
                  "ok": len(vals), "of": len(runs)}
    print(f"{a.label} median: " + "  ".join(
        f"{m}={med[m]['median']} ({med[m]['min']}-{med[m]['max']}, {med[m]['ok']}/{med[m]['of']})" for m in MILESTONES))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"label": a.label, "runs": runs, "median": med}, f, indent=2)


if __name__ == "__main__":
    main()
