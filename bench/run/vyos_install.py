#!/usr/bin/env python3
"""Install VyOS rolling from the ISO over the serial console and configure it
as the benchmark router (eth0 LAN, eth1 WAN, masquerade, DHCP + DNS forwarding
on LAN, SSH key, HTTPS API key), then load the small / large firewall.

Produces vyos/vyos-router.qcow2 (small policy) and vyos/vyos-router-large.qcow2.
"""
import json
import os
import re
import shutil
import sys
import time

import lab
from console import Console

V = f"{lab.BENCH}/vyos"
DOM = "sensrbench-vyos"
PORT = 45504
DISK = f"{V}/vyos-router.qcow2"
PW = "sensrbench"


def login(c, pw):
    c.sendline("")
    m = c.expect(r"login: $|vyos@\S+:~\$ $|vyos@\S+# $", 600)
    if "login" in m.group(0):
        c.sendline("vyos")
        c.expect("Password: ", 30)
        c.sendline(pw)
        c.expect(r"vyos@\S+:~\$ $", 60)


_Q = [
    ("Would you like to continue?", "y"),
    ("What would you like to name this image?", ""),
    ('Please enter a password for the "vyos" user', PW),
    ('Please confirm password for the "vyos" user', PW),
    ("What console should be used by default?", "S"),
    ("Which one should be used for installation?", ""),
    ("Installation will delete all data on the drive", "y"),
    ("Would you like to use all the free space on the drive?", "Y"),
    ("Which file would you like as boot config?", ""),
    ("Would you like to copy SSH host keys?", "n"),
    ("Would you like to", ""),  # any other yes/no: take the default
]
# vyos.utils.io prompts end with "(Default: x) " or "[y/N] "; match by prefix
# require the full prompt tail so a half-received line is never answered
INSTALL_ANSWERS = [(re.escape(q) + r"[^\n]*(?:\]|\)|:) $", a) for q, a in _Q]


def install():
    c = Console(PORT, f"{lab.BENCH}/work/vyos-install.log")
    login(c, "vyos")
    c.sendline("install image")
    while True:
        pats = "|".join(f"(?:{p})" for p, _ in INSTALL_ANSWERS)
        m = c.expect(pats + r"|(The image installed successfully[^\n]*)|(vyos@\S+:~\$ $)", 900)
        txt = m.group(0)
        if "installed successfully" in txt or txt.startswith("vyos@"):
            break
        for p, ans in INSTALL_ANSWERS:
            if re.fullmatch(p, txt):
                print("PROMPT", repr(txt[-60:]), "->", repr(ans), flush=True)
                c.sendline(ans)
                break
    c.expect(r"vyos@\S+:~\$ $", 120)
    c.sendline("sudo poweroff")
    c.close()
    for _ in range(60):
        if not lab.running(DOM):
            break
        time.sleep(2)
    if lab.running(DOM):
        lab.virsh("destroy", DOM)


def base_config():
    d, _ = lab.router_domain("vyos", fresh=False, disk=DISK)
    lab.virsh("start", d)
    c = Console(PORT, f"{lab.BENCH}/work/vyos-config.log")
    login(c, PW)
    key = open(f"{lab.BENCH}/keys/id_bench.pub").read().split()
    apikey = json.load(open(f"{lab.BENCH}/keys/vyos-apikey.json"))["key"]
    cmds = [
        "set interfaces ethernet eth0 address 192.168.1.1/24",
        "set interfaces ethernet eth1 address 10.99.0.1/24",
        "set protocols static route 0.0.0.0/0 next-hop 10.99.0.254",
        "set system host-name sensrbench-vyos",
        "set service ssh port 22",
        f"set system login user vyos authentication public-keys bench type {key[0]}",
        f"set system login user vyos authentication public-keys bench key {key[1]}",
        f"set service https api keys id bench key {apikey}",
        "set service https api rest",
        "set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 subnet-id 1",
        "set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 option default-router 192.168.1.1",
        "set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 option name-server 192.168.1.1",
        "set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 range 0 start 192.168.1.150",
        "set service dhcp-server shared-network-name LAN subnet 192.168.1.0/24 range 0 stop 192.168.1.199",
        "set service dns forwarding listen-address 192.168.1.1",
        "set service dns forwarding allow-from 192.168.1.0/24",
        "set service ntp allow-client address 192.168.1.0/24",
    ]
    c.sendline("configure")
    c.expect(r"vyos@\S+# $", 60)
    for cmd in cmds:
        c.sendline(cmd)
        c.expect(r"vyos@\S+# $", 60)
    c.sendline("commit")
    c.expect(r"vyos@\S+# $", 600)
    c.sendline("save")
    c.expect(r"vyos@\S+# $", 120)
    c.sendline("exit")
    c.close()
    lab.wait_ssh("vyos")


def vyos_script(cmds, commit=True):
    """Run a block of set commands in one configure session; return commit seconds."""
    body = "\n".join(cmds)
    script = f"""source /opt/vyatta/etc/functions/script-template
configure
{body}
T0=$(date +%s.%N)
commit
T1=$(date +%s.%N)
save
echo "COMMIT_S $T0 $T1"
exit
"""
    p = f"{lab.BENCH}/work/vyos-script.sh"
    open(p, "w").write(script)
    out = lab.sh(f"ssh -F {lab.SSHCFG} vyos 'vbash -s' < {p}", timeout=3600)
    m = re.search(r"COMMIT_S ([\d.]+) ([\d.]+)", out)
    if not m:
        raise RuntimeError(out[-2000:])
    return float(m.group(2)) - float(m.group(1)), out


def load(size):
    cmds = open(f"{lab.SRC}/generated/vyos/{size}.cmds").read().splitlines()
    pre = ["delete firewall", "delete nat source"]
    return vyos_script(pre + cmds)


def shutdown():
    lab.ssh("vyos", "sudo poweroff", check=False)
    for _ in range(60):
        if not lab.running(DOM):
            return
        time.sleep(2)
    lab.virsh("destroy", DOM)


if __name__ == "__main__":
    kf = f"{lab.BENCH}/keys/vyos-apikey.json"
    if not os.path.exists(kf):
        json.dump({"key": os.urandom(24).hex()}, open(kf, "w"))
        os.chmod(kf, 0o600)
    steps = sys.argv[1:] or ["install", "base", "small", "large"]
    if "install" in steps:
        install()
    if "base" in steps:
        base_config()
    if "small" in steps:
        if not lab.running(DOM):
            lab.router_domain("vyos", fresh=False, disk=DISK)
            lab.virsh("start", DOM)
            lab.wait_ssh("vyos")
        t, _ = load("small")
        print(json.dumps({"vyos_initial_commit_s": t, "size": "small"}), flush=True)
        shutdown()
    if "large" in steps:
        lab.sh(f"qemu-img convert -O qcow2 {DISK} {V}/vyos-router-large.qcow2 && setfacl -m u:qemu-libvirtd:rw {V}/vyos-router-large.qcow2")
        lab.router_domain("vyos", fresh=False, disk=f"{V}/vyos-router-large.qcow2")
        lab.virsh("start", DOM)
        lab.wait_ssh("vyos")
        t, _ = load("large")
        print(json.dumps({"vyos_initial_commit_s": t, "size": "large"}), flush=True)
        shutdown()
