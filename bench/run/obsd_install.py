#!/usr/bin/env python3
"""Unattended OpenBSD install over the serial console, then router config.

The install image's boot loader talks to the VGA console, so `set tty com0` is
typed with `virsh send-key`; from then on the installer is driven over the raw
TCP serial socket by answering its prompts. Sets: everything except X and games
(a router has no use for them; recorded in the report). Then: pf.conf from the
generator, net.inet.ip.forwarding=1, unbound + dhcpd on LAN (to match the other
routers' services), root SSH via the bench key.
"""
import os
import re
import sys
import time

import lab
from console import Console

B = f"{lab.BENCH}/openbsd"
DOM = "sensrbench-obsd"
PORT = 45503
DISK = f"{B}/openbsd-8.0-router.qcow2"
PW = "sensrbench"  # lab-only VM on an isolated network


def xml():
    return f"""<domain type='kvm'>
  <name>{DOM}</name><memory unit='MiB'>2048</memory><vcpu>2</vcpu>
  <cputune><vcpupin vcpu='0' cpuset='2'/><vcpupin vcpu='1' cpuset='3'/><emulatorpin cpuset='10,11'/></cputune>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features><cpu mode='host-passthrough' check='none'/>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='{B}/dl/install80.img'/><target dev='vda' bus='virtio'/><boot order='1'/><readonly/></disk>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{DISK}'/><target dev='vdb' bus='virtio'/></disk>
    <interface type='network'><source network='sensrbench-lan'/><mac address='52:54:00:5b:01:01'/><model type='virtio'/><driver name='vhost'/></interface>
    <interface type='network'><source network='sensrbench-wan'/><mac address='52:54:00:5b:01:02'/><model type='virtio'/><driver name='vhost'/></interface>
    <serial type='tcp'><source mode='bind' host='127.0.0.1' service='{PORT}'/><protocol type='raw'/></serial>
    <console type='tcp'><source mode='bind' host='127.0.0.1' service='{PORT}'/><protocol type='raw'/><target type='serial' port='0'/></console>
    <memballoon model='none'/>
  </devices>
</domain>"""


ANSWERS = [
    (r"\(I\)nstall, \(U\)pgrade, \(A\)utoinstall or \(S\)hell\? $", "I"),
    (r"Choose your keyboard layout[^\n]*$", ""),
    (r"Terminal type\? \[vt220\] $", ""),
    (r"System hostname\? [^\n]*$", "obsd"),
    (r"Network interface to configure\? [^\n]*$", "NIC"),
    (r"IPv4 address for vio0\? [^\n]*$", "192.168.1.1"),
    (r"Netmask for vio0\? [^\n]*$", "255.255.255.0"),
    (r"IPv6 address for vio0\? [^\n]*$", "none"),
    (r"IPv4 address for vio1\? [^\n]*$", "10.99.0.1"),
    (r"Netmask for vio1\? [^\n]*$", "255.255.255.0"),
    (r"IPv6 address for vio1\? [^\n]*$", "none"),
    (r"Default IPv4 route\? [^\n]*$", "10.99.0.254"),
    (r"DNS domain name\? [^\n]*$", "lab"),
    (r"DNS nameservers\? [^\n]*$", "none"),
    (r"Password for root account\? .*$", PW),
    (r"Password for root account\? \(again\) $", PW),
    (r"Start sshd\(8\) by default\? \[yes\] $", "yes"),
    (r"Do you expect to run the X Window System\? [^\n]*$", "no"),
    (r"Change the default console to com0\? \[yes\] $", "yes"),
    (r"Which speed should com0 use\? [^\n]*$", "115200"),
    (r"Setup a user\? [^\n]*$", "no"),
    (r"Allow root ssh login\? [^\n]*$", "prohibit-password"),
    (r"What timezone are you in\? [^\n]*$", "UTC"),
    (r"Which disk is the root disk\? [^\n]*$", "sd1"),
    (r"Encrypt the root disk with a [^\n]*$", "no"),
    (r"Use \(W\)hole disk MBR, whole disk \(G\)PT[^\n]*$", "W"),
    (r"Use \(A\)uto layout, \(E\)dit auto layout, or create \(C\)ustom layout\? \[a\] $", "a"),
    (r"Which disk do you wish to initialize\? .*\[done\] $", "done"),
    (r"Location of sets\? .*\[done\] $", "done"),
    (r"Location of sets\? [^\n]*$", "disk"),
    (r"Is the disk partition already mounted\? [^\n]*$", "no"),
    (r"Which disk contains the install media\? [^\n]*$", "sd0"),
    (r"Which sd0 partition has the install sets\? [^\n]*$", "a"),
    (r"Pathname to the sets\? [^\n]*$", ""),
    (r"Set name\(s\)\? \(or 'abort' or 'done'\) \[done\] $", None),  # handled below
    (r"Directory does not contain SHA256\.sig\. Continue without verification\? \[no\] $", "yes"),
    (r"Exit to \(S\)hell, \(H\)alt or \(R\)eboot\? \[reboot\] $", "S"),
    (r"Symbolic \(host\) name for [^\n]*$", ""),
    (r"\? \[[^\]\n]*\] $", ""),  # fallback: unknown prompt with a default -> accept it
]


def install():
    os.makedirs(B, exist_ok=True)
    if os.path.exists(DISK):
        os.remove(DISK)
    lab.sh(f"qemu-img create -q -f qcow2 {DISK} 8G && setfacl -m u:qemu-libvirtd:rw {DISK} && setfacl -m u:qemu-libvirtd:rx {B} {B}/dl && setfacl -m u:qemu-libvirtd:r {B}/dl/install80.img")
    p = f"{lab.BENCH}/work/{DOM}-install.xml"
    open(p, "w").write(xml())
    if lab.exists(DOM):
        if lab.running(DOM):
            lab.virsh("destroy", DOM)
        lab.virsh("undefine", DOM)
    lab.virsh("define", p)
    lab.virsh("start", DOM)
    c = Console(PORT, f"{lab.BENCH}/work/obsd-install.log")
    time.sleep(2.5)
    keys = "KEY_S KEY_E KEY_T KEY_SPACE KEY_T KEY_T KEY_Y KEY_SPACE KEY_C KEY_O KEY_M KEY_0 KEY_ENTER"
    lab.virsh("send-key", DOM, keys)
    c.expect(r"boot> $", 30)
    c.sendline("")  # boot default (bsd.rd from the install image)
    sets_done = False
    deadline = time.time() + 1800
    while time.time() < deadline:
        pats = "|".join(f"(?:{p})" for p, _ in ANSWERS)
        m = c.expect(pats + r"|(# $)", timeout=900)
        txt = m.group(0)
        if txt == "# " and sets_done:
            break
        for p, ans in ANSWERS:
            if re.fullmatch(p, txt):
                if ans == "NIC":
                    nics = getattr(install, "nics", ["vio0", "vio1", "done"])
                    c.sendline(nics.pop(0) if nics else "done")
                    install.nics = nics
                elif ans is None:  # set selection: drop X and games, then done
                    if not sets_done:
                        c.sendline("-x* -game*")
                        sets_done = True
                    else:
                        c.sendline("done")
                else:
                    c.sendline(ans)
                print("PROMPT", repr(txt[-70:]), "->", repr(ans), flush=True)
                break
        time.sleep(0.2)
    # final shell inside the installer: drop in the bench key
    key = open(f"{lab.BENCH}/keys/id_bench.pub").read().strip()
    c.sendline(f"mkdir -p /mnt/root/.ssh && echo '{key}' > /mnt/root/.ssh/authorized_keys && chmod 700 /mnt/root/.ssh && chmod 600 /mnt/root/.ssh/authorized_keys && echo KEYOK")
    c.expect("KEYOK", 30)
    c.sendline("halt -p")
    time.sleep(10)
    if lab.running(DOM):
        lab.virsh("destroy", DOM)
    lab.virsh("undefine", DOM)
    c.close()


def configure():
    """Boot the installed disk as a normal router domain and apply bench config."""
    d, _ = lab.router_domain("obsd", fresh=False, disk=DISK)
    lab.virsh("start", d)
    lab.wait_ssh("router")
    gen = f"{lab.SRC}/generated/pf"
    lab.sh(f"scp -F {lab.SSHCFG} -q {gen}/small.conf router:/etc/pf.conf")
    lab.ssh("router", "mkdir -p /etc/pf")
    lab.sh(f"scp -F {lab.SSHCFG} -q {gen}/small-tables/*.txt router:/etc/pf/")
    lab.ssh("router", """
echo net.inet.ip.forwarding=1 >> /etc/sysctl.conf
sysctl net.inet.ip.forwarding=1
pfctl -f /etc/pf.conf
cat > /var/unbound/etc/unbound.conf <<EOF
server:
  interface: 127.0.0.1
  interface: 192.168.1.1
  access-control: 192.168.1.0/24 allow
  hide-identity: yes
EOF
rcctl enable unbound; rcctl start unbound
cat > /etc/dhcpd.conf <<EOF
subnet 192.168.1.0 netmask 255.255.255.0 {
  option routers 192.168.1.1; option domain-name-servers 192.168.1.1;
  range 192.168.1.150 192.168.1.199;
}
EOF
rcctl enable dhcpd; rcctl set dhcpd flags vio0; rcctl start dhcpd
syspatch -l 2>/dev/null | tail -1; true
""")
    print(lab.ssh("router", "uname -a; sysctl kern.version hw.ncpu net.inet.ip.forwarding; pfctl -sr | wc -l; pfctl -t blocklist_v4 -T show | wc -l; rcctl ls on"))
    lab.ssh("router", "halt -p", check=False)
    time.sleep(15)
    if lab.running(d):
        lab.virsh("destroy", d)


if __name__ == "__main__":
    if "configure" not in sys.argv:
        install()
    configure()
