#!/usr/bin/env python3
"""Install the aarch64 NixOS router (same router.nix as x86) into a Pi-5-shaped
TCG VM without an aarch64 builder on the host and without internet in the VM:

  1. host evaluates nixosConfigurations.router-aarch64 -> toplevel .drv
  2. the official aarch64 minimal installer ISO boots in the VM (serial)
  3. host `nix copy --derivation` pushes the .drv closure into the VM
  4. the VM realises it: substitutes from cache.nixos.org through an SSH
     reverse tunnel opened by the host (the lab bridge stays isolated) and
     builds the few uncached, trivial derivations itself (under TCG)
  5. nixos-install --system, power off, boot from disk
The Rust prototype is cross-compiled on the build machine (static musl), since
compiling it under TCG would take hours; it is the same source.
"""
import os
import subprocess
import time

import lab
import pi5
from console import Console

P = pi5.P
DOM = "sensrbench-pi-nixr"
DISK = f"{P}/nixos-aarch64-router.qcow2"
ISO = f"{P}/dl/nixos-minimal-aarch64.iso"
SSH = f"ssh -F {lab.SSHCFG} -o ControlMaster=no"


def vm(cmd, timeout=7200):
    return lab.sh(f"{SSH} router {cmd!r}", timeout=timeout)


def main():
    drv = lab.sh(f"cd {lab.SRC} && nix eval --raw .#nixosConfigurations.router-aarch64.config.system.build.toplevel.drvPath").strip()
    out = lab.sh(f"cd {lab.SRC} && nix eval --raw .#nixosConfigurations.router-aarch64.config.system.build.toplevel").strip()
    print("drv", drv, "out", out, flush=True)
    if os.path.exists(DISK):
        os.remove(DISK)
    lab.sh(f"qemu-img create -q -f qcow2 {DISK} 8G && setfacl -m u:qemu-libvirtd:rw {DISK} && setfacl -m u:qemu-libvirtd:r {ISO}")
    lab.stop_routers()
    pi5.define(DOM, DISK, pi5.PORT["nixr"], iso=ISO)
    lab.virsh("start", DOM)
    c = Console(pi5.PORT["nixr"], f"{lab.BENCH}/work/pi-nixos-install.log")
    # NixOS prompts are coloured: "[nixos@nixos:~]$" + ESC[0m + " "
    # (the prompt also embeds a window-title OSC inside the brackets)
    c.expect(r"nixos@nixos:~\]\$(?:\x1b\[0m)? $", 3600)
    key = open(f"{lab.BENCH}/keys/id_bench.pub").read().strip()
    c.sendline("sudo -i")
    c.expect(r"root@nixos:~\]#(?:\x1b\[0m)? $", 120)
    for line in [
        # NetworkManager on the ISO would flush a manual address after its DHCP attempt fails
        "systemctl stop NetworkManager",
        "IF=$(ip -o link | awk -F': ' '/52:54:00:5b:01:01/{print $2}'); ip addr add 192.168.1.1/24 dev $IF; ip link set $IF up",
        f"mkdir -p /root/.ssh && echo '{key}' > /root/.ssh/authorized_keys",
        # /etc/hosts is a read-only store symlink on NixOS: replace it with a writable copy
        "cp --remove-destination $(readlink -f /etc/hosts) /etc/hosts && echo '127.0.0.1 cache.nixos.org' >> /etc/hosts",
        "echo READY",
    ]:
        c.sendline(line)
    c.expect("READY", 60)
    c.close()
    lab.wait_ssh("router")
    vm("parted -s /dev/vda -- mklabel gpt mkpart ESP fat32 1MiB 512MiB set 1 esp on mkpart root ext4 512MiB 100% && "
       "mkfs.vfat -n ESP /dev/vda1 && mkfs.ext4 -q -L nixos /dev/vda2 && mount /dev/vda2 /mnt && mkdir -p /mnt/boot && mount /dev/vda1 /mnt/boot")
    t0 = time.time()
    lab.sh(f"NIX_SSHOPTS='-F {lab.SSHCFG} -o ControlMaster=no' nix copy --no-check-sigs --derivation --to 'ssh-ng://router?remote-store=local%3Froot%3D/mnt' {drv}", timeout=7200)
    # reverse tunnel: VM's 127.0.0.1:443 -> cache.nixos.org:443 (TLS end to end)
    tun = subprocess.Popen(f"{SSH} -N -R 443:cache.nixos.org:443 router", shell=True)
    time.sleep(3)
    print(vm("curl -sS -m 20 https://cache.nixos.org/nix-cache-info | head -3; getent hosts cache.nixos.org"), flush=True)
    try:
        r = vm(f"nix-store --store /mnt --realise {drv} --option substituters https://cache.nixos.org --option max-jobs 4 > /root/realise.log 2>&1; echo rc=$?; tail -5 /root/realise.log", timeout=14400)
        print(r, flush=True)
        if "rc=0" not in r:
            raise RuntimeError("realise failed")
        r = vm(f"nixos-install --root /mnt --system {out} --no-root-passwd --no-channel-copy > /root/install.log 2>&1; echo rc=$?; tail -5 /root/install.log", timeout=3600)
        print(r, flush=True)
        if "rc=0" not in r:
            raise RuntimeError("nixos-install failed")
    finally:
        tun.terminate()
    print("install_s", time.time() - t0, flush=True)
    lab.sh(f"{SSH} router 'sync; umount -R /mnt; poweroff'", check=False)
    time.sleep(10)
    if lab.running(DOM):
        lab.virsh("destroy", DOM)
    pi5.define(DOM, DISK, pi5.PORT["nixr"])


if __name__ == "__main__":
    main()
