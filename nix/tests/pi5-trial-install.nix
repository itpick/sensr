# nix/pi5/trial-install.sh against disk images in a VM: an "SD card" with a
# Pi OS-like boot partition and an empty "NVMe" disk. Checks what the script
# leaves on both (tryboot.txt, sensr-trial/, the seed and trial timer on the
# target), its refusals, and --status / --commit / --uncommit / --cancel.
# The trial boot itself (firmware reading tryboot.txt) only happens on a
# board; nix/tests/pi5-qemu.sh boots the same kernel/initrd/cmdline files.
#
# The second half is the layout of a Pi that runs its OS from NVMe and tries
# sensr from the SD card (BOOT_ORDER 0xf461 tries the SD first): the card's
# config.txt must stay dormant, the trial boots from the NVMe partition's
# tryboot.txt, and a log partition is made. A model of the firmware's
# documented boot selection (bootable = has config.txt; tryboot reads
# tryboot.txt instead, once; Raspberry Pi docs "autoboot.txt" and "tryboot")
# then says what each state of the two disks would boot. Last, the trial's
# self-health gate (nix/pi5/trial-health.sh) with a stub reboot.
{
  pkgs,
  trialInstall,
  trialHealth,
}:
let
  # A stand-in for images.pi5: same partition layout and FAT contents
  # (current/ slot, config.txt), no real kernel. Built without root via
  # mtools.
  fakeImage = pkgs.runCommand "fake-sensr-pi5.img"
    {
      nativeBuildInputs = with pkgs; [
        dosfstools
        mtools
        util-linux
        e2fsprogs
      ];
    }
    ''
      truncate -s 64M fat.img
      mkfs.vfat -n FIRMWARE fat.img
      echo "fake kernel" > Image
      echo "fake initrd" > initrd
      echo "init=/nix/store/fake-system/init panic=10 console=ttyAMA10,115200" > cmdline.txt
      echo /nix/store/fake-system > system
      echo dtb > bcm2712-rpi-5-b.dtb
      echo dtbo > bcm2712d0.dtbo
      mmd -i fat.img ::current ::current/overlays ::sensr
      mcopy -i fat.img Image initrd cmdline.txt system bcm2712-rpi-5-b.dtb ::current/
      mcopy -i fat.img bcm2712d0.dtbo ::current/overlays/
      echo "os_prefix=current/" > config.txt
      mcopy -i fat.img config.txt ::
      truncate -s 64M root.img
      mkfs.ext4 -q -L NIXOS_SD root.img
      truncate -s 136M $out
      printf 'label: dos\nstart=8MiB, size=64MiB, type=c\nstart=72MiB, type=83\n' | sfdisk -q $out
      dd if=fat.img of=$out bs=1M seek=8 conv=notrunc status=none
      dd if=root.img of=$out bs=1M seek=72 conv=notrunc status=none
    '';
in
pkgs.testers.runNixOSTest {
  name = "sensr-pi5-trial-install";
  nodes.machine = {
    virtualisation.emptyDiskImages = [
      128
      256
      # the second layout: "NVMe" (the running OS) and a bigger "SD card"
      128
      512
    ];
    environment.systemPackages = [
      trialInstall
      trialHealth
      pkgs.dosfstools
      pkgs.mtools
      pkgs.e2fsprogs
    ];
    environment.etc."seed/authorized_keys".text = "ssh-ed25519 AAAAtest test@slice\n";
  };
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    env = "SENSR_TRIAL_SKIP_MODEL_CHECK=1 SENSR_TRIAL_SKIP_BOOT_ORDER=1"
    t = f"{env} sensr-pi5-trial-install"

    # The "SD card": a Pi OS-like boot partition.
    machine.succeed(
        "mkfs.vfat -n bootfs /dev/vdb && mkdir -p /boot/firmware && mount /dev/vdb /boot/firmware"
        " && printf '[all]\\nkernel=kernel_2712.img\\n' > /boot/firmware/config.txt"
    )

    with subtest("refuses a card that already uses autoboot.txt"):
        machine.succeed("touch /boot/firmware/autoboot.txt")
        machine.fail(f"{t} ${fakeImage} /dev/vdc --yes")
        machine.succeed("rm /boot/firmware/autoboot.txt")

    with subtest("refuses to replace a tryboot.txt it did not write"):
        machine.succeed("echo 'os_prefix=other/' > /boot/firmware/tryboot.txt")
        machine.fail(f"{t} ${fakeImage} /dev/vdc --yes")
        machine.succeed("rm /boot/firmware/tryboot.txt")

    with subtest("install: image on the target, trial armed on the SD card"):
        machine.succeed(f"{t} ${fakeImage} /dev/vdc --seed /etc/seed --minutes 7 --logs-mib 0 --yes")
        tb = machine.succeed("cat /boot/firmware/tryboot.txt")
        assert "os_prefix=sensr-trial/" in tb, tb
        assert "kernel_watchdog_timeout=300" in tb, tb
        machine.succeed("grep -q 'fake kernel' /boot/firmware/sensr-trial/Image")
        machine.succeed("test -e /boot/firmware/sensr-trial/overlays/bcm2712d0.dtbo")
        machine.succeed("grep -q 'sensr.trial=1' /boot/firmware/sensr-trial/cmdline.txt")
        machine.succeed("grep -q 'kernel_2712' /boot/firmware/config.txt")
        machine.succeed("mkdir -p /mnt/t && mount /dev/vdc1 /mnt/t")
        assert machine.succeed("cat /mnt/t/sensr/reboot-after-minutes").strip() == "7"
        machine.succeed("grep -q test@slice /mnt/t/sensr/authorized_keys")
        machine.succeed("umount /mnt/t")
        out = machine.succeed(f"{t} --status")
        assert "armed" in out, out

    with subtest("re-arming over its own trial is fine"):
        machine.succeed(f"{t} ${fakeImage} /dev/vdc --minutes 9 --logs-mib 0 --yes")

    with subtest("commit: SD config.txt renamed, trial timer removed; uncommit undoes it"):
        machine.succeed(f"{t} --commit")
        machine.succeed("test ! -e /boot/firmware/config.txt && test -e /boot/firmware/config.txt.sensr-committed")
        machine.succeed("mount /dev/vdc1 /mnt/t && test ! -e /mnt/t/sensr/reboot-after-minutes && umount /mnt/t")
        assert "committed" in machine.succeed(f"{t} --status")
        machine.succeed(f"{t} --uncommit")
        machine.succeed("test -e /boot/firmware/config.txt")

    with subtest("cancel disarms"):
        machine.succeed(f"{t} --cancel")
        machine.succeed("test ! -e /boot/firmware/tryboot.txt && test ! -e /boot/firmware/sensr-trial")
        assert "no trial armed" in machine.succeed(f"{t} --status")

    machine.succeed("umount /boot/firmware")

    with subtest("refuses when another disk has the image's labels"):
        # vdc still holds the first trial's image (FIRMWARE, NIXOS_SD)
        machine.succeed("mkfs.vfat -n NVMEFAT /dev/vdd && mount /dev/vdd /boot/firmware && echo x > /boot/firmware/config.txt")
        machine.fail(
            "SENSR_TRIAL_SKIP_MODEL_CHECK=1 SENSR_TRIAL_RUNNING_KIND=6 SENSR_TRIAL_TARGET_KIND=1"
            " sensr-pi5-trial-install ${fakeImage} /dev/vde --boot-order 0xf461 --logs-mib 0 --yes"
        )
        machine.succeed("umount /boot/firmware && wipefs -aq /dev/vdc1 /dev/vdc2 /dev/vdc && wipefs -aq /dev/vde")

    # ---- OS on NVMe (vdd), sensr on the SD card (vde), BOOT_ORDER 0xf461 ----
    ORDER = "0xf461"
    env2 = "SENSR_TRIAL_SKIP_MODEL_CHECK=1 SENSR_TRIAL_RUNNING_KIND=6 SENSR_TRIAL_TARGET_KIND=1"
    t2 = f"{env2} sensr-pi5-trial-install"
    machine.succeed(
        "mkfs.vfat -n NVMEFAT /dev/vdd && mount /dev/vdd /boot/firmware"
        " && printf '[pi5]\\nkernel=old-os/Image\\n' > /boot/firmware/config.txt"
    )

    def fat_files(dev):
        machine.succeed("sync")
        out = machine.succeed(f"MTOOLS_SKIP_CHECK=1 mdir -i {dev} -b :: 2>/dev/null || true")
        return {l.strip().lstrip(":").lstrip("/") for l in out.splitlines() if l.strip()}

    def boots(order, tryboot=False, sd_present=True):
        """The documented firmware rules, over what is on the disks now:
        devices in BOOT_ORDER from the low nibble up; a device is bootable
        when its FAT has config.txt; on a tryboot boot the bootable device's
        tryboot.txt is read instead (a bootable device without one is not
        defined by the docs, so the model refuses it)."""
        sd = fat_files("/dev/vde1") if sd_present else None
        nvme = fat_files("/dev/vdd")
        disks = {"1": sd, "6": nvme, "4": None}
        for nib in reversed(order[2:]):
            if nib == "f":
                return "nothing (loops)"
            files = disks.get(nib)
            if files is None or "config.txt" not in files:
                continue
            name = {"1": "sd", "6": "nvme"}[nib]
            if tryboot:
                assert "tryboot.txt" in files, f"tryboot on {name} without tryboot.txt: undocumented"
                return f"{name}:tryboot.txt"
            return f"{name}:config.txt"
        return "nothing"

    with subtest("before the trial: the plain boot is the NVMe OS"):
        # a card with no config.txt at all, as pi5-1's is today
        machine.succeed("echo 'type=c' | sfdisk -q /dev/vde && udevadm settle && mkfs.vfat -n OLDSD /dev/vde1")
        assert "config.txt" not in fat_files("/dev/vde1")
        assert boots(ORDER) == "nvme:config.txt"

    with subtest("refuses when BOOT_ORDER cannot be read"):
        machine.fail(f"{t2} ${fakeImage} /dev/vde --yes")

    with subtest("refuses a BOOT_ORDER that never tries the SD card"):
        machine.fail(f"{t2} ${fakeImage} /dev/vde --boot-order 0xf46 --yes")

    with subtest("install onto the SD card: dormant config.txt, logs partition, health file"):
        machine.succeed("printf 'WAN_IP=198.51.100.7\\n' > /tmp/health.env")
        machine.succeed(
            f"{t2} ${fakeImage} /dev/vde --boot-order {ORDER} --minutes 15 --logs-mib 128"
            " --health /tmp/health.env --deadline-minutes 8 --watchdog-seconds 120 --yes"
        )
        sd = fat_files("/dev/vde1")
        assert "config.txt" not in sd and "config.txt.sensr-dormant" in sd, sd
        machine.succeed("mount /dev/vde1 /mnt/t")
        assert machine.succeed("cat /mnt/t/sensr/reboot-after-minutes").strip() == "15"
        machine.succeed("grep -q WAN_IP=198.51.100.7 /mnt/t/sensr/trial-health.env")
        machine.succeed("umount /mnt/t")
        assert machine.succeed("blkid -o value -s LABEL /dev/vde3").strip() == "SENSR_LOGS"
        # root grown up to the log partition; the image's own first-boot
        # resize (sfdisk ",+") then has nothing to do and still succeeds
        p2_end = int(machine.succeed("cat /sys/class/block/vde2/start").strip()) + int(machine.succeed("cat /sys/class/block/vde2/size").strip())
        p3_start = int(machine.succeed("cat /sys/class/block/vde3/start").strip())
        assert p2_end == p3_start, (p2_end, p3_start)
        machine.succeed("echo ',+,' | sfdisk -N 2 --no-reread /dev/vde")
        machine.succeed("e2fsck -fn /dev/vde2")
        assert machine.succeed("cat /boot/firmware/sensr-trial/layout").strip() == "before"
        tb = machine.succeed("cat /boot/firmware/tryboot.txt")
        assert "os_prefix=sensr-trial/" in tb, tb
        assert "kernel_watchdog_timeout=120" in tb, tb
        cl = machine.succeed("cat /boot/firmware/sensr-trial/cmdline.txt")
        assert "sensr.trial=1 sensr.trial.deadline=480" in cl, cl
        machine.succeed("grep -q 'kernel=old-os' /boot/firmware/config.txt")
        out = machine.succeed(f"{t2} --status --boot-order {ORDER}")
        assert "dormant" in out and "journalctl -D" in out, out

    with subtest("boot selection while armed"):
        assert boots(ORDER) == "nvme:config.txt", "a plain boot must still start the NVMe OS"
        assert boots(ORDER, tryboot=True) == "nvme:tryboot.txt", "the trial boots from the NVMe partition"
        assert boots(ORDER, sd_present=False) == "nvme:config.txt"
        # one tryboot, then any reset: the flag is gone, so config.txt again
        assert boots(ORDER) == "nvme:config.txt"

    with subtest("commit: the SD card boots first, the NVMe OS is the fall-back"):
        machine.succeed(f"{t2} --commit --boot-order {ORDER}")
        assert boots(ORDER) == "sd:config.txt"
        assert boots(ORDER, sd_present=False) == "nvme:config.txt"
        machine.succeed("test ! -e /boot/firmware/tryboot.txt")
        machine.succeed("mount /dev/vde1 /mnt/t && test ! -e /mnt/t/sensr/reboot-after-minutes && test ! -e /mnt/t/sensr/trial-health.env && umount /mnt/t")
        assert "committed" in machine.succeed(f"{t2} --status --boot-order {ORDER}")

    with subtest("uncommit: dormant again, the NVMe OS boots"):
        machine.succeed(f"{t2} --uncommit --boot-order {ORDER}")
        assert boots(ORDER) == "nvme:config.txt"

    with subtest("the layout the docs leave undefined is never produced"):
        # tryboot.txt on a card without config.txt: the docs say such a
        # partition is not bootable, so nothing may depend on it
        assert "tryboot.txt" not in fat_files("/dev/vde1")

    # ---- the trial's self-health gate ----
    h = "SENSR_TRIAL_CMDLINE=/tmp/cmdline SENSR_TRIAL_INTERVAL=1 SENSR_TRIAL_REBOOT='touch /tmp/rebooted' sensr-trial-health"
    machine.succeed("mkdir -p /tmp/seed && echo 'quiet sensr.trial=1' > /tmp/cmdline")

    with subtest("health: not a trial boot, nothing happens"):
        machine.succeed("echo quiet > /tmp/nottrial")
        out = machine.succeed("SENSR_TRIAL_CMDLINE=/tmp/nottrial sensr-trial-health run")
        assert "not a trial boot" in out, out

    with subtest("health: a check that never passes reboots after the grace time"):
        machine.succeed("printf 'TRIAL_GRACE_SECONDS=0\\nWAN_IP=198.51.100.7\\n' > /tmp/seed/trial-health.env")
        machine.fail(f"{h} run")
        machine.succeed("test -e /tmp/rebooted && rm /tmp/rebooted")
        assert "198.51.100.7" in machine.succeed(f"{h} status")

    with subtest("health: passing, then failing three rounds in a row, reboots"):
        machine.succeed("ip link add trialwan type dummy && ip link set trialwan up && ip addr add 198.51.100.7/24 dev trialwan")
        machine.succeed("printf 'TRIAL_GRACE_SECONDS=600\\nWAN_IP=198.51.100.7\\nWAN_IF=trialwan\\nTRIAL_FAILS_TO_REBOOT=3\\n' > /tmp/seed/trial-health.env")
        machine.succeed(f"({h} run > /tmp/health.log 2>&1 &)")
        machine.wait_until_succeeds("grep -q 'all checks pass' /tmp/health.log", timeout=30)
        machine.succeed("test ! -e /tmp/rebooted")
        machine.succeed("ip addr del 198.51.100.7/24 dev trialwan")
        machine.wait_until_succeeds("test -e /tmp/rebooted", timeout=30)
        machine.succeed("rm /tmp/rebooted")

    with subtest("health: confirm stops the gate and the trial timer"):
        machine.succeed("ip addr add 198.51.100.7/24 dev trialwan && echo 15 > /tmp/seed/reboot-after-minutes")
        machine.succeed(f"({h} run > /tmp/health2.log 2>&1 &)")
        machine.wait_until_succeeds("grep -q 'all checks pass' /tmp/health2.log", timeout=30)
        machine.succeed(f"{h} confirm")
        machine.wait_until_succeeds("grep -q 'confirmed; the gate stops' /tmp/health2.log", timeout=30)
        machine.succeed("test ! -e /tmp/seed/reboot-after-minutes")
        machine.succeed("ip addr del 198.51.100.7/24 dev trialwan")
        machine.sleep(5)
        machine.succeed("test ! -e /tmp/rebooted")
  '';
}
