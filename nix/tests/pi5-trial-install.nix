# nix/pi5/trial-install.sh against disk images in a VM: an "SD card" with a
# Pi OS-like boot partition and an empty "NVMe" disk. Checks what the script
# leaves on both (tryboot.txt, sensr-trial/, the seed and trial timer on the
# target), its refusals, and --status / --commit / --uncommit / --cancel.
# The trial boot itself (firmware reading tryboot.txt) only happens on a
# board; nix/tests/pi5-qemu.sh boots the same kernel/initrd/cmdline files.
{ pkgs, trialInstall }:
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
    ];
    environment.systemPackages = [
      trialInstall
      pkgs.dosfstools
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
        machine.succeed(f"{t} ${fakeImage} /dev/vdc --seed /etc/seed --minutes 7 --yes")
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
        machine.succeed(f"{t} ${fakeImage} /dev/vdc --minutes 9 --yes")

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
  '';
}
