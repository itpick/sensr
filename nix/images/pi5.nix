# images.pi5: Raspberry Pi 5 SD/USB/NVMe image (docs/PLAN.md §6).
#
# Boot chain: the Pi 5's EEPROM bootloader reads config.txt on the FAT
# partition and starts the kernel, initrd and device tree from it directly.
# No UEFI, no U-Boot (U-Boot cannot drive the Pi 5's USB/PCIe, so it could
# not boot from NVMe or USB anyway).
#
# Kernel: nixpkgs' linuxPackages_latest, mainline. Its stock aarch64 config
# already has everything the Pi 5 needs (checked against 7.3.4's config):
# RP1 (MISC_RP1 -> rp1_pci, COMMON_CLK_RP1, PINCTRL_RP1) and its Ethernet
# (MACB), the BCM2712 PCIe controller and its MSI block (PCIE_BRCMSTB,
# BCM2712_MIP) for RP1 and NVMe, the SD controller (MMC_SDHCI_BRCMSTB,
# built in), DWC3 USB, r8152 for RTL8152/8153/8156/8157 USB NICs, the
# BCM2835 watchdog (built in), and the bcm2712 device trees with __symbols__
# so overlays apply. So there is no Raspberry Pi vendor kernel and no
# custom kernel build: the image uses the kernel cache.nixos.org already
# has. The vendor kernel would buy only what mainline lacks for a router's
# purposes: fan control (RP1 PWM) and HDMI console, neither of which a
# headless router needs.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  kernelPackages = pkgs.linuxPackages_latest;
  fw = "/boot/firmware";
  seedDir = "${fw}/sensr";

  bootFiles = pkgs.callPackage ../pi5/boot-files.nix { inherit (kernelPackages) kernel; };

  # Consoles: HDMI first, the debug UART (ttyAMA10 with the mainline tree,
  # PL011 at 0x107d001000) last so it is /dev/console; earlycon prints from
  # the kernel's first instruction.
  extraCmdline = "console=tty1 console=ttyAMA10,115200 earlycon=pl011,0x107d001000,115200n8";

  installBoot = pkgs.writeShellApplication {
    name = "sensr-pi5-install-boot";
    runtimeInputs = [ pkgs.coreutils ];
    text =
      builtins.replaceStrings
        [ "@bootFiles@" "@extraCmdline@" "@tryboot@" "@watchdogTimeout@" ]
        [ "${bootFiles}" extraCmdline "1" "300" ]
        (builtins.readFile ../pi5/install-boot.sh);
  };

  trybootCommit = pkgs.writeShellApplication {
    name = "sensr-pi5-tryboot-commit";
    runtimeInputs = with pkgs; [ coreutils ];
    text = builtins.readFile ../pi5/tryboot-commit.sh;
  };

  # Boot next/ once (the firmware's one-shot tryboot flag).
  tryboot = pkgs.writeShellApplication {
    name = "sensr-pi5-tryboot";
    runtimeInputs = [ config.systemd.package ];
    text = ''
      if [ ! -e ${fw}/tryboot.txt ]; then
        echo "nothing to try: no ${fw}/tryboot.txt (install a generation first)" >&2
        exit 1
      fi
      systemctl reboot --reboot-argument="0 tryboot"
    '';
  };

  bootlog = pkgs.writeShellApplication {
    name = "sensr-bootlog";
    runtimeInputs = with pkgs; [
      coreutils
      util-linux
      iproute2
      config.systemd.package
    ];
    text = builtins.replaceStrings [ "@seedDir@" ] [ seedDir ] (builtins.readFile ../pi5/bootlog.sh);
  };

  seedReadme = builtins.replaceStrings [ "@SEED_DIR@" ] [ seedDir ] (
    builtins.readFile ../modules/seed-README.txt
  );
in
{
  imports = [
    ./common.nix
    "${modulesPath}/installer/sd-card/sd-image.nix"
  ];

  services.sensr.build.image = "pi5";
  services.sensr.seedDir = seedDir;
  image.baseName = "sensr-pi5-${config.system.nixos.label}";

  boot.kernelPackages = kernelPackages;
  # sd-image pulls in all-hardware.nix; a Pi needs only its own drivers.
  hardware.enableAllHardware = lib.mkForce false;
  boot.initrd.availableKernelModules = [
    # SD card (sdhci-brcmstb is built in) and NVMe behind the BCM2712 PCIe
    "mmc_block"
    "pcie-brcmstb"
    "irq-bcm2712-mip"
    "nvme"
    # USB disks: the Pi 5's USB ports sit behind RP1
    "rp1_pci"
    "clk-rp1"
    "pinctrl-rp1"
    "usb_storage"
    "uas"
    # The seed/boot partition, and the initrd's own boot log
    "vfat"
    "nls_cp437"
    "nls_iso8859_1"
    # QEMU's virt machine (the image's boot test, nix/tests/pi5-qemu.sh)
    "virtio_pci"
    "virtio_blk"
  ];
  boot.kernelModules = [ "bcm2835_wdt" ];

  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = false;
  boot.loader.external = {
    enable = true;
    installHook = lib.getExe installBoot;
  };

  # The FAT partition is mounted for the seed folder, boot logs and
  # bootloader installs, but the system must come up without it: the
  # benchmark's aarch64 image hung in the initrd on its vfat mount in 3 of 5
  # boots (docs/research/07 "Boot"). Here it is not an initrd mount at all,
  # and `nofail` keeps local-fs.target from waiting for it. The device
  # timeout only bounds how long the FAT's own users (boot logs, tryboot
  # commit) wait: under QEMU's TCG udev's coldplug alone takes over a
  # minute, and 15 s lost the FAT on every emulated boot.
  fileSystems.${fw} = {
    options = lib.mkForce [
      "nofail"
      "x-systemd.device-timeout=90s"
      "umask=0077"
    ];
  };

  # The trial installer's log partition (sensr-pi5-trial-install
  # --logs-mib): the journal lives there, so a trial that fell back to the
  # previous OS can be read from it. Optional: without the partition the
  # journal stays on the root.
  fileSystems."/var/log" = {
    device = "/dev/disk/by-label/SENSR_LOGS";
    fsType = "ext4";
    options = [
      "nofail"
      "noatime"
      "x-systemd.device-timeout=10s"
    ];
  };

  sdImage = {
    firmwareSize = 512;
    compressImage = false;
    populateFirmwareCommands = ''
      ${lib.getExe installBoot} ${config.system.build.toplevel} --dir ./firmware --slot current
      mkdir -p ./firmware/sensr
      cp ${pkgs.writeText "README.txt" seedReadme} ./firmware/sensr/README.txt
    '';
    populateRootCommands = "";
  };

  # A trial boot that reached boot-complete.target becomes the default.
  systemd.services.sensr-pi5-tryboot-commit = {
    description = "Make a successful Pi 5 trial boot (tryboot) the default";
    wantedBy = [ "boot-complete.target" ];
    after = [
      "boot-complete.target"
      "boot-firmware.mount"
    ];
    unitConfig.RequiresMountsFor = fw;
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe trybootCommit;
    };
  };
  # Pi firmware boots have no systemd-boot counting to pull in
  # boot-complete.target; the selftest gates it, the commit follows it.
  systemd.targets.boot-complete.wantedBy = [ "multi-user.target" ];

  # Boot logs on the FAT partition: early (filesystems up), running
  # (selftest done), shutdown.
  systemd.services.sensr-bootlog = {
    description = "Boot log to the FAT partition";
    wantedBy = [ "multi-user.target" ];
    after = [ "local-fs.target" ];
    unitConfig.RequiresMountsFor = fw;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${lib.getExe bootlog} early";
      # Runs before the FAT partition is unmounted at shutdown.
      ExecStop = "${lib.getExe bootlog} shutdown";
    };
  };
  systemd.services.sensr-bootlog-running = {
    description = "Boot log to the FAT partition (system up)";
    wantedBy = [ "multi-user.target" ];
    after = [
      "sensr-bootlog.service"
      "sensr-selftest.service"
      "multi-user.target"
    ];
    unitConfig.RequiresMountsFor = fw;
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${lib.getExe bootlog} running";
    };
  };

  # The initrd's own post-mortem: when it gives up (root not found, a mount
  # failed) it writes its journal to the FAT partition before
  # boot.panic_on_fail panics and panic=10 reboots.
  boot.initrd.systemd.storePaths = [ "${config.boot.initrd.systemd.package}/bin/journalctl" ];
  boot.initrd.systemd.extraBin.blkid = "${config.boot.initrd.systemd.package.util-linux}/bin/blkid";
  boot.initrd.systemd.services.sensr-bootlog-initrd = {
    description = "Initrd failure log to the FAT partition";
    wantedBy = [ "emergency.target" ];
    before = [ "panic-on-fail.service" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig.Type = "oneshot";
    # The initrd may give up before udev has loaded the storage drivers or
    # made /dev/disk/by-label, so load them and find the partition by its
    # label directly, for up to 20 s.
    script = ''
      for m in mmc_block nvme pcie-brcmstb rp1_pci usb_storage uas vfat nls_cp437 nls_iso8859_1; do
        modprobe -q "$m" || true
      done
      dev=
      for _ in $(seq 1 40); do
        dev=$(blkid -L ${config.sdImage.firmwarePartitionName} 2>/dev/null) && [ -n "$dev" ] && break
        sleep 0.5
      done
      [ -n "$dev" ] || exit 0
      mkdir -p /run/sensr-fat
      mount -t vfat "$dev" /run/sensr-fat || exit 0
      mkdir -p /run/sensr-fat/sensr/boot-log
      ${config.boot.initrd.systemd.package}/bin/journalctl -b --no-pager -o short-monotonic \
        > /run/sensr-fat/sensr/boot-log/initrd-emergency-$(cat /proc/sys/kernel/random/boot_id).txt
      umount /run/sensr-fat
    '';
  };

  environment.systemPackages = [
    installBoot
    tryboot
    trybootCommit
    bootlog
  ];
}
