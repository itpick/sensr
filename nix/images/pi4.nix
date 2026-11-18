# images.pi4: Raspberry Pi 4 SD/USB image (docs/PLAN.md §6, §6 platform table).
#
# Boot chain: like the Pi 5 image, the Pi 4's bootloader reads config.txt on
# the FAT partition and starts the kernel, initrd and device tree from it
# directly. No UEFI, no U-Boot.
#
# Kernel: nixpkgs' linuxPackages_latest, mainline. Its stock aarch64 config
# already has what a Pi 4 router needs: the BCM2711 PCIe controller and its
# VL805 XHCI (PCIE_BRCMSTB, USB_XHCI_PCI), the SD host (MMC_SDHCI_IPROC),
# GENET Ethernet, DWC2, r8152 for the RTL8152/8153/8156/8157 USB NICs, the
# BCM2835 watchdog, and the bcm2711 device trees. No vendor kernel and no
# custom build, so the image uses what cache.nixos.org already has.
#
# Differences from pi5.nix: the debug UART is the 40-pin header (PL011 at
# 0x7e201000 -> ttyS0), the firmware has no early-watchdog hook in mainline
# trees, and the boot slot is written in place (`@tryboot@` = 0) rather than
# trial-booted: tryboot has not selected tryboot.txt on these mainline
# kernels (see docs/research on the Pi 5), so an upgrade takes effect on the
# next reboot and a generation that does not come up needs the FAT edited.
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

  bootFiles = pkgs.callPackage ../pi4/boot-files.nix { inherit (kernelPackages) kernel; };

  # HDMI first, the header UART (ttyS0 with the mainline tree) last so it is
  # /dev/console; earlycon prints from the kernel's first instruction.
  extraCmdline = "console=tty1 console=ttyS0,115200 earlycon=pl011,0x7e201000,115200n8";

  installBoot = pkgs.writeShellApplication {
    name = "sensr-pi4-install-boot";
    runtimeInputs = [ pkgs.coreutils ];
    text =
      builtins.replaceStrings
        [ "@bootFiles@" "@extraCmdline@" "@tryboot@" "@watchdogTimeout@" "@section@" "@board@" ]
        [ "${bootFiles}" extraCmdline "0" "300" "pi4" "Raspberry Pi 4" ]
        (builtins.readFile ../pi5/install-boot.sh);
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

  services.sensr.build.image = "pi4";
  services.sensr.seedDir = seedDir;
  image.baseName = "sensr-pi4-${config.system.nixos.label}";

  boot.kernelPackages = kernelPackages;
  # sd-image pulls in all-hardware.nix; a Pi needs only its own drivers.
  hardware.enableAllHardware = lib.mkForce false;
  # Same reason as pi5.nix: without this the r8152 firmware blobs are missing
  # and the RTL8156 dongles (LAN and LAN2) run on ROM defaults.
  hardware.enableRedistributableFirmware = true;
  boot.initrd.availableKernelModules = [
    # SD card and the root filesystem
    "mmc_block"
    "sdhci_iproc"
    # The VL805's XHCI behind the BCM2711 PCIe controller, and USB disks
    "pcie_brcmstb"
    "xhci_pci"
    "xhci_hcd"
    "usb_storage"
    "uas"
    # The seed/boot partition, and the initrd's own boot log
    "vfat"
    "nls_cp437"
    "nls_iso8859_1"
    # QEMU's virt machine (the image's boot test)
    "virtio_pci"
    "virtio_blk"
  ];
  # genet is the Pi 4's only built-in Ethernet (the WAN port on a stock board).
  boot.kernelModules = [
    "bcm2835_wdt"
    "genet"
  ];

  # Same USB power management as the Pi 5 (pi5.nix): no autosuspend and no
  # U1/U2 link states for the RTL8156 dongles, whose resets leave eth1 with a
  # dead TX path.
  boot.kernelParams = [
    "usbcore.autosuspend=-1"
    "usbcore.quirks=0bda:8156:k"
  ];

  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = false;
  boot.loader.external = {
    enable = true;
    installHook = lib.getExe installBoot;
  };

  fileSystems.${fw} = {
    options = lib.mkForce [
      "nofail"
      "x-systemd.device-timeout=90s"
      "umask=0077"
    ];
  };

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

  # A Pi firmware boot has no systemd-boot counting to pull in
  # boot-complete.target; the selftest gates it.
  systemd.targets.boot-complete.wantedBy = [ "multi-user.target" ];

  systemd.services.sensr-bootlog = {
    description = "Boot log to the FAT partition";
    wantedBy = [ "multi-user.target" ];
    after = [ "local-fs.target" ];
    unitConfig.RequiresMountsFor = fw;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${lib.getExe bootlog} early";
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

  # The initrd's own post-mortem, as on the Pi 5.
  boot.initrd.systemd.storePaths = [ "${config.boot.initrd.systemd.package}/bin/journalctl" ];
  boot.initrd.systemd.extraBin.blkid = "${config.boot.initrd.systemd.package.util-linux}/bin/blkid";
  boot.initrd.systemd.services.sensr-bootlog-initrd = {
    description = "Initrd failure log to the FAT partition";
    wantedBy = [ "emergency.target" ];
    before = [ "panic-on-fail.service" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig.Type = "oneshot";
    script = ''
      for m in mmc_block sdhci_iproc pcie_brcmstb xhci_pci xhci_hcd usb_storage uas vfat nls_cp437 nls_iso8859_1; do
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
    bootlog
  ];
}