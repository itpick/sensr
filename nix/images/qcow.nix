# images.qcow: x86_64 (and aarch64) UEFI qcow2 for KVM, Proxmox and libvirt;
# the image CI boots (docs/PLAN.md §6).
{
  config,
  lib,
  modulesPath,
  ...
}:
{
  imports = [
    ./common.nix
    "${modulesPath}/profiles/qemu-guest.nix"
    "${modulesPath}/virtualisation/disk-image.nix"
  ];

  image.format = "qcow2";
  image.efiSupport = true;
  image.baseName = "sensr-qcow-${config.system.nixos.label}";
  virtualisation.diskSize = "auto";
  services.sensr.build.image = "qcow";

  # systemd-boot with boot counting: a new generation gets 3 tries; it is
  # blessed only when boot-complete.target is reached, which the sensr
  # selftest gates (06 §2.4 item 1).
  boot.loader.systemd-boot = {
    enable = true;
    bootCounting.enable = true;
    bootCounting.tries = 3;
  };
  boot.loader.efi.canTouchEfiVariables = false;
  # No menu wait: boot counting picks the entry, and holding a key (space)
  # at power-on still shows the menu. Saves a second of every boot.
  boot.loader.timeout = 0;

  # The ESP holds the bootloader and the seed folder, but the system must
  # come up without it: a slow or missing ESP made the benchmark's NixOS
  # image hang in early boot (docs/research/07 "Boot": 3 of 5 boots failed).
  fileSystems."/boot".options = [
    "nofail"
    "x-systemd.device-timeout=15s"
    "umask=0077"
  ];

  boot.kernelParams = [
    "console=tty0"
    "console=ttyS0,115200"
  ];
}
