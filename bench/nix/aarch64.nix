# Pi 5 track (QEMU virt, UEFI): EFI boot instead of BIOS/grub-on-MBR.
{ lib, ... }:
{
  boot.loader.grub.enable = lib.mkForce false;
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelParams = lib.mkForce [ "console=ttyAMA0,115200" ];
  fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
}
