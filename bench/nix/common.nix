{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [
    "${modulesPath}/profiles/minimal.nix"
    "${modulesPath}/profiles/qemu-guest.nix"
  ];

  system.stateVersion = "26.11";
  boot.kernelParams = [ "console=ttyS0,115200" ];
  boot.loader.grub.device = lib.mkDefault "/dev/vda";
  boot.growPartition = true;
  fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; autoResize = true; };

  system.build.qcow2 = import "${modulesPath}/../lib/make-disk-image.nix" {
    inherit lib config pkgs;
    format = "qcow2";
    partitionTableType = if pkgs.stdenv.hostPlatform.isAarch64 then "efi" else "legacy";
    diskSize = "auto";
    additionalSpace = "512M";
  };

  networking.useNetworkd = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;
  services.openssh = { enable = true; settings.PermitRootLogin = "prohibit-password"; };
  users.users.root.openssh.authorizedKeys.keyFiles = [ ./bench_key.pub ];
  nix.enable = false;
  documentation.enable = false;
}
