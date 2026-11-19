# images.iso: x86_64 UEFI/BIOS live installer on a USB stick, for appliances
# and machines that are not written from a qcow2. It boots the same sensr
# system the other images run, so the box can be tried from the stick before
# anything is written to a disk, and `nixos-install` installs from the ISO's
# own store (no network needed for the closure).
#
# It does not import ./common.nix: that pulls in the perlless profile, and
# nixos-install is Perl. The ISO is an installer, not the appliance; the
# settings common.nix exists to guarantee (no Perl, no installer tools) are
# exactly the ones that do not apply here.
{
  lib,
  modulesPath,
  ...
}:
{
  imports = [
    "${modulesPath}/installer/cd-dvd/installation-cd-minimal.nix"
  ];

  services.sensr = {
    enable = true;
    applier = "slice";
    build.image = "iso";
    # The ISO is read-only, so the seed folder lives in the live system's
    # tmpfs; the README there explains the seed files to someone trying the
    # stick.
    seedDir = "/run/sensr/seed";
  };

  system.stateVersion = "26.11";
  networking.hostName = "sensr";

  # Appliances are usually headless: the installer's shell belongs on the
  # serial port as well as on a monitor.
  boot.kernelParams = [ "console=ttyS0,115200" ];

  isoImage = {
    # iso-image.nix derives the file name from image.baseName; force it so the
    # release publishes the same name the install page links to.
    makeEfiBootable = true;
    makeUsbBootable = true;
    # The ISO carries the whole system closure; zstd keeps it to a size that
    # fits a small stick.
    squashfsCompression = "zstd -Xcompression-level 19";
  };
  image.baseName = lib.mkForce "sensr-x86_64-installer";

  nix.settings.experimental-features = [ "nix-command" "flakes" ];
}