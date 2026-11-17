# The boot-time benchmark's router: images.qcow plus the bench SSH key for
# root (what the authorized_keys seed would give it).
# variant "home": home-router.xml sits in the seed folder at first boot,
# with the FreeBSD device names replaced by the Linux ones (what the import
# report asks the installer to do: igc0 -> eth0, igc1 -> eth1).
{ variant }:
{ lib, pkgs, ... }:
let
  seed = pkgs.runCommand "home-router-linux-names.xml" { } ''
    sed -e 's|<if>igc0</if>|<if>eth0</if>|; s|<if>igc1</if>|<if>eth1</if>|' \
      ${../../crates/sensr-import-opnsense/tests/fixtures/corpus/home-router.xml} > $out
  '';
in
{
  imports = [ ../images/qcow.nix ];
  image.baseName = lib.mkForce "sensr-bench-${variant}";
  users.users.root.openssh.authorizedKeys.keyFiles = [ ./bench_key.pub ];
  # The "kernel" milestone is the kernel banner on the serial console
  # (07's method), a notice-level message the image's default loglevel (4)
  # does not print.
  boot.consoleLogLevel = 6;
  systemd.tmpfiles.rules = lib.optionals (variant == "home") [
    "d /boot/sensr 0755 root root -"
    "C /boot/sensr/config.xml - - - - ${seed}"
  ];
}
