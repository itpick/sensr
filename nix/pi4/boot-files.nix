# The device-tree files the Pi 4 firmware loads, taken from the kernel sensr
# boots (mainline bcm2711 trees).
#
# Unlike the Pi 5 trees these are copied unchanged: the early-watchdog hook
# (boot-files.nix in ../pi5) is a BCM2712 firmware feature, and the Pi 4's
# watchdog is started by systemd instead (common.nix RuntimeWatchdogSec).
{ runCommand, kernel }:
runCommand "sensr-pi4-boot-files-${kernel.version}" { } ''
  mkdir -p $out
  for d in bcm2711-rpi-4-b bcm2711-rpi-400 bcm2711-rpi-cm4-io; do
    cp ${kernel}/dtbs/broadcom/$d.dtb $out/
  done
''