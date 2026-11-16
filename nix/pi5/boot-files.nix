# The device-tree files the Pi 5 firmware loads, from the kernel sensr boots:
#
#   bcm2712-rpi-5-b.dtb      mainline's C1 tree (the firmware loads this on
#                            every Pi 5), with the early-watchdog hooks added
#   bcm2712d0-rpi-5-b.dtb    mainline's D0 tree, likewise, for a firmware that
#                            loads it by that name
#   overlays/bcm2712d0.dtbo  turns the C1 tree into the D0 tree; the firmware
#                            applies it on D0 boards (./bcm2712d0-overlay.dts)
#
# Early watchdog: with config.txt's kernel_watchdog_timeout the firmware
# starts the BCM2712 watchdog before the kernel, and the kernel feeds it
# until systemd opens it, so a boot that hangs anywhere resets the board.
# The firmware does that only when the tree's "watchdog" alias points at a
# node with an "early-watchdog" property, which Raspberry Pi's trees get
# from dtparam=watchdog=on and mainline's lack (vyos-pi PR #6). Both are
# added here, at build time, with an overlay applied by fdtoverlay.
{
  runCommand,
  dtc,
  kernel,
}:
runCommand "sensr-pi5-boot-files-${kernel.version}"
  {
    nativeBuildInputs = [ dtc ];
  }
  ''
    dtbs=${kernel}/dtbs/broadcom
    c1=$dtbs/bcm2712-rpi-5-b.dtb
    d0=$dtbs/bcm2712-d-rpi-5-b.dtb
    mkdir -p $out/overlays

    dtc -q -@ -I dts -O dtb -o $out/overlays/bcm2712d0.dtbo ${./bcm2712d0-overlay.dts}

    # The overlay must turn C1 into exactly mainline's D0 tree.
    norm() {
      dtc -q -s -I dtb -O dts "$1" | grep -v -e phandle -e '^\s*$' \
        | sed '/__symbols__\|__fixups__\|__local_fixups__/,/};/d'
    }
    fdtoverlay -i $c1 -o c1-plus-d0.dtb $out/overlays/bcm2712d0.dtbo
    if ! diff <(norm c1-plus-d0.dtb) <(norm $d0) > d0.diff; then
      echo "overlays/bcm2712d0.dtbo no longer matches mainline's D0 tree in ${kernel.version}:"
      cat d0.diff
      exit 1
    fi

    watchdog() { # in out
      pm=$(fdtget "$1" /__symbols__ pm)
      cat > wd.dts <<DTS
    /dts-v1/;
    /plugin/;
    / {
      fragment@0 { target-path = "/aliases"; __overlay__ { watchdog = "$pm"; }; };
      fragment@1 { target-path = "$pm"; __overlay__ { early-watchdog; }; };
    };
    DTS
      dtc -q -@ -I dts -O dtb -o wd.dtbo wd.dts
      fdtoverlay -i "$1" -o "$2" wd.dtbo
      test "$(fdtget "$2" /aliases watchdog)" = "$pm"
      fdtget -l "$2" "$pm" >/dev/null
      fdtget -p "$2" "$pm" | grep -qx early-watchdog
    }
    watchdog $c1 $out/bcm2712-rpi-5-b.dtb
    watchdog $d0 $out/bcm2712d0-rpi-5-b.dtb
  ''
