# sensr-pi5-install-boot: put a NixOS generation on the Pi 5's FAT partition
# so the EEPROM bootloader starts it directly (no UEFI, no U-Boot).
#
#   sensr-pi5-install-boot TOPLEVEL [--dir DIR] [--slot current|next]
#
# Layout of the FAT partition (DIR, default /boot/firmware):
#
#   config.txt        [pi5] os_prefix=current/ ...: boots the current slot
#   tryboot.txt       the same with os_prefix=next/; the firmware reads it
#                     instead of config.txt for one boot after
#                     `reboot "0 tryboot"` (sensr-pi5-tryboot)
#   current/  next/   one generation each: Image, initrd, cmdline.txt, the
#                     device trees, overlays/, and `system` (its toplevel)
#   previous/         the slot current/ held before the last commit
#   sensr/            the seed folder and boot logs
#
# NixOS calls this as its bootloader installer for every switch or boot.
# On a running Pi the new generation goes to next/ and becomes current/ only
# after it has booted once through tryboot and reached boot-complete.target
# (sensr-pi5-tryboot-commit.service): a generation that never comes up is
# never booted again, because any reset after the trial reads config.txt.
# The image build calls it with --slot current.
set -euo pipefail

toplevel=$1
shift
dir=/boot/firmware
slot=
# 1: a running system installs into next/ and commits after a trial boot.
tryboot_enabled=@tryboot@
while [ $# -gt 0 ]; do
  case $1 in
    --dir) dir=$2; shift 2 ;;
    --slot) slot=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

if [ ! -d "$dir" ]; then
  echo "sensr-pi5-install-boot: $dir is not mounted" >&2
  exit 1
fi

if [ -z "$slot" ]; then
  if [ "$tryboot_enabled" = 1 ] && [ -e "$dir/current/system" ]; then
    slot=next
  else
    slot=current
  fi
fi

config_txt() { # os_prefix
  cat <<EOF
# sensr, Raspberry Pi 5. Written by sensr-pi5-install-boot; edits are lost.
# The EEPROM bootloader loads everything below from $1 on this partition.
[pi5]
arm_64bit=1
os_prefix=$1
kernel=Image
initramfs initrd followkernel
cmdline=cmdline.txt
# A mainline device tree: the firmware's downstream-kernel check does not
# apply. On D0 boards it still applies overlays/bcm2712d0.dtbo.
os_check=0
# Debug UART (3-pin header between the HDMI ports), 115200 8N1: firmware log,
# then the kernel from its first instruction (earlycon in cmdline.txt).
enable_uart=1
uart_2ndstage=1
# The firmware starts the hardware watchdog before the kernel; a boot that
# hangs anywhere resets the board after this many seconds (needs a 2025 or
# later bootloader EEPROM; older ones ignore it).
kernel_watchdog_timeout=@watchdogTimeout@

[all]
EOF
}

tmp="$dir/.$slot.new"
rm -rf "$tmp"
mkdir -p "$tmp/overlays"
cp "$toplevel/kernel" "$tmp/Image"
cp "$toplevel/initrd" "$tmp/initrd"
cp @bootFiles@/*.dtb "$tmp/"
cp @bootFiles@/overlays/*.dtbo "$tmp/overlays/"
echo "init=$toplevel/init $(cat "$toplevel/kernel-params") @extraCmdline@" > "$tmp/cmdline.txt"
readlink -f "$toplevel" > "$tmp/system"
sync -f "$tmp/system"

rm -rf "$dir/$slot.old"
if [ -e "$dir/$slot" ]; then
  mv "$dir/$slot" "$dir/$slot.old"
fi
mv "$tmp" "$dir/$slot"
rm -rf "$dir/$slot.old"

config_txt current/ > "$dir/config.txt.new"
mv "$dir/config.txt.new" "$dir/config.txt"
if [ "$slot" = next ]; then
  config_txt next/ > "$dir/tryboot.txt.new"
  mv "$dir/tryboot.txt.new" "$dir/tryboot.txt"
  echo "sensr-pi5-install-boot: $(cat "$dir/next/system") is in next/;" \
    "sensr-pi5-tryboot boots it once, and it becomes current after it comes up"
else
  rm -f "$dir/tryboot.txt"
fi
sync -f "$dir/config.txt"
