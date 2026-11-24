# sensr-pi*-install-boot: put a NixOS generation on the board's FAT partition
# so the EEPROM bootloader starts it directly (no UEFI, no U-Boot).
#
#   sensr-pi*-install-boot TOPLEVEL [--dir DIR] [--slot current|next] [--adopt]
#
#   --adopt   take over a partition whose config.txt this script did not
#             write: keep that file as config.txt.pre-adopt-DATE, install
#             TOPLEVEL into current/ and write our config.txt for it
#
# Layout of the FAT partition (DIR, default /boot/firmware):
#
#   config.txt        [@section@] os_prefix=current/ ...: boots the current slot
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
#
# config.txt decides what every plain boot starts, so it is only rewritten
# when this script owns it: it carries our "Written by" line and boots
# os_prefix=current/, or there is none and the card is not a dormant trial
# card (config.txt.sensr-dormant, nix/pi5/trial-install.sh). Anything else
# (a config.txt written by hand, by another OS, or edited to boot another
# folder) is left alone and the new generation is only staged: rewriting
# such a file once pointed a router at a stale trial slot that could not
# boot. --adopt hands the partition over explicitly.
set -euo pipefail

name=$(basename "$0")
toplevel=$1
shift
dir=/boot/firmware
slot=
adopt=0
# 1: a running system installs into next/ and commits after a trial boot.
tryboot_enabled=@tryboot@
while [ $# -gt 0 ]; do
  case $1 in
    --dir) dir=$2; shift 2 ;;
    --slot) slot=$2; shift 2 ;;
    --adopt) adopt=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

if [ ! -d "$dir" ]; then
  echo "$name: $dir is not mounted" >&2
  exit 1
fi

# 0 when FILE is missing or carries our "Written by" line.
ours() {
  [ ! -e "$1" ] || grep -q '^# sensr, .*Written by [^ ]*install-boot' "$1"
}

# 0 when config.txt is ours to rewrite (see the header).
owns_config() {
  if [ -e "$dir/config.txt" ]; then
    ours "$dir/config.txt" && grep -qx 'os_prefix=current/' "$dir/config.txt"
  else
    [ ! -e "$dir/config.txt.sensr-dormant" ]
  fi
}

if [ "$adopt" = 1 ]; then
  if [ -n "$slot" ] && [ "$slot" != current ]; then
    echo "$name: --adopt installs into current/; it cannot be used with --slot $slot" >&2
    exit 2
  fi
  if [ ! -e "$dir/config.txt" ] && [ -e "$dir/config.txt.sensr-dormant" ]; then
    echo "$name: $dir is a dormant trial card; sensr-pi5-trial-install --commit makes it the default" >&2
    exit 2
  fi
  slot=current
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
# sensr, @board@. Written by $name; edits are lost.
# The EEPROM bootloader loads everything below from $1 on this partition.
[@section@]
arm_64bit=1
os_prefix=$1
kernel=Image
initramfs initrd followkernel
cmdline=cmdline.txt
# A mainline device tree: the firmware's downstream-kernel check does not
# apply. (On a Pi 5 D0 board the firmware still applies overlays/bcm2712d0.dtbo.)
os_check=0
# Debug UART on the board's header, 115200 8N1: firmware log, then the kernel
# from its first instruction (earlycon in cmdline.txt).
enable_uart=1
uart_2ndstage=1
# Where the firmware supports it (Pi 5 with a 2025 or later bootloader EEPROM)
# it starts the hardware watchdog before the kernel; a boot that hangs
# anywhere then resets the board after this many seconds. Others ignore it.
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
# Boards whose trees need no overlays (the Pi 4) ship none.
if [ -d @bootFiles@/overlays ]; then
  cp @bootFiles@/overlays/*.dtbo "$tmp/overlays/"
fi
echo "init=$toplevel/init $(cat "$toplevel/kernel-params") @extraCmdline@" > "$tmp/cmdline.txt"
readlink -f "$toplevel" > "$tmp/system"
sync -f "$tmp/system"

rm -rf "$dir/$slot.old"
if [ -e "$dir/$slot" ]; then
  mv "$dir/$slot" "$dir/$slot.old"
fi
mv "$tmp" "$dir/$slot"
rm -rf "$dir/$slot.old"

if [ "$adopt" = 1 ] && [ -e "$dir/config.txt" ] && ! owns_config; then
  backup="$dir/config.txt.pre-adopt-$(date +%Y%m%d%H%M%S)"
  cp "$dir/config.txt" "$backup"
  echo "$name: adopting $dir: the old config.txt is kept as $(basename "$backup")"
  rm "$dir/config.txt"
fi

if owns_config; then
  config_txt current/ > "$dir/config.txt.new"
  mv "$dir/config.txt.new" "$dir/config.txt"
  sync -f "$dir/config.txt"
else
  if [ -e "$dir/config.txt" ]; then
    boots=$(sed -n 's/^os_prefix=//p' "$dir/config.txt" | tail -n 1)
    why="its config.txt was not written by $name (it boots os_prefix=${boots:-<none>})"
  else
    why="it is a dormant trial card (config.txt.sensr-dormant)"
  fi
  {
    echo "$name: WARNING: $dir is not managed by sensr's boot slots: $why."
    echo "$name: config.txt is left as it is, so a reboot does not start this generation;"
    echo "$name: $(cat "$dir/$slot/system") is only staged in $slot/."
    echo "$name: to boot sensr's slots from now on: $name $toplevel --adopt"
  } >&2
fi
# tryboot.txt is rewritten or removed only when it is ours too.
if [ "$slot" = next ]; then
  if ours "$dir/tryboot.txt"; then
    config_txt next/ > "$dir/tryboot.txt.new"
    mv "$dir/tryboot.txt.new" "$dir/tryboot.txt"
    sync -f "$dir/tryboot.txt"
    echo "$name: $(cat "$dir/next/system") is in next/;" \
      "sensr-pi5-tryboot boots it once, and it becomes current after it comes up"
  else
    echo "$name: WARNING: $dir/tryboot.txt was not written by $name; left as it is" >&2
  fi
elif [ -e "$dir/tryboot.txt" ] && ours "$dir/tryboot.txt"; then
  rm -f "$dir/tryboot.txt"
fi
