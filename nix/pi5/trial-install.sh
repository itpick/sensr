#!/usr/bin/env bash
# sensr-pi5-trial-install: try sensr on a Raspberry Pi 5 that already runs
# another OS (Raspberry Pi OS, Ubuntu) from its SD card, without risking it.
#
#   sensr-pi5-trial-install IMAGE DEVICE [--seed DIR] [--minutes N] [--yes]
#       write IMAGE (.img, .img.zst, .img.xz) to DEVICE (NVMe or USB disk;
#       erased), copy DIR's files into its seed folder, and arm a one-time
#       trial boot of it on the SD card
#   sensr-pi5-trial-install --reboot     boot sensr once (the firmware's tryboot)
#   sensr-pi5-trial-install --status     what is armed; the trial's boot logs
#   sensr-pi5-trial-install --cancel     disarm the trial
#   sensr-pi5-trial-install --commit     make DEVICE the default boot
#   sensr-pi5-trial-install --uncommit   undo --commit
#
# How it works: `reboot "0 tryboot"` makes the Pi firmware read tryboot.txt
# instead of config.txt for exactly one boot, and the flag is gone before
# the OS starts. tryboot.txt here is a whole config of its own with
# os_prefix=sensr-trial/, so kernel, initrd, cmdline and device trees come
# from that folder on the SD card, copied from the image; the system itself
# (root, store) is on DEVICE. Whatever happens to that boot (a panic, a hang,
# a watchdog reset, a power cut, or simply the trial timer), the next boot
# reads config.txt and the old OS is back. (Raspberry Pi docs, "fail-safe OS
# updates (tryboot)".)
#
# --commit renames the SD card's config.txt; a partition without one is not
# bootable, so the bootloader moves on to the next device in BOOT_ORDER,
# DEVICE. The EEPROM is never written.
#
# The same mechanism, from the other side, is how sensr upgrades itself on
# a Pi 5 (nix/pi5/install-boot.sh: next/ slot + tryboot.txt).
set -euo pipefail

MARK="# sensr-pi5-trial-install"
TRIAL=sensr-trial
SELF=$(basename "$0")

die() { echo "$SELF: $*" >&2; exit 1; }
say() { echo "$SELF: $*"; }

boot_dir() {
  # Raspberry Pi OS (bookworm+) and Ubuntu mount the boot partition here.
  for d in "${SENSR_TRIAL_BOOT_DIR:-}" /boot/firmware /boot; do
    if [ -n "$d" ] && { [ -e "$d/config.txt" ] || [ -e "$d/config.txt.sensr-committed" ]; }; then
      echo "$d"; return
    fi
  done
  die "no Pi boot partition with config.txt found (set SENSR_TRIAL_BOOT_DIR)"
}

part() { # DEVICE N -> partition N's device node
  case $1 in
    *[0-9]) echo "${1}p$2" ;;
    *) echo "$1$2" ;;
  esac
}

check_pi5() {
  [ -n "${SENSR_TRIAL_SKIP_MODEL_CHECK:-}" ] && return
  grep -q "Raspberry Pi 5" /proc/device-tree/model 2>/dev/null || die "this is not a Raspberry Pi 5"
}

# BOOT_ORDER is read right to left, one nibble per device: 1 SD, 4 USB,
# 6 NVMe. The SD card must come before the trial disk, or a plain reboot
# would start sensr with no way back.
check_boot_order() {
  local target=$1 order want
  [ -n "${SENSR_TRIAL_SKIP_BOOT_ORDER:-}" ] && return
  command -v rpi-eeprom-config >/dev/null || {
    say "warning: rpi-eeprom-config not found, BOOT_ORDER not checked"; return; }
  order=$(rpi-eeprom-config | sed -n 's/^BOOT_ORDER=0x//p')
  [ -n "$order" ] || { say "warning: no BOOT_ORDER in the EEPROM config"; return; }
  case $target in
    /dev/nvme*) want=6 ;;
    *) want=4 ;;
  esac
  local rev before_sd before_t
  rev=$(echo "$order" | rev)
  # Position of a device = how many nibbles come before it.
  before_sd=${rev%%1*}
  before_t=${rev%%"$want"*}
  [ "$before_sd" != "$rev" ] || die "BOOT_ORDER 0x$order never tries the SD card"
  [ "$before_t" != "$rev" ] || die "BOOT_ORDER 0x$order never tries $target (needs $want); --commit could not work"
  [ ${#before_sd} -lt ${#before_t} ] || die "BOOT_ORDER 0x$order tries $target before the SD card; set SD first (e.g. 0xf461) with rpi-eeprom-config --edit"
}

mount_target_fat() { # DEVICE MOUNTPOINT
  mkdir -p "$2"
  mount -t vfat "$(part "$1" 1)" "$2"
}

install() {
  local image=$1 dev=$2 seed=$3 minutes=$4 yes=$5 boot
  [ "$(id -u)" = 0 ] || die "run as root"
  check_pi5
  boot=$(boot_dir)
  [ -b "$dev" ] || die "$dev is not a block device"
  [ -e "$boot/autoboot.txt" ] && die "$boot/autoboot.txt exists: this card already uses A/B boot; not touching it"
  if [ -e "$boot/tryboot.txt" ] && ! grep -q "^$MARK" "$boot/tryboot.txt"; then
    die "$boot/tryboot.txt exists and is not ours; not replacing it"
  fi
  if lsblk -no MOUNTPOINTS "$dev" 2>/dev/null | grep -q .; then
    die "$dev has mounted partitions; it must not be the running system's disk"
  fi
  check_boot_order "$dev"
  if [ "$yes" != 1 ]; then
    read -r -p "Erase $dev and write $image to it? [y/N] " a
    [ "$a" = y ] || die "aborted"
  fi

  say "writing $image to $dev"
  case $image in
    *.zst) zstd -dc "$image" ;;
    *.xz) xz -dc "$image" ;;
    *) cat "$image" ;;
  esac | dd of="$dev" bs=4M conv=fsync status=none
  blockdev --rereadpt "$dev" 2>/dev/null || partprobe "$dev" 2>/dev/null || true
  udevadm settle 2>/dev/null || true

  local fat
  fat=$(mktemp -d)
  mount_target_fat "$dev" "$fat"
  trap 'umount "$fat" 2>/dev/null; rmdir "$fat" 2>/dev/null' EXIT
  [ -e "$fat/current/system" ] || die "$image is not a sensr Pi 5 image (no current/ on its FAT partition)"
  mkdir -p "$fat/sensr"
  if [ -n "$seed" ]; then
    # FAT has no symlinks: copy what they point to.
    cp -rL "$seed"/. "$fat/sensr/"
  fi
  # The trial timer: sensr reboots (back to this OS) after N minutes unless
  # someone deletes the file; --commit removes it.
  echo "$minutes" > "$fat/sensr/reboot-after-minutes"

  rm -rf "${boot:?}/$TRIAL.new"
  cp -r "$fat/current" "$boot/$TRIAL.new"
  sed -i 's/$/ sensr.trial=1/' "$boot/$TRIAL.new/cmdline.txt"
  echo "$dev" > "$boot/$TRIAL.new/target"
  umount "$fat"
  rmdir "$fat"
  trap - EXIT
  rm -rf "${boot:?}/$TRIAL"
  mv "$boot/$TRIAL.new" "$boot/$TRIAL"

  cat > "$boot/tryboot.txt.new" <<EOF
$MARK: a one-time trial boot of sensr on $dev.
# The firmware reads this file instead of config.txt after
# reboot "0 tryboot", for that one boot only.
[all]
arm_64bit=1
os_prefix=$TRIAL/
kernel=Image
initramfs initrd followkernel
cmdline=cmdline.txt
os_check=0
enable_uart=1
uart_2ndstage=1
kernel_watchdog_timeout=300
EOF
  mv "$boot/tryboot.txt.new" "$boot/tryboot.txt"
  sync
  say "armed: '$SELF --reboot' boots sensr once; any reset after that comes back here"
  say "the trial timer reboots sensr after $minutes minutes"
}

status() {
  local boot dev fat
  boot=$(boot_dir)
  if [ -e "$boot/config.txt.sensr-committed" ]; then
    say "committed: the SD card's config.txt is renamed, the Pi boots sensr ('$SELF --uncommit' to undo)"
  fi
  if [ -e "$boot/tryboot.txt" ] && grep -q "^$MARK" "$boot/tryboot.txt"; then
    say "armed: $(head -n1 "$boot/tryboot.txt" | sed "s/^$MARK: //")"
  else
    say "no trial armed"
  fi
  dev=$(cat "$boot/$TRIAL/target" 2>/dev/null || true)
  [ -n "$dev" ] && [ -b "$dev" ] || return 0
  fat=$(mktemp -d)
  if mount_target_fat "$dev" "$fat" 2>/dev/null; then
    if [ -d "$fat/sensr/boot-log" ]; then
      say "boot logs on $dev (sensr/boot-log):"
      ls -l "$fat/sensr/boot-log"
      local last
      last=$(find "$fat/sensr/boot-log" -name '*-*.txt' -printf '%T@ %p\n' | sort -n | tail -n1 | cut -d' ' -f2-)
      [ -n "$last" ] && { echo "--- $last"; head -n 20 "$last"; }
    else
      say "no boot logs on $dev yet (the trial never got as far as mounting its FAT partition)"
    fi
    umount "$fat"
  fi
  rmdir "$fat"
}

cancel() {
  local boot
  boot=$(boot_dir)
  if [ -e "$boot/tryboot.txt" ] && grep -q "^$MARK" "$boot/tryboot.txt"; then
    rm -f "$boot/tryboot.txt"
  fi
  rm -rf "${boot:?}/$TRIAL"
  sync
  say "trial disarmed"
}

commit() {
  local boot dev fat
  boot=$(boot_dir)
  [ -e "$boot/config.txt" ] || die "$boot/config.txt is already gone (committed?)"
  dev=$(cat "$boot/$TRIAL/target" 2>/dev/null || true)
  [ -n "$dev" ] || die "no trial was installed from this card"
  check_boot_order "$dev"
  if [ -b "$dev" ]; then
    fat=$(mktemp -d)
    if mount_target_fat "$dev" "$fat" 2>/dev/null; then
      rm -f "$fat/sensr/reboot-after-minutes"
      umount "$fat"
    fi
    rmdir "$fat"
  fi
  mv "$boot/config.txt" "$boot/config.txt.sensr-committed"
  sync
  say "committed: the next boot starts sensr from $dev ('$SELF --uncommit' to undo)"
}

uncommit() {
  local boot
  boot=$(boot_dir)
  [ -e "$boot/config.txt.sensr-committed" ] || die "not committed"
  mv "$boot/config.txt.sensr-committed" "$boot/config.txt"
  sync
  say "uncommitted: the SD card boots again"
}

seed='' minutes=30 yes=0 args=()
while [ $# -gt 0 ]; do
  case $1 in
    --reboot) [ -e "$(boot_dir)/tryboot.txt" ] || die "nothing armed"; exec reboot "0 tryboot" ;;
    --status) status; exit ;;
    --cancel) cancel; exit ;;
    --commit) commit; exit ;;
    --uncommit) uncommit; exit ;;
    --seed) seed=$2; shift 2 ;;
    --minutes) minutes=$2; shift 2 ;;
    --yes) yes=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit ;;
    -*) die "unknown option $1" ;;
    *) args+=("$1"); shift ;;
  esac
done
[ ${#args[@]} = 2 ] || die "usage: $SELF IMAGE DEVICE [--seed DIR] [--minutes N] [--yes] (or --help)"
install "${args[0]}" "${args[1]}" "$seed" "$minutes" "$yes"
