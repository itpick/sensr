#!/usr/bin/env bash
# sensr-pi5-trial-install: try sensr on a Raspberry Pi 5 that already runs
# another OS (Raspberry Pi OS, Ubuntu) from its SD card, without risking it.
#
#   sensr-pi5-trial-install IMAGE DEVICE [--seed DIR] [--minutes N]
#                           [--logs-mib N] [--boot-order 0xHEX] [--yes]
#       write IMAGE (.img, .img.zst, .img.xz) to DEVICE (an SD card, NVMe or
#       USB disk that the running OS does not boot from; erased), copy DIR's
#       files into its seed folder, and arm a one-time trial boot of it on the
#       boot partition of the OS that is running now
#       --health FILE      copied to the seed folder as trial-health.env: the
#                          checks a trial boot must pass, or it reboots back
#                          (nix/pi5/trial-health.sh)
#       --deadline-minutes N  a measure-only trial: sensr reboots N minutes
#                          after boot whatever happens (PID 1's timer, no
#                          confirmation possible; sensr.trial.deadline=)
#       --watchdog-seconds N  kernel_watchdog_timeout in tryboot.txt
#                          (default 300): a hang before systemd feeds the
#                          hardware watchdog resets the board after N s
#       --boot-order 0xHEX the EEPROM's BOOT_ORDER, when neither
#                          rpi-eeprom-config nor vcgencmd can read it here
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
# A Pi 5 partition is bootable only when it has a config.txt (Raspberry Pi
# docs, "autoboot.txt"). Two layouts follow from BOOT_ORDER (read right to
# left; 1 SD, 4 USB, 6 NVMe):
#
#   DEVICE after the running OS (OS on the SD card, trial on NVMe or USB):
#     DEVICE keeps its config.txt; the bootloader never gets that far.
#     --commit renames the running OS's config.txt, so it moves on to DEVICE.
#   DEVICE before the running OS (OS on NVMe, trial on the SD card):
#     DEVICE's config.txt is renamed to config.txt.sensr-dormant, so plain
#     boots skip it and keep starting the running OS, while the trial boots
#     from the running OS's own partition. --commit puts DEVICE's config.txt
#     back, so the bootloader stops at DEVICE; renaming it again (--uncommit,
#     or on any computer), or pulling the card, brings the old OS back.
#
# Either way the trial's kernel is read from the running OS's partition (the
# documented tryboot path) and the EEPROM is never written.
#
# --logs-mib N (default 2048, 0 for none) grows DEVICE's root to leave N MiB
# at its end for a third partition, ext4 labelled SENSR_LOGS: the trial
# keeps its journal there, so it can be read from the old OS after a fall
# back (--status prints where).
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

# BOOT_ORDER nibbles: 1 SD, 4 USB, 6 NVMe.
kind_nibble() { # DEVICE -> its BOOT_ORDER nibble
  case $1 in
    /dev/mmcblk*) echo 1 ;;
    /dev/nvme*) echo 6 ;;
    *) echo 4 ;;
  esac
}

# The device the running OS booted from: the disk under its boot partition.
running_nibble() {
  local boot=$1 src disk
  if [ -n "${SENSR_TRIAL_RUNNING_KIND:-}" ]; then echo "$SENSR_TRIAL_RUNNING_KIND"; return; fi
  src=$(findmnt -no SOURCE --target "$boot" 2>/dev/null || true)
  [ -n "$src" ] || die "cannot tell which disk $boot is on"
  disk=/dev/$(lsblk -no PKNAME "$src" 2>/dev/null | head -n1)
  [ "$disk" != /dev/ ] || disk=$src
  kind_nibble "$disk"
}

boot_order() {
  local order=${opt_boot_order:-}
  if [ -z "$order" ] && command -v rpi-eeprom-config >/dev/null; then
    order=$(rpi-eeprom-config 2>/dev/null | sed -n 's/^BOOT_ORDER=//p' | tail -n1)
  fi
  if [ -z "$order" ] && command -v vcgencmd >/dev/null; then
    order=$(vcgencmd bootloader_config 2>/dev/null | sed -n 's/^BOOT_ORDER=//p' | tail -n1)
  fi
  [ -n "$order" ] || die "cannot read BOOT_ORDER (no rpi-eeprom-config or vcgencmd); pass --boot-order 0x... as the EEPROM config shows it"
  order=${order#0x}
  echo "$order" | grep -qiE '^[0-9a-f]+$' || die "BOOT_ORDER $order is not hex"
  echo "$order" | tr 'A-F' 'a-f'
}

# Prints "after" (DEVICE is tried after the running OS) or "before".
# Both must be in BOOT_ORDER, or the trial could not be committed or the old
# OS could not be fallen back to.
layout() {
  local boot=$1 target=$2 order rev run want pos_run pos_t
  if [ -n "${SENSR_TRIAL_SKIP_BOOT_ORDER:-}" ]; then echo "${SENSR_TRIAL_LAYOUT:-after}"; return; fi
  order=$(boot_order)
  run=$(running_nibble "$boot")
  want=${SENSR_TRIAL_TARGET_KIND:-$(kind_nibble "$target")}
  [ "$run" != "$want" ] || die "$target is the same kind of device as the one the running OS boots from; BOOT_ORDER cannot tell them apart"
  rev=$(echo "$order" | rev)
  pos_run=${rev%%"$run"*}
  pos_t=${rev%%"$want"*}
  [ "$pos_run" != "$rev" ] || die "BOOT_ORDER 0x$order never tries the running OS's device ($run)"
  [ "$pos_t" != "$rev" ] || die "BOOT_ORDER 0x$order never tries $target ($want); it could never boot it"
  if [ ${#pos_t} -lt ${#pos_run} ]; then echo before; else echo after; fi
}

mount_target_fat() { # DEVICE MOUNTPOINT
  mkdir -p "$2"
  mount -t vfat "$(part "$1" 1)" "$2"
}

# Grow DEVICE's root (partition 2) to leave LOGS MiB at the end, and make
# partition 3 there, ext4 SENSR_LOGS. The image's own first-boot resize then
# finds nothing left to grow.
make_logs_partition() { # DEVICE MIB
  local dev=$1 mib=$2 total start2 size2 end line
  total=$(blockdev --getsz "$dev")
  line=$(sfdisk -d "$dev" | grep "^$(part "$dev" 2) *:" || true)
  start2=$(echo "$line" | sed -n 's/.*start= *\([0-9]*\).*/\1/p')
  size2=$(echo "$line" | sed -n 's/.*size= *\([0-9]*\).*/\1/p')
  [ -n "$start2" ] && [ -n "$size2" ] || die "no partition 2 on $dev after writing the image"
  # 512-byte sectors; keep 1 MiB alignment for the new partition.
  end=$(( (total - mib * 2048) / 2048 * 2048 ))
  # The root only grows; the image's own size is the least it needs.
  [ "$end" -ge $((start2 + size2)) ] || die "$dev is too small for the image plus a ${mib} MiB log partition"
  echo "start=$start2, size=$((end - start2))" | sfdisk -q --no-reread -N 2 "$dev"
  echo "start=$end, type=83" | sfdisk -q --no-reread --append "$dev"
  blockdev --rereadpt "$dev" 2>/dev/null || partprobe "$dev" 2>/dev/null || true
  udevadm settle 2>/dev/null || true
  e2fsck -fy "$(part "$dev" 2)" >/dev/null 2>&1 || true
  resize2fs "$(part "$dev" 2)" >/dev/null
  mkfs.ext4 -q -F -L SENSR_LOGS "$(part "$dev" 3)"
}

install() {
  local image=$1 dev=$2 seed=$3 minutes=$4 yes=$5 logs=$6 health=$7 deadline=$8 watchdog=$9 boot mode
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
  mode=$(layout "$boot" "$dev")
  [ -z "$health" ] || [ -r "$health" ] || die "cannot read $health"
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
  # The image finds its partitions by label: another disk with the same
  # labels (an older sensr, a copied card) could be mounted instead.
  local l other
  for l in FIRMWARE NIXOS_SD SENSR_LOGS; do
    for other in $(blkid -c /dev/null -t LABEL="$l" -o device 2>/dev/null); do
      case $other in "$dev"*) ;; *) die "$other is also labelled $l; the trial could mount it instead of $dev's" ;; esac
    done
  done
  if [ "$logs" -gt 0 ]; then
    say "making a ${logs} MiB log partition ($(part "$dev" 3), SENSR_LOGS)"
    make_logs_partition "$dev" "$logs"
  fi

  local fat
  fat=$(mktemp -d)
  mount_target_fat "$dev" "$fat"
  # The trap runs after this function's scope is gone, so it must not name the
  # local: with set -u a failure otherwise reports "fat: unbound variable"
  # instead of the error that stopped the install.
  trial_fat=$fat
  trap 'umount "${trial_fat:-}" 2>/dev/null; rmdir "${trial_fat:-}" 2>/dev/null' EXIT
  [ -e "$fat/current/system" ] || die "$image is not a sensr Pi 5 image (no current/ on its FAT partition)"
  mkdir -p "$fat/sensr"
  if [ -n "$seed" ]; then
    # FAT has no symlinks: copy what they point to.
    cp -rL "$seed"/. "$fat/sensr/"
  fi
  # The trial timer: sensr reboots (back to this OS) after N minutes unless
  # someone deletes the file; --commit removes it.
  echo "$minutes" > "$fat/sensr/reboot-after-minutes"
  [ -z "$health" ] || cp "$health" "$fat/sensr/trial-health.env"
  if [ "$mode" = before ]; then
    # Plain boots try DEVICE first: without config.txt they move on to the
    # running OS.
    mv "$fat/config.txt" "$fat/config.txt.sensr-dormant"
  fi

  rm -rf "${boot:?}/$TRIAL.new"
  # The running OS's boot partition may be small (an EFI system partition):
  # make sure the kernel, initrd and device trees fit, with 8 MiB to spare.
  local need have
  need=$(du -sk "$fat/current" | cut -f1)
  have=$(( $(df -Pk "$boot" | tail -n1 | tr -s ' ' | cut -d' ' -f4) + $(du -sk "$boot/$TRIAL" 2>/dev/null | cut -f1 || echo 0) ))
  [ "$have" -ge $((need + 8192)) ] || die "$boot has $((have / 1024)) MiB free, the trial's boot files need $((need / 1024 + 8)) MiB"
  cp -r "$fat/current" "$boot/$TRIAL.new"
  sed -i "s/\$/ sensr.trial=1${deadline:+ sensr.trial.deadline=$((deadline * 60))}/" "$boot/$TRIAL.new/cmdline.txt"
  echo "$dev" > "$boot/$TRIAL.new/target"
  echo "$mode" > "$boot/$TRIAL.new/layout"
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
kernel_watchdog_timeout=$watchdog
EOF
  mv "$boot/tryboot.txt.new" "$boot/tryboot.txt"
  sync
  say "armed: '$SELF --reboot' boots sensr once; any reset after that comes back here"
  say "the trial timer reboots sensr after $minutes minutes"
  [ "$mode" = after ] || say "$dev's config.txt is dormant: plain boots skip it and start this OS"
}

status() {
  local boot dev fat
  boot=$(boot_dir)
  if [ -e "$boot/$TRIAL.committed/target" ]; then
    say "committed: $(cat "$boot/$TRIAL.committed/target") boots first ('$SELF --uncommit' to undo)"
  fi
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
    [ -e "$fat/config.txt.sensr-dormant" ] && say "$dev's config.txt is dormant (plain boots skip it)"
    umount "$fat"
  fi
  rmdir "$fat"
  if [ -b "$(part "$dev" 3)" ] && [ "$(blkid -o value -s LABEL "$(part "$dev" 3)" 2>/dev/null)" = SENSR_LOGS ]; then
    say "the trial's journal: mount -o ro $(part "$dev" 3) /mnt && journalctl -D /mnt/journal --no-pager"
  fi
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

# The trial's target FAT partition, mounted; prints the mount point.
open_target() { # DEVICE
  local fat
  [ -b "$1" ] || return 1
  fat=$(mktemp -d)
  if mount_target_fat "$1" "$fat" 2>/dev/null; then echo "$fat"; else rmdir "$fat"; return 1; fi
}
close_target() { umount "$1"; rmdir "$1"; }

commit() {
  local boot dev fat mode
  boot=$(boot_dir)
  dev=$(cat "$boot/$TRIAL/target" 2>/dev/null || true)
  [ -n "$dev" ] || die "no trial was installed from this card"
  mode=$(cat "$boot/$TRIAL/layout" 2>/dev/null || echo after)
  [ "$(layout "$boot" "$dev")" = "$mode" ] || die "BOOT_ORDER changed since the trial was installed; reinstall it"
  fat=$(open_target "$dev") || die "cannot mount $dev's FAT partition"
  rm -f "$fat/sensr/reboot-after-minutes" "$fat/sensr/trial-health.env"
  if [ "$mode" = before ]; then
    [ -e "$fat/config.txt.sensr-dormant" ] || { close_target "$fat"; die "$dev has no dormant config.txt (committed?)"; }
    mv "$fat/config.txt.sensr-dormant" "$fat/config.txt"
    sync -f "$fat/config.txt"
    close_target "$fat"
    # The old OS stays as it is, the fall-back when DEVICE is not bootable.
    if grep -q "^$MARK" "$boot/tryboot.txt" 2>/dev/null; then rm -f "$boot/tryboot.txt"; fi
    rm -rf "${boot:?}/$TRIAL.committed"
    mv "$boot/$TRIAL" "$boot/$TRIAL.committed"
  else
    close_target "$fat"
    [ -e "$boot/config.txt" ] || die "$boot/config.txt is already gone (committed?)"
    mv "$boot/config.txt" "$boot/config.txt.sensr-committed"
  fi
  sync
  say "committed: the next boot starts sensr from $dev ('$SELF --uncommit' to undo)"
}

uncommit() {
  local boot dev fat
  boot=$(boot_dir)
  if [ -e "$boot/$TRIAL.committed/target" ]; then
    say "committed: $(cat "$boot/$TRIAL.committed/target") boots first ('$SELF --uncommit' to undo)"
  fi
  if [ -e "$boot/config.txt.sensr-committed" ]; then
    mv "$boot/config.txt.sensr-committed" "$boot/config.txt"
    sync
    say "uncommitted: this partition boots again"
    return
  fi
  dev=$(cat "$boot/$TRIAL.committed/target" 2>/dev/null || true)
  [ -n "$dev" ] || die "not committed"
  fat=$(open_target "$dev") || die "cannot mount $dev's FAT partition"
  [ -e "$fat/config.txt" ] && mv "$fat/config.txt" "$fat/config.txt.sensr-dormant"
  close_target "$fat"
  sync
  say "uncommitted: $dev is dormant again, plain boots start this OS"
}

seed='' minutes=30 yes=0 logs=2048 health='' deadline='' watchdog=300 opt_boot_order='' action=install args=()
while [ $# -gt 0 ]; do
  case $1 in
    --reboot) action=reboot; shift ;;
    --status) action=status; shift ;;
    --cancel) action=cancel; shift ;;
    --commit) action=commit; shift ;;
    --uncommit) action=uncommit; shift ;;
    --seed) seed=$2; shift 2 ;;
    --minutes) minutes=$2; shift 2 ;;
    --logs-mib) logs=$2; shift 2 ;;
    --health) health=$2; shift 2 ;;
    --deadline-minutes) deadline=$2; shift 2 ;;
    --watchdog-seconds) watchdog=$2; shift 2 ;;
    --boot-order) opt_boot_order=$2; shift 2 ;;
    --yes) yes=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit ;;
    -*) die "unknown option $1" ;;
    *) args+=("$1"); shift ;;
  esac
done
case $action in
  reboot)
    [ -e "$(boot_dir)/tryboot.txt" ] || die "nothing armed"
    sync
    exec systemctl reboot --reboot-argument="0 tryboot" ;;
  status) status; exit ;;
  cancel) cancel; exit ;;
  commit) commit; exit ;;
  uncommit) uncommit; exit ;;
esac
[ ${#args[@]} = 2 ] || die "usage: $SELF IMAGE DEVICE [--seed DIR] [--minutes N] [--logs-mib N] [--health FILE] [--boot-order 0xHEX] [--yes] (or --help)"
case $logs in *[!0-9]*|'') die "--logs-mib takes a number" ;; esac
case $deadline in *[!0-9]*) die "--deadline-minutes takes a number" ;; esac
case $watchdog in *[!0-9]*|'') die "--watchdog-seconds takes a number" ;; esac
install "${args[0]}" "${args[1]}" "$seed" "$minutes" "$yes" "$logs" "$health" "$deadline" "$watchdog"
