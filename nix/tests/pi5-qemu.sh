#!/usr/bin/env bash
# Boot images.pi5 the way a Pi 5 would, as far as QEMU can: kernel, initrd
# and cmdline.txt from the image's FAT partition (current/), the image as
# the disk. QEMU's virt machine (Cortex-A76) stands in for the board, with
# its own device tree and virtio disk, so this checks the files the image
# puts on the FAT partition, the initrd, and the boot to a passing selftest;
# not the Pi firmware, RP1 or the SD controller (only a board can).
#
#   nix/tests/pi5-qemu.sh IMAGE.img [BOOTS]
#
# Needs qemu-system-aarch64, mtools, jq, sfdisk. Runs under TCG on an x86
# host (nixtop): boot times are relative indicators only.
set -euo pipefail
img=$1
boots=${2:-3}
work=${WORK:-$(mktemp -d)}
mkdir -p "$work"
disk=$work/disk.img

fat_offset() {
  sfdisk -J "$1" | jq '.partitiontable.partitions[0].start * 512'
}
fat() { # mtools command, args...
  local cmd=$1; shift
  "$cmd" -i "$disk@@$(fat_offset "$disk")" "$@"
}

boot() { # name extra-cmdline timeout-seconds expect
  local name=$1 extra=$2 limit=$3 expect=$4
  local log=$work/$name.log
  fat mcopy -o -n ::current/Image "$work/Image"
  fat mcopy -o -n ::current/initrd "$work/initrd"
  local cmdline
  cmdline="$(fat mtype ::current/cmdline.txt | tr -d '\r\n') console=ttyAMA0,115200 $extra"
  local start end
  start=$(date +%s.%N)
  qemu-system-aarch64 -machine virt -cpu cortex-a76 -smp 4 -m 2048 \
    -accel tcg,thread=multi \
    -kernel "$work/Image" -initrd "$work/initrd" -append "$cmdline" \
    -drive file="$disk",if=virtio,format=raw \
    -nic none -display none -serial file:"$log" -no-reboot &
  local pid=$! ok=
  for _ in $(seq 1 $((limit * 10))); do
    if grep -q "$expect" "$log" 2>/dev/null; then ok=1; break; fi
    kill -0 $pid 2>/dev/null || break
    sleep 0.1
  done
  end=$(date +%s.%N)
  if [ -z "$ok" ] && kill -0 $pid 2>/dev/null; then kill $pid; fi
  if [ -n "$ok" ] && [ "$expect" = "sensr-selftest: PASS" ]; then
    # Let the "running" boot log reach the FAT partition, then pull the plug.
    for _ in $(seq 1 600); do
      grep -q "sensr-bootlog-running.service" "$log" && grep -q "Finished.*Boot log to the FAT partition (system up)" "$log" && break
      sleep 0.1
    done
    kill $pid 2>/dev/null || true
  fi
  wait $pid 2>/dev/null || true
  if [ -z "$ok" ]; then
    echo "$name: '$expect' not seen within ${limit}s"; tail -n 80 "$log"; return 1
  fi
  awk -v s="$start" -v e="$end" -v n="$name" 'BEGIN { printf "%s: %.1f s\n", n, e - s }'
}

echo "== image: $img ($(du -h "$img" | cut -f1), $(stat -c %s "$img") bytes)"
for n in $(seq 1 "$boots"); do
  cp --no-preserve=mode "$img" "$disk"
  echo "-- FAT partition"
  fat mtype ::config.txt | grep -q '^os_prefix=current/'
  fat mtype ::config.txt | grep -q '^kernel_watchdog_timeout=300'
  fat mdir -b ::current/overlays | grep -q bcm2712d0.dtbo
  fat mdir -b ::current | grep -q 'bcm2712-rpi-5-b.dtb'
  fat mtype ::current/cmdline.txt | grep -q 'panic=10'
  fat mtype ::sensr/README.txt | grep -q 'first-boot seed folder'
  echo "   config.txt, current/ (Image, initrd, cmdline.txt, dtbs, D0 overlay), sensr/README.txt: ok"
  boot "boot-$n" "" 1500 "sensr-selftest: PASS"
  fat mdir -b ::sensr/boot-log | tee "$work/boot-log-$n.txt"
  grep -q -- '-early.txt' "$work/boot-log-$n.txt"
  grep -q -- '-running.txt' "$work/boot-log-$n.txt"
  echo "   boot logs on the FAT partition: ok"
done

# A failing initrd reboots by itself and leaves its journal on FAT.
cp --no-preserve=mode "$img" "$disk"
boot initrd-failure "rd.systemd.unit=emergency.target" 900 "Rebooting in 10 seconds"
fat mdir -b ::sensr/boot-log | grep -q 'initrd-emergency-'
echo "   initrd failure: panicked and rebooted, journal on the FAT partition: ok"
