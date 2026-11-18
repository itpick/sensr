#!/usr/bin/env bash
# Read a Raspberry Pi SD card that has been put in this machine's reader.
# Read-only throughout: the card is never written to and never fsck'd.
# Run as root: sudo ./read-card.sh [--no-image]
set -uo pipefail

out=${OUT:-$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/pi4-card}
image=yes
[ "${1:-}" = "--no-image" ] && image=no

disks=$(lsblk -dn -o NAME,TYPE,TRAN | awk '$2=="disk" && $1 !~ /^(nvme|zram)/ {print $1}')
if [ -z "$disks" ]; then
  echo "No card reader disk found. Is the card inserted?" >&2
  exit 1
fi
if [ "$(wc -w <<<"$disks")" -gt 1 ]; then
  echo "More than one candidate: $disks -- re-run with the card alone." >&2
  exit 1
fi
dev=$disks

echo "== card"
lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,SERIAL "/dev/$dev"
blkid "/dev/$dev"?* 2>/dev/null
size=$(blockdev --getsize64 "/dev/$dev")
free=$(df -B1 --output=avail / | tail -1)
echo "== size $((size/1024/1024)) MiB, free $((free/1024/1024)) MiB"

mkdir -p "$out"
echo "$(date -Is) /dev/$dev $(lsblk -dn -o MODEL,SERIAL /dev/$dev)" >> "$out/README"

if [ "$image" = yes ] && [ $((size + 4294967296)) -lt "$free" ]; then
  echo "== imaging to $out/card.img (bad blocks kept, never aborting)"
  dd if="/dev/$dev" of="$out/card.img" bs=4M conv=noerror,sync status=progress || true
  sync
else
  echo "== not imaging (--no-image, or the card does not fit in the free space)"
fi

mkdir -p "$out/mnt"

# Every partition that looks like a filesystem, mounted read-only.
i=0
for p in "/dev/$dev"?*; do
  [ -b "$p" ] || continue
  fs=$(blkid -o value -s TYPE "$p" 2>/dev/null) || continue
  [ -n "$fs" ] || continue
  i=$((i+1))
  mp="$out/mnt/$i-$(basename "$p")"
  mkdir -p "$mp"
  if mount -o ro,noload "$p" "$mp" 2>/dev/null || mount -o ro "$p" "$mp" 2>/dev/null; then
    echo "== mounted $p ($fs) at $mp"
  else
    echo "== could not mount $p ($fs)"
    rmdir "$mp" 2>/dev/null
  fi
done

echo "== contents"
for mp in "$out"/mnt/*; do
  [ -d "$mp" ] || continue
  echo "-- $mp"
  ls "$mp" | head -20
  [ -f "$mp/etc/os-release" ] && sed -n '1,4p' "$mp/etc/os-release"
  [ -f "$mp/etc/hostname" ] && echo "hostname: $(cat "$mp/etc/hostname")"
done

echo "== saving the interesting trees read-only"
for mp in "$out"/mnt/*; do
  [ -d "$mp" ] || continue
  keep=""
  for d in etc home root boot opt srv var/log usr/local; do
    [ -e "$mp/$d" ] && keep="$keep $d"
  done
  [ -n "$keep" ] || continue
  name=$(basename "$mp")
  tar --numeric-owner --one-file-system -C "$mp" -cf - $keep 2>/dev/null \
    | zstd -T0 -3 -q -o "$out/$name.tar.zst" || echo "  (tar of $name had errors)"
  echo "  $name.tar.zst $(( $(stat -c %s "$out/$name.tar.zst" 2>/dev/null || echo 0) / 1024 / 1024 )) MiB"
done

echo "== unmounting"
for mp in "$out"/mnt/*; do [ -d "$mp" ] && umount "$mp" 2>/dev/null; done
sync

echo "== done"
du -sh "$out"/* 2>/dev/null