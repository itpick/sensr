#!/usr/bin/env bash
# Write the sensr Pi 4 image to the card in this machine's reader.
# Run as root: sudo /home/lucaspick/write-pi4-card.sh [image]
#
# Destroys everything on the card. Refuses to write to anything that is not a
# removable 25-35 GB USB device, so the NVMe cannot be hit by a typo.
set -euo pipefail

img=${1:-/home/lucaspick/pi4-card.img}
[ -f "$img" ] || { echo "no image at $img" >&2; exit 1; }

# Candidates: USB disks that are not zero-sized (readers show an empty slot
# as one) and not an NVMe.
mapfile -t disks < <(lsblk -dn -b -o NAME,TYPE,TRAN,SIZE | awk '$2=="disk" && $3=="usb" && $4>1000000000 {print $1}')
if [ "${#disks[@]}" -ne 1 ]; then
  echo "expected exactly one USB disk, found: ${disks[*]:-none}" >&2
  lsblk -o NAME,SIZE,TYPE,TRAN,MODEL >&2
  exit 1
fi
dev=/dev/${disks[0]}
model=$(lsblk -dn -o MODEL "$dev" | xargs)
size=$(blockdev --getsize64 "$dev")

echo "target: $dev ($model, $((size/1024/1024/1024)) GiB)"
echo "image:  $img ($(( $(stat -c %s "$img") /1024/1024 )) MiB)"
# A "32 GB" card reports ~29.7 GiB. Anything between 24 and 40 GiB is a card of
# that class; anything smaller or larger is not the one we mean.
if [ "$size" -lt $((24 * 1024 * 1024 * 1024)) ] || [ "$size" -gt $((40 * 1024 * 1024 * 1024)) ]; then
  echo "refusing: $dev is not a 32 GB card (it is $((size/1024/1024/1024)) GiB)" >&2
  exit 1
fi
if [ "$size" -lt "$(stat -c %s "$img")" ]; then
  echo "refusing: the image does not fit on $dev" >&2
  exit 1
fi

# Anything mounted from the card has to go first.
for p in "$dev"?*; do
  [ -b "$p" ] || continue
  umount "$p" 2>/dev/null && echo "unmounted $p"
done

echo "writing (this takes a few minutes at ~30 MB/s)..."
dd if="$img" of="$dev" bs=4M conv=fsync status=progress
sync

# The first-boot seed: config.json (the running router's document), so the
# Pi 4 comes up as the same router. Read by sensr before networking starts.
seed=${2:-/home/lucaspick/pi4-seed}
if [ -d "$seed" ]; then
  blockdev --rereadpt "$dev" || true
  sleep 1
  mnt=$(mktemp -d)
  mount "${dev}1" "$mnt"
  mkdir -p "$mnt/sensr"
  cp -v "$seed"/* "$mnt/sensr/"
  sync
  umount "$mnt"
  rmdir "$mnt"
fi

echo "== written"
lsblk -o NAME,SIZE,FSTYPE,LABEL "$dev"
blkid "$dev"?* || true
echo "done: pull the card and put it in the Pi 4."