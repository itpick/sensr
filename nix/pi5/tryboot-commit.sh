# sensr-pi5-tryboot-commit: after a trial boot of next/ reached
# boot-complete.target, make it the default (current/), keeping the old one
# as previous/. Does nothing on a normal boot, or when the running system is
# not the one in next/.
set -euo pipefail
dir=/boot/firmware
flag=/proc/device-tree/chosen/bootloader/tryboot

# A big-endian u32: 1 when the firmware booted tryboot.txt.
tryboot=0
if [ -r "$flag" ]; then
  tryboot=$(od -An -tu4 --endian=big "$flag" | tr -d ' ')
fi
if [ "$tryboot" != 1 ]; then
  echo "not a trial boot"
  exit 0
fi
if [ ! -e "$dir/next/system" ]; then
  echo "trial boot, but no next/ slot (already committed?)"
  exit 0
fi
running=$(readlink -f /run/booted-system)
if [ "$running" != "$(cat "$dir/next/system")" ]; then
  echo "trial boot of $running, but next/ holds $(cat "$dir/next/system"); not committing"
  exit 0
fi
rm -rf "$dir/previous"
if [ -e "$dir/current" ]; then
  mv "$dir/current" "$dir/previous"
fi
mv "$dir/next" "$dir/current"
rm -f "$dir/tryboot.txt"
sync -f "$dir/current/system"
echo "committed $running: current/ boots by default now, the old one is in previous/"
