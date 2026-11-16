# sensr-bootlog STAGE: write what this boot looked like to the FAT partition,
# so a box that never reaches the network still leaves a post-mortem any
# laptop can read (06 §1 L4, vyos-pi PR #6). Keeps the last 10 boots.
#   @seedDir@/boot-log/<boot>-<stage>.txt
# Best effort: a diagnostic that fails half-way must still write what it
# has (writeShellApplication turns on errexit; switch it off).
set +e
set -u
stage=$1
logdir=@seedDir@/boot-log
mkdir -p "$logdir" || exit 0

# One counter per boot, shared by the stages of that boot.
id=$(cat /proc/sys/kernel/random/boot_id)
if [ -e /run/sensr-bootlog.n ]; then
  n=$(cat /run/sensr-bootlog.n)
else
  last=$(cat "$logdir/last" 2>/dev/null || echo 0)
  n=$((last + 1))
  echo "$n" > "$logdir/last"
  echo "$n" > /run/sensr-bootlog.n
fi
tryboot=$(od -An -tu4 --endian=big /proc/device-tree/chosen/bootloader/tryboot 2>/dev/null | tr -d ' ')

{
  echo "== sensr boot $n ($id), stage $stage, $(date -Is)"
  echo "== cmdline"; cat /proc/cmdline
  echo "== tryboot=${tryboot:-n/a} system=$(readlink -f /run/booted-system 2>/dev/null)"
  echo "== uname"; uname -a
  echo "== uptime"; cat /proc/uptime
  echo "== failed units"; systemctl --failed --no-legend --no-pager 2>&1
  echo "== block devices"; lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS 2>&1
  echo "== addresses"; ip -br addr 2>&1
  echo "== modules"; cut -d' ' -f1 /proc/modules | sort | tr '\n' ' '; echo
  echo "== journal"; journalctl -b --no-pager -o short-monotonic 2>&1 | tail -n 2000
} > "$logdir/$n-$stage.txt.tmp" 2>&1
mv "$logdir/$n-$stage.txt.tmp" "$logdir/$n-$stage.txt"

# Keep the last 10 boots.
for f in "$logdir"/*-*.txt; do
  b=${f##*/}; b=${b%%-*}
  if [ "$b" -le $((n - 10)) ] 2>/dev/null; then rm -f "$f"; fi
done
sync -f "$logdir/last"
