#!/usr/bin/env bash
# Tests for nix/pi5/install-boot.sh without Nix or a Pi: renders the script's
# @placeholders@ and runs it against temporary FAT-partition directories.
#
#   bash nix/pi5/install-boot-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

boot_files=$work/boot-files
mkdir -p "$boot_files/overlays"
echo dtb > "$boot_files/bcm2712-rpi-5-b.dtb"
echo dtbo > "$boot_files/overlays/bcm2712d0.dtbo"

# One fake NixOS toplevel per generation name.
toplevel() {
  local t=$work/store/$1-nixos-system
  if [ ! -d "$t" ]; then
    mkdir -p "$t"
    echo "kernel $1" > "$t/kernel"
    echo "initrd $1" > "$t/initrd"
    echo "loglevel=4" > "$t/kernel-params"
    : > "$t/init"
  fi
  echo "$t"
}

# The script as Nix installs it, named like the real one.
bin=$work/bin/sensr-pi5-install-boot
mkdir -p "$(dirname "$bin")"
{
  echo '#!/usr/bin/env bash'
  sed -e "s#@bootFiles@#$boot_files#g" \
    -e 's#@extraCmdline@#console=ttyAMA10#g' \
    -e 's#@tryboot@#1#g' \
    -e 's#@watchdogTimeout@#300#g' \
    -e 's#@section@#pi5#g' \
    -e 's#@board@#Raspberry Pi 5#g' \
    "$here/install-boot.sh"
} > "$bin"
chmod +x "$bin"

fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; fails=$((fails + 1)); }
check() { # NAME COMMAND...
  local n=$1
  shift
  if "$@"; then pass "$n"; else fail "$n"; fi
}
fresh() {
  local d=$work/fat-$1
  rm -rf "$d"
  mkdir -p "$d"
  echo "$d"
}
run() { # DIR TOPLEVEL [ARGS...]: stdout+stderr in $work/out
  local d=$1 t=$2
  shift 2
  "$bin" "$t" --dir "$d" "$@" > "$work/out" 2>&1
}
prefix() { sed -n 's/^os_prefix=//p' "$1"; }

# 1. A new card: current/ and our config.txt, no trial.
d=$(fresh new)
run "$d" "$(toplevel a)"
check "new card: config.txt boots current/" test "$(prefix "$d/config.txt")" = current/
check "new card: current/ holds the generation" grep -q a-nixos-system "$d/current/system"
check "new card: no tryboot.txt" test ! -e "$d/tryboot.txt"

# 2. The next generation on that card: staged in next/ for a trial boot.
cp "$d/config.txt" "$work/config.before"
run "$d" "$(toplevel b)"
check "update: next/ holds the new generation" grep -q b-nixos-system "$d/next/system"
check "update: current/ still holds the old one" grep -q a-nixos-system "$d/current/system"
check "update: tryboot.txt boots next/" test "$(prefix "$d/tryboot.txt")" = next/
check "update: config.txt still boots current/" cmp -s "$d/config.txt" "$work/config.before"

# 3. A config.txt written by hand (pi5-1, Nov 2026: os_prefix=sensr-sd/, and a
#    stale trial slot in current/) is never rewritten.
d=$(fresh foreign)
mkdir -p "$d/current" "$d/sensr-sd"
echo /nix/store/stale-trial > "$d/current/system"
printf '# sensr booted from this SD card\n[all]\nos_prefix=sensr-sd/\n' > "$d/config.txt"
cp "$d/config.txt" "$work/config.before"
status=0
run "$d" "$(toplevel c)" || status=$?
check "foreign config.txt: the install succeeds" test "$status" = 0
check "foreign config.txt: left byte for byte" cmp -s "$d/config.txt" "$work/config.before"
check "foreign config.txt: a warning names what it boots" grep -q 'os_prefix=sensr-sd/' "$work/out"
check "foreign config.txt: the warning says how to adopt" grep -q -- '--adopt' "$work/out"
check "foreign config.txt: the generation is staged in next/" grep -q c-nixos-system "$d/next/system"

# 4. Our own file, edited by hand to boot another folder, is not ours any more.
d=$(fresh edited)
run "$d" "$(toplevel a)"
sed 's#^os_prefix=current/#os_prefix=rescue/#' "$d/config.txt" > "$d/config.txt.x"
mv "$d/config.txt.x" "$d/config.txt"
cp "$d/config.txt" "$work/config.before"
run "$d" "$(toplevel b)"
check "edited config.txt: left as it is" cmp -s "$d/config.txt" "$work/config.before"

# 5. A dormant trial card (sensr not committed) never becomes bootable here.
d=$(fresh dormant)
echo '# dormant' > "$d/config.txt.sensr-dormant"
run "$d" "$(toplevel a)"
check "dormant card: no config.txt is created" test ! -e "$d/config.txt"
check "dormant card: a warning says why" grep -q 'dormant trial card' "$work/out"
status=0
run "$d" "$(toplevel a)" --adopt || status=$?
check "dormant card: --adopt refuses" test "$status" = 2

# 6. --adopt takes over a foreign card: backup, current/, our config.txt.
d=$(fresh adopt)
mkdir -p "$d/current"
echo /nix/store/stale-trial > "$d/current/system"
printf '[all]\nos_prefix=sensr-sd/\n' > "$d/config.txt"
printf '# a tryboot.txt of the other OS\nos_prefix=other/\n' > "$d/tryboot.txt"
run "$d" "$(toplevel d)" --adopt
check "adopt: config.txt boots current/" test "$(prefix "$d/config.txt")" = current/
check "adopt: current/ holds the generation" grep -q d-nixos-system "$d/current/system"
check "adopt: the old config.txt is kept" grep -lq 'os_prefix=sensr-sd/' "$d"/config.txt.pre-adopt-*
check "adopt: a tryboot.txt that is not ours stays" grep -q 'os_prefix=other/' "$d/tryboot.txt"
run "$d" "$(toplevel e)"
check "adopt: later updates are staged in next/" grep -q e-nixos-system "$d/next/system"
check "adopt: config.txt still boots current/ after them" test "$(prefix "$d/config.txt")" = current/
check "adopt: the other OS's tryboot.txt is still untouched" test "$(prefix "$d/tryboot.txt")" = other/
status=0
run "$d" "$(toplevel e)" --adopt --slot next || status=$?
check "adopt: --slot next is refused" test "$status" = 2

if [ "$fails" -gt 0 ]; then
  echo "$fails failed" >&2
  exit 1
fi
echo "all passed"
