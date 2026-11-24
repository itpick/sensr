#!/usr/bin/env bash
# Tests for nix/modules/nic-recover.sh without a Pi: a fake /sys with a Pi 5
# built-in port (macb) and a USB adapter, and stub ethtool, ip and systemctl
# that record their calls.
#
#   bash nix/modules/nic-recover-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
calls=$work/calls

# ---- stubs ----
mkdir -p "$work/bin"
cat > "$work/bin/ethtool" <<STUB
#!/usr/bin/env bash
echo "ethtool \$*" >> "$calls"
case "\$1 \${2:-}" in
  "-g "*) printf 'Ring parameters for %s:\nPre-set maximums:\nRX:\t\t\t8192\nCurrent hardware settings:\nRX:\t\t\t%s\nTX:\t\t\t512\n' "\$2" "\$(cat "$work/rx")" ;;
  "--show-eee "*) echo "netlink error: Operation not supported" >&2; exit 1 ;;
  "-G "*) echo "\$4" > "$work/rx" ;;
  *) [ -e "$work/enodev.\$1" ] && { echo "Cannot get device settings: No such device" >&2; exit 1; } ;;
esac
exit 0
STUB
printf '#!/usr/bin/env bash\necho "ip $*" >> "%s"\n' "$calls" > "$work/bin/ip"
printf '#!/usr/bin/env bash\necho "systemctl $*" >> "%s"\n' "$calls" > "$work/bin/systemctl"
chmod +x "$work/bin"/*

script=$work/nic-recover
sed -e "s#@ethtool@#$work/bin/ethtool#" -e "s#@ip@#$work/bin/ip#" \
  -e "s#@systemctl@#$work/bin/systemctl#" "$here/nic-recover.sh" > "$script"

# ---- fake /sys ----
S=$work/sys
mk_sys() {
  rm -rf "$S" "$work/state"
  # Pi 5 built-in port
  local pdev=$S/devices/platform/axi/1f00100000.ethernet
  mkdir -p "$pdev/net/rp1eth0" "$S/bus/platform/drivers/macb" "$S/class/net/rp1eth0/queues/tx-0"
  : > "$S/bus/platform/drivers/macb/bind"
  : > "$S/bus/platform/drivers/macb/unbind"
  ln -s "$S/bus/platform/drivers/macb" "$pdev/driver"
  ln -s "$pdev" "$S/class/net/rp1eth0/device"
  echo 0 > "$S/class/net/rp1eth0/queues/tx-0/tx_timeout"
  # USB adapter on 4-1
  local udev=$S/devices/platform/axi/usb4/4-1/4-1:1.0
  mkdir -p "$udev/net/ue1" "$S/bus/usb/devices/4-1/power" "$S/bus/usb/drivers/r8152" "$S/class/net/ue1"
  ln -s "$S/bus/usb/drivers/r8152" "$udev/driver"
  ln -s "$udev" "$S/class/net/ue1/device"
  ln -s "$udev" "$S/bus/usb/devices/4-1/4-1:1.0"
  echo auto > "$S/bus/usb/devices/4-1/power/control"
  echo 1 > "$S/bus/usb/devices/4-1/authorized"
  echo 7 > "$S/class/net/ue1/ifindex"
  echo 512 > "$work/rx"
  rm -f "$work"/enodev.* "$calls"
  : > "$calls"
}
timeouts() { echo "$1" > "$S/class/net/rp1eth0/queues/tx-0/tx_timeout"; }
tick() {
  SENSR_NIC_SYS=$S SENSR_NIC_STATE=$work/state SENSR_NIC_SETTLE=0 \
    bash "$script" >> "$work/log" 2>&1
}

fails=0
check() { # NAME COMMAND...
  local n=$1
  shift
  if "$@"; then echo "ok   $n"; else echo "FAIL $n" >&2; fails=$((fails + 1)); fi
}
called() { grep -qx -- "$1" "$calls"; }
count() { grep -cx -- "$1" "$calls" || true; }

# 1. The RX ring is raised once, and the script needs no awk.
mk_sys
tick
check "macb: RX ring 512 -> 2048" called "ethtool -G rp1eth0 rx 2048"
: > "$calls"
tick
check "macb: a ring already at 2048 is left alone" test "$(count "ethtool -G rp1eth0 rx 2048")" = 0
check "the script calls no awk (it was missing on the router)" bash -c "! grep -qw awk '$here/nic-recover.sh'"

# 2. Short stalls (one tick of rising timeouts) are left to clear by themselves.
mk_sys
tick
timeouts 1; tick
timeouts 1; tick
timeouts 2; tick
check "macb: a stall that clears within a tick bounces nothing" test "$(count "ip link set dev rp1eth0 down")" = 0

# 3. A stall that outlasts two ticks bounces the link.
mk_sys
tick
timeouts 3; tick
timeouts 6; tick
check "macb: a lasting stall bounces the link (down)" called "ip link set dev rp1eth0 down"
check "macb: ... and up" called "ip link set dev rp1eth0 up"

# 4. Inside the cooldown nothing more happens.
: > "$calls"
timeouts 9; tick
timeouts 12; tick
check "macb: no second action inside the cooldown" test ! -s "$calls" -o "$(grep -c '^ip ' "$calls" || true)" = 0

# 5. Still stalling after the bounce (cooldown over, inside 15 min): rebind.
: > "$calls"
timeouts 15
SENSR_NIC_MACB_COOLDOWN=0 SENSR_NIC_SYS=$S SENSR_NIC_STATE=$work/state SENSR_NIC_SETTLE=0 bash "$script" >> "$work/log" 2>&1
timeouts 18
SENSR_NIC_MACB_COOLDOWN=0 SENSR_NIC_SYS=$S SENSR_NIC_STATE=$work/state SENSR_NIC_SETTLE=0 bash "$script" >> "$work/log" 2>&1
check "macb: a repeat stall unbinds the driver" grep -qx 1f00100000.ethernet "$S/bus/platform/drivers/macb/unbind"
check "macb: ... and binds it again" grep -qx 1f00100000.ethernet "$S/bus/platform/drivers/macb/bind"
check "macb: the port is brought up after the rebind" called "ip link set dev rp1eth0 up"
check "macb: the log says it rebinds" grep -q 'rebinding the driver' "$work/log"

# 6. A stall long after the last recovery starts again with a bounce.
mk_sys
tick
timeouts 1; tick
timeouts 2; tick
: > "$calls"
: > "$S/bus/platform/drivers/macb/unbind"
timeouts 3
SENSR_NIC_MACB_COOLDOWN=0 SENSR_NIC_MACB_HARD_WINDOW=0 SENSR_NIC_SYS=$S SENSR_NIC_STATE=$work/state SENSR_NIC_SETTLE=0 bash "$script" >> "$work/log" 2>&1
timeouts 4
SENSR_NIC_MACB_COOLDOWN=0 SENSR_NIC_MACB_HARD_WINDOW=0 SENSR_NIC_SYS=$S SENSR_NIC_STATE=$work/state SENSR_NIC_SETTLE=0 bash "$script" >> "$work/log" 2>&1
check "macb: outside the 15 min window it bounces again" called "ip link set dev rp1eth0 down"
check "macb: ... without a rebind" test ! -s "$S/bus/platform/drivers/macb/unbind"

# 7. USB adapter: prevention every tick, re-enumeration when wedged.
mk_sys
tick
check "usb: autosuspend off" grep -qx on "$S/bus/usb/devices/4-1/power/control"
check "usb: a healthy adapter is not re-enumerated" test "$(grep -c 'systemctl restart' "$calls" || true)" = 0
touch "$work/enodev.ue1"
tick
check "usb: a wedged adapter is re-enumerated (authorized back to 1)" grep -qx 1 "$S/bus/usb/devices/4-1/authorized"
check "usb: it is brought up again" called "ip link set dev ue1 up"
check "usb: Kea is restarted to rebind its sockets" called "systemctl restart sensr-kea-dhcp4.service"
: > "$calls"
tick
check "usb: no second re-enumeration inside two minutes" test "$(count "ip link set dev ue1 up")" = 0

if [ "$fails" -gt 0 ]; then
  echo "$fails failed" >&2
  exit 1
fi
echo "all passed"
