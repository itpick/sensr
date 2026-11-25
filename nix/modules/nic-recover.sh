# sensr-nic-recover: one tick of the Ethernet adapter watchdog
# (sensr-nic-recover.service runs one every 5 s). Prevents and cures the wedges seen
# on the Pi 5 router:
#
# - USB adapters (r8152) that wedge after an xHCI reset: the netdev stays in
#   /sys/class/net but every ioctl answers ENODEV, so neither a config apply
#   nor a link bounce revives it. Re-authorising the USB device makes it
#   re-enumerate; the pinned name comes back and networkd re-applies it.
# - The Pi 5's built-in port (RP1 macb), whose transmit queue stalls
#   ("NETDEV WATCHDOG: transmit queue 0 timed out"). Most stalls clear in
#   ~5 s; on 2026-11-23 one did not, and the WAN stayed down until a power
#   cycle. A stall that outlasts two ticks bounces the link; another one
#   within 15 minutes rebinds the macb driver.
#
# @ethtool@, @ip@ and @systemctl@ are store paths (nix/modules/sensr.nix).
# SENSR_NIC_SYS and SENSR_NIC_STATE move /sys and the state directory for
# nix/modules/nic-recover-test.sh.
set -u
ethtool=@ethtool@
ip=@ip@
systemctl=@systemctl@
sys=${SENSR_NIC_SYS:-/sys}
state=${SENSR_NIC_STATE:-/run/sensr/nic-recover}
# Seconds between two macb recoveries, and the window in which a second
# stall goes straight to a driver rebind.
macb_cooldown=${SENSR_NIC_MACB_COOLDOWN:-120}
macb_hard_window=${SENSR_NIC_MACB_HARD_WINDOW:-900}
settle=${SENSR_NIC_SETTLE:-2}

log() { echo "sensr-nic-recover: $*"; }
mkdir -p "$state"

# Kea's per-subnet sockets remember the interface index they were bound to
# (SO_BINDTODEVICE). A re-enumerated NIC keeps its pinned name but gets a new
# index, so such a socket stays listed by `ss` while the kernel no longer
# delivers to it: the link looks perfect and no DHCP client gets a lease.
rebind_dhcp() {
  log "$1 re-enumerated; restarting sensr-kea-dhcp4 to rebind its sockets"
  "$systemctl" restart sensr-kea-dhcp4.service ||
    log "WARNING: sensr-kea-dhcp4 restart failed"
}

# The netdev name under DEVICE_PATH (its net/ directory), waiting up to 30 s.
wait_netdev() {
  local n
  for _ in $(seq 1 30); do
    sleep 1
    for n in "$1"/net/*; do
      [ -e "$n" ] && { basename "$n"; return 0; }
    done
  done
  return 1
}

# ---- Pi 5 built-in port (macb) --------------------------------------------
macb_tick() { # NAME DEVICE_PATH
  local name=$1 path=$2 rx total f st prev streak last last_hard now dev drv new
  # The 512-slot RX ring overflowed under load (rx_resource_errors); the
  # setting resets with the driver, so it is re-checked every tick. (EEE is
  # not tunable here: ethtool --show-eee answers "Operation not supported".)
  rx=$("$ethtool" -g "$name" 2>/dev/null |
    sed -n '/^Current/,$ s/^RX:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' | head -n1)
  if [ -n "$rx" ] && [ "$rx" -lt 2048 ]; then
    "$ethtool" -G "$name" rx 2048 2>/dev/null && log "$name (macb): RX ring $rx -> 2048"
  fi

  # The kernel counts every transmit watchdog timeout per queue (one per
  # ~5 s of stall). A count that rose since the last tick, twice in a row,
  # is a stall of about 10 s or more: longer than the ~5 s ones that clear
  # by themselves.
  total=0
  for f in "$sys/class/net/$name"/queues/tx-*/tx_timeout; do
    [ -r "$f" ] && total=$((total + $(cat "$f")))
  done
  st=$state/macb.$name
  if ! { [ -r "$st" ] && read -r prev streak last last_hard < "$st"; }; then
    prev=$total streak=0 last=0 last_hard=0
  fi
  if [ "$total" -gt "$prev" ]; then
    streak=$((streak + 1))
  else
    streak=0
  fi
  now=$(date +%s)
  if [ "$streak" -ge 2 ] && [ $((now - last)) -ge "$macb_cooldown" ]; then
    if [ "$last" -gt 0 ] && [ $((now - last)) -lt "$macb_hard_window" ]; then
      dev=$(basename "$path")
      drv=$sys/bus/platform/drivers/macb
      log "$name (macb) is still stalling after a link bounce (tx_timeout $total); rebinding the driver ($dev)"
      echo "$dev" > "$drv/unbind" 2>/dev/null || log "WARNING: cannot unbind $dev"
      sleep "$settle"
      echo "$dev" > "$drv/bind" 2>/dev/null || log "WARNING: cannot bind $dev"
      if new=$(wait_netdev "$path"); then
        "$ip" link set dev "$new" up 2>/dev/null
        log "$name came back as $new and is up"
        rebind_dhcp "$name"
      else
        log "WARNING: $name did not come back after the rebind"
      fi
      last_hard=$now
      # a new netdev starts its counters at 0
      total=0
    else
      log "$name (macb): transmit queue stalled (tx_timeout $prev -> $total); bouncing the link"
      "$ip" link set dev "$name" down 2>/dev/null
      sleep "$settle"
      "$ip" link set dev "$name" up 2>/dev/null
    fi
    last=$now
    streak=0
  fi
  echo "$total $streak $last $last_hard" > "$st"
}

# ---- USB adapters -----------------------------------------------------------
usb_tick() { # NAME DEVICE_PATH
  local name=$1 path=$2 usb control bus lpm idxf idx authorized stamp now new n
  usb=$(basename "$(dirname "$path")")
  # Prevention, before the cure: USB autosuspend and EEE are the states the
  # r8152 resets out of. Both are cheap, idempotent and must be re-applied
  # after a re-enumeration, which starts the device in 'auto' again.
  control=$sys/bus/usb/devices/$usb/power/control
  if [ -e "$control" ] && [ "$(cat "$control" 2>/dev/null)" != on ]; then
    echo on > "$control" 2>/dev/null && log "$name ($usb): USB autosuspend off"
  fi
  # U1/U2 link states are the xHCI side of the same problem; the per-port
  # knob is 0 (neither) on this kernel.
  bus=${usb%%-*}
  for lpm in "$sys"/bus/usb/devices/usb"$bus"/*/usb"$bus"-port*/usb3_lpm_permit; do
    [ -e "$lpm" ] || continue
    if [ "$(cat "$lpm" 2>/dev/null)" != 0 ]; then
      echo 0 > "$lpm" 2>/dev/null && log "$name ($usb): USB3 LPM off"
    fi
  done
  if "$ethtool" --show-eee "$name" 2>/dev/null | grep -q 'EEE status: enabled'; then
    "$ethtool" --set-eee "$name" eee off 2>/dev/null && log "$name: EEE off"
  fi
  idxf=$state/ifindex.$name
  idx=$(cat "$sys/class/net/$name/ifindex" 2>/dev/null)
  if [ -n "$idx" ]; then
    if [ -e "$idxf" ] && [ "$(cat "$idxf")" != "$idx" ]; then
      rebind_dhcp "$name"
    fi
    echo "$idx" > "$idxf"
  fi
  # ethtool works on a healthy link whether it is up or down; it is the
  # ioctl that answers ENODEV once the driver has lost the device.
  "$ethtool" "$name" >/dev/null 2>&1 && return 0
  authorized=$sys/bus/usb/devices/$usb/authorized
  [ -e "$authorized" ] || return 0
  stamp=$state/$usb
  now=$(date +%s)
  # One attempt every two minutes: re-enumeration is not free, and a port
  # that is simply unplugged must not be cycled forever.
  if [ -e "$stamp" ] && [ $((now - $(cat "$stamp"))) -lt 120 ]; then
    return 0
  fi
  echo "$now" > "$stamp"
  log "$name ($usb) is wedged (ethtool: ENODEV); re-enumerating the USB device"
  echo 0 > "$authorized"
  sleep "$settle"
  echo 1 > "$authorized"
  # Wait for it to come back, then make sure the link is up; networkd
  # applies the address configuration as soon as the netdev exists under
  # its pinned name.
  for _ in $(seq 1 30); do
    sleep 1
    new=
    for n in "$sys/bus/usb/devices/$usb"/*/net/*; do
      [ -e "$n" ] && { new=$(basename "$n"); break; }
    done
    [ -n "$new" ] || continue
    "$ip" link set dev "$new" up 2>/dev/null || continue
    log "$name came back as $new and is up"
    # Record the new index before restarting Kea, so the next tick does
    # not see a change and restart it a second time.
    cat "$sys/class/net/$new/ifindex" > "$idxf" 2>/dev/null || true
    rebind_dhcp "$name"
    break
  done
}

for devlink in "$sys"/class/net/*/device; do
  [ -e "$devlink" ] || continue
  name=$(basename "$(dirname "$devlink")")
  path=$(readlink -f "$devlink") || continue
  drv=$(basename "$(readlink -f "$path/driver" 2>/dev/null)" 2>/dev/null)
  if [ "$drv" = macb ]; then
    macb_tick "$name" "$path"
    continue
  fi
  # USB adapters only: the USB bus is in the resolved device path.
  case $path in */usb[0-9]*/*) usb_tick "$name" "$path" ;; esac
done
