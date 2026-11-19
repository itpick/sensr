# sensr-trial-health: the hard deadline and the self-health gate of a trial
# boot
# (sensr-pi5-trial-install). Runs only when the kernel command line has
# sensr.trial=1 and the seed folder has trial-health.env. Every check in it
# must pass within TRIAL_GRACE_SECONDS of boot, and keep passing until
# someone confirms the trial (`sensr-trial-health confirm`, which also stops
# the trial timer); otherwise the box reboots, which on a trial boot means
# back to the previous OS.
#
# trial-health.env (shell variables; all optional, an empty file checks
# nothing and only keeps the timer):
#   TRIAL_GRACE_SECONDS=600    time from boot for all checks to pass
#   TRIAL_FAILS_TO_REBOOT=3    consecutive failed rounds, after passing once
#   WAN_IP=203.0.113.7         an address that must be on some interface
#   WAN_IF=end0                ...on this interface
#   DHCP_UNIT=sensr-kea-dhcp4  a unit that must be active and on UDP 67
#   DNS_SERVER=192.168.1.1     where DNS_CHECKS are asked
#   DNS_CHECKS="example.com host.lan=192.168.1.10"   name, or name=address
#   URL_CHECKS="https://example.com/"                any 2xx/3xx answer
#   LOG_UDP=192.168.1.20:5514  stream the journal there (one line per
#                              datagram; e.g. `nc -klu 5514` on a laptop)
#
#   sensr-trial-health detect    early in a trial boot (sensr-trial-detect):
#                                marks it (/run/sensr-trial/active) and, with
#                                sensr.trial.deadline=SECONDS on the kernel
#                                command line, has PID 1 reboot that long after
#                                boot whatever else happens (a transient timer:
#                                no agent, seed folder or network involved),
#                                and force the reboot 90 s later
#   sensr-trial-health run       the gate (sensr-trial-health.service)
#   sensr-trial-health revert    early in a trial boot: take this partition's
#                                config.txt away again (the trial was armed by
#                                copying config.txt.sensr-dormant over it), so
#                                every reset from now on boots the installed OS
#   sensr-trial-health confirm   keep this trial: no more checks, no timer
#   sensr-trial-health status    what the gate saw last
set -u
SEED=@seedDir@
ENV=$SEED/trial-health.env
STATE=/run/sensr-trial
REBOOT=${SENSR_TRIAL_REBOOT:-systemctl reboot}

log() { echo "sensr-trial-health: $*"; }

is_trial() { grep -qw sensr.trial=1 "${SENSR_TRIAL_CMDLINE:-/proc/cmdline}"; }

cmdline_deadline() {
  tr ' ' '\n' < "${SENSR_TRIAL_CMDLINE:-/proc/cmdline}" | sed -n 's/^sensr\.trial\.deadline=\([0-9][0-9]*\)$/\1/p' | tail -n1
}

detect() {
  is_trial || { log "not a trial boot"; exit 0; }
  mkdir -p "$STATE"
  touch "$STATE/active"
  local d
  d=$(cmdline_deadline)
  if [ -z "$d" ]; then log "trial boot without a deadline"; exit 0; fi
  echo "$d" > "$STATE/deadline"
  # Units of PID 1's own, written to /run: systemd-run would need D-Bus,
  # which does not run yet this early (and must not be waited for).
  local units=${SENSR_TRIAL_UNITDIR:-/run/systemd/system} name at cmd
  mkdir -p "$units"
  for name in sensr-trial-deadline sensr-trial-deadline-force; do
    if [ "$name" = sensr-trial-deadline ]; then at=$d cmd="systemctl reboot"
    else at=$((d + 90)) cmd="systemctl reboot --force --force"; fi
    printf '[Unit]\nDescription=Trial deadline (%s s after boot): back to the previous OS\nDefaultDependencies=no\n[Timer]\nOnBootSec=%ss\nAccuracySec=1s\n' "$at" "$at" > "$units/$name.timer"
    printf '[Unit]\nDescription=Trial deadline: reboot\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=%s %s\n' "$(command -v systemctl)" "${cmd#systemctl }" > "$units/$name.service"
  done
  systemctl daemon-reload
  systemctl start --no-block sensr-trial-deadline.timer sensr-trial-deadline-force.timer
  log "trial deadline armed: reboot ${d} s after boot (forced at $((d + 90)) s), whatever happens"
}

# One round of checks; prints a line per failure, returns non-zero on any.
round() {
  local bad=0 n want got
  if [ -n "${WAN_IP:-}" ]; then
    if ! ip -4 -o addr show ${WAN_IF:+dev "$WAN_IF"} | grep -q " $WAN_IP/"; then
      echo "wan: $WAN_IP is not on ${WAN_IF:-any interface}"; bad=1
    fi
  fi
  if [ -n "${DHCP_UNIT:-}" ]; then
    if ! systemctl is-active -q "$DHCP_UNIT"; then
      echo "dhcp: $DHCP_UNIT is not active"; bad=1
    elif ! ss -Hlun 'sport = :67' | grep -q .; then
      echo "dhcp: nothing listens on UDP 67"; bad=1
    fi
  fi
  for n in ${DNS_CHECKS:-}; do
    want=
    case $n in *=*) want=${n#*=}; n=${n%%=*} ;; esac
    got=$(dig +short +time=3 +tries=2 ${DNS_SERVER:+@"$DNS_SERVER"} "$n" A 2>/dev/null | tr '\n' ' ')
    if [ -z "$got" ] || { [ -n "$want" ] && ! echo " $got" | grep -q " $want "; }; then
      echo "dns: $n -> ${got:-nothing}${want:+ (want $want)}"; bad=1
    fi
  done
  for n in ${URL_CHECKS:-}; do
    got=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$n" 2>/dev/null)
    case $got in 2??|3??) ;; *) echo "url: $n -> ${got:-no answer}"; bad=1 ;; esac
  done
  return $bad
}

uptime_s() { cut -d. -f1 /proc/uptime; }

run() {
  is_trial || { log "not a trial boot"; exit 0; }
  [ -r "$ENV" ] || { log "no $ENV: only the trial timer applies"; exit 0; }
  # shellcheck disable=SC1090
  . "$ENV"
  mkdir -p "$STATE"
  local grace=${TRIAL_GRACE_SECONDS:-600} limit=${TRIAL_FAILS_TO_REBOOT:-3}
  # A typo must not switch the gate off.
  case $grace in ''|*[!0-9]*) log "TRIAL_GRACE_SECONDS=$grace is not a number: using 600"; grace=600 ;; esac
  case $limit in ''|*[!0-9]*|0) log "TRIAL_FAILS_TO_REBOOT=$limit is not a positive number: using 3"; limit=3 ;; esac
  local passed=0 fails=0 out
  while :; do
    if [ -e "$STATE/confirmed" ]; then log "confirmed; the gate stops"; exit 0; fi
    if out=$(round); then
      [ "$passed" = 1 ] || log "all checks pass ($(uptime_s) s after boot); waiting for confirmation"
      passed=1 fails=0
      echo "ok $(date -Is)" > "$STATE/health"
    else
      printf 'failing %s\n%s\n' "$(date -Is)" "$out" > "$STATE/health"
      echo "$out" | while read -r l; do log "$l"; done
      if [ "$passed" = 0 ] && [ "$(uptime_s)" -ge "$grace" ]; then
        log "checks still failing ${grace} s after boot: rebooting to the previous OS"
        sync; $REBOOT; exit 1
      fi
      if [ "$passed" = 1 ]; then
        fails=$((fails + 1))
        if [ "$fails" -ge "$limit" ]; then
          log "checks failed $fails times in a row: rebooting to the previous OS"
          sync; $REBOOT; exit 1
        fi
      fi
    fi
    sleep "${SENSR_TRIAL_INTERVAL:-20}"
  done
}

# The trial installer's tryboot flag never reaches the kernel on every
# downstream kernel (VyOS does not pass the reboot reason on), so a trial on
# those is armed by copying the dormant config.txt.sensr-dormant over
# config.txt on the trial's own FAT partition. That makes the trial the
# default OS for every boot, not one. Count down seed/trial-boots-left here,
# at sysinit and before anything can hang, and take config.txt away when it
# runs out: the trial then gets its boots (the first one imports the seed and
# pins the NICs; the gates need one more) and every reset after that runs the
# installed OS, whether or not the gate ever gets to reboot. The image keeps
# config.txt.sensr-dormant next to it, so a committed install (where the
# dormant file is gone) is left alone.
is_our_config() { # FILE
  # The trial's own config, whether written by trial-install (the marker) or
  # by the same layout by hand (os_prefix=sensr-trial/, which no other OS uses).
  grep -q "^# sensr-pi5-trial-install" "$1" 2>/dev/null ||
    grep -q "^os_prefix=sensr-trial/" "$1" 2>/dev/null
}

config_backup() { # DIR -> the previous OS's config on that FAT, if any
  # Two layouts exist. When the trial's disk comes first in BOOT_ORDER, its
  # config.txt is renamed config.txt.sensr-dormant while the trial runs. When
  # the running OS's disk (NVMe here) comes first, the config it boots by is
  # kept as config.<name>.txt (config.vyos.txt, ...) and config.txt is the
  # trial's. Restore whichever is there; never our own.
  local dir=$1 f
  if [ -f "$dir/config.txt.sensr-dormant" ]; then
    echo "$dir/config.txt.sensr-dormant"
    return
  fi
  for f in "$dir"/config.*.txt; do
    [ -e "$f" ] || continue
    is_our_config "$f" && continue
    echo "$f"
    return
  done
}

revert() {
  is_trial || { log "not a trial boot"; exit 0; }
  local dev mnt left backup done=
  # This runs at sysinit, before udev has finished: give the disks' nodes a
  # moment rather than skip the revert on a boot that is merely fast.
  udevadm settle --timeout=15 2>/dev/null || true
  mnt=$(mktemp -d)
  # The boot partition can be the SD card's (FIRMWARE) or, on this board, the
  # NVMe's EFI partition: try every FAT rather than only the label the image
  # happens to use, or a trial armed on another one could never disarm itself.
  for dev in $(blkid -c /dev/null -t TYPE=vfat -o device 2>/dev/null); do
    [ -f "$mnt/config.txt" ] && umount "$mnt" 2>/dev/null
    if ! mount -o rw "$dev" "$mnt" 2>/dev/null; then
      log "cannot mount $dev: leaving its boot config alone"
      continue
    fi
    if [ ! -f "$mnt/config.txt" ] || ! is_our_config "$mnt/config.txt"; then
      umount "$mnt"
      continue
    fi
    backup=$(config_backup "$mnt")
    if [ -z "$backup" ]; then
      log "$dev has the trial's config but no previous one: leaving it"
      umount "$mnt"
      continue
    fi
    left=2
    if [ -r "$mnt/sensr/trial-boots-left" ]; then
      read -r left < "$mnt/sensr/trial-boots-left" || true
    fi
    case $left in ''|*[!0-9]*) left=2 ;; esac
    left=$((left - 1))
    if [ "$left" -gt 0 ]; then
      echo "$left" > "$mnt/sensr/trial-boots-left"
      log "$left more trial boot(s) allowed"
    else
      cp -f "$backup" "$mnt/config.txt.new"
      mv -f "$mnt/config.txt.new" "$mnt/config.txt"
      rm -f "$mnt/sensr/trial-boots-left"
      log "restored $dev/config.txt from $(basename "$backup"): the next reset boots the installed OS"
    fi
    sync
    umount "$mnt"
    done=1
    break
  done
  rmdir "$mnt" 2>/dev/null || true
  [ -n "$done" ] || log "no FAT with the trial's config.txt: leaving the boot config alone"
}

confirm() {
  if [ -e "$STATE/deadline" ]; then
    log "this trial has a hard deadline ($(cat "$STATE/deadline") s after boot) and is measure-only: nothing to confirm"
    exit 1
  fi
  mkdir -p "$STATE"
  touch "$STATE/confirmed"
  rm -f "$SEED/reboot-after-minutes"
  sync
  log "trial confirmed: no health reboots, no trial timer (this boot; the next reset still returns to the previous OS until it is committed)"
}

# The journal, one line per datagram, to LOG_UDP (bash's /dev/udp: no
# extra tools on the box, nothing to install on the receiver but nc).
stream() {
  is_trial || exit 0
  [ -r "$ENV" ] || exit 0
  # shellcheck disable=SC1090
  . "$ENV"
  [ -n "${LOG_UDP:-}" ] || exit 0
  local host=${LOG_UDP%:*} port=${LOG_UDP##*:} line
  log "streaming the journal to $host:$port (udp)"
  journalctl -b -f -n all -o short-iso --no-pager | while IFS= read -r line; do
    printf '%s %s\n' "$(hostname)" "$line" > "/dev/udp/$host/$port" 2>/dev/null || true
  done
}

case ${1:-run} in
  detect) detect ;;
  run) run ;;
  revert) revert ;;
  confirm) confirm ;;
  stream) stream ;;
  status)
    cat "$STATE/health" 2>/dev/null || echo "no health result yet"
    if [ -e "$STATE/confirmed" ]; then echo confirmed; fi ;;
  *) echo "usage: sensr-trial-health detect|run|revert|confirm|stream|status" >&2; exit 2 ;;
esac
