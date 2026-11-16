# sensr-trial-health: the self-health gate of a trial boot
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
#   sensr-trial-health run       the gate (sensr-trial-health.service)
#   sensr-trial-health confirm   keep this trial: no more checks, no timer
#   sensr-trial-health status    what the gate saw last
set -u
SEED=@seedDir@
ENV=$SEED/trial-health.env
STATE=/run/sensr-trial
REBOOT=${SENSR_TRIAL_REBOOT:-systemctl reboot}

log() { echo "sensr-trial-health: $*"; }

is_trial() { grep -qw sensr.trial=1 "${SENSR_TRIAL_CMDLINE:-/proc/cmdline}"; }

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

confirm() {
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
  run) run ;;
  confirm) confirm ;;
  stream) stream ;;
  status)
    cat "$STATE/health" 2>/dev/null || echo "no health result yet"
    if [ -e "$STATE/confirmed" ]; then echo confirmed; fi ;;
  *) echo "usage: sensr-trial-health run|confirm|stream|status" >&2; exit 2 ;;
esac
