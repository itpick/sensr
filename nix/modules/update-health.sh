# sensr-update-health: is the router still doing its job after an update?
# (nix/modules/updates.nix; docs/research/04a §5.2, ISS-C-005)
#
#   sensr-update-health baseline
#       One pass of every check, before the switch, as JSON on stdout:
#       {"checks": {"<name>": true|false}, "failed_units": [...]}
#   sensr-update-health gate [--baseline FILE] [--timeout S] [--interval S]
#       After the switch: run the required checks every S seconds until
#       they all pass twice in a row, or the timeout. JSON on stdout:
#       {"result": "pass"|"fail", "failed": [...], "reasons": {...},
#        "skipped": [...], "warnings": [...], "seconds": N}
#       Exit 0 on pass, 1 on fail.
#
# The checks (their names are what status.json and the Updates page show):
#   agent        sensr-agent is active, answers `sensr status` on its socket,
#                and its boot apply was not rejected
#   agent-clean  the boot apply held nothing back (no last_apply_error)
#   dns          sensr-unbound answers `localhost A` on its own listener (a
#                record it serves itself: no internet involved)
#   dhcp         sensr-kea-dhcp4 is active, its control socket answers and
#                its sockets are ready on every interface the config lists
#   api          sensr-api answers HTTPS (or HTTP) on loopback
#   route        there is an IPv4 default route
#   gateway      the default route's gateway answers ping
#   units        no sensr-* unit has failed (other than those that had
#                already failed before the switch)
# Soft, logged but never a reason to roll back: internet (a public address
# answers ping); the ISP may simply be down.
#
# The baseline: a check that already failed before the switch is not held
# against the new generation. A WAN gateway that drops ping, DHCP switched
# off, an agent already degraded by a bad config: those are the box's state,
# not the update's doing, and rolling back would not fix them. With no
# baseline every check is required.
#
# Passing twice, one interval apart, keeps a daemon that starts and then
# crashes a few seconds later from passing the gate.
set -euo pipefail

# Set by the module: the address sensr-api was told to listen on
# (services.sensr.api.listen), empty when it follows system.webgui.
api_listen=@apiListen@

CHECKS=(agent agent-clean dns dhcp api route gateway units)

why=""
agent_json=""
baseline_units=()
selftest_retried=0

log() { echo "sensr-update-health: $*" >&2; }

unit_state() { systemctl is-active "$1" 2>/dev/null || true; }

# in_list NEEDLE ITEM...: no pipe into `grep -q`, which under pipefail can
# fail the writer with SIGPIPE.
in_list() {
  local n=$1 x
  shift
  for x in "$@"; do
    [ "$x" = "$n" ] && return 0
  done
  return 1
}

check_agent() {
  agent_json=""
  if [ "$(unit_state sensr-agent.service)" != active ]; then
    why="sensr-agent is $(unit_state sensr-agent.service)"
    return 1
  fi
  local st
  if ! st=$(timeout 10 sensr status --json 2>/dev/null) || ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$st"; then
    why="sensr-agent does not answer on its socket"
    return 1
  fi
  agent_json=$st
  local err
  err=$(jq -r '.last_apply_error // ""' <<<"$st")
  if ! jq -e '.applied != null' >/dev/null <<<"$st"; then
    why="the agent has applied no revision (boot apply rejected): ${err:-no detail}"
    return 1
  fi
  # A degraded boot apply (some daemons held back, the rest up) is judged by
  # agent-clean; anything else in last_apply_error means the apply itself
  # was rejected.
  case "$err" in
    "" | *"applied at startup without part of its configuration"*) return 0 ;;
    *)
      why="the agent's boot apply was rejected: $err"
      return 1
      ;;
  esac
}

check_agent_clean() {
  if [ -z "$agent_json" ]; then
    check_agent || return 1
  fi
  local err
  err=$(jq -r '.last_apply_error // ""' <<<"$agent_json")
  if [ -n "$err" ]; then
    why=$err
    return 1
  fi
}

check_dns() {
  local conf=/run/sensr/unbound/unbound.conf
  if [ ! -e "$conf" ]; then
    why="no unbound.conf: the agent did not render DNS"
    return 1
  fi
  if [ "$(unit_state sensr-unbound.service)" != active ]; then
    why="sensr-unbound is $(unit_state sensr-unbound.service)"
    return 1
  fi
  local port addr addrs ans
  port=$(awk '$1 == "port:" { print $2; exit }' "$conf")
  port=${port:-53}
  # Ask on loopback when Unbound listens there or everywhere, else on the
  # first address it binds (an `addr@port` entry keeps only the address).
  addrs=$(awk '$1 == "interface:" { print $2 }' "$conf")
  addr=""
  if [ -z "$addrs" ] || grep -qxE '0\.0\.0\.0|127\.0\.0\.1' <<<"$addrs"; then
    addr=127.0.0.1
  elif grep -qxE '::|::1' <<<"$addrs"; then
    addr=::1
  else
    addr=$(head -n1 <<<"$addrs")
    addr=${addr%@*}
  fi
  ans=$(dig +short +time=2 +tries=1 -p "$port" "@$addr" localhost A 2>/dev/null || true)
  if ! grep -qx '127\.0\.0\.1' <<<"$ans"; then
    why="unbound did not answer localhost A on $addr port $port (got: ${ans:-nothing})"
    return 1
  fi
}

check_dhcp() {
  local conf=/run/sensr/kea/kea-dhcp4.conf
  if [ ! -e "$conf" ]; then
    why="no kea-dhcp4.conf: the agent did not render DHCP"
    return 1
  fi
  if [ "$(unit_state sensr-kea-dhcp4.service)" != active ]; then
    why="sensr-kea-dhcp4 is $(unit_state sensr-kea-dhcp4.service)"
    return 1
  fi
  local sock resp sockets ifaces i missing=""
  sock=$(jq -r '.Dhcp4["control-socket"]["socket-name"] // .Dhcp4["control-sockets"][0]["socket-name"] // "/run/kea/kea4-ctrl-socket"' "$conf")
  resp=$(printf '{"command": "status-get"}' | timeout 10 socat -t 5 - "UNIX-CONNECT:$sock" 2>/dev/null || true)
  if ! jq -e 'type == "object" or type == "array"' >/dev/null 2>&1 <<<"$resp"; then
    why="Kea does not answer on its control socket $sock"
    return 1
  fi
  # Kea answers the socket state of its interfaces: ready, retrying (some
  # interface could not be bound yet) or failed.
  sockets=$(jq -r 'if type == "array" then .[0] else . end | .arguments.sockets.status // "unknown"' <<<"$resp")
  case "$sockets" in
    ready | unknown) ;;
    *)
      why="Kea's sockets are $sockets: $(jq -r 'if type == "array" then .[0] else . end | (.arguments.sockets.errors // []) | join("; ")' <<<"$resp")"
      return 1
      ;;
  esac
  # Every interface Kea is configured for must exist with an IPv4 address,
  # and (if this Kea does not report socket state) have something on UDP 67.
  mapfile -t ifaces < <(jq -r '.Dhcp4["interfaces-config"].interfaces[]? | split("/")[0]' "$conf")
  for i in "${ifaces[@]}"; do
    [ "$i" = "*" ] && continue
    if [ -z "$(ip -4 -o addr show dev "$i" 2>/dev/null)" ]; then
      missing="$missing $i (no IPv4 address)"
    elif [ "$sockets" = unknown ] && [ -z "$(ss -Hlun 'sport = :67' 2>/dev/null)" ]; then
      missing="$missing $i (nothing on UDP 67)"
    fi
  done
  if [ -n "$missing" ]; then
    why="DHCP is not serving on:$missing"
    return 1
  fi
}

check_api() {
  local targets=() t host port scheme code
  if [ -n "$api_listen" ]; then
    targets=("$api_listen")
  else
    mapfile -t targets < <(ss -Htlnp 2>/dev/null | awk '/"sensr-api"/ { print $4 }' | sort -u)
  fi
  if [ "${#targets[@]}" = 0 ]; then
    why="sensr-api is not listening"
    return 1
  fi
  for t in "${targets[@]}"; do
    port=${t##*:}
    host=${t%:*}
    # A listener bound to a device (0.0.0.0%lan) has a loopback twin (the
    # API always binds lo as well); ask there.
    host=${host%%\%*}
    case "$host" in
      "" | "*" | 0.0.0.0) host=127.0.0.1 ;;
      "[::]") host="[::1]" ;;
    esac
    for scheme in https http; do
      code=$(curl -ks -o /dev/null -w '%{http_code}' --max-time 5 "$scheme://$host:$port/healthz" 2>/dev/null || true)
      if [ -n "$code" ] && [ "$code" != 000 ]; then
        return 0
      fi
    done
  done
  why="sensr-api does not answer on ${targets[*]}"
  return 1
}

default_route() { ip -4 route show default 2>/dev/null | head -n1; }

check_route() {
  if [ -z "$(default_route)" ]; then
    why="no IPv4 default route"
    return 1
  fi
}

check_gateway() {
  local r gw dev
  r=$(default_route)
  if [ -z "$r" ]; then
    why="no IPv4 default route"
    return 1
  fi
  gw=$(awk '{ for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit } }' <<<"$r")
  dev=$(awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }' <<<"$r")
  # A point-to-point WAN (PPPoE, a tunnel) has no gateway address to ask.
  [ -n "$gw" ] || return 0
  if ! ping -n -c 1 -W 2 ${dev:+-I "$dev"} "$gw" >/dev/null 2>&1; then
    why="the WAN gateway $gw${dev:+ on $dev} does not answer ping"
    return 1
  fi
}

failed_units() {
  systemctl list-units --failed --plain --no-legend 'sensr-*' 2>/dev/null |
    awk '{ print $1 }' |
    grep -v '^sensr-update' || true
}

check_units() {
  local u new=() f
  mapfile -t f < <(failed_units)
  # The boot selftest runs alongside the agent's restart in a switch and can
  # lose that race (2026-11-23: a false "switch failed"). It is a check, not
  # a daemon: run it once more before holding it against the update.
  if [ "$selftest_retried" = 0 ] && in_list sensr-selftest.service "${f[@]}"; then
    selftest_retried=1
    log "sensr-selftest failed during the switch; running it once more"
    systemctl restart sensr-selftest.service >/dev/null 2>&1 || true
    mapfile -t f < <(failed_units)
  fi
  for u in "${f[@]}"; do
    [ -n "$u" ] || continue
    if ! in_list "$u" "${baseline_units[@]}"; then
      new+=("$u")
    fi
  done
  if [ "${#new[@]}" -gt 0 ]; then
    why="failed: ${new[*]}"
    return 1
  fi
}

check_internet() {
  local a
  for a in 1.1.1.1 9.9.9.9; do
    if ping -n -c 1 -W 3 "$a" >/dev/null 2>&1; then
      return 0
    fi
  done
  why="neither 1.1.1.1 nor 9.9.9.9 answers ping"
  return 1
}

run_check() {
  why=""
  "check_${1//-/_}"
}

baseline() {
  local c checks='{}' units ok
  agent_json=""
  for c in "${CHECKS[@]}"; do
    if [ "$c" = units ]; then
      continue
    fi
    if run_check "$c"; then
      ok=true
    else
      ok=false
      log "before the switch: $c fails ($why); it will not be required afterwards"
    fi
    checks=$(jq -c --arg k "$c" --argjson v "$ok" '.[$k] = $v' <<<"$checks")
  done
  checks=$(jq -c '.units = true' <<<"$checks")
  units=$(failed_units | jq -R . | jq -sc 'map(select(. != ""))')
  jq -n --argjson checks "$checks" --argjson units "$units" \
    '{checks: $checks, failed_units: $units}'
}

gate() {
  local base="" timeout=120 interval=5
  while [ $# -gt 0 ]; do
    case "$1" in
      --baseline) base=$2; shift 2 ;;
      --timeout) timeout=$2; shift 2 ;;
      --interval) interval=$2; shift 2 ;;
      *) echo "sensr-update-health gate: unknown argument $1" >&2; exit 2 ;;
    esac
  done
  local required=() skipped=() c
  for c in "${CHECKS[@]}"; do
    if [ -n "$base" ] && [ -r "$base" ] &&
       [ "$(jq -r --arg k "$c" '.checks[$k] // true' "$base" 2>/dev/null || echo true)" = false ]; then
      skipped+=("$c")
    else
      required+=("$c")
    fi
  done
  if [ -n "$base" ] && [ -r "$base" ]; then
    mapfile -t baseline_units < <(jq -r '.failed_units[]?' "$base" 2>/dev/null || true)
  fi
  if [ "${#skipped[@]}" -gt 0 ]; then
    log "not required (already failing before the switch): ${skipped[*]}"
  fi

  local start=$SECONDS streak=0 failed=() reasons='{}'
  while :; do
    failed=()
    reasons='{}'
    agent_json=""
    for c in "${required[@]}"; do
      if ! run_check "$c"; then
        failed+=("$c")
        reasons=$(jq -c --arg k "$c" --arg v "$why" '.[$k] = $v' <<<"$reasons")
      fi
    done
    if [ "${#failed[@]}" = 0 ]; then
      streak=$((streak + 1))
      if [ "$streak" -ge 2 ]; then
        break
      fi
    else
      streak=0
      log "$((SECONDS - start)) s: failing: $(jq -r 'to_entries | map("\(.key): \(.value)") | join("; ")' <<<"$reasons")"
    fi
    if [ $((SECONDS - start)) -ge "$timeout" ]; then
      break
    fi
    sleep "$interval"
  done

  local warnings='[]'
  if ! run_check internet; then
    log "soft check: no internet ($why); not a reason to roll back"
    warnings=$(jq -c --arg v "internet: $why" '. + [$v]' <<<"$warnings")
  fi

  local result=pass
  if [ "${#failed[@]}" -gt 0 ]; then
    result=fail
    log "gate FAILED after $((SECONDS - start)) s: ${failed[*]}"
  else
    log "gate passed after $((SECONDS - start)) s"
  fi
  jq -n \
    --arg result "$result" \
    --argjson failed "$(printf '%s\n' "${failed[@]}" | jq -R . | jq -sc 'map(select(. != ""))')" \
    --argjson reasons "$reasons" \
    --argjson skipped "$(printf '%s\n' "${skipped[@]}" | jq -R . | jq -sc 'map(select(. != ""))')" \
    --argjson warnings "$warnings" \
    --argjson seconds "$((SECONDS - start))" \
    '{result: $result, failed: $failed, reasons: $reasons, skipped: $skipped, warnings: $warnings, seconds: $seconds}'
  [ "$result" = pass ]
}

case "${1:-}" in
  baseline) baseline ;;
  gate) shift; gate "$@" ;;
  *) echo "usage: sensr-update-health baseline | gate [--baseline FILE] [--timeout S] [--interval S]" >&2; exit 2 ;;
esac
