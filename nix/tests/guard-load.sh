#!/usr/bin/env bash
# The loader's live assertions, shared by nix/tests/guard-load.nix (x86_64
# VM) and manual runs on any BPF-LSM kernel (as root; needs curl, bpftool,
# mkfifo):
#
#   guard-load.sh <guard-load-probe> <pack dir> <reachable url> <programs>
#
# <reachable url> is an HTTP server that must stay reachable; 192.0.2.1:80
# is the address the test blocks (it should answer HTTP too, so the kill
# switch step can show the connection going through; set
# GUARD_BLOCKED_REACHABLE=0 if nothing listens there). <programs> is how
# many programs the pack must attach.
set -euo pipefail

probe=$1 pack=$2 ok_url=$3 programs=$4
blocked_url=http://192.0.2.1/
work=$(mktemp -d)
pid=
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT
mkfifo "$work/cmd" "$work/reply"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
ask() { echo "$1" > "$work/cmd"; cat "$work/reply"; }

"$probe" "$pack" "$work" > "$work/log" 2>&1 &
pid=$!
# The verifier walks ~180k instructions per program: seconds on KVM, minutes
# under emulation (GUARD_LOAD_TIMEOUT, in seconds).
timeout_s=${GUARD_LOAD_TIMEOUT:-600}
start=$SECONDS
while ! grep -q '^loaded' "$work/log"; do
  kill -0 "$pid" 2>/dev/null || { cat "$work/log"; fail "probe exited"; }
  [ $((SECONDS - start)) -lt "$timeout_s" ] || { cat "$work/log"; fail "probe did not load in $timeout_s s"; }
  sleep 0.5
done
echo "probe loaded in $((SECONDS - start)) s"

# 1. every program is attached
status=$(ask status)
echo "$status"
n=$(grep -c ' attached' <<<"$status" || true)
[ "$n" -eq "$programs" ] || fail "$n of $programs programs attached"
if grep -q ' detached' <<<"$status"; then fail "a program is detached"; fi
pass "all $programs programs attached"
loaded_progs=$(bpftool prog show | grep -c 'name guard_' || true)
[ "$loaded_progs" -eq "$programs" ] || fail "bpftool shows $loaded_progs guard programs"
pass "bpftool shows the $programs guard programs"

# curl <url>, returning "ok", "eperm" or "other: <why>". curl does not
# print errno, so when it fails, bash's /dev/tcp (another process, which
# does) connects to the same host and port to tell EPERM from the rest.
try() {
  local url=$1 hostport host port err
  if curl -s --max-time 5 -o /dev/null "$url"; then
    echo ok
    return
  fi
  hostport=${url#http://}; hostport=${hostport%%/*}
  host=${hostport%%:*}; port=80
  [ "$host" = "$hostport" ] || port=${hostport##*:}
  err=$(timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>&1 || true)
  if grep -qi 'not permitted' <<<"$err"; then
    echo eperm
  else
    echo "other: curl failed; /dev/tcp: ${err:-connected}"
  fi
}

rules() { # <file> <json>
  printf '%s\n' "$2" > "$1"
}
block='{"id": "t-block", "enabled": true, "hook": "connect",
  "target": {"net": {"cidr": "192.0.2.1/32", "ports": [80]}}, "action": "block"}'
alert='{"id": "t-alert", "enabled": true, "hook": "connect",
  "target": {"net": {"cidr": "198.51.100.0/24"}}, "action": "alert"}'

# 2. a block rule on 192.0.2.1/32 port 80
rules "$work/r1.json" "[$block]"
[ "$(ask "apply $work/r1.json 0")" = ok ] || fail "apply r1"
r=$(try "$blocked_url"); [ "$r" = eperm ] || fail "blocked curl: $r"
pass "curl 192.0.2.1 fails with EPERM"
r=$(try "$ok_url"); [ "$r" = ok ] || fail "reachable curl: $r"
pass "curl $ok_url works"
hits=$(ask hits); echo "$hits"
grep -Eq '^t-block [1-9]' <<<"$hits" || fail "no hits for t-block"
pass "t-block has hits"
events=$(ask events); echo "$events"
grep -q 'rule=0 hook=1 blocked=1 port=80' <<<"$events" || fail "no blocked event"
pass "blocked event in the ring buffer"

# 3. the rule moves to slot 1: its old count does not follow the slot
rules "$work/r2.json" "[$alert, $block]"
[ "$(ask "apply $work/r2.json 0")" = ok ] || fail "apply r2"
hits=$(ask hits); echo "$hits"
grep -q '^t-block 0$' <<<"$hits" || fail "t-block's hits not reset after moving"
grep -q '^t-alert 0$' <<<"$hits" || fail "t-alert inherited slot 0's hits"
r=$(try "$blocked_url"); [ "$r" = eperm ] || fail "blocked curl after move: $r"
hits=$(ask hits); echo "$hits"
grep -Eq '^t-block [1-9]' <<<"$hits" || fail "t-block not counted in its new slot"
grep -q '^t-alert 0$' <<<"$hits" || fail "t-alert counted a block"
ask events > /dev/null
pass "hits stay attributed by rule id"

# 4. the kill switch: nothing blocks
[ "$(ask "apply $work/r2.json 1")" = ok ] || fail "apply kill switch"
r=$(try "$blocked_url")
[ "$r" != eperm ] || fail "kill switch on, still EPERM"
if [ "${GUARD_BLOCKED_REACHABLE:-1}" = 1 ]; then
  [ "$r" = ok ] || fail "kill switch on, curl 192.0.2.1: $r"
fi
events=$(ask events); echo "$events"
grep -q 'rule=1 hook=1 blocked=0 port=80' <<<"$events" || fail "no unblocked event"
pass "kill switch: curl 192.0.2.1 is not EPERM ($r), still reported"

# 5. dropping Loaded detaches everything, with the probe still running
# (so it is Drop, not the process exit, that detaches). Sleepable programs
# may take a moment to go (RCU tasks trace), so the check retries for 2 s.
[ "$(ask drop)" = dropped ] || fail "drop"
kill -0 "$pid" 2>/dev/null || fail "probe exited on drop"
left=1
for _ in $(seq 20); do
  left=$(bpftool prog show | grep -c 'name guard_' || true)
  [ "$left" -eq 0 ] && break
  sleep 0.1
done
[ "$left" -eq 0 ] || { bpftool prog show | grep 'name guard_'; fail "$left guard programs left after drop"; }
kill -0 "$pid" 2>/dev/null || fail "probe gone before the check"
pass "after dropping Loaded (probe alive), bpftool shows no guard programs"
[ "$(ask quit)" = bye ] || fail "quit"
wait "$pid" || fail "probe exit status $?"
echo "guard-load: all checks passed"
