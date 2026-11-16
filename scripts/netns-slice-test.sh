#!/usr/bin/env bash
# Functional packet test of the M-slice ruleset (crates/sensr-rules/tests/golden/
# slice.nft.json) in unprivileged network namespaces: client (LAN) — router —
# server (WAN). Checks masquerade, default deny, a port forward, NAT reflection
# with hairpin SNAT and the anti-lockout rule with real packets.
#
# Run as an unprivileged user on a Linux host with user namespaces, with nft,
# ip, ping, nc (openbsd) and coreutils on PATH:
#   MOUNT=$(command -v mount) unshare -rnm --propagation private \
#     bash scripts/netns-slice-test.sh crates/sensr-rules/tests/golden/slice.nft.json
# It mounts a private tmpfs on /run, so every tool must resolve outside /run.
set -u
RULES=$1
${MOUNT:-mount} -t tmpfs tmpfs /run && mkdir -p /run/netns
ip netns add client; ip netns add server
ip link add eth1 type veth peer name c0 netns client
ip link add eth0 type veth peer name s0 netns server
ip link set lo up
ip addr add 192.168.1.1/24 dev eth1; ip link set eth1 up
ip addr add 203.0.113.2/24 dev eth0; ip link set eth0 up
ip -n client link set lo up; ip -n client addr add 192.168.1.100/24 dev c0; ip -n client addr add 192.168.1.10/24 dev c0
ip -n client link set c0 up; ip -n client route add default via 192.168.1.1
ip -n server link set lo up; ip -n server addr add 203.0.113.1/24 dev s0; ip -n server link set s0 up
echo 1 > /proc/sys/net/ipv4/ip_forward
nft -j -f "$RULES" || { echo "APPLY FAILED"; exit 1; }
# what the agent does when the DHCP WAN address appears
nft add element inet sensr if_wan_a4 '{ 203.0.113.2 }'
nft add element inet sensr if_wan_n4 '{ 203.0.113.0/24 }'
# services: web server on LAN host .10:8443, sshd-ish listener on router :22
ip netns exec client sh -c 'while true; do echo hello | nc -l -s 192.168.1.10 -p 8443 -q0 >/dev/null 2>&1; done' &
sleep 0.5
pass=0; fail=0
check() { # name expect(ok|blocked) cmd...
  local name=$1 want=$2; shift 2
  if timeout 3 "$@" >/tmp/out 2>&1; then got=ok; else got=blocked; fi
  if [ "$got" = "$want" ]; then echo "PASS $name ($got)"; pass=$((pass+1)); else echo "FAIL $name: want $want got $got: $(head -c 200 /tmp/out)"; fail=$((fail+1)); fi
}
check "LAN->WAN ping (masquerade)"   ok      ip netns exec client ping -c1 -W2 203.0.113.1
check "WAN->router ping (default deny)" blocked ip netns exec server ping -c1 -W2 203.0.113.2
check "WAN->LAN host direct (no route/blocked)" blocked ip netns exec server ping -c1 -W2 192.168.1.100
check "port forward WAN:443 -> 192.168.1.10:8443" ok sh -c 'ip netns exec server nc -w2 203.0.113.2 443 </dev/null | grep -q hello'
check "reflection LAN->WANIP:443"     ok sh -c 'ip netns exec client nc -w2 -s 192.168.1.100 203.0.113.2 443 </dev/null | grep -q hello'
check "WAN->router tcp/22 (dropped)" blocked ip netns exec server nc -z -w2 203.0.113.2 22
check "LAN->router tcp/22 anti-lockout (RST=reached)" ok sh -c 'ip netns exec client nc -z -w2 192.168.1.1 22; [ $? -ne 0 ] && ! ip netns exec client nc -z -w2 192.168.1.1 22 2>&1 | grep -qi timed'
(ip netns exec server timeout 3 nc -l -p 9000 -v >/tmp/srv 2>&1 &) ; sleep 0.3
ip netns exec client sh -c 'echo x | timeout 2 nc -w1 203.0.113.1 9000' >/dev/null 2>&1; sleep 0.5
echo "server saw: $(grep -o 'from [^ ]*\|Connection from.*' /tmp/srv | head -1)"
kill $(jobs -p) 2>/dev/null
echo "RESULT pass=$pass fail=$fail"
