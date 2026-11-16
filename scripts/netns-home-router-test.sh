#!/usr/bin/env bash
# Packet test of the home-router corpus ruleset (tests/golden/doc-home-router.nft.json),
# the same assertions as nix/tests/slice where they concern the firewall.
# Namespaces inet (WAN peer) — router — lan (client + NAS) / iot (VLAN host).
#
#   MOUNT=$(command -v mount) unshare -rnm --propagation private \
#     bash scripts/netns-home-router-test.sh crates/sensr-rules/tests/golden/doc-home-router.nft.json
#
# Needs nft, ip, ping, nc (openbsd) and coreutils on PATH outside /run.
set -u
RULES=$1
${MOUNT:-mount} -t tmpfs tmpfs /run && mkdir -p /run/netns
for n in inet lan iot; do ip netns add $n; done
ip link set lo up
ip link add igc0 type veth peer name i0 netns inet
ip link add igc1 type veth peer name l0 netns lan
ip link add vlan01 type veth peer name t0 netns iot
ip addr add 203.0.113.2/24 dev igc0; ip link set igc0 up
ip addr add 192.168.1.1/24 dev igc1; ip link set igc1 up
ip addr add 192.168.20.1/24 dev vlan01; ip link set vlan01 up
ip -n inet link set lo up; ip -n inet addr add 203.0.113.1/24 dev i0; ip -n inet link set i0 up
ip -n inet route add 203.0.113.40/32 via 203.0.113.2
ip -n lan link set lo up; ip -n lan addr add 192.168.1.100/24 dev l0; ip -n lan addr add 192.168.1.10/24 dev l0
# the 1:1 game server; its public 203.0.113.40 is routed to the router (on
# OPNsense and sensr alike a real WAN needs a virtual IP or a routed block)
ip -n lan addr add 192.168.1.40/24 dev l0
ip -n lan link set l0 up; ip -n lan route add default via 192.168.1.1
ip -n iot link set lo up; ip -n iot addr add 192.168.20.50/24 dev t0; ip -n iot link set t0 up; ip -n iot route add default via 192.168.20.1
echo 1 > /proc/sys/net/ipv4/ip_forward
nft -j -f "$RULES" || { echo "APPLY FAILED"; exit 1; }
# services: NAS https on 192.168.1.10:443, an "internet" web server, a DNS-ish listener on the router
ip netns exec lan sh -c 'while true; do echo nas | nc -l -s 192.168.1.10 -p 443 -q0 >/dev/null 2>&1; done' &
ip netns exec inet sh -c 'while true; do echo web | nc -l -s 203.0.113.1 -p 80 -q0 >/dev/null 2>&1; done' &
for p in 25565 8080; do
  ip netns exec lan sh -c "while true; do echo game | nc -l -s 192.168.1.40 -p $p -q0 >/dev/null 2>&1; done" &
done
# logs the source address each connection arrives from
ip netns exec inet sh -c 'while true; do nc -nlv -s 203.0.113.1 -p 81 -q0 </dev/null >/dev/null 2>>/tmp/peers81; done' &
sh -c 'while true; do echo dns | nc -l -s 192.168.20.1 -p 53 -q0 >/dev/null 2>&1; done' &
sh -c 'while true; do echo wg | nc -u -l -s 203.0.113.2 -p 51820 -q1 >/dev/null 2>&1; done' &
sleep 0.5
pass=0; fail=0
check() {
  local name=$1 want=$2; shift 2
  if timeout 4 "$@" >/tmp/out 2>&1; then got=ok; else got=blocked; fi
  if [ "$got" = "$want" ]; then echo "PASS $name"; pass=$((pass+1)); else echo "FAIL $name: want $want got $got: $(head -c 200 /tmp/out)"; fail=$((fail+1)); fi
}
check "LAN -> internet (NAT, LAN to any)"   ok      sh -c "ip netns exec lan nc -w2 203.0.113.1 80 </dev/null | grep -q web"
check "IoT -> internet (NAT, rule 'IoT: allow internet')" ok sh -c "ip netns exec iot nc -w2 203.0.113.1 80 </dev/null | grep -q web"
check "IoT -> LAN NAS dropped"               blocked sh -c "ip netns exec iot nc -w2 192.168.1.10 443 </dev/null | grep -q nas"
check "IoT -> router DNS tcp/53 allowed"     ok      sh -c "ip netns exec iot nc -w2 192.168.20.1 53 </dev/null | grep -q dns"
check "LAN -> NAS allowed"                   ok      sh -c "ip netns exec lan nc -w2 192.168.1.10 443 </dev/null | grep -q nas"
check "WAN 443 -> NAS port forward"          ok      sh -c "ip netns exec inet nc -w2 203.0.113.2 443 </dev/null | grep -q nas"
check "LAN -> WANIP 443 reflected to NAS"    ok      sh -c 'ip netns exec lan nc -w2 -s 192.168.1.100 203.0.113.2 443 </dev/null | grep -q nas'
# the source the internet sees for one connection from $1 must be $2
seen_as() { echo ": >/tmp/peers81; ip netns exec lan nc -w2 -s $1 203.0.113.1 81 </dev/null >/dev/null 2>&1; sleep 0.3; grep -q 'received on $2 ' /tmp/peers81 || { cat /tmp/peers81; false; }"; }
check "WAN -> 203.0.113.40:25565 1:1 binat to game server" ok sh -c "ip netns exec inet nc -w2 203.0.113.40 25565 </dev/null | grep -q game"
check "1:1 host leaves as 203.0.113.40 (binat before automatic NAT)" ok sh -c "$(seen_as 192.168.1.40 203.0.113.40)"
check "other LAN hosts still leave as the WAN address" ok sh -c "$(seen_as 192.168.1.100 203.0.113.2)"
check "LAN -> 203.0.113.40 reflected to game server (1:1 reflection)" ok sh -c "ip netns exec lan nc -w2 -s 192.168.1.100 203.0.113.40 25565 </dev/null | grep -q game"
check "WAN -> 203.0.113.40:8080 blocked by filter" blocked sh -c "ip netns exec inet nc -w2 203.0.113.40 8080 </dev/null | grep -q game"
check "WAN -> router ssh closed"             blocked ip netns exec inet nc -z -w2 203.0.113.2 22
check "WAN -> router ping closed"            blocked ip netns exec inet ping -c1 -W2 203.0.113.2
check "WAN -> router udp/51820 (Allow WireGuard)" ok sh -c "nft list chain inet sensr in_wan | grep -q 51820"
kill $(jobs -p) 2>/dev/null
echo "RESULT pass=$pass fail=$fail"
