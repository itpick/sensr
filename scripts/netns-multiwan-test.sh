#!/usr/bin/env bash
# Policy routing (route-to) of the multiwan corpus ruleset with real packets:
# LAN traffic must leave through the WAN_FAILOVER group's tier-1 member (WAN2,
# igc2), traffic to LOCAL_NETS stays unmarked, the main default route is WAN1.
# The ip rule / table below are what the routing layer installs from
# Compiled::routing. Run inside: unshare -rnm --propagation private (MOUNT=…)
set -u
RULES=$1
${MOUNT:-mount} -t tmpfs tmpfs /run && mkdir -p /run/netns
for n in up1 up2 lan; do ip netns add $n; done
ip link set lo up
ip link add igc0 type veth peer name u1 netns up1
ip link add igc2 type veth peer name u2 netns up2
ip link add igc1 type veth peer name l0 netns lan
ip addr add 203.0.113.2/24 dev igc0; ip link set igc0 up
ip addr add 198.51.100.2/30 dev igc2; ip link set igc2 up
ip addr add 192.168.10.1/24 dev igc1; ip link set igc1 up
ip route add default via 203.0.113.1
# WAN_FAILOVER (mark 0x400) -> table 10004 -> WAN2_GW
ip route add default via 198.51.100.1 dev igc2 table 10004
ip rule add fwmark 0x400/0xff00 lookup 10004
for i in 1 2; do
  ip -n up$i link set lo up
done
ip -n up1 addr add 203.0.113.1/24 dev u1; ip -n up1 link set u1 up
ip -n up2 addr add 198.51.100.1/30 dev u2; ip -n up2 link set u2 up
# the same "internet" host behind both uplinks
ip -n up1 addr add 192.0.2.10/32 dev lo; ip -n up2 addr add 192.0.2.10/32 dev lo
ip -n lan link set lo up; ip -n lan addr add 192.168.10.50/24 dev l0; ip -n lan link set l0 up
ip -n lan route add default via 192.168.10.1
echo 1 > /proc/sys/net/ipv4/ip_forward
nft -j -f "$RULES" || { echo "APPLY FAILED"; exit 1; }
ip netns exec up1 sh -c 'while true; do echo wan1 | nc -l -s 192.0.2.10 -p 80 -q0 >/dev/null 2>&1; done' &
ip netns exec up2 sh -c 'while true; do echo wan2 | nc -l -s 192.0.2.10 -p 80 -q0 >/dev/null 2>&1; done' &
sleep 0.5
got=$(ip netns exec lan timeout 3 nc -w2 192.0.2.10 80 </dev/null)
again=$(ip netns exec lan timeout 3 nc -w2 192.0.2.10 80 </dev/null)
echo "LAN -> internet via: $got / $again (want wan2 / wan2)"
nft list chain inet sensr pr_lan | grep -c 'meta mark set' | sed 's/^/marking rules: /'
kill $(jobs -p) 2>/dev/null
[ "$got" = wan2 ] && [ "$again" = wan2 ] && echo "RESULT pass" || echo "RESULT fail"
