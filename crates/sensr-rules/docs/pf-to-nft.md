# pf → nftables semantics

Normative table for `sensr-rules`: how each pf construct OPNsense generates
is expressed in nftables. Every row has a golden pair under
`tests/golden/` (`*.pf` from the pf oracle, `*.nft.json` loaded by CI with
`nft -c -j -f`).

## Table layout

One table, `inet sensr`, replaced atomically (`add table; delete table; add
table …` in one `nft -j -f -` transaction), so other tables on the host are
left alone.

| Chain | Hook | Contents |
|---|---|---|
| `input` | filter input, prio 0, policy drop | `ct state vmap { established, related: accept, invalid: drop }`, `iifname lo accept`, `jump in_dispatch`, `accept` |
| `forward` | filter forward, prio 0, policy drop | `[flow add @ft]`, ct state fast path, `jump in_dispatch`, `jump out_dispatch`, `accept` |
| `output` | filter output, prio 0, policy drop | ct state fast path, `oifname lo accept`, `jump out_dispatch`, `accept` |
| `in_dispatch` / `out_dispatch` | — | `iifname`/`oifname vmap { "<dev>": goto in_<iface> }`, then `goto in__any` |
| `in_<iface>` / `out_<iface>` | — | that interface's rules in evaluation order |
| `in__any` / `out__any` | — | rules for devices that are not a logical interface |

## Rules

| pf (OPNsense) | nftables | Golden |
|---|---|---|
| `pass in` | rule in `in_*` chains (reached from `input` and `forward`), verdict `return` | `direction` |
| `pass out` | rule in `out_*` chains (reached from `forward` and `output`) | `direction` |
| `pass` (direction `any`) | rule in both | `direction` |
| `block` | `drop` | `features_addresses` |
| `block return` | `reject with tcp reset` for TCP, `reject` (ICMP port unreachable) otherwise; `any`/`tcp/udp` split into two rules | `features_addresses` |
| `quick` | first match wins in chain order | `features_quick` |
| non-`quick` | placed after all quick rules, in reverse order (last match wins) | `features_quick` |
| `on em0` | chain `in_<iface>`; floating rules are copied into every interface chain | `features_addresses` |
| `on ! em0` | every interface chain except that one, plus `__any` | `features_addresses` |
| `inet` / `inet6` | implied by address matches, else `meta nfproto` | `features_quick` |
| `inet46` (`inet` + `inet6`) | two rules, merged into `meta nfproto { ipv4, ipv6 }` when nothing else differs | `features_quick` |
| `proto tcp` | `meta l4proto 6` (numbers always: no `/etc/protocols` dependency) | `protocol` |
| `proto {tcp udp}` | `meta l4proto { 6, 17 }` | `protocol` |
| `proto "skip"`, `proto "a/n"` | `meta l4proto 57` / `107` — they are IANA protocols (SKIP, A/N), quoted in pf only because of pf's grammar | `protocol` |
| `from {1.2.3.4}` / `{10.0.0.0/8}` | `ip saddr 1.2.3.4` / prefix | `features_addresses` |
| `from {(em1:network)}` | `ip saddr @if_<iface>_n4` (named set, updated on address change) | `features_addresses` |
| IPv6 `(em1:network),fe80::/10` | two rules: `@if_<iface>_n6` and `fe80::/10` (`!`: both negated in one rule) | `features_addresses` |
| `to {(em1)}` (`lanip`) | `ip daddr @if_<iface>_a4` | `features_addresses` |
| `to {(self)}` | `fib daddr type local` | `features_addresses` |
| `from $alias` | `ip saddr @a_<alias>_4` / `@a_<alias>_6`; a family-less rule renders once per family | `features_addresses` |
| `<table>` (`<sshlockout>`, `<bogons>`) | `@t_<table>_4` / `_6`, declared empty | — |
| `!` | `!=` | `features_addresses` |
| `port {80}` / `{80:90}` | `th dport 80` / `th dport 80-90` (with `meta l4proto`) | `features_addresses` |
| `port $alias` | `th dport @a_<alias>_p` | `features_addresses` |
| `icmp-type {…}` | `icmp type { … }` (nft keyword or number); pf `skip` is ICMP type 39 | `icmp` |
| `icmp6-type {…}` | `icmpv6 type { … }` | — |
| `flags S/SA` | `tcp flags & (syn \| ack) == syn` | `features_addresses` |
| `log` | `log prefix "<label>" group <n>` (nflog → `sensr-fwlog`) | `features_addresses` |
| `label "<md5>"` | rule `comment` (labels are `calcRuleHash`-compatible) | all |
| `keep state` | conntrack (always on); replies pass via the ct state fast path | — |
| `no state` | rendered as a plain pass; conntrack still tracks | — |
| runs of per-host rules | one `meta l4proto . ip saddr . ip daddr . th dport vmap { … }` per run; a new map starts at any key that overlaps an earlier one, so the first match still wins | `features_vmap` |
| rules differing in one value | one rule with an anonymous set | `features_quick` |
| `set skip on lo0` | `iifname`/`oifname lo accept` before dispatch | all |

## NAT

Chains `nat_pre` (nat prerouting, prio −100) and `nat_post` (nat postrouting,
prio 100) in the same table. pf NAT rules are first-match; so are nft NAT
statements. Goldens: `slice`, `doc-home-router`, `nat-one-to-one`;
`scripts/netns-slice-test.sh` and `scripts/netns-home-router-test.sh` check
them with real packets in network namespaces; `tests/nat.rs` pins the order.

Order: upstream registers rules by priority (`Plugin::outputNatRules`):
MVC `snatrules` 50, legacy manual outbound 100 (only in hybrid and advanced
mode), automatic outbound 200 (automatic and hybrid), anti-lockout `no rdr`
300, 1:1 500, port forwards 600. pf keeps three translation rulesets and
consults them as `pf_get_translation` does: inbound rdr, then binat;
outbound binat, then nat. So `nat_pre` holds the rdr-type rules by priority
followed by the inbound half of every `binat`, and `nat_post` starts with the
outbound half of every `binat` (ahead of the CARP exemption, which pf only
has in the nat ruleset), then the nat-type rules by priority. sensr keeps
one manual outbound list and puts all of it at 100; the pf oracle therefore
prints MVC rules under `# [prio: 100]` instead of 50 (order unchanged).

| pf (OPNsense) | nftables |
|---|---|
| `no nat proto carp all`, `no rdr proto carp all` | `meta l4proto 112 accept` first in both chains |
| `nat on wan from (lan:network) to any -> (wan:0)` | `oifname "<wan>" ip saddr @if_lan_n4 masquerade` |
| `… port 1024:65535` (pf's default source-port range) | plain `masquerade` (conntrack keeps the port unless it clashes) |
| `… static-port` | `masquerade` (same) |
| `nat … -> 203.0.113.5` / `-> 203.0.113.0/29` | `snat ip to 203.0.113.5` / `snat ip to <first>-<last>` |
| `no nat …` | `accept` (stops NAT evaluation) |
| automatic outbound (`filter_auto_source_nat`) | the same rule list, generated from interfaces with/without gateways |
| `rdr on wan proto tcp to (wan) port 443 -> 192.168.1.10 port 8443` | `iifname "<wan>" meta l4proto 6 ip daddr @if_wan_a4 th dport 443 dnat ip to 192.168.1.10:8443` |
| `rdr … port 1000:1010 -> … port 2000` (shifted range) | one rule per port (≤ 64), so the offset is exact |
| `rdr pass …` | `ct mark set ct mark \| 0x10000` before `dnat`; `forward` accepts marked connections before the filter |
| `no rdr …` (anti-lockout: `filter_auto_destination_nat`) | `accept` before the redirects |
| NAT reflection (`natreflection` enable/purenat) | the `rdr` repeated on every interface without a gateway that has an address of the forward's family; `enable` and `purenat` are the same in OPNsense (`ForwardRule`), FreeBSD's NAT+proxy mode does not exist there |
| reflection per rule vs global | the rule's `natreflection` wins; empty takes `reflection_dnat` (`nat.reflection.port_forwards`) |
| reflection helper (`enablenatreflectionhelper`) | `oifname "<if>" ip saddr @if_<if>_n4 ip daddr <target> th dport <port> masquerade` in `nat_post` |
| `binat on wan from 10.0.0.5 to any -> 203.0.113.5` (1:1) | `nat_post`: `oifname "<wan>" ip saddr 10.0.0.5 snat ip to 203.0.113.5`; `nat_pre`: `iifname "<wan>" ip daddr 203.0.113.5 dnat ip to 10.0.0.5` |
| `binat … from 10.0.0.0/24 … -> 203.0.113.0/24` | `snat ip prefix to 203.0.113.0/24` / `dnat ip prefix to 10.0.0.0/24` (JSON `"flags": ["netmap"], "type_flags": ["prefix"]`): host bits are kept, as pf's `pf_poolmask` does; a bare external host takes the internal prefix length (`DNatRule`) |
| `binat … to 198.51.100.0/24` (1:1 destination) | outbound `ip daddr 198.51.100.0/24`, inbound `ip saddr 198.51.100.0/24` |
| `nat on wan from (lan:network) to any -> 203.0.113.9` (1:1 type nat) | outbound only, at priority 500 among the nat rules; an external network maps every source to its first address as written (pf pool type none) |
| 1:1 reflection `rdr on lan from {any} to {203.0.113.0/24} -> {10.0.0.0/24} bitmask` | `iifname "<lan>" ip daddr 203.0.113.0/24 dnat ip prefix to 10.0.0.0/24`, at priority 500 among the redirects; emitted when the rule's `natreflection` is `enable` or empty with `reflection_binat` (`nat.reflection.one_to_one`) |
| 1:1 reflection helper `nat on lan inet from (lan:network) to {10.0.0.0/24} -> (lan)` | `oifname "<lan>" ip saddr @if_lan_n4 ip daddr 10.0.0.0/24 masquerade`; follows `reflection_snat` (`nat.reflection.source_nat`) whatever `natreflection` says, also on the rule's own interface |
| a 1:1 external address on a real WAN | the address must reach the router: a virtual IP (proxy ARP / IP alias) or a routed block, as on OPNsense |
| a port forward with filter association "rule" | its filter rule at priority 500000 (destination = target, port = local port) |
| port given without protocol | `meta l4proto { 6, 17 }` — a pf port test only ever matches TCP/UDP |

## Policy routing

pf routes at filter time; Linux routes before the filter, from the packet
mark. See `src/routing.rs` for the mark layout; golden `doc-multiwan`,
packet test `scripts/netns-multiwan-test.sh`.

| pf (OPNsense) | nftables |
|---|---|
| `pass in … route-to (igc2 198.51.100.1)` (rule gateway / group) | chain `route_pre` (prerouting, prio −150): new connections re-walk the inbound rules up to the last gateway rule in `pr_<iface>`; the deciding rule sets `meta mark` and stores it in the ct mark (`0x0000ff00`) |
| later packets of the connection | `ct state established,related ct direction original meta mark set ct mark & 0xff00` |
| automatic `reply-to` on multi-WAN | new connections arriving on a WAN store that WAN's gateway in ct mark bits `0x00ff0000`; reply packets (forwarded: `route_pre`, the firewall's own: `route_out`, a `route` chain) get `meta mark set (ct mark >> 8) & 0xff00` |
| gateways and gateway groups | `Compiled::routing`: one mark and routing table per target, for the routing layer's `ip rule fwmark <mark>/0xff00 lookup <table>` |

## Degraded on import (warning, rule still loads)

| pf | Status |
|---|---|
| `tag` / `tagged` | not rendered yet |
| `set prio` | not rendered yet |
| `modulate state` | no nftables equivalent |
| `synproxy state` | not rendered yet |
| state limits (`max`, `max-src-conn`, …) | not rendered yet |
| NAT to an alias pool | not rendered yet (`rdr` to a host alias is a `numgen inc` round-robin map) |
| 1:1 reflection of a type-nat rule whose source is an alias or interface network | not rendered (pf's `bitmask` needs a literal network); the `nat` itself loads |
| `rdr` with a shifted port range wider than 64 ports | not rendered yet |
| `allow-opts` | Linux does not block IP options by default |

## Fast path

With `Options::flowtable`, established TCP/UDP flows between the interfaces'
devices are offloaded to `flowtable ft` (hook ingress) by `meta l4proto { 6, 17
} flow add @ft` at the top of `forward` (golden `features_flowtable`).
