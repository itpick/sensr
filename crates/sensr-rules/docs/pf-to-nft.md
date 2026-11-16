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

## Degraded on import (warning, rule still loads)

| pf | Status |
|---|---|
| `route-to` / `reply-to` (gateways) | not rendered yet (policy routing via fwmark tables is `sensr-net` work) |
| `tag` / `tagged` | not rendered yet |
| `set prio` | not rendered yet |
| `modulate state` | no nftables equivalent |
| `synproxy state` | not rendered yet |
| state limits (`max`, `max-src-conn`, …) | not rendered yet |
| `allow-opts` | Linux does not block IP options by default |

## Fast path

With `Options::flowtable`, established TCP/UDP flows between the interfaces'
devices are offloaded to `flowtable ft` (hook ingress) by `meta l4proto { 6, 17
} flow add @ft` at the top of `forward` (golden `features_flowtable`).
