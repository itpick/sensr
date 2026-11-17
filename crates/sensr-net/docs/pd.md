# IPv6 prefix delegation (`sensr_net::ipv6::pd`)

One state machine per uplink owns the delegated prefix, its lifetimes and the
prefixes being deprecated after a change. Everything that depends on the
prefix (RA, DHCPv6 server subnets, NPTv6, nft sets, HOME_NET) is meant to be
derived from it in one reconcile (ISS-C-002). This crate is pure logic: the
agent feeds observations in and renders the output.

```text
networkd DHCPv6 client ──► kernel (routes, addresses)
                                   │  ip -j -6 route / addr
                                   ▼
                     observe::observation_from_kernel
                                   │  Observation
                                   ▼
          PdStore::load ──► PdState::observe(now, obs) ──► Vec<PdEvent>
                                   │                          (reconcile)
                         PdStore::save (on events)
                                   ▼
                  PdState::advertised(now, consumers)
                    ──► per interface: [AdvertisedPrefix]  (networkd [IPv6Prefix] / sensr-ra)
```

## Prefix maths

- `calculate_prefix(delegated, id)`: the prefix ID fills the bits between the
  delegated length and /64. `2001:db8:1234:ab00::/56` + 16 (0x10) =
  `2001:db8:1234:ab10::/64`. Host bits in `delegated` are ignored. Returns
  `None` when the ID does not fit the available bits, or the delegation is
  longer than /64.
- `delegation_size(len)`: number of /64s (`2^(64-len)`); `None` for /0 and >/64.
- `usable_prefix_length(len, id, range)`: the largest block of
  `2^(64-result)` /64s that starts at `id`, is aligned to its own size, holds
  no more than `range` slots (`None` = 1) and stays inside the delegation.
  `allocated_prefix` returns it as a prefix.

## State machine

Clock: every method takes `now`, wall-clock seconds since the Unix epoch, so
deadlines persist across reboots and tests use a fake clock. A deadline of
`u64::MAX` means infinite (DHCPv6 lifetime `0xffffffff`).

`observe(now, Option<Observation>)`, after first dropping whatever has passed
its deadline (`Expired`):

| Situation | Event | Effect |
|---|---|---|
| no current, prefix seen | `Acquired` | becomes current |
| same prefix, deadlines within ±2 s of the stored ones, already confirmed | none | no-op (ISS-C-003: polling the same lease changes nothing) |
| same prefix, new lifetimes, or first confirmation after a restart/loss | `Renewed` | lifetimes updated, `obtained_at` kept; not a change |
| different prefix | `Changed { old, new }` | old becomes stale |
| nothing seen, current was confirmed | `Lost` | current kept, unconfirmed, until its valid lifetime runs out (the lease may come back; hosts keep working addresses) |
| prefix seen with valid lifetime 0 | `Lost` | server withdrew it: stale at once (RFC 9096 §3.5) |
| current or stale deadline passed | `Expired` | dropped |

A stale prefix is advertised until
`deprecate_until = min(old valid_until, stale_since + ND_VALID_LIMIT)`. Every
Valid Lifetime sensr advertised was capped at `ND_VALID_LIMIT` and never
exceeded `valid_until`, so hosts cannot hold the address longer than that.
A prefix that comes back while stale is removed from the stale list.

If `now` is earlier than the last `now` seen (a Pi without an RTC booting
before NTP, or NTP stepping back), all deadlines move back by the same step:
sensr assumes no time passed, which keeps stale prefixes deprecated at least
as long as required. A later forward step just makes them expire sooner.

`advertised(now, consumers)` returns, per consumer interface:

1. the current prefix's /64 with `preferred = min(remaining preferred,
   ND_PREFERRED_LIMIT)`, `valid = min(remaining valid, ND_VALID_LIMIT)`,
   `deprecated: false`;
2. each stale prefix's /64 with `preferred = 0`, `deprecated: true` and
   `valid` per `StaleSignal`:
   - `CountDown` (default): `deprecate_until - now`, reaching 0 at the
     deadline;
   - `Zero`: 0, the literal RFC 9096 §3.5 text.

A stale /64 equal to a live one on the same interface (e.g. /56 → /60 from
the same base) is skipped. A consumer whose prefix ID does not fit a
delegation gets nothing from it.

Call `next_deadline()` to know when the output changes on its own (preferred
lifetime ends, something expires) and re-render then.

## RFC numbers

RFC 9096 (Improving the Reaction of CE Routers to IPv6 Renumbering Events):

| Constant | Value | Source |
|---|---|---|
| `ND_PREFERRED_LIMIT` | 2700 s (45 min) | §4 |
| `ND_VALID_LIMIT` | 5400 s (90 min, 2 × ND_PREFERRED_LIMIT) | §4 |

- L-15 / §3.3: PIO lifetimes MUST NOT exceed the remaining DHCPv6-PD
  lifetimes.
- L-16 / §3.4: PIO lifetimes SHOULD be capped at the limits above.
- L-13 (replaced) / §3.5: stale prefixes MUST be signalled: PIO with
  Preferred Lifetime 0 (RFC text: Valid Lifetime 0 too), A and L bits
  unchanged, in unsolicited RAs, for at least the Valid Lifetime previously
  advertised, i.e. `ND_VALID_LIMIT` when L-16 is followed. CE routers SHOULD
  keep the advertised prefixes on stable storage — `PdStore`.
- On RFC 4862 hosts (§5.5.3 e, the two-hour rule) a PIO with a small valid
  lifetime only shortens an address to 2 h; `CountDown` and `Zero` behave the
  same there. `CountDown` is the default because RA daemons (networkd's
  `[IPv6Prefix]`) may refuse a zero valid lifetime; switch with
  `PdState::with_stale_signal(StaleSignal::Zero)` once the RA side is
  sensr-ra.

RFC 8415 IA_PD: lifetimes are seconds relative to receipt, `0xffffffff` is
infinity, a valid lifetime of 0 withdraws the prefix. Preferred is clamped to
valid. T1/T2 belong to the client (networkd) and are not tracked here; a
renewal is visible as refreshed lifetimes.

## Observation from the kernel (networkd as the DHCPv6 engine)

networkd stays the DHCPv6 protocol engine for now; the agent polls the kernel
instead of DBus:

- `ip -j -6 route show table all`: networkd (`networkd-dhcp-prefix-delegation.c`;
  from memory of the source, present since about systemd 250 and still so in
  256+, not yet confirmed on the router — check with
  `ip -6 route show table all type unreachable proto dhcp`) installs, for each delegated prefix
  **shorter than /64**, a route of `type unreachable`, `protocol dhcp` for the
  whole prefix (RFC 7084 WPD-5) with the prefix's valid lifetime, which the
  kernel reports as `expires` (whole seconds remaining). The route sits on
  `lo`, so it does not say which uplink it belongs to.
- `ip -j -6 addr show`: networkd's addresses on the downstream links carry
  the delegation's preferred/valid lifetimes (`dynamic`,
  `preferred_life_time`, `valid_life_time`).

`observation_from_kernel(routes, addrs, downstream_ifnames)`:

- one PD route → that prefix; several → the one containing an address on a
  listed downstream link; none does → `ParseError::Ambiguous`;
- no PD route (a /64 delegation, for which networkd installs none) → the one
  /64 of the dynamic global addresses on the downstream links;
- valid lifetime from the route (no `expires` = infinite); preferred from the
  downstream addresses inside the prefix, clamped to valid, or equal to valid
  when no LAN has an address yet;
- downstream addresses whose valid lifetime differs from the route by more
  than 60 s are returned as `mismatches` (log them).

Assumptions to re-check on the real router: `expires` is printed as an
integer (older iproute2 printed `"3539sec"`; both parse), the route really
uses `proto dhcp` (a static `unreachable` route the admin added is ignored),
and 6rd from DHCPv4 (which networkd also covers with `unreachable … dhcp`
routes) is not in use on the same box. IAID is not visible in the kernel
(`iaid: None`).

## Persistence

`PdStore::new("/var/lib/sensr/state/pd/<uplink>.json")`. `save` writes
`<file>.tmp`, fsyncs it, renames it over the target and fsyncs the directory.
`load` never fails: missing file, unreadable file, corrupt JSON (moved to
`<file>.corrupt`) or an unknown `format` version give a fresh state plus a
`LoadIssue`. A loaded state is unconfirmed, so the first observation is
`Renewed` (same prefix) or `Changed` (the persisted prefix is deprecated).
Save after every `observe` that returned events.

## Differences from OPNsense

| Topic | OPNsense | sensr |
|---|---|---|
| Prefix ID too large for the delegation | high bits silently dropped, subnet overlaps another LAN | `None`; the consumer gets nothing and the reconciler can report it |
| Host bits in the delegated prefix | kept in the result | cleared |
| No prefix yet | consumers get a fake `dead:beef:N::/48` prefix so Kea does not crash | nothing is advertised; consumers render without the subnet |
| Prefix change | dhcp6c hook → `rc.newwanipv6` → reconfigure everything; the old prefix is forgotten | `Changed` event; old prefix's /64s advertised deprecated until `deprecate_until` (RFC 9096) |
| Reboot with a new prefix | old prefix unknown, hosts keep stale addresses | persisted state; first observation deprecates the old prefix |
| RENEW with the same prefix | historically re-ran interface configuration (#6522, #6816) | no event within ±2 s; `Renewed` only when lifetimes change |
| Advertised lifetimes | radvd defaults or user values, independent of the lease | capped by remaining lease and RFC 9096 limits |
| Lifetimes | not tracked until 26.1 (#9521) | preferred/valid deadlines tracked, exposed (serde) for the API |
| Clock | n/a | clock-step-back handling for RTC-less boards |
