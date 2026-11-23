# Per-host modes: Isolated and Quarantine

Status: draft for owner approval (2026-11-22)

## Intent

The owner wants to lock individual devices down from the dashboard Hosts card
(PR #93) without new hardware. A device can be in one of four modes:

| Mode | Internet | Other local devices | The router |
|------|----------|---------------------|------------|
| Normal | yes | yes | yes |
| Isolated | yes | **no** | yes (all services, as today's Firewall › Isolation) |
| Quarantine | **no** | **no** | DHCP, DNS and NTP only |
| Allowlist | only listed domains | no | DHCP, DNS and NTP only |

This piece builds **Normal, Isolated and Quarantine**. Allowlist is piece 3
(DNS-driven nft sets). The data model leaves room for it, but this piece does
not accept `allowlist` as a value.

### The flat-LAN problem and the chosen fix

The owner's LAN is flat: one router port, one switch, Wi-Fi access points,
and no VLANs. Two devices on the same LAN talk through the switch, so the
router never sees that traffic. Firewall rules alone can block only traffic
that crosses the router: the internet, other subnets, and the router itself.

The owner chose two layers (2026-11-22):

1. **Router-side enforcement by MAC address** (nftables). This is airtight
   for anything crossing the router: all internet blocking, other subnets,
   and router access.
2. **ARP interception** for same-LAN traffic of hosts in Isolated or
   Quarantine. This is the method Firewalla ("Simple mode"), Circle and
   Fing use. The router tells the locked-down host that every other LAN
   address is at the router's MAC. It tells every other host that the
   locked-down host's address is at the router's MAC. Same-LAN traffic in
   both directions then flows through the router, where layer 1 drops it.

VLANs (the airtight, industry-standard fix) come with the later VLAN UI
piece. Modes stay the same then; only the enforcement underneath changes.

## Goals

- A **Mode** column on the dashboard Hosts card, with a select per row:
  Normal / Isolated / Quarantine.
  - It is shown only for rows keyed by MAC; `id:` rows show "—".
  - It is hidden or disabled for read-only users, in the same way Forget is.
- Changing a mode stages the change and applies it in one action, so a
  Quarantine takes effect within seconds.
  - If the candidate config already holds *other* unapplied changes, the
    mode change is staged only. The card then says "Staged — Apply to take
    effect", so we never apply someone's half-finished edits behind their
    back.
- Modes persist in the config document, so they go with backups, history
  and rollback, and they survive reboots.
- The mode is keyed by MAC, so it follows the device across IP changes, new
  leases and moves between internal interfaces.
- Same-LAN blocking via ARP interception, with one global switch (default
  **on**) to turn it off.
- REST: modes go through the normal config API (`/api/v1/config/...`). The
  `GET /api/v1/hosts` view gains a `mode` field per host.

## Non-goals (this piece)

- Allowlist mode (piece 3).
- IPv6 same-LAN interception (NDP spoofing). IPv6 traffic crossing the router
  *is* enforced, by MAC on ingress. A locked-down device can still reach a
  neighbour's link-local or global IPv6 address directly over the switch.
  This gap is stated in the UI help text and queued as a follow-up.
- Defeating a hostile device that pins static ARP entries or sniffs the
  wire. ARP interception stops ordinary devices, not determined attackers;
  VLANs are the fix for that.
- A "default mode for new devices" (owner: new devices start Normal).
- A captive "you are quarantined" page.

## Anti-goals

- Breaking the LAN for Normal hosts. Interception must poison only:
  - the locked-down host's view of others;
  - others' view of the locked-down host.
  Nothing else.
- Leaving devices broken after a mode goes back to Normal, the global switch
  is turned off, or the agent stops. Every exit path sends healing ARP with
  the true MACs.
- Poisoning the router itself or the gateway/upstream on WAN. Interception
  runs only on internal, non-gateway interfaces (`internal_interfaces(doc)`).

## Design

### Config model (`sensr-schema`, `models/firewall.rs`)

```rust
pub host_modes: ArrayField<HostMode>,           // in Firewall
pub host_mode_settings: HostModeSettings,       // in Firewall, serde default

pub struct HostMode {
    #[serde(default = "yes")] pub enabled: bool,
    pub mac: MacAddressField,                    // lowercase, unique across entries
    pub mode: HostModeKind,                      // "isolated" | "quarantine"
    pub description: Option<Description>,
}
pub struct HostModeSettings {
    #[serde(default = "yes")] pub arp_intercept: bool,
}
```

- Normal is the absence of an entry.
- Validation rejects two entries with the same MAC.
- `HostModeKind` is a closed enum. Piece 3 adds `Allowlist`.

### Router-side rules (`sensr-rules`)

There is a new module beside `isolation.rs`.

- The rule IR has no MAC match today. This piece adds a source-MAC-set
  operand (`ether saddr @set`) to `ir.rs`, `compile.rs` and the nft
  renderer.
- The pf renderer is out of scope. It emits nothing for host modes, apart
  from a comment saying they are nft-only.
- Isolated rules register at priority 6, after the existing isolation.
- **Quarantine rules register before anti-lockout (priority 5).** A
  quarantined device must not reach the GUI or SSH (my call; the device is
  presumed compromised). The UI guard below keeps this from locking the
  admin out.
- Cover both the input chain (traffic to the router) and the forward chain.
  `(self)` only means something in input. A forward-chain "pass" is a
  `return`, so correctness must not depend on an early accept.

- Two nft sets of MACs: `host_isolated` and `host_quarantine`.
- Two dynamic IP sets for the reverse direction: `host_locked_v4` and
  `host_locked_v6`.
  - They hold the addresses currently seen for any locked-down MAC, from the
    neighbour table and leases, the same sources MAC aliases use
    (`alias/mac.rs`, `alias/sources.rs`).
  - They are refreshed when the alias resolver refreshes.
- On every internal interface, for traffic arriving from a locked MAC:
  - **Isolated:**
    - pass to `(self)`, as in today's isolation;
    - block to every internal network;
    - pass everything else (the internet).
  - **Quarantine:**
    - pass to `(self)` for DHCP (udp 67), DNS (udp/tcp 53) and NTP (udp 123);
    - block everything else, including other router services and the
      internet.
- On every internal interface, block traffic *to* `host_locked_v4/v6` from
  any internal network, except from the router itself. This covers the
  reverse direction for both modes, including traffic routed between LAN and
  LAN2.
- **Quarantine blocks inbound from everywhere** (added after the final review).
  - Quarantined addresses also go in `host_quarantine_v4` / `host_quarantine_v6`. These are filled at runtime like `host_locked_*`.
  - Traffic *to* them is dropped on every interface's `in` chain at priority 0, covering WAN, VPN and internal interfaces, with the router-sourced pass first.
  - A forward-hook drop runs ahead of the `rdr pass` skip, so port forwards and 1:1 NAT can't reach a quarantined device.
  - Isolated hosts keep their inbound forwards.
- Forwarded same-interface traffic (iif == oif, produced by interception)
  hits these same rules in the forward chain.
- **Existing connections are cut.**
  - The forward chain accepts `ct state established,related` first, and
    offloaded flows skip the chain.
  - So when a host enters a mode (or moves Isolated → Quarantine), the agent
    deletes conntrack entries to or from the host's addresses and flushes
    the flowtable entries for them.
  - The goal is that the new mode bites within seconds, not on the device's
    next new connection.
- Rule labels carry `#ref` `ui/core/dashboard` and the description, for the
  firewall log.
- Goldens: add nft golden cases for one Isolated and one Quarantine host on
  the `home-router` corpus.

### ARP interceptor (`sensr-agent`, new `arp_intercept.rs`)

This is a task owned by the slice applier, started like `HostCollector`. It
is active only when `arp_intercept` is on and at least one enabled Isolated or
Quarantine host exists.

- **Inputs,** recomputed on each config apply, each `HostCollector` poll,
  and every 10 s (`FEED_TICK`) from a direct read of the neighbour table, so
  a new neighbour is covered quickly:
  - the locked MACs and their current IPv4 addresses;
  - per internal interface: the router's MAC and IPv4 address, and the
    *live* IPv4 neighbours on the same subnet.
    - Live means REACHABLE/DELAY/PROBE/STALE in the kernel table, or
      inventory `last_seen` within `ONLINE_SECS` (300 s).
    - Rows that only exist in the inventory (offline, up to 90 days) are
      never poisoned.
- **Plan** (a pure function, unit-tested). For each locked host T on
  interface I:
  - for every other live neighbour X on I (not the router):
    - send T: "X's IP is at the router's MAC";
    - send X: "T's IP is at the router's MAC".
  - Never claim the router's own IP. Never target the router.
  - Never act on interfaces outside `internal_interfaces(doc)`.
- **It must hold reliably, not best effort (my call).** Linux ignores
  unsolicited replies for entries it doesn't already have, and an expired
  entry re-resolves by broadcast, which the real neighbour answers. So the
  interceptor does three things on an `AF_PACKET` raw socket per interface
  (socket2 is a workspace dependency; the agent runs as root):
  1. **Answers requests.** It listens for ARP requests from T for any X, and
     from any X for T. It replies immediately with the router's MAC, racing
     the real owner. It then repeats the reply about 50 ms later, so the
     last answer the requester hears is the router's.
  2. **Seeds with requests, not just replies.** Every **2 s** it sends a
     unicast ARP *request* to T whose sender fields are (X's IP, router
     MAC), and the reverse to each X. Receivers create or update neighbour
     entries from requests addressed to them.
  3. Measuring this on real devices is part of the acceptance check (see
     Testing). Two cases count as success:
     - from a locked host, `ping` to a LAN neighbour fails;
     - over several minutes, the neighbour's real MAC never appears in the
       locked host's ARP table for more than about 2 s.
- **Kernel settings:** whenever interception is configured, the sysctl
  applier (`appliers/sysctl.rs`, which owns `net.ipv4.*`) sets
  `send_redirects=0` for `all` and for each internal interface. That way the
  kernel never tells T to go direct, and no other code fights the applier
  over these keys. When interception stops being configured, the applier turns `send_redirects` back to 1 for the keys it last set to 0, using the conf file it wrote under /run. Interception being configured means `arp_intercept` is on
  and at least one host is locked. IP forwarding is already on.
- **Heal:** when a host leaves the locked set, interception is switched off,
  or the agent shuts down (Drop / SIGTERM path, like the inventory flush),
  send three rounds 1 s apart of correct replies:
  - tell T each X's real MAC;
  - tell each X T's real MAC.
- **Status:** the `Op::Runtime{Hosts}` view gains `mode` per host and a
  top-level `intercept: {active: bool, interfaces: [..], error: Option<String>}`.
  If the raw socket fails to open, record the error there and keep the nft
  layer working. The card shows a one-line warning.

### UI (`sensr-ui`)

- Hosts card: a Mode `<select>` per MAC row. Locked rows get a coloured badge
  (Isolated amber, Quarantine red) so they stand out in the list.
- A new agent write op, `Op::HostModeSet{mac, mode}` (REST `POST
  /api/v1/hosts/mode`, privilege `page-sensr-hosts` plus config write). It
  writes or removes the `firewall.host_modes` entry by MAC.
  - The "no other changes" check and the commit happen atomically inside
    the agent, so another user's edit can't slip in between.
  - It commits only if the candidate equals the applied config apart from
    this entry, and no provisional commit is waiting for confirmation.
    Otherwise it stages only.
  - It returns `Applied` or `Staged`.
  - A UI server function `set_host_mode` calls it. MockBackend gets the same
    behaviour.
- **Self-protection guard:** the UI and the op refuse to Quarantine the MAC
  of the client making the request. That client is found by matching the
  request's source IP against the inventory. The error reads "That's the
  device you're using — quarantine it from another device."
- The card footer carries help text when any host is locked:
  "Same-network blocking works by redirecting the device's local traffic
  through the router (IPv4). It stops ordinary devices, not ones configured
  to bypass it."
- If `intercept.error` is set, the footer shows "Same-network blocking is
  off: <error>".

### ACL

- Mode changes go through config writes. Users with `page-sensr-hosts` but
  only read-only config (`CONFIG_READONLY`) see the mode but can't change it.
- No new privilege.

## Testing

- Unit tests:
  - interception plan: who gets told what; never the router; only live
    neighbours; only internal interfaces;
  - ARP frame build/parse;
  - request-answering decisions;
  - the atomic commit rule (no other changes / other changes / pending
    confirm).
- nft goldens for Isolated and Quarantine on `home-router`, including the
  pre-anti-lockout Quarantine block.
- UI component tests and a Playwright e2e for the Mode select, the badges,
  the "Staged" path, the read-only view and the self-quarantine refusal.
- An on-router acceptance check after release (manual, with the owner's go):
  1. Put a test device in Isolated.
  2. Confirm that from it a LAN neighbour is unreachable and the internet
     works.
  3. Put it in Quarantine; the internet should stop.
  4. Set it back to Normal; it should recover within about 5 s.

## Approaches considered

1. **MAC rules plus ARP interception (chosen).** Works on the current
   hardware and covers devices with hand-set IPs. It is the common commercial
   method. Costs: it is a deliberate network trick, it is IPv4-only in this
   piece, and a hostile device can defeat it.
2. **DHCP /32 lease trick.** Rejected: uncommon, and a device with a hand-set
   IP bypasses it.
3. **VLANs on a managed switch and APs.** Airtight and the industry
   standard, but it needs hardware. Deferred to the VLAN UI piece.

## Left to the builder

- Exact nft set and chain wiring within the existing renderer conventions.
- How the interceptor gets the router's per-interface MAC (`ip -j link` or
  rtnetlink; rtnetlink is a workspace dependency).
- Whether `set_host_mode` uses one ConfigSet plus ConfigCommit, or a
  dedicated op, provided the "no other pending changes" rule holds.
- Test seams for the raw socket: a trait so the plan and send loop are
  testable without root.
