# Host inventory and dashboard Hosts card

Status: draft for owner approval (2026-11-22)

## Intent

The owner wants two per-device lockdown modes on the router: **Isolated** and
**Allowlist internet**. Both need one dependable list of every device on the
internal networks, so a device can be picked and locked down from where you
already look. This piece builds that list: a host **inventory** the agent keeps,
shown as a **Hosts card on `/ui/core/dashboard`**.

It is piece 1 of 3:

1. Host inventory and Hosts card (this document).
2. Isolated mode per host (later; builds on the existing `firewall.isolation`).
3. Allowlist internet mode per host (later; DNS-driven).

## Goals

- One list of every device seen on the internal (non-gateway) interfaces, LAN
  and LAN2 today, merged from three sources:
  - static DHCP reservations in the config (`dhcpv4.reservations`);
  - Kea DHCPv4 leases (`sensr_apply::appliers::kea::LEASE_FILE`);
  - the kernel neighbour table (`ip -j neigh show`). This catches devices with
    hand-set addresses that never ask DHCP.
- One row per device, **keyed by MAC address**, so later modes stay attached
  when the IP changes.
- Devices stay listed while offline and across reboots, until forgotten or
  pruned (see Retention).
- The card is on the dashboard, full width, below the existing cards:
  - search by name, MAC or IP;
  - a network filter (All / per internal interface);
  - the 20 most recently seen rows, then a **Show all (N)** toggle;
  - updates live at the dashboard's existing refresh cadence;
  - per-row **Make static** (reuses `reserve_lease`, which stages a reservation)
    and **Forget**.

## Non-goals (this piece)

- The Mode column and the Isolated/Allowlist behaviour (pieces 2 and 3). The
  data model leaves room for them (see Data model).
- New-device alerts or approval. The owner will decide the default mode for
  unseen devices in piece 2.
- Vendor (OUI) lookup, mDNS/NetBIOS name discovery, OS fingerprinting.
- DHCPv6 leases. IPv6 addresses come only from the neighbour table.
- Editing names inline. Names come from reservations; Make static is the way to
  pin one.

## Anti-goals

- **No SD-card wear.** The router is a Pi on an SD card, so the inventory must
  not rewrite its file every poll.
- **No WAN-side devices** (for example the AT&T gateway) and no router-owned
  addresses in the list.
- **No new privileges for the API or UI processes.** The agent stays the only
  reader of root-owned state.
- **No unbounded growth** from randomized MACs.

## Constraints (from the codebase)

- **Agent:** runs as root and owns `/var/lib/sensr` (0700). Persistent agent
  state lives under `/var/lib/sensr/state/…` (for example `pd/`, `aliases/`)
  and is written atomically.
- **API:** `sensr-api` (uid 731) cannot read `/var/lib/sensr` and reaches the
  agent only through the IPC socket (`sensr-ipc`).
- **UI:** Leptos SSR with server functions under `/ui/fn`. It reads through
  `imp::backend()` (see `dhcp_leases` in `crates/sensr-ui/src/actions.rs`), with
  a mock backend (`crates/sensr-ui/src/mock.rs`) used by tests and e2e.
- **Existing source readers:** `SliceApplier::system_with_feeds` already reads
  the neighbour table and the Kea leases for MAC aliases
  (`sensr_feeds::neigh::{parse_ip_neigh_json, read_kea_leases}`). The inventory
  reuses those parsers.
- **Project rules:**
  - latest dependency versions;
  - tests for every behaviour (unit, mock-backed component tests, and a
    Playwright e2e for the card);
  - no AI attribution in commits.

## Approaches considered

- **A. Build the list on each request** from the reservations, leases and
  neighbour table.
  - Small, with no new state.
  - Rejected: devices with hand-set IPs vanish minutes after they go quiet, there
    is no first-seen time, and offline devices can't be targeted by modes.
- **B. An inventory the agent keeps (chosen by the owner).**
  - A collector merges the three sources on a timer into a persisted list that
    the UI reads over IPC.
  - More work, but it remembers devices, which modes and later new-device
    handling need.
- **C. Passive capture** (DHCP snooping or ARP sniffing with a raw socket).
  - Not pursued: more code and privileges for little gain over the kernel
    neighbour table plus Kea.

## Design

### Collector (agent)

- **Loop:** a `hosts` module in `sensr-agent` runs a loop every **30 s**:
  1. read the neighbour table, parsed to `(mac, ip, ifname, state)`;
  2. read the Kea leases, including the lease hostname, expiry and state;
  3. read the reservations from the applied document.
- **Merge into the in-memory inventory by MAC.** Any active lease or neighbour
  entry creates the row (setting `first_seen`) and refreshes its IPs and
  interface. Only real activity moves `last_seen` (my call, from the builder
  check):
  - a neighbour entry in state REACHABLE, DELAY or PROBE (not STALE, which
    lingers after a device leaves);
  - a lease that was issued or renewed since the last poll (its Kea `cltt`
    changed).

  An active lease alone keeps the row but does not make the device look online.
  So a switched-off device ages normally, and the 90-day prune clock runs.
- **Interfaces:** only internal interfaces count, meaning those that are not
  gateways and not virtual. Use the same test `sensr-rules` isolation uses to
  pick internal networks. Ignore neighbour entries on WAN/uplink interfaces, and
  addresses the router itself holds.
- **Reservations:** they create or refresh their host even if it has never been
  seen (`last_seen` = null, source `reserved`), so a configured device always
  appears.

### Data model (`Host`)

| Field | Meaning |
|---|---|
| `mac` | Lowercase, colon-separated. The key. |
| `key` | My call: client-id-only reservations (`ClientMatch::ClientId`) and leases without a MAC can't use the MAC. The key is the MAC when known, else `id:<client-id>`. Once a lease links that client id to a MAC, the `id:` row merges into the MAC row. A reservation with no `ip_address` still appears, with no IP. |
| `name` | Display name, by precedence: reservation hostname → DHCP lease hostname → none (the UI shows the MAC). |
| `lease_hostname` | Optional. |
| `reserved_name` | Optional. |
| `interface` | The sensr interface id (`lan`, `opt1`) where last seen, plus its display name in the API response. |
| `ipv4` | Current or last known. |
| `ipv6` | Up to 4 most recent, skipping temporary or link-local where a global exists. |
| `sources` | Set of `reserved`, `lease`, `neighbour`, for the UI's Source column: "static" if reserved, else "dynamic" if leased, else "seen". |
| `lease` | Optional `{ state, expires }`. |
| `first_seen`, `last_seen` | Unix seconds; `last_seen` is optional. |
| `online` | `last_seen` within 5 min, or the neighbour state is REACHABLE. Computed, not stored. |

Leave room for a future `mode` field (piece 2). Do not add it now. The stored
file carries a `version: 1` so it can grow.

### Persistence

- **File:** `/var/lib/sensr/state/hosts.json`, written atomically (temp file plus
  rename).
- **Flush:** the in-memory copy is authoritative. It is flushed when the set of
  hosts, their names or their IPs change, at most once every **5 min** for
  `last_seen`-only changes, and on clean shutdown.
- **On start:** load the file; if it is missing or corrupt, start empty and log.

### Retention

- **Auto-prune:** hosts not seen for **90 days**, unless reserved.
- **Cap:** 5,000 hosts; beyond that, drop the oldest `last_seen` first, never
  reserved ones.
- **Forget:** removes a host now. If it is still on the network, it reappears on
  the next poll with a new `first_seen`. That is intended.

### IPC, API, UI

- **IPC:** new requests `Hosts` (returns `Vec<Host>` plus `now`) and
  `ForgetHost { mac }`.
- **API backend:** methods `hosts()` and `forget_host(mac)` on the backend trait,
  implemented for the real client and the mock (with a seeded host list
  including LAN, LAN2, static, dynamic, seen-only and offline rows).
- **UI server functions:** `hosts()` and `forget_host(mac)`.
- **Dashboard island:** `HostsCard`, rendered after the existing dashboard cards.
  - **Columns:** Name, MAC, IP (IPv4; IPv6 in a tooltip or second line), Network,
    Source, Seen ("now" when online, else a relative time), and actions.
  - **Sorting:** online first, then `last_seen` descending.
  - **Filtering:** search filters client-side over all rows. The network filter
    lists internal interfaces.
  - **Make static:** shown only for leased, non-reserved hosts; calls the
    existing `reserve_lease`, then bumps the Apply banner as the Leases card does.
  - **Forget:** asks for confirmation. My call: it is hidden on reserved rows,
    which would come straight back. Their row says "remove the reservation on
    the DHCP page to forget this host". Forget never touches config.
- **Access (my call):**
  - two new ACL entries checked with `may_access`, like the IDS and insight
    cards: `/api/v1/hosts` (read the list) and `/api/v1/hosts/forget` (write);
  - users without the read entry don't get the card at all;
  - read-only users (`user-config-readonly`) see the list but no Forget or Make
    static buttons;
  - mock and e2e cover the full, read-only and hidden states.

## Left to the builder

- Exact IPC message and struct names, and the module layout.
- Whether the collector reuses the `neighbours` closure in `slice_applier.rs` or
  shares a helper with it.
- How the 30 s loop is scheduled inside the agent runtime.
- CSS and markup details matching the existing cards.
- Relative-time formatting (reuse `until` and friends where they fit).
