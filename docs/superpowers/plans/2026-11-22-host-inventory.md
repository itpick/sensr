# Host Inventory and Dashboard Hosts Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The sensr agent keeps a persisted inventory of every device on the internal networks. The dashboard shows it as a Hosts card.

**Architecture:**
- A pure `Inventory` in `sensr-agent` merges three sources by key (MAC, else `id:<client-id>`) every 30 s:
  - neighbour-table entries;
  - Kea lease records;
  - DHCP reservations.
- A `HostStore` persists it to `/var/lib/sensr/state/hosts.json` under a write-throttle policy.
- The agent exposes it through `Op::Runtime { section: Hosts }` and a new write op, `Op::HostForget`.
- `sensr-api` serves `GET /api/v1/hosts` and `POST /api/v1/hosts/forget` behind a new privilege.
- A Leptos island renders the card on `/ui/core/dashboard`.

**Tech Stack:** Rust (tokio, serde, axum, Leptos islands), Kea memfile CSV, `ip -j neigh`, Playwright e2e.

**Spec:** `docs/superpowers/specs/2026-11-22-host-inventory-design.md`

## Global Constraints

- **Poll interval:** 30 s.
- **Online:** `last_seen` within 300 s (5 min).
- **Flush:**
  - Immediately on a structural change: a host added or removed, a name, IP, interface or source set changed, or a forget.
  - Otherwise at most every 300 s for `last_seen`-only changes.
  - Also on clean shutdown.
- **Retention:**
  - Prune hosts whose `last_seen` (or `first_seen` if never seen) is older than 90 days (7,776,000 s), unless reserved.
  - Cap: 5,000 hosts. Beyond that, drop the oldest `last_seen` first, never reserved ones.
- **Card:**
  - 20 rows shown before **Show all (N)**.
  - Sort: online first, then `last_seen` descending.
- **ACL:**
  - Privilege `page-sensr-hosts` ("sensr: Hosts"), covering `ui/core/dashboard/hosts`, `api/v1/hosts` and `api/v1/hosts/*`.
  - Forget is a write op, so `user-config-readonly` users are refused.
- **Storage file:** `/var/lib/sensr/state/hosts.json`, `{"version":1,"hosts":[…]}`, written atomically (temp file + rename).
- **Project rules:**
  - latest dependency versions; add no new crates unless needed;
  - every behaviour gets a test;
  - no AI attribution lines in commits (repo rule overrides any harness default);
  - commit messages in the repo style (`agent: …`, `ui: …`, `api: …`).

## Wire Format (shared by Tasks 4–7)

`Op::Runtime { section: Hosts }` returns `Response::Value(Some(json))` with:

```json
{ "now": 1763830000,
  "hosts": [ {
    "key": "84:47:09:38:a5:fc",            // MAC, or "id:<hex client id>"
    "mac": "84:47:09:38:a5:fc",            // omitted when unknown
    "name": "old-router",                  // reserved_name, else lease_hostname; omitted if neither
    "reserved_name": null, "lease_hostname": "old-router",
    "interface": "opt1", "interface_name": "LAN2",
    "ipv4": "192.168.72.2", "ipv6": ["2600:…"],
    "sources": ["lease","neighbour"],      // subset of reserved|lease|neighbour
    "lease": {"state":"active","expires":1763840000},  // omitted without a lease
    "first_seen": 1763800000, "last_seen": 1763829990, // last_seen omitted if never seen
    "online": true
} ] }
```

The UI mirrors this leniently, with every field defaulted, as `crates/sensr-ui/src/runtime.rs` does.

## Review Focus

1. **A device that was switched off but still holds a valid lease must not show as online.** Task 2 test `lease_alone_does_not_refresh_last_seen`.
2. **Agent restart must not mark every leased device as "just renewed".** On the first poll there is no previous expiry to compare. Task 2 test `first_poll_does_not_count_existing_leases_as_activity`.
3. **A neighbour seen on the WAN device (for example the AT&T gateway) must never be listed.** Task 2 test `wan_and_unknown_devices_are_ignored`.
4. **A corrupt or truncated `hosts.json` after a power cut must not stop the agent.** It starts empty and logs. Task 3 test `corrupt_file_starts_empty`.
5. **Forget on a host that is still online must bring it back on the next poll with a new `first_seen`, not an error.** Task 2 test `forgotten_online_host_returns_with_new_first_seen`.

---

### Task 1: Richer neighbour and lease readers (sensr-feeds)

**Files:**
- Modify: `crates/sensr-feeds/src/neigh.rs`, adding two record readers next to the existing ones. Leave the existing ones unchanged.
- Test: the same file's `#[cfg(test)]` modules.

**Interfaces:**
- Produces:
  - `pub struct NeighEntry { pub mac: String, pub ip: std::net::IpAddr, pub dev: String, pub state: Vec<String> }`
  - `pub fn parse_ip_neigh_entries(json: &[u8]) -> Vec<NeighEntry>`: keeps entries with a MAC, lowercases the MAC, and keeps `state` as given (`"REACHABLE"`, `"STALE"`, `"DELAY"`, `"PROBE"`, …).
  - `pub struct KeaLease { pub address: std::net::Ipv4Addr, pub mac: Option<String>, pub client_id: Option<String>, pub hostname: Option<String>, pub subnet_id: u32, pub expire: u64, pub active: bool }`
  - `pub fn read_kea_lease_records(base: &std::path::Path, now: u64) -> Vec<KeaLease>`
- `read_kea_lease_records` details:
  - It takes the last record per address across the same files, in the same load order as `read_kea_leases`, and locates columns by the header line.
  - `active` = state 0, `valid_lifetime` > 0 and `expire` > `now`.
  - Lowercase MACs. `client_id` is lowercase hex with colons as Kea wrote it. An empty hostname becomes `None`.

- [ ] **Step 1: Write failing tests.**
  - `neigh_entries_keep_device_and_state`: JSON with three entries returns two `NeighEntry`s, with `dev` and `state` preserved.
    - `{dst:192.168.68.10, dev:ue1, lladdr:AA:BB:CC:00:00:01, state:[REACHABLE]}`
    - `{dst:192.168.68.11, dev:ue1, state:[FAILED]}` (no lladdr, dropped)
    - `{dst:fe80::1, dev:ue0, lladdr:aa:bb:cc:00:00:02, state:[STALE]}`
  - `lease_records_take_last_record_and_flag_active`: a CSV with a header plus two records for 192.168.68.20 (the later one has expire 2000 and hostname `tablet`), and one released record (valid_lifetime 0) for .21. With `now`=1000:
    - .20 is active with hostname `Some("tablet")`;
    - .21 is present with `active == false`.
  - `lease_records_missing_file_is_empty`.
- [ ] **Step 2:** `cargo test -p sensr-feeds neigh` fails because the functions are undefined.
- [ ] **Step 3:** Implement both readers in `neigh.rs`.
  - Reuse the existing CSV header lookup and the file-order helper. Factor out a private helper if `parse_kea_lease_csv` inlines it.
- [ ] **Step 4:** `cargo test -p sensr-feeds` passes, and `cargo clippy -p sensr-feeds -- -D warnings` is clean.
- [ ] **Step 5:** Commit: `feeds: neighbour and lease records with device, state and host name`.

### Task 2: The inventory merge (pure logic)

**Files:**
- Modify: `crates/sensr-rules/src/document.rs`, adding a public internal-interface helper.
- Create: `crates/sensr-agent/src/hosts.rs`, the pure model and merge with no I/O.
- Modify: `crates/sensr-agent/src/lib.rs`, adding `pub mod hosts;`.
- Test: `crates/sensr-agent/src/hosts.rs` `#[cfg(test)]`.

**Interfaces:**
- Produces (sensr-rules):
  - `pub struct InternalIf { pub id: String, pub device: String, pub descr: String, pub subnets: Vec<ipnet::Ipv4Net> }`
  - `pub fn internal_interfaces(doc: &sensr_schema::Document) -> Vec<InternalIf>`
  - It returns interfaces where `!virtual && !gateway_v4 && !gateway_v6`, the same test `isolation::register` uses.
  - Build it from the private `interfaces(doc, rt)` with the empty runtime (no learned addresses). Its `subnets` are the interface's static IPv4 networks.
- Produces (agent):
  - `pub struct Snapshot { pub neigh: Vec<NeighEntry>, pub leases: Vec<KeaLease>, pub reservations: Vec<ReservationView>, pub internal: Vec<InternalIf>, pub subnet_iface: BTreeMap<u32, String> }`
    - `subnet_iface` maps a Kea subnet id to an interface id. Build it from the doc's `dhcpv4.subnets` (its `interface`, else the internal interface whose subnet contains it), in the same order Kea ids are assigned by `sensr-apply/src/appliers/kea.rs`. Reuse that function if it is public; make it `pub` if not.
  - `pub struct ReservationView { pub key: String, pub mac: Option<String>, pub client_id: Option<String>, pub ip: Option<Ipv4Addr>, pub hostname: Option<String>, pub interface: Option<String> }`
  - `pub fn reservations(doc: &Document) -> Vec<ReservationView>`
  - `#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)] pub struct Host`
    - Fields exactly as in the Wire Format, minus `online` and `interface_name`, which are computed at render.
    - Plus `#[serde(skip)] last_expire: Option<u64>`, holding the previous poll's lease expiry.
  - `pub struct Inventory { hosts: BTreeMap<String, Host>, primed: bool }` with:
    - `pub fn from_hosts(Vec<Host>) -> Self`
    - `pub fn observe(&mut self, snap: &Snapshot, now: u64) -> Change`
    - `pub fn forget(&mut self, key: &str) -> bool`: returns false if the key is unknown or reserved.
    - `pub fn prune(&mut self, now: u64) -> bool`
    - `pub fn hosts(&self) -> impl Iterator<Item=&Host>`
    - `pub fn view(&self, now: u64, internal: &[InternalIf]) -> serde_json::Value`: the Wire Format, sorted online first, then `last_seen` descending.
  - `#[derive(PartialEq, Debug)] pub enum Change { None, Seen, Structural }`
    - `Seen` means only `last_seen` moved.
- Rules in `observe`:
  - Only neighbour entries whose `dev` is an internal device count. Lease and reservation interfaces come from `subnet_iface` or the reservation subnet.
  - Key = lowercase MAC, else `id:<client_id>`. When a lease has both a client id and a MAC and an `id:` row exists, merge the `id:` row into the MAC row: keep the earliest `first_seen` and union the sources. That is a Structural change.
  - `last_seen = now` only when either:
    - a neighbour state contains `REACHABLE`, `DELAY` or `PROBE`; or
    - `primed` and an active lease's `expire` differs from the stored `last_expire`.
  - `primed` becomes true after the first `observe`.
  - New rows get `first_seen = now`. Reservation-only rows have `last_seen = None`.
  - IPv6: keep at most 4, newest first; drop link-local `fe80::/10` when a global exists.

- [ ] **Step 1: Write failing tests**, each building a `Snapshot` by hand with internal `[{id:"lan", device:"ue1", descr:"LAN", subnets:[192.168.68.0/22]}]` and WAN device `rp1eth0` not internal.
  - `reachable_neighbour_creates_and_sees_host`: one REACHABLE entry on ue1 at now=1000 gives 1 host with `first_seen==1000`, `last_seen==Some(1000)` and `sources==["neighbour"]`; the result is `Change::Structural`.
  - `stale_neighbour_keeps_but_does_not_see`: the same host at now=2000 with state STALE has `last_seen` still `Some(1000)` and the result is `Change::None`.
  - `lease_alone_does_not_refresh_last_seen`: an active lease (expire 9000) at polls 1000, 1030, 1060 with no neighbour entry leaves `last_seen==None` throughout and the row present with `sources==["lease"]`.
  - `renewed_lease_counts_as_activity`: poll at 1000 (expire 9000), then at 1030 with expire 9030, gives `last_seen==Some(1030)` and `Change::Seen`.
  - `first_poll_does_not_count_existing_leases_as_activity`: a fresh `Inventory::from_hosts(vec![host with last_expire None])` whose first observe sees an active lease leaves `last_seen` unchanged.
  - `wan_and_unknown_devices_are_ignored`: a REACHABLE entry on `rp1eth0` leaves the inventory empty.
  - `reservation_without_sighting_is_listed`: a reservation (mac, ip .40, hostname `printer`) gives a row with `name=="printer"`, `sources==["reserved"]` and `last_seen==None`.
  - `client_id_row_merges_into_mac`: a reservation `id:01:aa`, then a lease with client_id `01:aa` and MAC `aa:bb:…`, leaves one row keyed by the MAC whose sources contain `reserved` and `lease`.
  - `name_precedence`: reserved name `nas` beats lease hostname `diskstation`, giving `name=="nas"`.
  - `forget_refuses_reserved_and_unknown`: `forget("printer-mac")==false` and `forget("nope")==false`.
  - `forgotten_online_host_returns_with_new_first_seen`: forget at 1000, then a REACHABLE observe at 1030, gives `first_seen==1030`.
  - `prune_drops_after_90_days_but_keeps_reserved`: a `last_seen` of now−7,776,001 is pruned; a reserved row with the same age is kept.
  - `cap_drops_oldest_unreserved`: 5,001 unreserved hosts are pruned to 5,000, and the removed one has the oldest `last_seen`.
  - `view_sorts_online_first_and_flags_online`: two hosts, `last_seen` now−10 and now−400, give `online` true and false, in that order, with `interface_name=="LAN"`.
  - In `document.rs` tests: `internal_interfaces_excludes_wan_and_virtual`, using an existing fixture doc with a WAN plus a LAN plus a WireGuard interface, returns only the LAN.
- [ ] **Step 2:** `cargo test -p sensr-agent hosts` and `cargo test -p sensr-rules internal_interfaces` fail.
- [ ] **Step 3:** Implement `internal_interfaces`, `reservations`, `Host`, `Inventory` and `Change` per the Interfaces block.
- [ ] **Step 4:** Both test commands pass, and clippy is clean for both crates.
- [ ] **Step 5:** Commit: `agent: host inventory merge`.

### Task 3: Persistence and write throttle

**Files:**
- Modify: `crates/sensr-agent/src/hosts.rs`, adding `HostStore`.
- Test: the same file.

**Interfaces:**
- Consumes: `Inventory`, `Host` and `Change` (Task 2).
- Produces:
  - `pub struct HostStore { path: PathBuf, last_flush: Option<u64>, dirty: Change }` with:
    - `pub fn new(path: PathBuf) -> Self`
    - `pub fn load(&self) -> Vec<Host>`: returns an empty list and logs `tracing::warn!` when the file is missing, unparsable or the wrong version.
    - `pub fn note(&mut self, c: Change)`: keeps the strongest pending change (`Structural` > `Seen` > `None`).
    - `pub fn maybe_flush(&mut self, inv: &Inventory, now: u64) -> std::io::Result<bool>`: writes when the pending change is `Structural`, or when it is `Seen` and `now - last_flush >= 300` or nothing has been flushed yet. Returns whether it wrote.
    - `pub fn flush(&mut self, inv: &Inventory, now: u64) -> std::io::Result<()>`: an unconditional write for shutdown.
  - Atomic write: write `hosts.json.tmp` in the same directory, `sync_all`, then rename. Create the parent directory if it is missing (mode 0700 is inherited from `/var/lib/sensr`).

- [ ] **Step 1: Write failing tests** in a `tempfile::tempdir()`.
  - `round_trip`: save two hosts, then `load` returns them equal.
  - `corrupt_file_starts_empty`: the file contains `{"version":1,"hosts":[` and `load` returns an empty list.
  - `seen_only_changes_are_throttled`: note `Seen` and flush at t=0 (writes), note `Seen` at t=100 (no write), note `Seen` at t=300 (writes).
  - `structural_change_flushes_immediately`: after a flush at t=0, note `Structural` at t=10, and it writes.
  - `no_tmp_left_behind`: after a flush, the dir holds only `hosts.json`.
- [ ] **Step 2:** `cargo test -p sensr-agent hosts::store` fails.
- [ ] **Step 3:** Implement `HostStore`.
- [ ] **Step 4:** The tests pass and clippy is clean.
- [ ] **Step 5:** Commit: `agent: persist the host inventory with a write throttle`.

### Task 4: Agent wiring, IPC ops and the 30 s collector

**Files:**
- Modify: `crates/sensr-ipc/src/proto.rs`, adding:
  - `RuntimeSection::Hosts`;
  - `Op::HostForget { key: String }`;
  - `HostForget` in `Op::is_write`.
- Modify: `crates/sensr-agent/src/applier.rs`, adding the trait method `fn forget_host(&mut self, _key: &str) -> Result<bool, ApplyError> { Ok(false) }`.
- Modify: `crates/sensr-agent/src/slice_applier.rs`:
  - in `system_with_feeds`, start a `HostCollector` when `feeds_dir` has a parent state dir; the store path is `<state>/hosts.json`;
  - `runtime(Hosts)` returns `inventory.view(..)`;
  - implement `forget_host`.
- Modify: `crates/sensr-agent/src/hosts.rs`, adding `HostCollector`.
- Modify: `crates/sensr-agent/src/agent.rs`:
  - dispatch `Op::HostForget`: `Ok(true)` gives `Response::Value(Some(json!({"forgotten":true})))`, and `Ok(false)` gives an `ErrorKind::Conflict` error with the message `"host is reserved or unknown"`;
  - add `"host.forget"` to the op name list.
- Modify: `crates/sensr-cli/src/lib.rs`, adding a `RuntimeArg::Hosts` arm so the match stays exhaustive.
- Test: `crates/sensr-agent/tests/agent_ipc.rs`, plus unit tests in `hosts.rs`.

**Interfaces:**
- Consumes: Tasks 1–3, `Runner`/`Cmd` for `ip -j neigh show`, and `sensr_apply::appliers::kea::LEASE_FILE`.
- Produces:
  - `pub struct HostCollector`, shared as `Arc<Mutex<..>>` like `PdService`, with:
    - `pub fn new(store: HostStore, sources: Arc<dyn Fn() -> (Vec<NeighEntry>, Vec<KeaLease>) + Send + Sync>) -> Arc<Self>`
    - `pub fn set_document(&self, doc: &Document)`: called from `apply`, it refreshes `internal`, `subnet_iface` and the reservations.
    - `pub fn poll(&self, now: u64)`: observe, prune, note, maybe_flush; it logs and never panics on I/O errors.
    - `pub fn start(self: &Arc<Self>)`: spawns a thread polling every 30 s, the same way `PdService::start` does.
    - `pub fn view(&self, now: u64) -> Value`
    - `pub fn forget(&self, key: &str) -> bool`: forgets and flushes immediately.
    - `pub fn shutdown(&self)`: final `flush`. Call it wherever `PdService` is stopped on shutdown; if there is no such hook, add one to `SliceApplier`'s `Drop`.

- [ ] **Step 1: Write failing tests.**
  - `collector_poll_and_view` (unit): a fake `sources` closure returns one REACHABLE entry on the doc's LAN device, then `poll(1000)` and `view(1000)` give `hosts[0].online == true`, and the store file exists.
  - `collector_forget_flushes`: after a forget, reading the store file no longer contains the key.
  - In `agent_ipc.rs`:
    - `runtime_hosts_section_round_trips`: with the test applier returning a canned value for `Hosts`, `Op::Runtime{Hosts}` gives `Response::Value(Some(_))`.
    - `host_forget_is_refused_for_readonly`: a read-only principal gets `ErrorKind::Forbidden`.
  - In `proto.rs` tests: `host_forget_is_write` asserts `Op::HostForget{key:"x".into()}.is_write()`.
- [ ] **Step 2:** `cargo test -p sensr-ipc -p sensr-agent` fails.
- [ ] **Step 3:** Implement the wiring per the Files list.
  - `apply` calls `collector.set_document(&doc)` after a successful apply.
  - The sources closure reuses the existing `ip -j neigh show` runner call and `read_kea_lease_records(Path::new(LEASE_FILE), now)`.
- [ ] **Step 4:** `cargo test --workspace` passes (the VM/nix tests are out of scope), and clippy is clean workspace-wide.
- [ ] **Step 5:** Commit: `agent: collect hosts every 30 s and serve them over IPC`.

### Task 5: REST routes and privilege (sensr-api, sensr-auth)

**Files:**
- Modify: `crates/sensr-auth/src/acl.rs`, adding to `builtin()`: `r.insert("page-sensr-hosts", "sensr: Hosts", &["ui/core/dashboard/hosts", "api/v1/hosts", "api/v1/hosts/*"]);`
- Modify: `crates/sensr-api/src/native.rs`, adding:
  - `pub async fn hosts(...) -> ApiResult`: calls `Op::Runtime{section: Hosts}` and returns the JSON, or `{"now":0,"hosts":[]}` when the value is `None`.
  - `pub async fn forget_host(...)`: body `{"key": String}`, calls `Op::HostForget`, and maps Conflict to 409 and Forbidden to 403.
- Modify: `crates/sensr-api/src/lib.rs` `ROUTES`, adding `("/api/v1/hosts", || get(native::hosts))` and `("/api/v1/hosts/forget", || post(native::forget_host))`.
- Modify: `crates/sensr-api/src/native.rs` `runtime`, adding `"hosts" => RuntimeSection::Hosts` so `/api/v1/status/hosts` also works.
- Test: `crates/sensr-api/tests/api.rs`.

- [ ] **Step 1: Write failing tests.**
  - `hosts_requires_privilege`: a user without `page-sensr-hosts` gets 403 on `GET /api/v1/hosts`; one with it gets 200 and `hosts` is an array.
  - `forget_host_readonly_forbidden`: a user with `page-sensr-hosts` + `user-config-readonly` gets 403 on `POST /api/v1/hosts/forget {"key":"aa:bb:cc:00:00:01"}`.
  - The existing ACL walk test (T-0368) must still pass, now covering the two new routes.
- [ ] **Step 2:** `cargo test -p sensr-api -p sensr-auth` fails.
- [ ] **Step 3:** Implement per the Files list.
- [ ] **Step 4:** The tests pass and clippy is clean.
- [ ] **Step 5:** Commit: `api: hosts list and forget routes behind page-sensr-hosts`.

### Task 6: UI backend, mock, server functions and the Hosts card

**Files:**
- Modify: `crates/sensr-ui/src/runtime.rs`, adding:
  - `RuntimeSection::Hosts`;
  - lenient mirrors `HostList { now: u64, hosts: Vec<HostRow> }`;
  - `HostRow`, with the Wire Format fields, all `#[serde(default)]`.
- Modify: `crates/sensr-ui/src/api.rs` (Backend trait), adding:
  - `fn forget_host(&self, key: String) -> BoxFuture<'_, ApiResult<()>>`;
  - `fn read_only(&self) -> bool { false }`.
- Modify: `crates/sensr-api/src/ui.rs`:
  - map `RuntimeSection::Hosts`;
  - implement `forget_host` via `Op::HostForget`;
  - `read_only()` is true when the caller's privileges contain `sensr_auth::acl::CONFIG_READONLY`.
- Modify: `crates/sensr-ui/src/mock.rs`:
  - `runtime(Hosts)` returns a seeded list of 25 hosts across `lan`/LAN and `opt1`/LAN2, including at least:
    - one static (reserved) row;
    - one dynamic row;
    - one seen-only row;
    - one offline row (`last_seen` 2 h ago);
    - one never-seen reserved row;
  - `forget_host` removes non-reserved keys.
  - Add a way to build a read-only mock and a mock without `page-sensr-hosts`, following how existing mocks vary privileges.
- Modify: `crates/sensr-ui/src/actions.rs`, adding server functions:
  - `hosts() -> Result<Option<HostCard>, ServerFnError>`:
    - `None` when `!may_access("/api/v1/hosts")`;
    - `HostCard { list: HostList, read_only: bool, networks: Vec<(String,String)> }`, with the internal interfaces taken from the doc as `(id, display name)`.
  - `forget_host(key: String) -> Result<(), ServerFnError>`.
- Modify: `crates/sensr-ui/src/islands.rs`:
  - add `#[island] pub fn HostsCard(initial: Option<HostCard>)`;
  - render it after the existing cards in `DashboardLive`'s page, full width (`card card-wide`, or the class wide cards already use);
  - it re-fetches `hosts()` at the same interval `DashboardLive` uses.
- Modify: the dashboard page in `crates/sensr-ui/src/pages.rs`, which loads `hosts()` for the initial render.
- Test: `crates/sensr-ui/tests/components.rs`.

**Card behaviour (exact copy and rules):**
- **Title:** `Hosts (N)`, where N is the total count.
- **Search:** placeholder `Search name, MAC or IP`; case-insensitive substring over name, MAC, IPv4 and IPv6.
- **Network filter:** a select with `All networks`, then each internal interface's display name.
- **Columns:** `Name`, `MAC`, `IP`, `Network`, `Source`, `Seen`, plus an unlabeled actions column.
  - **Name:** the name, or the MAC when there is no name.
  - **IP:** IPv4 on the first line and the first IPv6 on a second, muted line.
  - **Source:** `static` if sources contain reserved, else `dynamic` if they contain lease, else `seen`.
  - **Seen:** `now` if online, `never` if `last_seen` is null, else a relative time (`5m`, `3h`, `2d`).
- **Rows:** filter and search apply first, then the first 20 rows show, then a button `Show all (M)`, where M is the filtered count. It is shown only when M > 20.
- **Actions:**
  - `Make static`: only when sources contain `lease` but not `reserved`, the host has a MAC and an IPv4, and the user is not read-only. It calls `reserve_lease` with `(ipv4, mac, None, name)`, then `bump()`.
  - `Forget`: only when not reserved and not read-only. It asks `confirm("Forget <name>? It reappears if it is still on the network.")`, then calls `forget_host` and refreshes.
  - Reserved rows show the muted text `remove the reservation on the DHCP page to forget this host` in place of Forget, only when not read-only.
- **Empty list:** `No hosts seen yet.`

- [ ] **Step 1: Write failing component tests** against the mock.
  - `hosts_card_lists_first_20_and_show_all`: 25 hosts give `Hosts (25)`, 20 rows, and a `Show all (25)` button.
  - `hosts_card_source_and_seen_labels`: the reserved never-seen row shows `static` and `never`; the offline row shows `2h`.
  - `hosts_card_hidden_without_privilege`: with a mock lacking `page-sensr-hosts`, `hosts()` returns `None` and no `Hosts (` text renders.
  - `hosts_card_read_only_has_no_actions`: the read-only mock renders no `Forget` and no `Make static`.
  - `hosts_card_reserved_row_has_no_forget`.
- [ ] **Step 2:** `cargo test -p sensr-ui --test components hosts_card` fails.
- [ ] **Step 3:** Implement per the Files list and the Card behaviour block. Search, filter and show-all are client-side signals over the fetched list.
- [ ] **Step 4:** `cargo test -p sensr-ui` passes, clippy is clean, and the islands build (`cargo leptos build` or the repo's xtask equivalent) succeeds.
- [ ] **Step 5:** Commit: `ui: Hosts card on the dashboard`.

### Task 7: End-to-end tests (Playwright)

**Files:**
- Create: `crates/sensr-ui/e2e/tests/hosts.spec.ts`, using the helpers in `e2e/tests/helpers.ts` and the mock-backed server the other specs use.
- Modify: `crates/sensr-ui/e2e/fixtures/agent-seed.json`, if the e2e server seeds from it, so the 25 mock hosts appear.

- [ ] **Step 1: Write the specs.**
  - `dashboard shows the Hosts card with 20 rows and Show all`: click `Show all (25)` and expect 25 rows.
  - `search filters by MAC`: type a seeded MAC suffix and expect exactly 1 row.
  - `network filter shows only LAN2`: select `LAN2` and every row's Network cell is `LAN2`.
  - `forget removes a dynamic host`: accept the confirm dialog, the row disappears, and the title count drops by 1.
  - `read-only user sees no actions`: log in as the read-only fixture user and expect zero `Forget` buttons.
- [ ] **Step 2:** Run `npx playwright test tests/hosts.spec.ts` from `crates/sensr-ui/e2e`. It fails before Task 6's card exists, which confirms the spec targets the new card. If Task 6 is already in, confirm by temporarily breaking the title selector.
- [ ] **Step 3:** Fix any selector or fixture gaps. Do not change product behaviour here; a real bug goes back to Task 6.
- [ ] **Step 4:** The whole e2e suite passes: `npx playwright test`.
- [ ] **Step 5:** Commit: `ui: e2e for the dashboard Hosts card`.

---

## Done when

- `cargo test --workspace`, `cargo clippy --workspace -- -D warnings` and the Playwright suite pass.
- The branch `feat/host-inventory` has a PR with the spec and plan linked.
- Rollout to the live router happens only on the owner's go: through the release workflow and `sensr-update`, as with v0.1.10.
