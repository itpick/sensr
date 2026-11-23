# Smart Host Labels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Under each MAC on the dashboard Hosts card show `maker · type` with a confidence. The label is inferred offline from the MAC's IEEE registration and from passively observed DHCP and mDNS. The owner can override the type and the maker per device.

**Architecture:**
- **New pure crate `sensr-fingerprint`**
  - An embedded IEEE OUI table.
  - DHCP and mDNS packet parsers.
  - A rule-based `classify(&Evidence) -> Label`.
- **`sensr-agent`**
  - A passive `sensr-fp` AF_PACKET sniffer on internal interfaces, plus one DNS-SD query every 15 min.
  - It records evidence on inventory rows in `hosts.json`.
  - The hosts view computes `label` at render time and merges owner overrides from config.
- **`sensr-schema`**: a new top-level `hosts` section (labels and the fingerprint switch).
- **`sensr-ipc`/`sensr-api`**: an `Op::HostLabelSet` route, using the same atomic-commit pattern as `Op::HostModeSet`.
- **`sensr-ui`**: renders the label line, a tooltip and an inline override editor.

**Tech Stack:** Rust (serde, socket2/nix AF_PACKET, cfg-gated Linux), Leptos islands, Playwright.

**Spec:** docs/superpowers/specs/2026-11-23-host-labels-design.md

## Global Constraints

- **Privacy and network behaviour**
  - No device data leaves the router.
  - No active scanning.
  - The only packet the router sends is one mDNS query (`_services._dns-sd._udp.local` PTR, IPv4 224.0.0.251:5353, plus IPv6 ff02::fb when the interface has an IPv6 link-local address).
    - Sent per internal interface at sniffer start, then every **900 s**.
  - The sniffer never transmits on its AF_PACKET socket.
  - It runs only on `internal_interfaces(doc)`, never on WAN.
- **Kinds** (schema `HostKind`, serde snake_case)
  - `phone`, `tablet`, `computer`, `tv`, `speaker`, `camera`, `printer`, `console`, `network`, `smart_home`, `server`, `wearable`, `virtual`, `unknown`.
  - Display: Phone, Tablet, Computer, TV/streaming, Speaker, Camera, Printer, Game console, Network gear, Smart home, Server, Wearable, Virtual machine, Unknown.
- **Confidence**: `high` | `medium` | `low` (serde lowercase).
- **Label wire shape** (in the hosts view, per row): `"label": {"maker": string|null, "kind": HostKind, "confidence": "...", "reasons": [string], "by": "auto"|"owner"}`.
  - Always present for rows with a MAC.
  - Absent for `id:` rows.
- **Private MAC**
  - Defined as the locally administered bit (`first_octet & 0x02 != 0`).
  - Its maker is `"Private MAC"`.
  - With no other evidence, kind is `phone` at `low` with the reason `Randomised address (phones, tablets and laptops do this)`.
  - The UI shows `Private MAC · Phone/laptop?`.
  - Exceptions, checked first:
    - `02:42:*` → maker `Docker`, kind `virtual`, `high`.
    - `52:54:00:*` → maker `QEMU/KVM`, kind `virtual`, `high`.
- **Config**
  - `hosts.labels: ArrayField<HostLabel { enabled: bool (default true), mac: MacAddr (unique), kind: Option<HostKind>, maker: Option<String> (1–64 chars, trimmed), description: Option<Description> }>`.
  - `hosts.fingerprint.enabled: bool` (default **true**).
  - The section is omitted from serialisation when it is the default.
- **Override semantics**
  - A set field in an enabled `HostLabel` replaces the auto field.
  - `by` is `"owner"` when any field came from the override.
  - Owner fields have confidence `high`, and their reason is `Set by you`.
- **Op**: `Op::HostLabelSet { mac: String, kind: Option<HostKind>, maker: Option<String> }`.
  - Both `None` removes the entry.
  - Its name is `host.label_set`.
  - It is a write.
  - Commit message: `set host label <mac> → <kind|auto>/<maker|auto>`.
  - Atomic: applied when the candidate equals head and no confirm is pending; otherwise staged. This is exactly `Op::HostModeSet`'s rule; reuse its helper.
  - REST: `POST /api/v1/hosts/label`, body `{"mac","kind","maker"}`, returns `{"result":"applied"|"staged"}`. It is covered by the existing `api/v1/hosts/*` privilege.
- **Evidence on the host row** (`hosts.rs` `Host`, serde-defaulted, omitted when empty): `evidence: { dhcp_vendor: Option<String>, dhcp_prl: Option<String> /* comma-joined decimal option codes */, dhcp_hostname: Option<String>, mdns_services: BTreeSet<String> /* max 16 */, mdns_model: Option<String>, mdns_name: Option<String> }`.
  - Strings are capped at 128 bytes and lossy UTF-8.
- **OUI table**
  - Lives in `crates/sensr-fingerprint/data/oui.tsv`, one line `HEXPREFIX\tName` per entry: 6, 7 or 9 hex digits, uppercase.
  - Sorted.
  - Embedded with `include_str!`.
  - Lookup is longest prefix first (9, then 7, then 6).
- **Project rules**
  - Latest deps; no new third-party crates (socket2, nix and ureq are already workspace deps).
  - `unsafe` is forbidden.
  - Linux-only code is cfg-gated, with stubs elsewhere (pattern: `crates/sensr-agent/src/arp_intercept.rs` `mod sys`).
  - No AI attribution in commits.
  - Commit prefixes `schema:`/`fingerprint:`/`agent:`/`api:`/`ui:`/`xtask:`/`ci:`.
- **Toolchain**
  - `export PATH=$HOME/.cargo/bin:$PATH`, and prefix cargo with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`.
  - Use `CARGO_TARGET_DIR=$HOME/workspace/itpick/sensr/target`, because disk is tight.
  - Scope commands with `-p`.
- **Checks**: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, the wasm clippy for sensr-ui, `cargo xtask parity --check`, `cargo xtask lint-fixtures`.

## Review Focus

1. **A confident wrong label.**
   - A generic maker (Espressif, Realtek, Intel, Murata, AzureWave, Foxconn, Liteon, Samsung) must never alone give more than `low`. Samsung makes phones, TVs and appliances.
   - Pin in Task 3: `generic_makers_are_low_confidence`.
2. **A conflict between signals.**
   - mDNS says `_ipp._tcp` (printer), but the hostname says `iPhone`. The higher-confidence signal wins; on a tie, the order mDNS > DHCP vendor > hostname > OUI decides.
   - Pin in Task 3: `higher_confidence_signal_wins`.
3. **Malformed or hostile packets.**
   - Truncated DHCP options, an option length past the end, mDNS name-compression loops and labels over 63 bytes must return `None`/partial without panicking.
   - Pin in Task 3: `parsers_survive_garbage`, which loops 10 000 random-ish byte strings from a fixed-seed LCG, plus specific truncation cases.
4. **Evidence churn causing constant `hosts.json` writes.**
   - A phone re-announcing the same mDNS services every few seconds must not mark the inventory changed.
   - Pin in Task 4: `same_evidence_is_not_a_change`.
5. **An override for a MAC that is not in the inventory, or a host that disappears.**
   - The view must not crash or invent a row. The override applies when the host reappears.
   - Pin in Task 5: `override_for_unknown_mac_is_kept_but_not_rendered`.

---

### Task 1: `hosts` config section and `HostKind` (`sensr-schema`)

**Files:**
- Create: `crates/sensr-schema/src/models/hosts.rs`.
- Modify: `crates/sensr-schema/src/models/mod.rs` and `document.rs` (field `pub hosts: Hosts`, `#[serde(default, skip_serializing_if = "Hosts::is_default")]`).
- Test: in-module tests, plus the existing schema/golden tests.
  - If JSON-schema snapshots exist (`grep -rn "schema.json" crates/sensr-schema/tests`), regenerate them the way that test says.

**Interfaces:**
- Produces:
  - `pub enum HostKind`: the 14 variants in Global Constraints, `#[serde(rename_all = "snake_case")]`, with `JsonSchema`, `Copy`, `Eq`, `Ord`.
  - `impl HostKind { pub fn display(self) -> &'static str; pub const ALL: [HostKind; 14] }`.
  - `pub struct Hosts { labels: ArrayField<HostLabel>, fingerprint: HostFingerprint }` and `pub struct HostFingerprint { enabled: bool }`, with defaults per Global Constraints.
  - `pub struct HostLabel` as in Global Constraints.
  - Validation: MAC unique across `labels` (the message style of `host_modes`' uniqueness check), and maker length 1–64 after trimming.

- [ ] **Step 1: Write the failing tests.**
  - `hosts_default_is_omitted`: a default `Document` serialises without a `hosts` key.
  - `host_label_round_trips`: `{"labels":[{"mac":"aa:bb:cc:dd:ee:ff","kind":"camera","maker":"Wyze"}]}` parses, gets `enabled == true`, and re-serialises equal.
  - `host_label_duplicate_mac_rejected`.
  - `host_label_maker_too_long_rejected` (65 chars).
  - `host_kind_display`: `HostKind::Tv.display() == "TV/streaming"` and `HostKind::SmartHome.display() == "Smart home"`.
- [ ] **Step 2:** `cargo test -p sensr-schema hosts` must FAIL.
- [ ] **Step 3:** Implement, following `HostMode`/`HostModeSettings` in `firewall.rs`.
- [ ] **Step 4:** `cargo test -p sensr-schema` and `cargo xtask parity --check` must pass.
- [ ] **Step 5:** Commit `schema: hosts section with owner labels and the fingerprint switch`.

### Task 2: `sensr-fingerprint` crate, OUI table, `xtask oui`, and the monthly refresh workflow

**Files:**
- Create: `crates/sensr-fingerprint/{Cargo.toml,src/lib.rs,src/oui.rs,data/oui.tsv}`, and add the crate to the workspace `members` and `[workspace.dependencies]`.
  - Depends on `sensr-schema` (for `HostKind`) only.
- Create: `crates/xtask/src/oui.rs` and the subcommand `Oui(oui::Args)` with `--check` (exit 1 if regenerating would change the file).
  - Add `ureq.workspace = true` to xtask.
- Create: `.github/workflows/oui-refresh.yml`.
  - Triggers: `schedule: cron "17 4 1 * *"` and `workflow_dispatch`.
  - Runs `cargo xtask oui`.
  - If there is a diff, opens a PR with `peter-evans/create-pull-request` (latest major), on branch `chore/oui-refresh` with title `fingerprint: refresh the IEEE OUI table`.

**Interfaces:**
- `pub fn oui::lookup(mac: &str) -> Option<&'static str>`.
  - Accepts `aa:bb:cc:dd:ee:ff`, any case.
  - Returns `None` for private MACs and unknown prefixes.
- `pub fn oui::is_private(mac: &str) -> bool`.
- `pub fn oui::parse_mac(mac: &str) -> Option<[u8; 6]>`.
- **xtask oui**
  - Downloads from `https://standards-oui.ieee.org/oui/oui.csv`, `…/oui28/mam.csv` and `…/oui36/oui36.csv`.
    - Uses the User-Agent `sensr-xtask (+https://github.com/itpick/sensr)`.
    - Retries each download 3× and fails the run on any non-200.
  - CSV columns: `Registry,Assignment,Organization Name,Organization Address`.
    - Parse quoted fields properly: names contain commas.
    - Assignment is 6, 7 or 9 hex digits.
  - Shortening (`fn short_name(&str) -> String`, unit-tested):
    1. Trim.
    2. Collapse whitespace.
    3. Repeatedly strip trailing legal suffixes, case-insensitively, with any preceding `,`/`.`/space: `co., ltd`, `co.,ltd`, `co ltd`, `company limited`, `limited`, `ltd`, `inc`, `incorporated`, `corp`, `corporation`, `gmbh`, `ag`, `s.a.`, `sa`, `b.v.`, `bv`, `llc`, `l.l.c.`, `plc`, `pty`, `s.r.l.`, `srl`, `oy`, `ab`, `as`, `a/s`, `kg`, `co`, `technology`, `technologies`, `electronics`.
       - Stop if the name would become empty.
    4. Apply an alias map, matched as a case-insensitive prefix of the original:
       - `Raspberry Pi` → `Raspberry Pi`
       - `Hon Hai Precision` → `Foxconn`
       - `Apple` → `Apple`
       - `Google` → `Google`
       - `Amazon Technologies` → `Amazon`
       - `Samsung Electronics` → `Samsung`
       - `Espressif` → `Espressif`
       - `Sonos` → `Sonos`
       - `Wyze Labs` → `Wyze`
       - `Ubiquiti` → `Ubiquiti`
       - `TP-LINK` / `TP-Link` → `TP-Link`
       - `Hewlett Packard` → `HP`
       - `Intel Corporate` → `Intel`
       - `Microsoft` → `Microsoft`
       - `Nintendo` → `Nintendo`
       - `Sony Interactive` → `PlayStation`
       - `Roku` → `Roku`
       - `Ring LLC` → `Ring`
       - `Reolink` → `Reolink`
       - `Synology` → `Synology`
       - `Netgear` → `Netgear`
       - `ASUSTek` → `ASUS`
       - `Realtek` → `Realtek`
       - `Liteon` / `Lite-On` → `Lite-On`
       - `Murata` → `Murata`
       - `AzureWave` → `AzureWave`
       - `Shenzhen` + rest → the rest's first word.
  - Output: sorted by prefix; the file starts with a `# generated by cargo xtask oui from IEEE registries; do not edit` comment line, which the loader skips.
- This task generates and commits the real table by running `cargo xtask oui` once.
  - If the network or the IEEE site blocks it, report BLOCKED. Do not hand-write the data.

- [ ] **Step 1: Write the failing tests.**
  - In `oui.rs`, using the embedded real table:
    - `lookup("b8:27:eb:7d:4e:25") == Some("Raspberry Pi")`
    - `lookup("DC:A6:32:02:8E:35") == Some("Raspberry Pi")`
    - `lookup("7c:78:b2:14:b2:de")` is `Some` (any name)
    - `lookup("02:cf:67:c6:7b:71") == None` and `is_private` is true
    - `lookup("zz")` is `None`
    - A test proving a 9-digit (MA-S) prefix wins over its 6-digit parent: find one in the table at test time by scanning for a 9-digit line whose 6-digit prefix also exists, and assert `lookup` returns the 9-digit name.
  - In xtask: `short_name_strips_suffixes`:
    - `"Wyze Labs Inc"` → `"Wyze"`
    - `"Shenzhen Bilian Electronic Co.,Ltd"` → `"Bilian"`
    - `"Hon Hai Precision Ind. Co.,Ltd."` → `"Foxconn"`
    - `"Raspberry Pi Trading Ltd"` → `"Raspberry Pi"`
    - `"Brother Industries, Ltd."` → `"Brother Industries"`
  - In xtask: `csv_parses_quoted_commas`.
- [ ] **Step 2:** The tests fail (no crate or table).
- [ ] **Step 3:** Implement. Run `cargo xtask oui` to produce `data/oui.tsv`. The expected size is about 1–2 MB; report the line count.
- [ ] **Step 4:** `cargo test -p sensr-fingerprint -p xtask`, `cargo xtask oui --check` (exit 0), and clippy must all pass.
- [ ] **Step 5:** Commit `fingerprint: embedded IEEE OUI table and xtask oui` and `ci: monthly OUI refresh PR` (two commits).

### Task 3: Packet parsers and the `classify` rules (`sensr-fingerprint`)

**Files:**
- Create: `crates/sensr-fingerprint/src/{dhcp.rs,mdns.rs,classify.rs}`.

**Interfaces:**
- `pub struct DhcpInfo { pub chaddr: [u8;6], pub msg_type: Option<u8>, pub hostname: Option<String>, pub vendor_class: Option<String>, pub prl: Option<String> }`.
- `pub fn dhcp::parse_bootp(udp_payload: &[u8]) -> Option<DhcpInfo>`.
  - Requires op=1, htype=1, hlen=6 and the magic cookie `63 82 53 63`.
  - Options: 12, 53, 55 (codes comma-joined, e.g. `"1,3,6,15,119,252"`), 60. It stops at 255 and skips 0.
- `pub struct MdnsInfo { pub services: Vec<String> /* e.g. "_googlecast._tcp" */, pub model: Option<String>, pub instance: Option<String> }`.
- `pub fn mdns::parse(udp_payload: &[u8]) -> Option<MdnsInfo>`.
  - It reads responses only (QR=1), from the answer, authority and additional sections.
  - Services:
    - From PTR records under `_services._dns-sd._udp.local`, the target service type.
    - From any PTR record whose owner is `_x._tcp|_udp.local`, that owner's service type.
  - Model comes from TXT keys `model=`, `md=` and `am=` (case-insensitive key), taking the first non-empty value.
  - `instance` comes from the instance label of an SRV/TXT owner (e.g. `Living Room._googlecast._tcp.local` → `Living Room`).
  - Name decompression follows pointers with a hop limit of 16 and rejects labels over 63 bytes.
- `pub struct Evidence<'a> { pub mac: &'a str, pub hostname: Option<&'a str>, pub dhcp_vendor: Option<&'a str>, pub dhcp_prl: Option<&'a str>, pub mdns_services: &'a [String], pub mdns_model: Option<&'a str> }`.
- `pub enum Confidence { Low, Medium, High }`, ordered.
- `pub struct Label { pub maker: Option<String>, pub kind: HostKind, pub confidence: Confidence, pub reasons: Vec<String> }`.
- `pub fn classify(e: &Evidence) -> Label`.
- **Algorithm**
  1. **Maker.** VM/container prefixes (Global Constraints) come first. Otherwise, if private, the maker is `"Private MAC"`. Otherwise `oui::lookup`.
     - When `mdns_model` starts with an Apple model family (`iPhone`, `iPad`, `Mac`, `MacBook`, `iMac`, `AppleTV`, `AudioAccessory`, `Watch`) and the maker is private or None, the maker becomes `"Apple"`.
  2. **Candidates.** Collect `(kind, confidence, reason)` from each signal using the table below.
  3. **Pick.** Highest confidence wins. Ties go by signal order mDNS model > mDNS service > DHCP vendor > hostname > DHCP PRL > maker.
  4. **Fallbacks.**
     - No candidates on a private MAC: `phone`/`low`.
     - No candidates otherwise: `unknown`/`low`.
  5. **Reasons.** `reasons` lists every contributing signal, winner first, in the forms:
     - `MAC maker: Wyze`
     - `mDNS service: _googlecast._tcp`
     - `mDNS model: MacBookPro18,1`
     - `DHCP vendor class: android-dhcp-14`
     - `Host name: iPhone`
     - `DHCP fingerprint: Windows`
     - `Randomised address (phones, tablets and laptops do this)`
- **Rule table** (`const` slices; a builder may add rows but must test each one):
  - **mDNS model, High**
    - `iPhone*` → phone; `iPad*` → tablet
    - `MacBook*`, `Mac*`, `iMac*` → computer
    - `AppleTV*` → tv; `AudioAccessory*` → speaker (HomePod); `Watch*` → wearable
    - `Chromecast*` / `Google TV*` → tv; `Google Home*` / `Google Nest*` / `Nest*` → speaker
  - **mDNS service, High**
    - `_ipp._tcp`, `_ipps._tcp`, `_printer._tcp`, `_pdl-datastream._tcp` → printer
    - `_googlecast._tcp`, `_androidtvremote2._tcp` → tv
    - `_raop._tcp` without `_companion-link._tcp` → speaker
    - `_sonos._tcp`, `_spotify-connect._tcp` → speaker
    - `_hap._tcp` → smart_home
    - `_smb._tcp` + `_adisk._tcp` → server
    - `_companion-link._tcp` → phone at **Medium** (iPhone/iPad/Mac all advertise it)
  - **DHCP vendor class**
    - `android-dhcp-*` → phone, High
    - `MSFT 5.0` → computer, High
    - `dhcpcd-*` → computer, Low
    - `udhcp*` → network, Low (embedded Linux)
    - `HUAWEI:*` / `ubnt` → network, Medium
  - **Host name** (case-insensitive regexes; the `regex` crate is a workspace dep)
    - Medium:
      - `^iphone` → phone; `^ipad` → tablet; `^(galaxy|sm-[a-z0-9]+|pixel|oneplus)` → phone
      - `^(desktop|laptop)-[a-z0-9]{7}$` → computer (Windows defaults); `macbook|imac|mac-?mini` → computer
      - `^hp[0-9a-f]{6}$` / `^(brw|epson|canon)` → printer
      - `^(chromecast|roku|appletv|fire-?tv)` → tv; `^(xbox|playstation|ps[45]|nintendo|switch)` → console
      - `^(ring|wyze|reolink|camera|cam-)` → camera; `^(sonos|homepod|echo)` → speaker
      - `^(esp|tasmota|shelly|tuya)` → smart_home
      - `^(sw|switch|ap|unifi|usw|uap|ism-sw)[-_]?` → network
    - Low:
      - `^(pi|rpi|raspberrypi|nas|server|node|picknode)` → server
  - **DHCP PRL, Medium**
    - Exact strings for well-known OS families: macOS/iOS `1,121,3,6,15,108,114,119,252,95,44,46` → phone (iOS vs macOS ambiguous; use the reason `DHCP fingerprint: Apple`, kind computer at **Low** instead).
    - Windows 10/11 `1,3,6,15,31,33,43,44,46,47,119,121,249,252` → computer.
    - The builder adds Android and Linux strings from public observation, written as our own data.
  - **Maker**
    - Medium (single-purpose makers):
      - Wyze, Ring, Reolink, Arlo, Hikvision, Dahua → camera
      - Sonos, Bose → speaker
      - Roku → tv
      - Nintendo, PlayStation → console
      - Ubiquiti, TP-Link, Netgear, Cisco, Aruba, MikroTik → network
      - Synology, QNAP → server
      - Brother, Canon, Epson, HP → printer, **Low** for HP and Canon (they make computers and cameras too)
      - Raspberry Pi → server, **Low**
      - Espressif, Tuya, Shelly → smart_home, **Low**
      - Apple, Samsung, Google, Amazon, Intel, Realtek and other generic makers → no candidate.

- [ ] **Step 1: Write the failing tests.**
  - `dhcp_discover_parses`: a hand-built DISCOVER with options 53=1, 12=`"iPhone"`, 55=`[1,3,6,15,119,252]` and 60=`"android-dhcp-14"` gives each field.
  - `mdns_response_parses`: a hand-built response with a PTR `_services._dns-sd._udp.local → _googlecast._tcp.local`, a TXT `md=Chromecast` and compressed names gives the services and the model.
  - `parsers_survive_garbage`, plus explicit cases:
    - an option length past the end
    - a compression pointer loop
    - a 64-byte label
    - a zero-length payload
  - `classify` cases:
    - `wyze_is_camera_medium`: OUI 7c:78:b2 → `Wyze · camera · medium`.
    - `pi_is_server_low`: b8:27:eb.
    - `private_mac_defaults_to_phone_low` (`02:cf:67:…`).
    - `docker_prefix_is_virtual`.
    - `chromecast_model_is_tv_high`.
    - `android_vendor_class_is_phone_high`.
    - `hp_printer_hostname` (`HPC2E1D9` → printer, medium).
    - `generic_makers_are_low_confidence`: Espressif-only gives at most low; Samsung-only gives `unknown`.
    - `higher_confidence_signal_wins`: an `_ipp._tcp` service plus the hostname `iPhone` gives printer/high, and the reasons contain both, printer first.
    - `apple_model_sets_maker_on_private_mac`: a private MAC with `mdns_model = "iPhone15,2"` gives maker `Apple`, phone/high.
- [ ] **Step 2:** The tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p sensr-fingerprint` and clippy must pass.
- [ ] **Step 5:** Commit `fingerprint: DHCP and mDNS parsers and label rules`.

### Task 4: Evidence capture and the auto label in the hosts view (`sensr-agent`)

**Files:**
- Create: `crates/sensr-agent/src/fingerprint.rs`.
  - It holds the `Sniffer` (thread `sensr-fp`).
  - It uses a `PacketSource` trait with `recv(&self, buf) -> io::Result<(usize, u32 /*ifindex*/)>`, with an AF_PACKET implementation (`ETH_P_ALL`, read-only, `PACKET_OUTGOING` frames skipped) and a mock for tests.
  - It parses Ethernet → IPv4/IPv6 → UDP. It keeps only UDP dst 67 (DHCP from clients), or src/dst 5353 when the destination is multicast.
  - Evidence is keyed by **source Ethernet MAC**, except DHCP, which uses `chaddr`.
  - Mapping the ifindex to an internal interface reuses the device/index lookup pattern in `arp_intercept`.
  - A `Querier` sends the DNS-SD PTR query over a normal UDP socket bound per interface (`IP_MULTICAST_IF` by interface address) at start, then every 900 s. A send error is logged at debug level and ignored.
- Modify: `crates/sensr-agent/src/hosts.rs`.
  - `Host` gains `#[serde(default, skip_serializing_if = "Evidence::is_empty")] pub evidence: HostEvidence`.
  - The new `HostCollector::record_evidence(&self, mac: &str, ev: EvidenceUpdate)` merges into the row only if the row exists. It never creates rows; the inventory stays driven by leases and neighbours.
    - It marks a change only when the merged evidence differs.
    - `absorb` merges evidence, with the MAC row winning.
  - `view()` adds `label` for MAC rows: `sensr_fingerprint::classify` on the row's evidence (hostname = `lease_hostname` or `evidence.dhcp_hostname`), with `by: "auto"`.
- Modify: `crates/sensr-agent/src/slice_applier.rs`, or wherever the collector starts.
  - Start the sniffer when `doc.hosts.fingerprint.enabled` is true and there are internal interfaces.
  - Stop it when the setting is off.
  - Update its interface list on each apply.
  - Pattern: the interceptor ownership in `slice_applier.rs` (~line 57/191).
- Modify: `crates/sensr-agent/tests/golden/hosts-view.json`, or its equivalent, to add `label` to existing rows. Regenerate it the way its test documents, and review the diff.
- Modify: NixOS module, only if the agent lacks `CAP_NET_RAW`. ARP interception already needs it; check `nix/modules/sensr.nix`.

- [ ] **Step 1: Write the failing tests.**
  - `sniffer_records_dhcp_evidence`: the mock source yields an Ethernet+IPv4+UDP 68→67 DISCOVER from `aa:bb:cc:00:00:01` on the LAN ifindex, so that row's evidence has `dhcp_vendor`/`dhcp_prl`/`dhcp_hostname`.
  - `sniffer_ignores_wan_and_unknown_ifindex`.
  - `sniffer_records_mdns_services_capped_at_16`.
  - `same_evidence_is_not_a_change`: recording the same update twice returns `Change::None` (or this module's equivalent) the second time.
  - `evidence_for_unknown_mac_creates_no_row`.
  - `view_has_auto_label`: a row with MAC `7c:78:b2:…` has `label.kind == "camera"` and `label.by == "auto"`; an `id:` row has no `label`.
  - `querier_sends_one_query_per_interval`: with a mock clock and a mock sender, there is 1 send per interface at start, none at +899 s, and 1 at +900 s.
  - `fingerprint_disabled_starts_nothing`.
- [ ] **Step 2:** The tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p sensr-agent` and clippy, also with `--target x86_64-unknown-linux-gnu` if that toolchain target is installed (`cargo check` at least, so the cfg-linux code compiles), must pass.
- [ ] **Step 5:** Commit `agent: passive DHCP/mDNS evidence and auto host labels`.

### Task 5: Owner overrides, `Op::HostLabelSet`, and the REST route (`sensr-ipc`, `sensr-agent`, `sensr-api`)

**Files:**
- Modify: `crates/sensr-ipc/src/proto.rs` (`Op::HostLabelSet`, `is_write`, `op_name`).
- Modify: `crates/sensr-agent/src/agent.rs`.
  - Add a dispatch arm.
  - Factor out the atomic stage-or-commit used by `HostModeSet` (agent.rs ~970–1010) into a shared helper rather than copying it.
- Modify: `crates/sensr-agent/src/hosts.rs`.
  - `set_document` builds `labels: BTreeMap<mac, HostLabel>` from enabled entries.
  - `view()` overlays them per Global Constraints.
- Modify: `crates/sensr-api/src/native.rs` and `src/lib.rs` (`POST /api/v1/hosts/label` added to `ROUTES`).
- Modify: `crates/sensr-api/src/ui.rs` (the UI backend's `set_host_label`).
- Test: `crates/sensr-agent/tests/agent_ipc.rs`, `hosts.rs`, `crates/sensr-api/tests/api.rs`, and the proto test.

- [ ] **Step 1: Write the failing tests.**
  - `host_label_set_is_write`.
  - `label_set_applies_on_clean_head`: the result is `applied`, the committed doc has the entry, and the commit message is exactly `set host label aa:bb:cc:dd:ee:ff → camera/auto`.
  - `label_set_both_none_removes_entry`.
  - `label_set_stages_when_candidate_is_dirty`.
  - `label_set_stages_when_confirm_pending`.
  - `label_set_readonly_forbidden`.
  - `view_overlays_owner_label`:
    - kind set, maker unset → kind from owner, maker from OUI, `by == "owner"`, reasons start with `Set by you`.
    - a disabled entry is ignored.
  - `override_for_unknown_mac_is_kept_but_not_rendered`.
  - `set_host_label_route`: 200 with the result for a hosts-privileged user, 403 for read-only; the ACL walk still passes.
- [ ] **Step 2:** The tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p sensr-ipc -p sensr-agent -p sensr-api` and clippy must pass.
- [ ] **Step 5:** Commit `agent: HostLabelSet op, REST route and owner labels in the hosts view`.

### Task 6: UI label line, tooltip and inline override editor (`sensr-ui`)

**Files:**
- Modify: `crates/sensr-ui/src/runtime.rs`.
  - `HostRow` gains `#[serde(default)] pub label: Option<HostLabelView>`.
  - `HostLabelView { maker: Option<String>, kind: String, confidence: String, reasons: Vec<String>, by: String }`.
  - Add `fn text(&self) -> String`, which renders:
    - `"<maker> · <Kind display>"`;
    - with no maker, just the kind display;
    - for kind `unknown`, just the maker, or `""` when there is no maker either;
    - for the private-MAC-only case, exactly `Private MAC · Phone/laptop?`;
    - otherwise a `?` suffix when the confidence is `low`.
- Modify: `crates/sensr-ui/src/api.rs` (Backend `set_host_label(mac, kind: Option<String>, maker: Option<String>) -> ApiResult<String>`), `actions.rs` (server fn), and `mock.rs`.
  - Seed labels:
    - bench-pi: `Raspberry Pi · Server`, low.
    - one Wyze camera, medium.
    - one private MAC.
    - one owner-labelled host.
  - Mock `set_host_label` mutates and returns `"applied"`.
- Modify: `crates/sensr-ui/src/islands.rs`, in the MAC cell of the `HostsCard` row:

  ```html
  <td class="num host-mac">
    aa:bb:…
    <span class="host-label [host-label-guess]" title="<reasons joined by \n>">
      <span class="host-kind-icon" aria-hidden="true">…</span>Wyze · Camera
    </span>
    <button class="icon-btn host-label-edit" aria-label="Edit label for <host>">✎</button>
  </td>
  ```

  - The label goes on its own line (`display:block`), muted, at 12px; `host-label-guess` makes it italic.
  - The edit button is hidden when the card is read-only.
  - The editor is inline in the same cell. It contains:
    - a `<select aria-label="Type for <host>">`: `Auto` (value `""`), then the 14 kinds by display name in `HostKind::ALL` order;
    - an `<input type="text" aria-label="Maker for <host>" placeholder="Auto">`;
    - `Save` and `Reset to auto`, both `btn btn-sm`.
  - Save calls `set_host_label`, then refreshes; a `"staged"` result shows the existing staged note text `Staged — Apply to take effect`.
  - Errors use the card's existing `mode_error` line, or a sibling of it.
  - Icons are single Unicode glyphs:
    - phone 📱, tablet 📱, computer 💻, tv 📺, speaker 🔊, camera 📷, printer 🖨, console 🎮
    - network 🌐, smart_home 🏠, server 🗄, wearable ⌚, virtual 🧩, unknown •
- Modify: `crates/sensr-ui/style/main.css`, for `.host-label`, `.host-label-guess` and `.host-label-edit` (compact, 24px; 44px on mobile, following the media block).
- Test: `crates/sensr-ui/tests/components.rs`.

- [ ] **Step 1: Write the failing tests.**
  - `host_label_line_renders`: bench-pi's MAC cell contains `.host-label` with the text `Raspberry Pi · Server?`, the class `host-label-guess`, and a `title` containing `MAC maker: Raspberry Pi`.
  - `host_label_private_mac_text`: exactly `Private MAC · Phone/laptop?`.
  - `host_label_owner_not_guess`: the owner-labelled row has no `host-label-guess`, and its title contains `Set by you`.
  - `host_label_edit_hidden_read_only`.
  - `host_label_editor_options`: the type select has 15 options, the first `("", "Auto")`, then `("phone","Phone")` … `("unknown","Unknown")`.
  - `assert_all_labelled` still passes.
- [ ] **Step 2:** The tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p sensr-ui --features ssr --test components`, the wasm clippy, and `cargo leptos build` (if cargo-leptos is installed; otherwise note it, since CI runs it) must pass.
- [ ] **Step 5:** Commit `ui: smart host labels and inline label override on the Hosts card`.

### Task 7: End-to-end tests (Playwright)

**Files:**
- Create: `crates/sensr-ui/e2e/tests/host-labels.spec.ts`, using the same helpers as `host-modes.spec.ts`.
- Modify: `crates/sensr-ui/e2e/fixtures/agent-seed.json` if the stack run needs seeded evidence or labels.

- [ ] **Step 1: Write the specs.**
  - `shows a smart label under the MAC`: bench-pi's row shows `Raspberry Pi · Server?`.
  - `override the type`: open the editor on bench-pi, choose `Camera`, Save; the label becomes `Raspberry Pi · Camera` (no `?`). Reset to auto restores `Raspberry Pi · Server?`. Leave the state clean, as `host-modes.spec.ts` does with `discardStaged`.
  - `override the maker`: type `Pi Foundation`, Save; the label starts `Pi Foundation ·`. Then reset.
  - `read-only user has no label editor`.
- [ ] **Step 2:** From `crates/sensr-ui/e2e`, run `npx playwright test tests/host-labels.spec.ts`. If the local build can't run, write the specs and rely on CI; report which.
- [ ] **Step 3:** Fix selectors and fixtures only. A product bug goes back to Task 6.
- [ ] **Step 4:** The whole suite passes in CI.
- [ ] **Step 5:** Commit `ui: e2e for smart host labels`.

---

## Done when

- `cargo test --workspace`, clippy (workspace and wasm), `fmt --check`, `xtask parity --check`, `lint-fixtures`, `xtask oui --check` and the Playwright suite all pass in CI. The nix VM jobs are known to be flaky on main and are not a gate.
- A PR for `feat/host-labels` links the spec and this plan.
- After merge: release, then install on the router, as pre-authorized for Hosts-card updates. Verify that at least a few of the 56 nameless hosts get a label other than `unknown`.
