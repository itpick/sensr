# Per-host DNS Activity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A per-device activity page (`/ui/hosts/<mac>`) showing minutes per service and category, an hourly timeline, and every domain the device looked up. The data comes from Unbound dnstap answers joined with insight's kernel per-(host, remote IP) byte counters.

**Architecture:**
- **Unbound** is built with DNSTAP and streams client queries and responses to a unix socket.
- **`sensr-insight`** (crates/sensr-flow) does the rest:
  - decodes the stream with hand-written Frame Streams, protobuf and DNS decoders;
  - keeps a per-device remote-IP → qname map;
  - reads a new kernel counter set keyed by (local host . remote address);
  - attributes each minute's bytes to services through a built-in catalogue plus owner overrides;
  - stores the results in its SQLite.
- **API and UI:** the agent/API serve `GET /api/v1/hosts/<mac>/activity`, the UI adds a host page, and the Hosts card links to it.

**Tech Stack:** Rust, NixOS (Unbound `withDNSTAP`), nftables, SQLite (rusqlite, already used by sensr-flow), Leptos 0.8 SSR + islands, Playwright.

**Spec:** docs/superpowers/specs/2026-11-23-host-dns-activity-design.md

## Global Constraints

- **dnstap**
  - Socket path: `/run/sensr-insight/dnstap.sock`.
  - Unbound settings: `dnstap-enable: yes`, `dnstap-socket-path: <that>`, `dnstap-log-client-query-messages: yes`, `dnstap-log-client-response-messages: yes`.
  - Rendered only when insight is enabled.
  - Permissions: insight creates the socket with mode 0660, group `sensr-dnstap`; the `sensr-unbound` and `sensr-insight` users are both members of that group.
- **Kernel pair set:** kind `p` (local host . remote address) with counters, in both directions, and both families as with the other kinds. Same `ELEMENT_TIMEOUT` as the other sets, and the same `max_entries` bound.
- **Minute rule** (per device, per service, per minute): the minute is active when either
  - bytes to/from IPs attributed to the service total at least **32 768**; or
  - the device queried a domain of the service in that minute **and** moved at least **4 096** bytes to it.

  Category minutes are the **union** of that category's service minutes. "Apple/Google/Microsoft system" and "Ads & tracking" are excluded from the headline screen-time total.
- **IP → qname map, per device:** each entry lasts answer TTL + **600 s**. Caps: **4096** entries per device and **65 536** in total, evicting the oldest first.
- **Retention:**
  - `dns_queries` and `service_minutes`: **7 days**.
  - `service_days` and `domains_seen`: **90 days**.
  - Pruning works the same way as `traffic`.
- **Categories (exact names, in this order):** Video, Social, Games, Messaging, Music, Education, Shopping, Apple/Google/Microsoft system, Ads & tracking, Smart home, Other.
- **Fallback buckets:** unattributed traffic goes to service `Other (by address)` in category Other.
- **Badges:** **new** = first seen within the last 24 h. **blocked** = answered by a blocklist (A/AAAA `0.0.0.0` or `::`, or NXDOMAIN from a blocklisted name; compare against sensr-dns's blocklist semantics).
- **Override config:** `insight.dns.service_overrides: ArrayField<ServiceOverride { enabled, suffix: String (domain suffix, lowercase), service: String (1–48), category: <Category> }>`. An override beats the built-in catalogue, and the longest matching suffix wins.
- **API:** `GET /api/v1/hosts/<mac>/activity?range=today|7d&domains_page=N`. It needs both the hosts and the insight privileges.
- **Privacy:** no data leaves the router.
- **Performance:** at most 2 % of one Pi 5 core at home load. Memory is bounded by the caps above.
- **Degradation:** if the dnstap socket gets no frames for 5 min while Unbound is up, the page shows a banner (`DNS answers aren't arriving; showing lookups only.`) and the domains list is built from the existing query-log path.
- **Project rules:**
  - latest deps, **no new crates** (protobuf, Frame Streams and DNS are hand-decoded);
  - `unsafe` is forbidden;
  - Linux socket code is cfg-gated with stubs;
  - no AI attribution;
  - the island bundle stays under 430 KB brotli.
- **Toolchain:**
  - `export PATH=$HOME/.cargo/bin:$PATH CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$HOME/workspace/itpick/sensr/target`.
  - Never `cargo clean`; the target dir is shared.
  - `touch crates/sensr-ui/src/lib.rs` before `cargo leptos build --release`.
  - There is no Nix locally: Nix changes are verified in CI.

## Review Focus

1. **The same IP serves several services.** A CDN address resolves for both `youtube.com` and `googlevideo.com`, or another device's mapping points elsewhere. Attribution uses the *requesting device's* most recent mapping for that IP, never another device's. Pin in Task 4 with `ip_map_is_per_device_and_latest_wins`.
2. **Long streams with no fresh lookup.** A device streams for 60 min after a single lookup with a 300 s TTL. Its minutes keep counting, because the map entry is refreshed whenever bytes keep flowing to the IP (the expiry slides while active). Pin in Task 4 with `active_flow_keeps_mapping_alive`.
3. **Malformed or hostile dnstap frames** (truncated protobuf, varint overflow, bad Frame Streams control frames, a compressed-name loop in the DNS payload) never panic or wedge the reader, and the reader resyncs on the next frame. Pin in Task 2 with `decoders_survive_garbage`, a 10 000-iteration fixed-seed loop plus explicit cases.
4. **Device IP changes or IPv6 privacy addresses.** A client's IPv6 temporary address must still map to its MAC through the neighbour table. Traffic from an unknown IP is dropped, not attributed to a wrong host. Pin in Task 5 with `unknown_client_ip_is_ignored` and `ipv6_temporary_address_maps_via_neigh`.
5. **Clock jumps on a Pi without an RTC.** A minute bucket is never written for a time more than 1 day before the newest bucket, and a backwards jump does not double-count. Pin in Task 4 with `minute_engine_ignores_clock_jumps`.

---

### Task 1: Unbound with DNSTAP (nix + render)

**Files:**
- Modify: `nix/modules/sensr.nix`.
  - Build the Unbound package with `pkgs.unbound.override { withDNSTAP = true; }`; find where `pkgs.unbound` is referenced (~:83, ~:903).
  - Add the `sensr-dnstap` group, with `sensr-unbound` and `sensr-insight` as members.
  - Give `sensr-insight` `RuntimeDirectory = "sensr-insight"` with `RuntimeDirectoryMode = "0750"` and group `sensr-dnstap`, so Unbound can reach the socket. Check the existing unit (~:1195).
- Modify: `crates/sensr-apply/src/appliers/unbound.rs`. Render the dnstap block from Global Constraints when `doc.insight.enabled`. Find how the applier sees insight state, and pass a flag through the convert layer as the other tuning flags are passed.
- Test: the unbound applier tests and snapshots: `dnstap_rendered_when_insight_enabled`, `no_dnstap_when_insight_disabled`. Regenerate snapshots the way the crate documents.

- [ ] **Step 1:** Write the failing tests.
- [ ] **Step 2:** Run `cargo test -p sensr-apply unbound` and confirm it fails.
- [ ] **Step 3:** Implement the render and the Nix changes.
- [ ] **Step 4:** Run the tests and clippy.
- [ ] **Step 5:** Commit: `nix: build Unbound with dnstap; render the dnstap socket when insight is on`.

### Task 2: dnstap decoders (pure, `crates/sensr-flow/src/dnstap.rs`)

**Files:**
- Create: `crates/sensr-flow/src/dnstap.rs`. It is built without the `store` feature too, so it stays pure.
- DNS message parsing: reuse `sensr-fingerprint`'s DNS name and record reader if it is exposed for A/AAAA/CNAME answers. Otherwise add a small `pub mod dns` there with `parse_response(&[u8]) -> Option<DnsResponse>`, used by both crates. Do not duplicate the name decompression.

**Interfaces:**
- **Produces:**
  - `pub struct FrameReader` with `pub fn push(&mut self, bytes: &[u8]) -> Vec<Frame>`. It handles the Frame Streams bidirectional handshake (READY/ACCEPT/START/STOP control frames). Data frames come out as `Frame::Data(Vec<u8>)`; control frames are handled inside the reader. It also exposes `pub fn reply(&mut self) -> Option<Vec<u8>>`, the ACCEPT to send back.
  - `pub fn decode(frame: &[u8]) -> Option<DnstapEvent>`.
  - `pub struct DnstapEvent { pub kind: EventKind /* ClientQuery | ClientResponse */, pub client: IpAddr, pub time: i64, pub qname: String, pub qtype: u16, pub rcode: u8, pub answers: Vec<(IpAddr, u32 /*ttl*/)>, pub cnames: Vec<String> }`.
  - `pub fn is_blocked(ev: &DnstapEvent) -> bool`, per Global Constraints.
- **Field numbers:** protobuf fields follow dnstap.proto:
  - `Dnstap`: `type`=15, `message`=14.
  - `Message`: `type`=1, `socket_family`=2, `query_address`=4, `query_time_sec`=8, `query_message`=10, `response_time_sec`=12, `response_message`=14.

  Check these numbers against the upstream dnstap.proto and cite it in a comment.

- [ ] **Step 1: Write the failing tests:**
  - `frame_stream_handshake_and_data`, using hand-built control and data frames;
  - `decode_client_response_with_answers`: a hand-built protobuf around a DNS response for `www.youtube.com` with a CNAME to `youtube-ui.l.google.com` and two A records, giving the answers, TTLs and cnames;
  - `blocked_answers_detected` (0.0.0.0, ::, and NXDOMAIN);
  - `decoders_survive_garbage` (Review Focus 3).
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test -p sensr-flow --no-default-features --lib dnstap` and the full `cargo test -p sensr-flow`, then clippy.
- [ ] **Step 5:** Commit: `flow: Frame Streams and dnstap decoders`.

### Task 3: Service catalogue and overrides (`crates/sensr-flow/src/services.rs`, schema)

**Files:**
- Create: `crates/sensr-flow/src/services.rs`.
- Create: `crates/sensr-flow/data/services.tsv`, one row per line: `suffix<TAB>service<TAB>category`, embedded with `include_str!`.
  - Cover about 150 services, including at least the spec's list.
  - Include common CDN and support domains so the big services attribute well: for YouTube, `googlevideo.com`, `ytimg.com`, `youtubei.googleapis.com`, `youtube.com`, `youtu.be`; for Roblox, `rbxcdn.com`, `roblox.com`, `rbx.com`; and so on.
  - Map trackers to "Ads & tracking" and OS phone-home domains to "Apple/Google/Microsoft system".
  - This is our own data.
- Modify: `crates/sensr-schema/src/models/insight.rs`.
  - Add `pub dns: InsightDns { service_overrides: ArrayField<ServiceOverride> }`, default empty and omitted when default.
  - Add `pub enum Category` with the 11 categories, serde snake_case, plus `display()`.
  - Validate: the suffix is a valid lowercase domain suffix, the service is 1–48 chars with no control characters, and suffixes are unique.

**Interfaces:**
- **Produces:**
  - `pub struct Catalogue` with `pub fn builtin() -> &'static Catalogue` and `pub fn with_overrides(&self, o: &[ServiceOverride]) -> Catalogue`.
  - `pub fn lookup(&self, qname: &str) -> Option<(&str /*service*/, Category)>`. Matching is on the longest suffix, at a label boundary.
  - `Category` is defined in sensr-schema and reused here.

- [ ] **Step 1: Write the failing tests:**
  - `youtube_cdn_maps_to_youtube_video`;
  - `roblox_cdn_maps_to_roblox_games`;
  - `suffix_matches_on_label_boundary`: `notyoutube.com` does not match `youtube.com`;
  - `longest_suffix_wins`;
  - `override_beats_builtin`;
  - `every_category_has_services`;
  - `catalogue_rows_are_valid` (well-formed, no duplicate suffixes);
  - schema tests: `service_override_round_trips`, `bad_suffix_rejected`, `duplicate_suffix_rejected`.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test -p sensr-flow -p sensr-schema`, `cargo xtask parity --check`, and clippy.
- [ ] **Step 5:** Commit: `flow: built-in service catalogue with owner overrides`.

### Task 4: Pair counters and the attribution + minute engine

**Files:**
- Modify: `crates/sensr-flow/src/nft.rs`. Add the `Kind::Pair` sets per Global Constraints, the ruleset rules on the forward hook (as for `Remote`), and the listing parser for `(local, remote)` elements. Update the nft golden or snapshot tests in that crate.
- Create: `crates/sensr-flow/src/attrib.rs` (pure).

**Interfaces:**
- **Produces:**
  - `pub struct Attributor` with:
    - `pub fn new(caps: Caps) -> Self`;
    - `pub fn on_dns(&mut self, mac: &str, ev: &DnstapEvent, cat: &Catalogue)`;
    - `pub fn on_bytes(&mut self, mac: &str, remote: IpAddr, bytes: u64, now: i64)`;
    - `pub fn drain_minute(&mut self, minute: i64, cat: &Catalogue) -> MinuteResult`.
  - `MinuteResult { per_host: BTreeMap<String /*mac*/, HostMinute { services_active: BTreeSet<String>, queries: Vec<(String /*qname*/, u32 /*count*/, bool /*blocked*/)>, bytes_by_service: BTreeMap<String, u64> }> }`.
- Implement the Global Constraints minute rule.
- The expiry of a mapping slides forward while bytes keep flowing to that IP (Review Focus 2).

- [ ] **Step 1: Write the failing tests:**
  - `streaming_minutes_count_after_one_lookup`: a single lookup, then 40 minutes with at least 32 KB each, gives 40 active YouTube minutes;
  - `background_pings_do_not_count`: 1 KB per minute gives 0;
  - `query_plus_small_transfer_counts` (a lookup and 4 KB in the same minute);
  - `category_minutes_are_union` (YouTube and Netflix in the same minute count as 1 Video minute);
  - `ip_map_is_per_device_and_latest_wins` (Review Focus 1);
  - `active_flow_keeps_mapping_alive` (Review Focus 2);
  - `minute_engine_ignores_clock_jumps` (Review Focus 5);
  - `caps_evict_oldest` (per device and global);
  - `unattributed_goes_to_other_by_address`;
  - nft: `pair_sets_rendered`, `pair_listing_parsed`.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test -p sensr-flow` and clippy.
- [ ] **Step 5:** Commit: `flow: per-host remote counters and service-minute attribution`.

### Task 5: Store tables and the sensr-insight daemon wiring

**Files:**
- Modify: `crates/sensr-flow/src/store.rs`.
  - Add the four tables from the spec, with indexes and pruning per the Global Constraints retention.
  - Add `write_minute(&MinuteResult, minute)` and a daily rollup into `service_days`.
  - Add query functions: `host_activity(mac, range) -> HostActivity`, which returns header-less data (services with minutes and category, categories with minutes, timeline cells `(day, hour, minutes)`, and domains paged with `count`/`first_seen`/`last_seen`/`service`/`new`/`blocked`), and `today_minutes() -> BTreeMap<mac, u32>`. The today figure uses the headline screen-time categories only.
- Modify: `crates/sensr-flow/src/bin/sensr-insight.rs`.
  - Add a dnstap listener thread on Linux: bind the socket, set perms per Global Constraints, read with `FrameReader`, and send the ACCEPT reply.
  - Map client IP to MAC through `ip -j neigh show`, refreshed every sample. Reuse the `sensr_feeds::neigh` parser if sensr-flow can depend on it; otherwise parse locally, staying small.
  - Feed the `Attributor` from the dnstap events and the pair-set deltas each sample.
  - Write each closed minute.
  - Watch for 5 minutes with no frames and record a `dns_feed_stale` flag in a small status file that the API reads.
  - Degradation: if the feed is stale, read the existing query log for queries only.
- Modify: `crates/sensr-flow/src/config.rs`. Add whatever the agent must pass, such as the socket path and the overrides, and update the agent's writer of `FlowConfig`.
- Test: `crates/sensr-flow` tests against an in-memory store:
  - `host_activity_today_and_7d`;
  - `retention_prunes`;
  - `today_minutes_excludes_system_and_ads`;
  - `unknown_client_ip_is_ignored` and `ipv6_temporary_address_maps_via_neigh` (Review Focus 4), using a neigh fixture;
  - a Linux-only `dnstap_socket_end_to_end` test that writes frames to a temporary socket through the listener. It is `#[ignore]` if it needs root.

- [ ] **Step 1:** Write the failing tests.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test -p sensr-flow -p sensr-agent` and clippy (macOS, plus aarch64 Linux if zig is available).
- [ ] **Step 5:** Commit: `insight: store per-host DNS activity from the dnstap feed`.

### Task 6: API endpoint and backend

**Files:**
- Modify: `crates/sensr-api/src/native.rs` and `src/lib.rs` `ROUTES`. Add `GET /api/v1/hosts/<mac>/activity`.
  - Read the insight DB read-only, the way existing insight endpoints do (find them: Reporting › Insight).
  - Join the host header (name, label, IPs, mode, last seen) from the hosts view.
  - Privileges: hosts and insight.
  - 404 for an unknown MAC; 400 for a bad range.
- Modify: `crates/sensr-ui/src/api.rs`. Add Backend `fn host_activity(&self, mac: String, range: String, page: u32) -> BoxFuture<'_, ApiResult<HostActivityView>>`, implement it in `crates/sensr-api/src/ui.rs`, and add a mock in `mock.rs` with rich seeded data:
  - a "kid-tablet" host with YouTube, Roblox, Discord and TikTok minutes over 7 days;
  - an IoT host with only domains, one of them new and one blocked.
- Modify: the hosts view or `today_minutes` exposure, so the Hosts card can show the today figure as row field `today_minutes: Option<u32>`.
- Test: in `crates/sensr-api/tests/api.rs`, `host_activity_route` (200, 403 without the insight privilege, 404 unknown MAC, 400 bad range); a mock unit test.

- [ ] **Step 1:** Write the failing tests.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests and clippy.
- [ ] **Step 5:** Commit: `api: per-host activity endpoint`.

### Task 7: Host page UI, Hosts card link, overrides editor

**Files:**
- Modify: `crates/sensr-ui/src/app.rs` (route `/ui/hosts/:mac`), `pages.rs` (`HostPage`), `islands.rs` (small islands only), and `style/main.css`.
- Page layout, using existing card styles:
  1. **Header card:** name, smart label, MAC, IPs, mode pill, last seen.
  2. **Range toggle:** Today / 7 days, links with `?range=`; this can be SSR-only.
  3. **Services card:** rows `icon? · service · category · bar · 1 h 12 m`.
  4. **Categories card:** a stacked bar plus a legend. The headline "Screen time" total excludes the two system categories.
  5. **Timeline:** a 7 × 24 CSS grid heat strip with intensity by minutes. Each cell has a title `Tue 15:00 — 42 min` and an accessible table alternative (a visually hidden table or `aria-label`s).
  6. **Domains card:** a table with search, `new` and `blocked` pills, and paging.
  7. **Stale banner:** shown when the API says the feed is stale, with the exact copy from Global Constraints.
- **Hosts card:** the name links to `/ui/hosts/<mac>`, and rows with `today_minutes` show `1 h 12 m` in muted text.
- **Overrides editor (spec Part B):**
  - On the Domains card, each row has a "Set service" button. It opens a small dialog with suffix (prefilled with the registrable domain), service and category.
  - Saving stages and commits `insight.dns.service_overrides` through a new op. Follow the `HostLabelSet` stage-or-commit pattern and reuse its helper.
  - Bundle: stay under 430 KB; measure before and after.
- Test: component tests in `crates/sensr-ui/tests/components.rs`:
  - `host_page_renders_services_categories_timeline_domains` (mock kid-tablet);
  - `host_page_stale_banner`;
  - `hosts_card_links_to_host_page`;
  - `hosts_card_today_minutes`;
  - `assert_all_labelled` and the contrast test.

- [ ] **Step 1:** Write the failing tests.
- [ ] **Step 2:** Run the tests and confirm they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests, both clippy runs, and `cargo leptos build --release` plus bundle-size.
- [ ] **Step 5:** Commit: `ui: per-host activity page and service overrides`.

### Task 8: End to end (Playwright + VM)

**Files:**
- Create: `crates/sensr-ui/e2e/tests/host-activity.spec.ts`. Cover:
  - opening a host from the Hosts card;
  - the today/7d toggle;
  - service minutes visible;
  - domain search;
  - the new and blocked pills;
  - setting a service override and seeing the domain move to that service, then resetting it;
  - the phone layout;
  - axe on the page.
- Modify: `nix/tests/slice.nix`, inside `if not REFERENCE:`. Add a subtest in which the LAN client resolves a name served by the test's internet host and downloads at least 64 KB from it in one minute. Within 3 minutes, the router's `sensr` API or CLI must report at least 1 active minute for that host, under the service its domain maps to.
  - Use an override `suffix → "Test video" / video` committed through the CLI first, so the catalogue match is deterministic.
  - Write the Nix and Python carefully; this is verified in CI.

- [ ] **Step 1:** Write the specs.
- [ ] **Step 2:** Run the Playwright suite locally. The VM part runs in CI.
- [ ] **Step 3:** Fix selectors and fixtures only.
- [ ] **Step 4:** The whole suite passes.
- [ ] **Step 5:** Commit: `ui: e2e and VM check for per-host activity`.

---

## Done when

- All CI jobs that gate merges are green: rust, ui, xtask, nft-goldens and nix-aarch64. The `nix` VM job is flaky on main, so check its slice log for the new subtest.
- The PR is merged, released and installed on the router, with a health check.
- On the router, after about 15 minutes of normal use, at least a few hosts show service minutes.
