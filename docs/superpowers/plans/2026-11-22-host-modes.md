# Per-host Modes (Isolated, Quarantine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** From the dashboard Hosts card an operator puts a single device in **Normal**, **Isolated** or **Quarantine**. Isolated loses the other local networks but keeps the internet and the router; Quarantine loses everything but DHCP/DNS/NTP. Enforcement is two layers: nftables MAC rules for anything crossing the router, and an ARP interceptor for same-LAN traffic on the flat LAN.

**Architecture:**
- Config (`sensr-schema`): `firewall.host_modes` (per-MAC) and `firewall.host_mode_settings.arp_intercept`. Normal = no entry.
- Rules (`sensr-rules`): a new `host_modes` module registers nft filter rules beside `isolation`; the IR gains a source-MAC-set operand (`ether saddr @set`); the nft renderer declares two MAC sets and two reverse-direction IP sets. pf emits a comment only.
- Agent (`sensr-agent`): `Op::HostModeSet` edits `firewall.host_modes` and commits atomically; the Hosts view gains `mode`; on lock-down the agent cuts conntrack; an `arp_intercept` task owned by the slice applier poisons same-LAN ARP and heals on exit. The sysctl applier sets `send_redirects=0` whenever interception is configured.
- UI (`sensr-ui`): a Mode select and badges per MAC row, footer help, a self-quarantine guard, `set_host_mode` server fn and MockBackend parity.

**Tech Stack:** Rust (tokio, serde, axum, Leptos islands), nftables JSON, `ip -j neigh`/rtnetlink, AF_PACKET raw sockets (`nix`, cfg linux), Playwright e2e.

**Spec:** docs/superpowers/specs/2026-11-22-host-modes-design.md

## Global Constraints

- **Modes built this piece:** Normal, Isolated, Quarantine. `allowlist` is **not** an accepted value (piece 3).
- **Key:** modes are keyed by lowercase MAC; `id:` hosts cannot have a mode. MAC unique across `host_modes`.
- **Priorities:** Isolated rules register at **priority 6** (after isolation); Quarantine rules register at **priority 5**, *before* the anti-lockout rule (also priority 5), registered earlier so they win within the band.
- **Chains covered:** both input (traffic to the router) and the forward chain. A forward-chain "pass" is a `return`; correctness must not depend on an early accept.
- **Isolated** (per internal interface, from a locked MAC): pass to `(self)`; block to every internal network; pass the rest.
- **Quarantine** (per internal interface, from a locked MAC): pass to `(self)` for DHCP (udp 67), DNS (udp/tcp 53), NTP (udp 123); block everything else.
- **Reverse direction:** on every internal interface, block traffic *to* `host_locked_v4`/`host_locked_v6` from any internal network except from the router itself.
- **nft set names:** `host_isolated`, `host_quarantine` (type `ether_addr`); `host_locked_v4` (`ipv4_addr`), `host_locked_v6` (`ipv6_addr`).
- **Rule labels:** `#ref` = `ui/core/dashboard`, descr = `host mode <kind>: <what>` plus the entry description.
- **pf:** nft-only; pf renders a single comment line per host-mode rule, no rule body.
- **IPv6 same-LAN:** out of scope (no NDP spoofing). IPv6 across the router is still MAC-enforced on ingress.
- **ARP interception:** IPv4 only; one global switch `arp_intercept`, default **on**; runs only on `internal_interfaces(doc)`, never the router/gateway; every exit path heals with true MACs.
- **sysctl:** whenever interception is configured (arp_intercept on and ≥1 host locked), `net.ipv4.conf.all.send_redirects=0` and the same for each internal interface's device.
- **Atomic apply:** `Op::HostModeSet` stages-and-commits in one agent operation under the inner lock; it commits only if the candidate equals head apart from this entry *and* no provisional commit is pending; otherwise it stages. Returns `applied` or `staged`.
- **Self-protection:** the op and the UI refuse to Quarantine the MAC of the requesting client (matched by request source IP against the inventory). Message: `That's the device you're using — quarantine it from another device.`
- **ACL:** no new privilege. Mode changes go through `page-sensr-hosts` (which already covers `api/v1/hosts/*`) plus config write; `user-config-readonly` sees the mode but cannot change it.
- **Project rules:** latest deps, add no new crates unless needed (`nix` is already a transitive dep; promote to a direct, cfg-gated dependency); every behaviour tested; nft goldens on `home-router`; no AI attribution in commits; commit message prefixes in repo style (`schema:`/`rules:`/`agent:`/`api:`/`ui:`).
- **Toolchain:** `export PATH=$HOME/.cargo/bin:$PATH` (rustc 1.100); prefix cargo with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` (disk is tight); scope with `-p <crate>`.
- **unsafe is forbidden workspace-wide.** Raw-socket and conntrack code compiles on macOS: gate Linux-only paths with `cfg(target_os = "linux")` and provide stubs elsewhere, as `sensr-monitor/src/icmp.rs::device_index` does. Use `nix`'s safe `socket`/`sendto(LinkAddr)` API for AF_PACKET; do not hand-roll `sockaddr_ll`.
- **nft golden update:** `SENSR_GOLDEN_UPDATE=1 cargo test -p sensr-rules`; goldens live in `crates/sensr-rules/tests/golden/` and are kernel-checked by `scripts/nft-check-goldens.sh` (`nft -c -j -f`). Keep every new golden loadable.
- **xtask CI checks:** `cargo xtask parity --check`, `cargo xtask lint-fixtures`, plus `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings`.

## Review Focus

1. **Quarantine must beat anti-lockout.** Both are priority 5; order of registration decides. If the anti-lockout pass is registered first, a quarantined admin device still reaches the GUI. Pin in Task 3: `quarantine_blocks_the_gui_before_anti_lockout` asserts the quarantine `block to (self):443` rule precedes every `anti-lockout` pass in `compile(doc).filter` for the same interface/priority.
2. **The reverse-direction block must not break Normal hosts reaching a locked host's *old* address.** The IP set holds only addresses currently seen for a locked MAC; a stale address lingering in the set silently blackholes a reassigned IP. Pin in Task 3: `reverse_block_targets_only_locked_addresses` asserts `host_locked_v4` set-update contents equal exactly the locked MACs' current IPv4s (Task 3 `host_mode_set_updates`).
3. **Forward-chain return vs accept.** A quarantine "pass to (self)" is a `return` in the forward chain, so a later blanket block in the same chain could still drop DHCP relay / inter-LAN DNS. Pin in Task 3: `quarantine_forward_chain_passes_dns_to_router` checks the nft golden contains the quarantine DNS-to-self rule in both the input and forward dispatch for the interface.
4. **Atomic commit must not apply someone else's half-finished edit.** If another user has a dirty candidate, the mode change must stage, not commit. Pin in Task 5: `mode_set_stages_when_candidate_is_dirty` and `mode_set_stages_when_confirm_pending`.
5. **Heal must run on agent crash/stop, or devices stay broken.** If the `Drop`/shutdown path does not send corrective ARP, a quarantined neighbour's table keeps pointing at the router after the agent dies. Pin in Task 7: `heal_plan_restores_true_macs` and a `Drop` test `collector_shutdown_sends_heal` using the mock socket.

---

### Task 1: Config model and validation (`sensr-schema`)

**Files:**
- Modify: `crates/sensr-schema/src/models/firewall.rs` — add `host_modes`, `host_mode_settings` to `Firewall`; add `HostMode`, `HostModeKind`, `HostModeSettings`; extend `impl Validate for Firewall`.
- Test: `crates/sensr-schema/tests/models.rs` (new `host_mode_rules`); `crates/sensr-schema/tests/schema.rs` already walks the slice — confirm it still passes.

**Interfaces:**
- Produces:
  - `pub struct HostMode { #[serde(default = "yes")] pub enabled: bool, pub mac: MacAddr, pub mode: HostModeKind, #[serde(default, skip_serializing_if = "Option::is_none")] pub description: Option<Description> }` (derive `Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema`, `#[serde(deny_unknown_fields)]`). Use the concrete newtype `MacAddr` (`super::super::fields::MacAddr`), as other model structs do; its `Display` is already lowercase.
  - `#[serde(rename_all = "lowercase")] pub enum HostModeKind { Isolated, Quarantine }` — closed; piece 3 adds `Allowlist`. Derive `JsonSchema` + copy.
  - `pub struct HostModeSettings { #[serde(default = "yes")] pub arp_intercept: bool }` with `#[serde(default)]` at the field in `Firewall`; add `is_default`/`Default` so a factory doc round-trips.
  - In `Firewall`: `#[serde(default, skip_serializing_if = "ArrayField::is_empty")] pub host_modes: ArrayField<HostMode>` and `#[serde(default)] pub host_mode_settings: HostModeSettings`.
- Consumes: `ArrayField`, `MacAddr`, `Description`, `yes`, `check::unique`, `RefContext`, `Validations`, `ValidatorKind`.

- [ ] **Step 1: Write failing tests** in `models.rs`:
  - `host_mode_rules`: build a `Firewall`; push two `HostMode`s with the same MAC → `validate` reports a `host_modes` duplicate-MAC error with message `A host mode for this MAC already exists.`; distinct MACs validate clean; a JSON doc with `"mode":"allowlist"` fails to deserialize (assert `serde_json::from_value::<HostMode>` is `Err`); `#[serde(deny_unknown_fields)]` rejects an extra key.
  - Assert `HostModeSettings::default().arp_intercept == true` and that a `Firewall::default()` serialises without `host_modes`/with `host_mode_settings` default (every validation message ends in a period — covered by the existing `every_validation_message_is_a_sentence` test, so keep the message a full sentence).
- [ ] **Step 2:** `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo test -p sensr-schema host_mode` — fails (types undefined).
- [ ] **Step 3:** Implement the structs and the validation arm: in `impl Validate for Firewall`, after the `isolation` block, `let hm = at.join("host_modes"); check::unique(self.host_modes.iter().map(|(id, h)| (hm.join(id), Some(h.mac.to_string()))), "mac", "A host mode for this MAC already exists.", out);`
- [ ] **Step 4:** `cargo test -p sensr-schema` and `cargo clippy -p sensr-schema -- -D warnings` clean; `cargo xtask lint-fixtures` still passes.
- [ ] **Step 5:** Commit: `schema: per-host modes model and validation`.

### Task 2: Source-MAC-set operand in the rule IR and nft renderer (`sensr-rules`)

**Files:**
- Modify: `crates/sensr-rules/src/ir.rs` — add `Addr::MacSet(String)`.
- Modify: `crates/sensr-rules/src/compile.rs` — add `Field::EtherSaddr`; handle `Addr::MacSet` in `addr_alternatives`; make a MAC-only rule family-agnostic in `families`/`needs_family`/`literal_family`.
- Modify: `crates/sensr-rules/src/render/nft.rs` — `field_expr(Field::EtherSaddr) => Expr::Payload("ether", "saddr")`; declare `ether_addr` MAC sets in `emit_sets`.
- Modify: `crates/sensr-rules/src/render/pf.rs` — `addr_text`/`filter_rule`: a rule whose source is `Addr::MacSet` renders as a single `# host mode (nft-only): <descr>` comment, no rule body.
- Test: `compile.rs` and `render/nft.rs` `#[cfg(test)]`.

**Interfaces:**
- Produces:
  - `ir::Addr::MacSet(String)` — the set *name* (without `@`); source-only.
  - `compile::Field::EtherSaddr` (ordered before `Saddr`, i.e. cheap; it is family-independent). Lowers to `Match { field: Field::EtherSaddr, neg: false, val: Val::SetRef(name) }`. No `Val::Fam` nfproto match is added for a MAC-only rule.
- Consumes: existing `Val::SetRef`, `Expr::Payload`, `Expr::set_ref`.
- `families(spec)`: when the only source term is `Addr::MacSet` and there is no other family-bearing address, return `vec![None]` (one family-agnostic alternative). `needs_family(Addr::MacSet) == false`, `literal_family(Addr::MacSet) == None`.

- [ ] **Step 1: Write failing tests** in `compile.rs`/`nft.rs`:
  - `mac_set_source_lowers_to_ether_saddr`: a `FilterRule` with `src.addr = Addr::MacSet("host_isolated".into())`, action Block, dst `IfaceNet{lan}` lowers to matches containing `Match{Field::EtherSaddr, Val::SetRef("host_isolated")}`.
  - `mac_only_rule_needs_no_family`: a rule with `Addr::MacSet` source and `Addr::Any` dst lowers without error to exactly one alternative with `fam == None`.
  - In `nft.rs`: `ether_saddr_renders` — `field_expr(Field::EtherSaddr)` is `Expr::Payload("ether","saddr")`; a set-ref right operand renders `@host_isolated`.
- [ ] **Step 2:** `cargo test -p sensr-rules mac_set` / `ether_saddr` — fails.
- [ ] **Step 3:** Implement the variants and lowering; add `ether_addr` set emission helper `compile::host_mode_set(name: &str) -> String` returning the name verbatim (sets are pre-named).
- [ ] **Step 4:** `cargo test -p sensr-rules` and clippy clean.
- [ ] **Step 5:** Commit: `rules: source-MAC-set operand (ether saddr @set) in IR and nft`.

### Task 3: Host-mode rules module and goldens (`sensr-rules`)

**Files:**
- Create: `crates/sensr-rules/src/host_modes.rs` — rule registration + set builders.
- Modify: `crates/sensr-rules/src/lib.rs` (`pub mod host_modes;`), `crates/sensr-rules/src/document.rs` (call `host_modes::register` and thread sets into `Compiled`/`nft::Policy`), `crates/sensr-rules/src/render/nft.rs` (`emit_sets` declares the four host-mode sets; `render_set_updates` reuse for the IP sets).
- Test: `crates/sensr-rules/tests/host_modes.rs`; goldens `tests/golden/host-modes-isolated.nft.json` and `tests/golden/host-modes-quarantine.nft.json` on the `home-router` corpus.

**Interfaces:**
- Produces:
  - `pub struct HostModeEntry<'a> { pub mac: &'a MacAddr, pub kind: HostModeKind, pub description: &'a str }`
  - `pub fn register(rs: &mut Ruleset, entries: &[HostModeEntry<'_>], ctx: &Context<'_>)` — for each enabled entry, on every `internal_interfaces`-equivalent interface in `ctx`, registers the input+forward rules below, with `#ref = "ui/core/dashboard"`. The MAC's set membership (`host_isolated` vs `host_quarantine`) is implied by the set name used in the rule's `Addr::MacSet`; the rule matches `ether saddr @host_<kind>`.
  - `pub struct HostModeSets { pub isolated: Vec<MacAddr>, pub quarantine: Vec<MacAddr>, pub locked_v4: Vec<Ipv4Addr>, pub locked_v6: Vec<Ipv6Addr> }` — `isolated`/`quarantine` from the config; `locked_v4/v6` left empty at compile and filled at runtime by the agent from the neighbour table/leases (Task 5/6), exactly as interface sets are.
  - `pub fn host_mode_set_updates(sets: &HostModeSets) -> Vec<(String, nft::SetContents)>` — reuses `render_set_updates`; MAC sets are `SetContents` of type `ether_addr` (add a `SetContents::Macs(Vec<MacAddr>)` variant).
  - `document.rs`: `Compiled.host_modes: HostModeSets`; `nft::Policy.host_modes: Option<&HostModeSets>`; `emit_sets` declares `host_isolated`/`host_quarantine` (`ether_addr`, non-interval), `host_locked_v4` (`ipv4_addr`), `host_locked_v6` (`ipv6_addr`) whenever any host mode exists.
- Consumes: `isolation`-style registration, `internal_interfaces`, `Context`, `MacAddr`, `HostModeKind` (re-exported path).

**Rule set per entry (registration order matters):**
```
# Quarantine (priority 5, registered before anti-lockout)
#   input + forward, direction in, quick, interface=<each internal>
#   from = ether saddr @host_quarantine
#   pass to (self), udp 67 (DHCP)
#   pass to (self), udp/tcp 53 (DNS)
#   pass to (self), udp 123 (NTP)
#   block to any (everything else, incl. internet and other router services)
# Isolated (priority 6)
#   pass to (self)
#   block to <each internal iface net>
#   (no final block: the internet falls through)
# Reverse (priority 5, once per internal interface, independent of entries)
#   block to @host_locked_v4 / @host_locked_v6 from <internal nets>,
#   except from (self): precede with a quick pass "from (self)".
```
Register quarantine entries *before* `system_rules::register`'s anti-lockout within priority 5 by registering host modes in `document::compile` immediately after `isolation::register` and before user rules — but since anti-lockout is a system rule at priority 5 registered inside `system_rules::register` (called first), verify ordering empirically and, if needed, register quarantine at priority 4. The pinning test (Review Focus 1) is authoritative: quarantine block-to-self must precede anti-lockout pass-to-self for the same interface in `Compiled.filter`.

- [ ] **Step 1: Write failing tests** in `tests/host_modes.rs` (load `home-router` like `tests/isolation.rs`):
  - `isolated_passes_self_blocks_local_keeps_internet`: one Isolated MAC → rules with `src.addr == Addr::MacSet("host_isolated")`; a pass to `Addr::SelfAddr`, a block per internal `IfaceNet`, and no `block to Any`.
  - `quarantine_allows_only_dhcp_dns_ntp_to_self`: one Quarantine MAC → passes to `(self)` on udp67, 53 (udp+tcp), udp123, then a `block to Any`.
  - `quarantine_blocks_the_gui_before_anti_lockout` (Review Focus 1).
  - `quarantine_forward_chain_passes_dns_to_router` (Review Focus 3): render nft and assert the golden has the quarantine DNS rule under both the interface's `in_<iface>` chain and that the forward dispatch reaches it.
  - `reverse_block_targets_only_locked_addresses` (Review Focus 2): `host_mode_set_updates` with two locked MACs mapped to `192.168.68.50`/`.51` yields `host_locked_v4` contents `[192.168.68.50, 192.168.68.51]` and nothing else.
  - `golden_isolated` / `golden_quarantine`: `common::golden_json("host-modes-isolated", &buf)` etc., one locked host each on `home-router`.
- [ ] **Step 2:** `cargo test -p sensr-rules host_mode` — fails (module/goldens absent).
- [ ] **Step 3:** Implement the module, thread `HostModeSets` through `document::compile`/`Compiled`/`nft::Policy`, declare the sets in `emit_sets`, add `SetContents::Macs`.
- [ ] **Step 4:** `SENSR_GOLDEN_UPDATE=1 cargo test -p sensr-rules host_mode` to write goldens; review the diff; run `scripts/nft-check-goldens.sh crates/sensr-rules/tests/golden` if `nft` is available (CI enforces it; the Mac has no nft — note it in the PR). `cargo test -p sensr-rules` + clippy clean.
- [ ] **Step 5:** Commit: `rules: host-mode (Isolated, Quarantine) nft rules and goldens`.

### Task 4: sysctl `send_redirects` when interception is configured (`sensr-apply`)

**Files:**
- Modify: `crates/sensr-apply/src/appliers/sysctl.rs` — `SysctlModel` gains `pub send_redirects_off: Vec<String>` (device names, plus the implicit `all`/`default`); `to_map` emits `net.ipv4.conf.all.send_redirects=0`, `net.ipv4.conf.default.send_redirects=0` and `net.ipv4.conf.<dev>.send_redirects=0` for each listed device when the list is non-empty.
- Modify: `crates/sensr-apply/src/appliers/convert.rs` — `SliceModels::from_document` fills `send_redirects_off` with the internal interface devices when `firewall.host_mode_settings.arp_intercept` and `!firewall.host_modes.is_empty()` (any enabled entry).
- Test: `sysctl.rs` `#[cfg(test)]` and `convert.rs` tests; update the `default_model_golden` insta snapshot only if the default (empty list) output is unchanged (it must be — empty list emits nothing).

**Interfaces:**
- Produces: `SysctlModel.send_redirects_off: Vec<String>` (default empty; no keys emitted when empty, so existing callers and the golden are unaffected).
- Consumes: `internal_interfaces(doc)` for device names; `doc.firewall.host_mode_settings`/`host_modes`.

- [ ] **Step 1: Write failing tests:**
  - `send_redirects_off_when_hosts_locked`: a `SysctlModel` with `send_redirects_off = ["eth1"]` → `to_map` contains `net.ipv4.conf.all.send_redirects=0`, `...default...=0`, `net.ipv4.conf.eth1.send_redirects=0`.
  - `no_redirect_keys_by_default`: default model omits every `send_redirects` key (keeps `default_model_golden`).
  - In `convert.rs`: `host_modes_disable_redirects` — a doc with one enabled Isolated host and arp_intercept on yields the internal device in `send_redirects_off`; with arp_intercept off, empty.
- [ ] **Step 2:** `cargo test -p sensr-apply sysctl` / `convert` — fails.
- [ ] **Step 3:** Implement; keep the `/proc/sys` write path (`Sysctl::apply`) unchanged — it iterates `to_map`, so the new keys apply and revert idempotently.
- [ ] **Step 4:** `cargo test -p sensr-apply`, clippy clean, `default_model_golden` snapshot unchanged.
- [ ] **Step 5:** Commit: `apply: disable ICMP redirects on internal links while hosts are locked`.

### Task 5: `Op::HostModeSet`, atomic commit, REST route, Hosts view `mode` (`sensr-ipc`, `sensr-agent`, `sensr-api`)

**Files:**
- Modify: `crates/sensr-ipc/src/proto.rs` — `Op::HostModeSet { mac: String, mode: Option<HostModeMode>, remote_addr: Option<std::net::IpAddr> }` where `pub enum HostModeMode { Isolated, Quarantine }` (`None` = back to Normal, i.e. remove the entry); add to `is_write` and `op_name` (`"host.mode_set"`); `Response` reuse `Response::Value(Some(json!({"result":"applied"|"staged"})))`.
- Modify: `crates/sensr-agent/src/agent.rs` — dispatch arm doing the atomic edit+commit; `problems`/`decode` reuse; self-quarantine guard via a new applier hook.
- Modify: `crates/sensr-agent/src/applier.rs` — `fn client_mac(&self, _ip: std::net::IpAddr) -> Option<String> { None }` (default), implemented by `SliceApplier` against the collector.
- Modify: `crates/sensr-agent/src/slice_applier.rs` — implement `client_mac` (look up the MAC the inventory holds for `ip`); feed `HostModeSets.locked_v4/v6` and the MAC sets at apply via a runtime set-update (reuse Task 3 `host_mode_set_updates` through `engine.update_host_mode_sets`).
- Modify: `crates/sensr-apply/src/engine.rs` — `pub fn update_host_mode_sets(&self, sets: &HostModeSets) -> Result<(), EngineError>` mirroring `update_interface_sets`.
- Modify: `crates/sensr-agent/src/hosts.rs` — the wire `Host`/view gains `mode: Option<"isolated"|"quarantine">` filled from the applied document's `host_modes` by MAC; keep `tests/golden/hosts-view.json` in sync.
- Modify: `crates/sensr-api/src/native.rs` + `src/lib.rs` — `POST /api/v1/hosts/mode` → `native::set_host_mode` calling `Op::HostModeSet` (remote from `ConnectInfo`); route added to `ROUTES` (covered by `api/v1/hosts/*`). Map the self-quarantine refusal to 409/422 and readonly to 403.
- Test: `crates/sensr-agent/tests/agent_ipc.rs`, `crates/sensr-agent/src/hosts.rs` tests, `crates/sensr-api/tests/api.rs`, `crates/sensr-ipc` proto test.

**Interfaces:**
- `Op::HostModeSet` dispatch (inside `execute`, holding `inner`):
  1. `let mac = mac.to_ascii_lowercase();`
  2. Self-guard: if `mode == Some(Quarantine)` and `remote_addr` resolves via `inner.applier.client_mac(ip)` to `mac` → `Err(err(ErrorKind::Conflict, "That's the device you're using — quarantine it from another device."))`.
  3. `let base = inner.candidate.clone().unwrap_or_else(|| inner.head.1.clone());` edit `base.firewall.host_modes` (remove any entry for `mac`; if `mode` is `Some`, insert one with `enabled=true`). Produce `doc`.
  4. `let other_changes = inner.candidate.as_ref().is_some_and(|c| *c != inner.head.1);` and `let pending = inner.store.pending_confirm()?.is_some();`
  5. If `other_changes || pending`: `self.stage(inner, &base, doc)?;` return `Response::Value(Some(json!({"result":"staged"})))`.
  6. Else: `self.stage(inner, &inner.head.1.clone(), doc.clone())?;` then `self.commit(inner, principal, Some("set host mode".into()), None).await?;` return `Response::Value(Some(json!({"result":"applied"})))`.
- `Applier::client_mac` as above. `SliceApplier::client_mac` queries the collector: add `HostCollector::mac_for_ip(&self, ip: IpAddr) -> Option<String>` scanning `inv.hosts()` for a host whose `ipv4`/`ipv6` equals `ip`, returning its `mac`.
- `host_locked_v4/v6` refresh: besides each apply, refresh the IP sets (via `engine.update_host_mode_sets`) on every `FEED_TICK` (10 s) from the neighbour table and leases, as MAC aliases refresh, so a locked host's new address is covered within 10 s and a released one drops out.
- `hosts.rs` view: after serialising each `Host`, set `v["mode"]` from a `BTreeMap<String, &'static str>` the collector keeps (`mac -> "isolated"|"quarantine"`) built in `set_document` from `doc.firewall.host_modes`. Omit `mode` when Normal.

- [ ] **Step 1: Write failing tests:**
  - `proto.rs`: `host_mode_set_is_write` asserts `Op::HostModeSet{mac:"x".into(), mode:None, remote_addr:None}.is_write()`.
  - `hosts.rs`: `view_includes_mode` — with `set_document` given a doc holding an Isolated entry for the seen MAC, `view` row has `mode == "isolated"`; a Normal host omits `mode`. Update `hosts-view.json` only if the fixture doc gains a mode (keep the existing three rows Normal; add a dedicated test fixture rather than mutating the golden unless a row is given a mode — if so, regenerate and review).
  - `agent_ipc.rs`: `mode_set_applies_on_clean_head` (TestApplier records apply; result `applied`); `mode_set_stages_when_candidate_is_dirty` (pre-stage an unrelated edit → result `staged`, no apply); `mode_set_stages_when_confirm_pending` (seed a pending confirm → `staged`); `mode_set_self_quarantine_refused` (applier `client_mac` returns the target MAC → Conflict); `mode_set_readonly_forbidden`.
  - `api.rs`: `set_host_mode_route` — user with `page-sensr-hosts` gets 200 and `{"result":...}`; readonly gets 403; the ACL-walk test still passes with the new route.
- [ ] **Step 2:** `cargo test -p sensr-ipc -p sensr-agent -p sensr-api host_mode` / `mode_set` — fails.
- [ ] **Step 3:** Implement all arms; `set_document` builds the mode map and refreshes `HostModeSets`; `apply` calls `engine.update_host_mode_sets` after commit (like interface sets).
- [ ] **Step 4:** `cargo test --workspace` (VM/nix tests out of scope) + clippy clean.
- [ ] **Step 5:** Commit: `agent: HostModeSet op with atomic commit, REST route and mode in the hosts view`.

### Task 6: Cut conntrack and flowtable on lock-down (`sensr-apply`, `sensr-agent`)

**Files:**
- Modify: `crates/sensr-apply/src/engine.rs` — `pub fn cut_host(&self, addrs: &[std::net::IpAddr]) -> Result<(), EngineError>` running, per address, `conntrack -D -s <ip>` and `conntrack -D -d <ip>` through the `Runner` (ignoring "0 flow entries" non-zero exit), and flushing offloaded flows for them (deleting the conntrack entries removes the flowtable offload, so no separate flowtable delete is needed; document this).
- Modify: `crates/sensr-agent/src/slice_applier.rs` — in `apply`, diff the previous vs new locked-address set (from `HostModeSets.locked_v4/v6` before/after) and call `engine.cut_host` for addresses newly locked or moved Isolated→Quarantine.
- Test: `engine.rs` `#[cfg(test)]` with `FakeRunner`; `slice_applier.rs` test.

**Interfaces:**
- Produces: `Engine::cut_host`. `conntrack` is a subprocess, portable (no cfg gate); tests assert the emitted command lines on `FakeRunner`, not a live kernel.
- Consumes: the applied `HostModeSets` and the newly-computed one.

- [ ] **Step 1: Write failing tests:**
  - `cut_host_deletes_conntrack`: `cut_host(&["192.168.68.50".parse().unwrap()])` emits `conntrack '-D' '-s' '192.168.68.50'` and `... '-d' ...` on the FakeRunner; a non-zero "no entries" exit is swallowed (returns Ok).
  - `apply_cuts_newly_locked_hosts`: applying a doc that newly Isolates a MAC with a known lease address calls `cut_host` with that address; re-applying the same doc does not.
- [ ] **Step 2:** `cargo test -p sensr-apply cut_host` / `-p sensr-agent apply_cuts` — fails.
- [ ] **Step 3:** Implement; resolve a locked MAC's current addresses from the collector/neighbour snapshot at apply time.
- [ ] **Step 4:** `cargo test -p sensr-apply -p sensr-agent` + clippy clean.
- [ ] **Step 5:** Commit: `apply: cut existing connections when a host enters a mode`.

### Task 7: ARP interceptor (`sensr-agent`)

**Files:**
- Create: `crates/sensr-agent/src/arp_intercept.rs` — pure plan, frame build/parse, request-answering, the socket trait, the task, heal, status.
- Modify: `crates/sensr-agent/src/lib.rs` (`pub mod arp_intercept;`), `crates/sensr-agent/src/slice_applier.rs` (own and drive the task like `HostCollector`; include `intercept` in the Hosts view), `crates/sensr-agent/Cargo.toml` (add `nix = { version = "0.32", features = ["socket", "net"] }` and `libc` as needed, used only under `cfg(target_os = "linux")`).
- Test: `arp_intercept.rs` `#[cfg(test)]`.

**Interfaces:**
- Produces:
  - `pub struct Neighbour { pub ip: Ipv4Addr, pub mac: [u8; 6], pub live: bool }`
  - `pub struct IfaceView { pub id: String, pub device: String, pub index: u32, pub router_ip: Ipv4Addr, pub router_mac: [u8; 6], pub neighbours: Vec<Neighbour> }`
  - `pub struct Locked { pub mac: [u8; 6], pub ip: Ipv4Addr, pub iface: String }`
  - `pub struct PoisonMsg { pub iface: String, pub target_ip: Ipv4Addr, pub target_mac: [u8; 6], pub claim_ip: Ipv4Addr, pub claim_mac: [u8; 6] }` — "tell `target` that `claim_ip` is at `claim_mac`".
  - `pub fn plan(ifaces: &[IfaceView], locked: &[Locked]) -> Vec<PoisonMsg>` (pure, unit-tested).
  - `pub fn heal_plan(ifaces: &[IfaceView], locked: &[Locked]) -> Vec<PoisonMsg>` — same pairs, but `claim_mac` is the *true* owner's MAC.
  - `pub fn answer(req: &ArpFrame, ifaces: &IfaceView, locked: &[Locked]) -> Option<PoisonMsg>` — decide a reply to an observed request.
  - `pub struct ArpFrame { pub op: u16, pub sender_mac: [u8;6], pub sender_ip: Ipv4Addr, pub target_mac: [u8;6], pub target_ip: Ipv4Addr }` with `pub fn parse(frame: &[u8]) -> Option<ArpFrame>` and `pub fn build_reply(m: &PoisonMsg) -> Vec<u8>` / `build_request(m: &PoisonMsg) -> Vec<u8>`.
  - `pub trait PacketSocket: Send { fn send(&self, iface_index: u32, frame: &[u8]) -> std::io::Result<()>; fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>; }`
  - Linux impl `struct AfPacketSocket` (cfg linux) using `nix::sys::socket` (`AF_PACKET`, `SOCK_RAW`, `ETH_P_ARP`), `sendto` with `LinkAddr`; non-linux stub returns `ErrorKind::Unsupported`.
  - `pub struct Interceptor { ... }` with `fn set_inputs(&self, ifaces, locked)`, `fn start`, `fn status(&self) -> InterceptStatus`, `fn stop_and_heal(&self)`. `pub struct InterceptStatus { pub active: bool, pub interfaces: Vec<String>, pub error: Option<String> }`.
- Hosts view gains top-level `intercept: {active, interfaces, error}` (from `Interceptor::status`); add to `tests/golden/hosts-view.json`? No — `intercept` is only present when the interceptor runs; keep it out of the collector golden and assert it in the UI mock/test instead.

**Plan rules (the pure function, pin exactly):** for each `Locked` host `T` on its interface `I`:
- for every `Neighbour X` on `I` with `X.live && X.ip != router_ip && X.ip != T.ip`:
  - emit `PoisonMsg{ iface:I, target:T, claim_ip:X.ip, claim_mac:router_mac }` (tell T that X is at the router);
  - emit `PoisonMsg{ iface:I, target:X, claim_ip:T.ip, claim_mac:router_mac }` (tell X that T is at the router).
- never target the router; never claim the router's own IP; skip interfaces not in the view (callers pass only `internal_interfaces`).

**Timing and gating (pin exactly, from the spec):**
- The interceptor is active only when `firewall.host_mode_settings.arp_intercept` is true and at least one enabled Isolated/Quarantine entry exists; otherwise it is idle (and heals if it was active).
- Seeding: every **2 s**, send for each `PoisonMsg` a unicast ARP **request** (`build_request`) whose sender fields are (`claim_ip`, `claim_mac`), addressed to the target.
- Answering: on an observed request matched by `answer`, send the reply immediately and again **50 ms** later.
- Heal: **three rounds, 1 s apart**, of `heal_plan` replies, on: a host leaving the locked set, `arp_intercept` turned off, and agent shutdown.
- Inputs refresh on each apply, each `HostCollector` poll, and every `FEED_TICK` (10 s) from a direct neighbour-table read; `live` = kernel state REACHABLE/DELAY/PROBE/STALE or inventory `last_seen` within `ONLINE_SECS`.
- Tests for timing use an injectable clock/tick (no real sleeps over 100 ms).

**ARP/Ethernet frame layout (`build_reply`, 42 bytes):** Ethernet: dst = `target_mac` (6), src = `router_mac` (6), ethertype `0x0806` (2). ARP: htype `0x0001`, ptype `0x0800`, hlen `6`, plen `4`, op `0x0002` (reply) or `0x0001` (request), sender_mac = `claim_mac`, sender_ip = `claim_ip`, target_mac = `target_mac`, target_ip = `target_ip` (= the receiver's own IP). All multi-byte fields big-endian.

- [ ] **Step 1: Write failing tests** (no root; use a mock `PacketSocket` recording frames):
  - `plan_tells_both_sides_via_router`: two live neighbours + one locked host → four `PoisonMsg` all with `claim_mac == router_mac`, none targeting the router.
  - `plan_ignores_offline_and_router`: a non-live neighbour and the router are never targeted/claimed.
  - `plan_only_internal_interfaces`: a `Locked` on an interface absent from `ifaces` yields nothing.
  - `answer_replies_to_requests_for_locked_or_from_locked`: a parsed request from T for X (and from X for T) returns a reply with `claim_mac == router_mac`; unrelated requests return `None`.
  - `frame_round_trips`: `parse(build_reply(&m))` recovers op/sender/target.
  - `heal_plan_restores_true_macs` (Review Focus 5): `heal_plan` emits the same pairs with the true owner MACs.
  - `collector_shutdown_sends_heal`: an `Interceptor` with a mock socket and one locked host, on `stop_and_heal`, sends three rounds of heal frames.
  - `status_reports_socket_error`: a socket whose open fails records `error` and leaves `active=false` while the nft layer is untouched.
- [ ] **Step 2:** `cargo test -p sensr-agent arp` — fails.
- [ ] **Step 3:** Implement the module; wire `Interceptor` into `SliceApplier` (start on `system_with_feeds`, `set_inputs` on each apply/`HostCollector` poll/`FEED_TICK`); `stop_and_heal` from `SliceApplier::Drop` beside `HostCollector::shutdown`; router per-interface MAC via rtnetlink (already a workspace dep) or `/sys/class/net/<dev>/address`. Linux-only socket behind `cfg(target_os = "linux")`; stub + `#[cfg(not(target_os="linux"))]` elsewhere so the Mac builds.
- [ ] **Step 4:** `cargo test -p sensr-agent` + `cargo clippy -p sensr-agent -- -D warnings` clean on macOS (the raw-socket path is cfg-gated out).
- [ ] **Step 5:** Commit: `agent: ARP interceptor for same-LAN host-mode enforcement`.

### Task 8: UI Mode select, badges, footer, self-quarantine guard, MockBackend (`sensr-ui`)

**Files:**
- Modify: `crates/sensr-ui/src/runtime.rs` — `HostRow` gains `#[serde(default)] pub mode: Option<String>` and `HostList`/the view gains `intercept: Option<Intercept>` (`{active, interfaces, error}`), all lenient/defaulted.
- Modify: `crates/sensr-ui/src/api.rs` (Backend) — `fn set_host_mode(&self, mac: String, mode: Option<String>) -> BoxFuture<'_, ApiResult<String>>` (returns `"applied"|"staged"`).
- Modify: `crates/sensr-api/src/ui.rs` — implement `set_host_mode` via `Op::HostModeSet` (remote from request parts).
- Modify: `crates/sensr-ui/src/actions.rs` — `set_host_mode(mac, mode) -> Result<String, ServerFnError>` server fn; self-quarantine guard here too (compare `imp::remote()`-matched MAC in the `HostCard` list against `mac`); `HostCard` gains `arp_error: Option<String>` and the card footer text.
- Modify: `crates/sensr-ui/src/islands.rs` — `HostsCard`: a Mode `<select>` (Normal/Isolated/Quarantine) per MAC row (hidden/"—" for `id:` rows, hidden when `read_only`); Isolated=amber badge, Quarantine=red badge; footer help when any host is locked, and the `arp_error` line.
- Modify: `crates/sensr-ui/src/mock.rs` — seed at least one Isolated and one Quarantine host and an `intercept` block; `set_host_mode` mutates the seeded list and returns `"applied"`; self-quarantine on the mock's own client MAC returns the error; a read-only mock variant.
- Test: `crates/sensr-ui/tests/components.rs`.

**Card copy (verbatim):**
- Footer (any host locked): `Same-network blocking works by redirecting the device's local traffic through the router (IPv4). It stops ordinary devices, not ones configured to bypass it.`
- Footer (`intercept.error` set): `Same-network blocking is off: <error>`
- Self-quarantine error: `That's the device you're using — quarantine it from another device.`
- Badges: Isolated amber, Quarantine red; `id:`-keyed rows show `—` in the Mode column.

- [ ] **Step 1: Write failing component tests** against the mock:
  - `host_mode_select_present_for_mac_rows`: a MAC row renders a Mode `<select>` with Normal/Isolated/Quarantine; an `id:` row shows `—`.
  - `host_mode_badges`: the seeded Isolated row has the amber badge class, Quarantine the red.
  - `host_mode_read_only_has_no_select`: read-only mock renders no Mode select.
  - `host_mode_footer_text`: with a locked host, the footer help renders; with `intercept.error`, the off-line footer renders.
  - `self_quarantine_refused`: selecting Quarantine on the mock's own client MAC surfaces the exact error.
- [ ] **Step 2:** `cargo test -p sensr-ui --test components host_mode` — fails.
- [ ] **Step 3:** Implement per the Files/Copy blocks; the select calls `set_host_mode` then `bump()`/refresh; a `"staged"` result shows `Staged — Apply to take effect`.
- [ ] **Step 4:** `cargo test -p sensr-ui` + wasm clippy (`cargo clippy -p sensr-ui --lib --target wasm32-unknown-unknown --no-default-features --features hydrate -- -D warnings`) + `cargo leptos build` succeed.
- [ ] **Step 5:** Commit: `ui: host Mode select, badges and footer on the Hosts card`.

### Task 9: End-to-end tests (Playwright)

**Files:**
- Create: `crates/sensr-ui/e2e/tests/host-modes.spec.ts` using `e2e/tests/helpers.ts` and the mock-backed dev server (`crates/sensr-ui/src/bin/dev.rs`, `e2e/playwright.config.ts`).
- Modify: `crates/sensr-ui/e2e/fixtures/agent-seed.json` if the stack run needs seeded locked hosts.

- [ ] **Step 1: Write the specs:**
  - `set a host to Isolated`: choose Isolated on a MAC row, expect the amber badge and the row's Mode select value.
  - `quarantine shows the footer help`: after locking a host, the footer help text appears.
  - `self-quarantine is refused`: selecting Quarantine on the client's own device shows the exact error and leaves the mode Normal.
  - `read-only user has no Mode select`: the read-only fixture renders zero Mode selects.
  - `staged path`: with a pre-staged unrelated change, a mode change shows `Staged — Apply to take effect`.
- [ ] **Step 2:** From `crates/sensr-ui/e2e`: `npx playwright test tests/host-modes.spec.ts` — fails before Task 8 lands (confirms the spec targets the new UI).
- [ ] **Step 3:** Fix selectors/fixtures only; a real product bug goes back to Task 8.
- [ ] **Step 4:** `npx playwright test` (whole suite) passes.
- [ ] **Step 5:** Commit: `ui: e2e for per-host modes`.

---

## Done when

- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `cargo xtask parity --check` / `lint-fixtures`, the nft golden kernel-check (`scripts/nft-check-goldens.sh`, CI), and the Playwright suite all pass.
- The branch `feat/host-modes` has a PR linking this plan and the spec.
- On-router acceptance (manual, owner's go, after release): Isolated → LAN neighbour unreachable, internet works; Quarantine → internet stops; Normal → recovers within ~5 s.
