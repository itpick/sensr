# Runtime Guard (Dynamic eBPF) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `sensr-guard` service that loads signed eBPF packs into the running kernel. Rules from the config make the loaded programs watch and block exec, connect, listen, file writes, setuid, module loads and BPF loads on the router.

**Architecture:**
- **BPF side:** C programs compiled by clang in the Nix build (CO-RE, `vmlinux.h` generated from the image kernel's BTF).
- **Packs:** a pack bundles the objects with a manifest. Packs delivered between releases are Ed25519 (minisign) signed; the built-in `core` pack ships in the image.
- **Rust daemon** (`crates/sensr-guard`):
  - loads the packs (aya, or libbpf-rs if the Task 4 spike says so);
  - compiles the config's rules into BPF map entries;
  - drains the ring buffer into a batched SQLite events database;
  - serves a JSON-lines control socket.
- **Wiring:** config model plus applier, a NixOS unit, the API, the CLI and the UI, following the same patterns as `sensr-scan`.

**Tech Stack:**
- BPF: C (clang 19, libbpf headers, bpftool for `vmlinux.h`).
- Rust: aya (fallback libbpf-rs), tokio, rusqlite, minisign-verify.
- Leptos SSR UI, NixOS module and VM tests.

**Spec:** `docs/superpowers/specs/2026-11-25-ebpf-guard-design.md`. Its "Decisions from the design review" and "Feasibility spike" sections are binding.

## Global Constraints

- Rust stays on stable (rust-toolchain.toml), no nightly. The BPF programs are C, compiled by clang in Nix.
- Latest stable dependency versions, added to `[workspace.dependencies]` first.
- Tests for every behaviour.
- Every new API route needs a privilege (`every_route_has_privilege_t0368`).
- No AI attribution in commits or PRs.
- Programs are **not pinned**. They live and die with `sensr-guard` (fail open). Set `Restart=always`, `RestartSec=1`. While the daemon is down, the UI shows every rule inactive.
- **Never-block** is compiled into the programs as leaf cgroup names, and no rule can override it:
  - `init.scope`, `sensr-agent.service`, `sensr-guard.service`, `sensr-api.service`, `sshd.service`;
  - `systemd-networkd.service`, `systemd-resolved.service`, `systemd-journald.service`;
  - `sensr-kea-dhcp4.service`, `sensr-unbound.service`, `nix-daemon.service`, `sensr-nic-recover.service`;
  - plus the prefixes `sensr-update`, `sensr-pi5-`, `sensr-bootlog`, `sensr-trial-`.
  - Alerts still apply to these.
- New rules default to `alert`. Any change that makes a rule `block` goes through commit-confirm.
- Kill switch: if `/boot/firmware/sensr/guard-off` exists at start, or `sensr guard off` is run, nothing blocks (alerts only), and the status says so.
- sensr-guard refuses to start (and reports why) if `/sys/kernel/security/lockdown` is `confidentiality`. The module pins `lsm=` with `bpf` in it.
- The `core` pack is built into the image and trusted without a signature. Packs delivered between releases need an Ed25519 minisign signature from a key in the image's key list. The release signing key is the GitHub Actions secret `GUARD_PACK_KEY`.
- Pack default rules stay with the pack. The owner overrides them via `guard.pack_rules: [{pack, rule_id, enabled?, action?}]`. Packs are switched on and off with `guard.packs: [{name, enabled}]`. Installing or updating a pack never edits the config.
- Events: one ring buffer (1 MiB). Identical events within 10 s are de-duplicated into one row with a count. Writes are batched, at most one per 5 s. Rate cap: 100 events/s global, and overflow increments a dropped counter. Retention: 30 days or 200,000 rows.
- Module loads are watched through `kernel_read_file` (READING_MODULE) and `kernel_load_data`.
- Unit capability bounding set: `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE`.

## Review Focus

1. **A block rule against a protected unit's child processes.** `nft` and `systemctl` spawned by sensr-agent run in `sensr-agent.service`'s cgroup, so they are never blocked. Covered by a test in Task 2 (cgroup-name check) and Task 11 (VM).
2. **Path-prefix rules on a component boundary.** A rule on `/nix/store` must not match `/nix/storefoo`, and `/nix/store/` must behave the same as `/nix/store`. Test in Task 3.
3. **An exec storm** (a fork bomb, or a loop exec'ing `/tmp/x`). Memory stays bounded, rows are de-duplicated, the dropped counter rises, and the daemon keeps up. Test in Task 5.
4. **A well-signed pack that can't run here** (newer `min_sensr`, a missing hook, a verifier rejection). It is refused or partially active with a reason, the previous version stays loaded, and nothing claims protection it doesn't give. Test in Task 6 (manifest checks) and Task 7 (load failure keeps last good).
5. **Daemon down, or an unenforceable rule.** Status and UI show the rule inactive with its reason, never "protected". Test in Task 9 (API status when the socket is gone) and Task 10 (UI shows inactive).

---

### Task 1: Contract types, config model and applier

**Files:**
- Create: `crates/sensr-guard/{Cargo.toml,src/lib.rs,src/config.rs,src/proto.rs,src/rule.rs}`
- Create: `crates/sensr-schema/src/models/guard.rs`; modify `models/mod.rs` and `models/document.rs` (field `guard`, omitted while default)
- Create: `crates/sensr-apply/src/appliers/guard.rs`; modify `appliers/mod.rs` and `engine.rs` (`plan_guard`, next to `plan_portscan`)

**Interfaces:**
- Produces, in `sensr_guard::config`:
  - Constants: `CONFIG_PATH = "/run/sensr/guard/guard.json"`, `STATE_DIR = "/var/lib/sensr-guard"`, `EVENTS_DB = "events.db"`, `SOCKET = "/run/sensr-guard/guard.sock"`, `KILL_SWITCH = "/boot/firmware/sensr/guard-off"`, `BUILTIN_PACKS = "/run/current-system/sw/share/sensr-guard/packs"`.
  - `Config { enabled: bool, packs: Vec<PackToggle>, pack_rules: Vec<PackRuleOverride>, rules: Vec<Rule>, retention_days: u16, max_rows: u32 }`.
- Produces, in `sensr_guard::rule` (always compiled, serde snake_case):
  - `Rule { id: String, enabled: bool, description: String, hook: Hook, process: ProcessMatch, target: Target, action: Action }`
  - `enum Hook { Exec, Connect, Listen, FileWrite, Setuid, Module, Bpf }`
  - `ProcessMatch { exe_prefix: Option<String>, unit: Option<String> }`
  - `enum Target { Any, PathPrefix(String), Net { cidr: IpNet, ports: Vec<u16> }, Uid(u32) }`
  - `enum Action { Alert, Block }`
- Produces, in `sensr_guard::proto` (JSON lines, `tag="op"`):
  - `Request { Status, Reload, KillSwitch { on: bool } }`
  - `Reply { Ok, Status(StatusView), Error(String) }`
  - `StatusView { running: bool, kill_switch: bool, lockdown: String, packs: Vec<PackStatus>, rules: Vec<RuleStatus>, dropped: u64 }`
  - `RuleStatus { id, active: bool, reason: Option<String>, hits: u64 }`
  - `PackStatus { name, version, source: Builtin | Signed, verified: bool, active: bool, reason: Option<String> }`
- Produces, in the schema: `Guard { enabled (yes), packs: ArrayField<GuardPack>, pack_rules: ArrayField<GuardPackRule>, rules: ArrayField<GuardRule>, retention_days (30, 1..=365), max_rows (200000, 1000..=5000000) }`. Validation: a `PathPrefix` must be absolute, and an `exe_prefix` absolute when set.
- Produces `sensr_apply::appliers::guard::{DIR = "run/sensr/guard", CONFIG = "guard.json", UNIT = "sensr-guard.service", fn config(doc) -> Option<Config>}`. It returns `None` when disabled.

- [ ] Step 1: write failing tests.
  - The schema defaults deserialize from `{}`.
  - A relative `path_prefix` fails validation at `guard.rules.<uuid>.target`.
  - The applier maps a schema rule to `sensr_guard::rule::Rule` (enabled rules only, `id` = the ArrayField uuid) and returns `None` when `guard.enabled = false`.
  - `Rule` round-trips through serde.
- [ ] Step 2: run `cargo test -p sensr-guard -p sensr-schema guard -p sensr-apply guard` and confirm FAIL.
- [ ] Step 3: implement, following `portscan` (models/portscan.rs, appliers/portscan.rs, `plan_portscan`). Add `Section::Guard`.
- [ ] Step 4: re-run → PASS. Run `cargo test --workspace` once.
- [ ] Step 5: commit `feat(guard): contract types, config model and applier`.

### Task 2: BPF programs and their Nix build

**Files:**
- Create: `bpf/guard/{common.h,exec.bpf.c,connect.bpf.c,listen.bpf.c,file.bpf.c,creds.bpf.c,module.bpf.c,bpf.bpf.c,neverblock.h}`
- Create: `nix/packages/sensr-guard-bpf.nix`; modify `nix/overlays/default.nix` (package `sensr-guard-bpf`)
- Create: `bpf/guard/README.md` (map layout contract)

**Interfaces:**
- Produces map names and layouts in `common.h`, shared with the Rust side (Task 3 mirrors them with `#[repr(C)]`):
  - `rules_meta`: ARRAY of `struct rule_meta { u32 id; u8 hook; u8 action; u8 enabled; }` (max 1024).
  - `exe_prefix_lpm`: LPM_TRIE, key `{u32 prefixlen; char path[256]}`, value `u32 rule_bitmap_idx`.
  - `path_prefix_lpm`: same layout.
  - `net4_lpm` and `net6_lpm`: LPM_TRIE CIDR → rule set.
  - `port_rules`: HASH (rule id, port).
  - `unit_rules`: HASH (cgroup leaf name[64]) → rule set.
  - `uid_rules`: HASH.
  - `hits`: PERCPU_ARRAY of `u64` per rule.
  - `config`: ARRAY[1] of `{ u8 kill_switch; u32 guard_tgid; }`.
  - `events`: RINGBUF 1 MiB.
  - `task_exe`: TASK_STORAGE holding the cached exe path.
  - `struct event { u64 ts; u32 pid, ppid, uid; u32 rule_id; u8 hook, action, blocked; char exe[256]; char target[256]; u8 addr[16]; u16 port; u8 family; char unit[64]; }`
- Produces programs (section names):
  - `lsm.s/bprm_check_security` (caches the exe in `task_exe` and emits exec events);
  - `lsm/socket_connect`;
  - `lsm/socket_bind`;
  - `lsm/socket_listen`;
  - `lsm.s/file_open` (write modes only);
  - `lsm/path_unlink`, `lsm/path_rename`;
  - `lsm/task_fix_setuid`;
  - `lsm/kernel_read_file`, `lsm/kernel_load_data`;
  - `lsm/bpf`.
- Behaviour of every program: look up the matching rules. On a match, emit an event and bump `hits`. Return `-EPERM` only when the action is `block`, the kill switch is off, and the task's leaf cgroup name is **not** in `neverblock.h`. The `bpf` hook never blocks the `guard_tgid`.
- Produces the Nix derivation output: `$out/share/sensr-guard/packs/core/{manifest.json,*.bpf.o,rules.json}`. `vmlinux.h` comes from `bpftool btf dump file ${kernel.dev}/vmlinux format c`, built per system with `-D__TARGET_ARCH_{x86,arm64}`.

- [ ] Step 1: write `nix/tests/guard-bpf-build.nix`, a `runCommand` check. It asserts every object exists, that `bpftool prog loadall` is *not* run (no kernel in the sandbox), and that `llvm-objdump -h` shows each expected section name. It also unit-tests `neverblock.h` through a tiny host C test (`cc`) of the shared `is_neverblock(const char *leaf)` helper:
  - `sensr-agent.service` → true;
  - `sensr-update-check.service` → true (prefix);
  - `session-3.scope` → false;
  - `sensr-agentx.service` → false.
- [ ] Step 2: run `nix build .#checks.x86_64-linux.guard-bpf-build` (CI) → FAIL.
- [ ] Step 3: implement the programs and the derivation. The spike's program in the spec's "Feasibility spike" section shows the proven patterns: `bpf_d_path` in `lsm.s`, task storage, and `bpf_htonl` comparisons.
- [ ] Step 4: re-run → PASS. Also add `checks.aarch64-linux.guard-bpf-build` (built on the CI `nix-aarch64` job).
- [ ] Step 5: commit `feat(guard): BPF programs for the core pack`.

### Task 3: Rule compiler

**Files:** create `crates/sensr-guard/src/compile.rs`, `src/maps.rs` (`#[repr(C)]` mirrors of `common.h`).

**Interfaces:**
- Consumes: `Rule` (Task 1) and the map contract (Task 2).
- Produces:
  - `fn compile(rules: &[Rule]) -> Result<Compiled, CompileError>`;
  - `Compiled { meta: Vec<RuleMeta>, exe_lpm: Vec<(LpmPath, RuleSet)>, path_lpm: …, net4: …, net6: …, ports: …, units: …, uids: … }`;
  - `RuleSet` is a 1024-bit bitmap index table.
  - `CompileError::{TooMany, PathTooLong, …}`.

- [ ] Step 1: failing tests.
  - `prefix_matches_on_component_boundary` (RF2): `/nix/store` compiles to a key that matches `/nix/store/x` and `/nix/store`, but not `/nix/storefoo`. Implement by storing the prefix with a trailing `/` and also an exact-match key.
  - `trailing_slash_equivalent`.
  - `cidr_and_ports`: `10.0.0.0/8` with ports `[22]` → a `net4` entry and a `ports` entry.
  - `too_many_rules_errors` at 1025.
  - `disabled_rules_not_compiled`.
  - `deterministic_output`: the same input gives the same output, for idempotent swaps.
- [ ] Steps 2–4: TDD (`cargo test -p sensr-guard compile`).
- [ ] Step 5: commit `feat(guard): compile rules to BPF map entries`.

### Task 4: Loader spike and loader

**Files:** create `crates/sensr-guard/src/loader.rs` (behind feature `daemon`); create `nix/tests/guard-load.nix`.

**Interfaces:**
- Consumes: the pack directory layout (Task 2) and `Compiled` (Task 3).
- Produces:
  - `struct Loaded`;
  - `fn load(pack_dir: &Path) -> Result<Loaded, LoadError>`, which loads every object and attaches every program, recording a per-program `Result`;
  - `fn apply(&mut self, c: &Compiled, kill_switch: bool, guard_tgid: u32) -> Result<()>`. It updates the maps by building the new entries first, then swapping (delete stale keys after inserting new ones).
  - `fn status(&self) -> Vec<ProgramStatus { name, hook, attached: bool, reason: Option<String> }>`;
  - `fn ringbuf(&mut self) -> RingBuf`;
  - `fn hits(&self) -> HashMap<u32, u64>`.
  - Dropping `Loaded` detaches everything.

- [ ] Step 1 (spike, recorded in the report): in the VM test `guard-load.nix` (x86_64), load the core pack with **aya**. Check that `task_exe` (TASK_STORAGE defined in C) is created and that the `lsm.s/` programs attach. If either fails, switch the loader to **libbpf-rs** (allowed by the spec) and record the decision.
- [ ] Step 2: VM test assertions:
  - every program reports `attached`;
  - after `apply` with a rule `{Connect, Net 192.0.2.1/32, [80], Block}`, `curl 192.0.2.1` fails with EPERM, while a curl to the test server node works;
  - after `apply` with the kill switch on, the same curl is no longer EPERM;
  - dropping `Loaded` (exit of the test binary `guard-load-probe`) leaves `bpftool prog show` with no guard programs.
- [ ] Step 3: implement. The `guard-load-probe` binary is under `src/bin/`, test-only behind feature `daemon`.
- [ ] Step 4: CI run → PASS.
- [ ] Step 5: commit `feat(guard): load the core pack and apply compiled rules`.

### Task 5: Events pipeline and store

**Files:** create `crates/sensr-guard/src/events.rs` (decode, dedupe, rate limit) and `src/store.rs` (feature `store`).

**Interfaces:**
- Produces:
  - `fn decode(raw: &[u8]) -> Option<Event>` (the Rust mirror of `struct event`);
  - `struct Pipeline` with `fn push(&mut self, e: Event, now: Instant) -> Option<Batch>`. Dedupe key: `(hook, rule_id, exe, target, unit)` within 10 s. Caps: 100/s global, overflow counted.
  - `Store::open(path)`, `open_ro`, `write_batch(&Batch)` (one transaction), `events(filter, limit, offset)`, `prune(retention_days, max_rows, now)`.
  - Table: `events(id, ts, hook, action, blocked, rule_id, exe, target, unit, pid, uid, count)`.

- [ ] Step 1: failing tests.
  - `dedupes_within_10s` (count 3 → 1 row with count 3).
  - `rate_cap_counts_dropped` (RF3): 10,000 events in 1 s → at most 100 kept, the rest counted as dropped, and memory bounded. Assert that the pending map length stays ≤ 4096.
  - `batch_at_most_every_5s`.
  - `prune_by_age_and_rows`.
  - `decode_rejects_short_buffer`.
  - Text fields are taken up to the NUL and sanitised.
- [ ] Steps 2–4: TDD (`cargo test -p sensr-guard --features store,daemon events store`).
- [ ] Step 5: commit `feat(guard): event pipeline and events database`.

### Task 6: Packs: manifest, signatures, last-good

**Files:** create `crates/sensr-guard/src/packs.rs`, `nix/pi5/guard-keys/` (the public key list); modify root `Cargo.toml` (`minisign-verify`).

**Interfaces:**
- Produces:
  - `Manifest { name, version, min_sensr: semver, programs: Vec<String>, rules: Vec<Rule> }`;
  - `fn verify(archive: &[u8], sig: &str, keys: &[PublicKey]) -> Result<(), PackError>`;
  - `fn install(archive, sig, keys, state_dir, current_sensr: &Version) -> Result<PackStatus, PackError>`, which unpacks into `state_dir/packs/<name>/<version>` and moves the `current` symlink only after verify and manifest checks pass;
  - `fn resolve(name, builtin_dir, state_dir) -> PackDir`: the signed `current` if present and verified, otherwise the built-in pack;
  - `PackError::{BadSignature, UnknownKey, TooNew { need, have }, MissingProgram(String), Corrupt}`.

- [ ] Step 1: failing tests (keys generated in the test with `minisign`'s keypair API, or fixtures):
  - `good_signature_installs`;
  - `wrong_key_refused`;
  - `tampered_archive_refused`;
  - `too_new_refused_and_current_kept` (RF4);
  - `missing_program_refused`;
  - `resolve_falls_back_to_builtin`.
- [ ] Steps 2–4: TDD.
- [ ] Step 5: commit `feat(guard): signed packs with last-good fallback`.

### Task 7: Daemon, control socket, kill switch, NixOS unit, release signing

**Files:**
- Create: `crates/sensr-guard/src/{server.rs,daemon.rs}`, `src/bin/sensr-guard.rs`.
- Modify: `nix/modules/sensr.nix` (unit, `lsm=` pin, the bpf package in `environment.systemPackages` so `BUILTIN_PACKS` exists), `nix/overlays/default.nix` (build with `--features sensr-guard/daemon`), `.github/workflows/release.yml` (build and sign the core pack as a release asset when the `GUARD_PACK_KEY` secret is present; skip with a notice otherwise), `.github/workflows/ci.yml` (sensr-guard all-features test and clippy).

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces:
  - Binary flags: `sensr-guard --config <json> --state <dir> --socket <path> --builtin <dir> --keys <dir>`.
  - At start, it checks lockdown (refuses `confidentiality`), reads the kill switch file, resolves and loads enabled packs, merges pack rules with `pack_rules` overrides and the config rules, compiles, applies, and serves the socket.
  - `Reload` re-reads the config and re-applies, keeping the last good state if compilation fails.
  - `CheckPacks` (added to `proto::Request`, Task 1 types extended here):
    1. Fetch `guard-packs.json` from `Config.pack_index` (new field, default `https://github.com/itpick/sensr/releases/latest/download/guard-packs.json`). It lists `{name, version, url, sig_url}`.
    2. Download any newer pack and `packs::install` it, then reload.
    3. Reply with per-pack results.
  - An optional daily check runs when `Config.pack_auto_check` is set (schema `guard.pack_auto_check`, default false).
  - Tests: `check_packs_installs_newer_and_reloads` and `check_packs_keeps_current_on_bad_sig`, against a local HTTP fixture.
  - `KillSwitch{on}` toggles it live.
  - The events loop drains the ring buffer, pushes events through the pipeline, and writes batches.
  - A rule whose hook's program didn't attach is reported `active:false, reason`.
  - Unit `sensr-guard.service`:
    - root with `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE`;
    - `Restart=always`, `RestartSec=1`;
    - `StateDirectory`/`RuntimeDirectory` `sensr-guard` (0750, group `sensr`);
    - `ProtectSystem=strict` with `ReadWritePaths` for the state directory;
    - `ConditionPathExists` on the config.

- [ ] Step 1: failing tests (unit tests with a fake loader behind a `trait Backend`):
  - `rule_on_unattached_hook_is_inactive` (RF5);
  - `kill_switch_file_disables_blocking`;
  - `reload_with_bad_rule_keeps_previous`;
  - `pack_override_disables_default_rule`;
  - `lockdown_confidentiality_refuses_start`.
- [ ] Steps 2–4: TDD. CI evaluates the module.
- [ ] Step 5: commit `feat(guard): sensr-guard daemon and unit` (plus `ci: …` / `release: …`).

### Task 8: Block changes go through commit-confirm

**Files:** modify `crates/sensr-agent/src/agent.rs` (the commit path, around `fn commit` at ~1279).

**Interfaces:**
- Produces: when the candidate's diff makes any `guard.rules` rule, `guard.pack_rules` action or `guard.packs` entry newly `block` (or enables a pack whose defaults include a block), a commit without `confirm_secs` gets `confirm_secs = Some(120)` and the reply says so. Commits that explicitly set `confirm_secs` keep their value.

- [ ] Step 1: failing tests in the agent test suite:
  - `block_change_forces_confirm_window` (the commit returns a pending confirm, and a rollback happens after 120 s with a mocked clock, using the existing commit-confirm test harness);
  - `alert_only_change_commits_directly`.
- [ ] Steps 2–4: TDD (`cargo test -p sensr-agent guard`).
- [ ] Step 5: commit `feat(guard): block rules need a confirmed commit`.

### Task 9: API, privilege, CLI, alerts merge

**Files:** create `crates/sensr-api/src/guard.rs`; modify `lib.rs` (routes), `crates/sensr-auth/src/acl.rs`, `crates/sensr-cli/src/lib.rs`, `crates/sensr-api/tests/api.rs`; modify the IDS alerts route to merge guard events (`source: "runtime-guard"`).

**Interfaces:**
- Produces:
  - Routes: `GET /api/v1/guard/status` (daemon `Status`; if the socket is down → `{running:false}` with every rule `active:false, reason:"sensr-guard is not running"`), `GET /api/v1/guard/events?hook=&q=&limit=&offset=`, `POST /api/v1/guard/reload`, `POST /api/v1/guard/kill-switch {on}`.
  - Privilege `page-services-guard` ("Services: Runtime Guard", `ui/guard`, `ui/guard/*`, `api/v1/guard/*`). Read-only principals get 403 on POST.
  - CLI: `sensr guard status|events|off|on`.

- [ ] Step 1: failing tests:
  - `status_when_daemon_down_marks_rules_inactive` (RF5);
  - `events_filtered`;
  - `readonly_cannot_toggle_kill_switch`;
  - the privilege test;
  - CLI arg parsing;
  - alerts merged and sorted by time.
- [ ] Steps 2–4: TDD.
- [ ] Step 5: commit `feat(guard): API, privilege, CLI and alerts`.

### Task 10: UI — Services › Runtime Guard

**Files:** create `crates/sensr-ui/src/guard.rs`; modify `actions.rs`, `pages.rs`, `menu.rs` (SERVICES: `n("Guard").label("Runtime Guard").url("/ui/guard")`), `api.rs` and `mock.rs` (Backend: `guard_status`, `guard_events`, `guard_kill_switch`, `guard_dir`); create `crates/sensr-ui/e2e/tests/guard.spec.ts`.

**Interfaces:**
- Produces a server-rendered page (no new island code; bundle budget 440 KB) with four sections:
  - **Status:** daemon running, kill switch, lockdown, dropped count.
  - **Rules:** a table showing description, hook, target, action, active/inactive with reason, and hits, plus an add/edit form using the model-driven ArrayField form for `guard.rules`. Choosing `Block` shows "Blocking: you'll have 2 minutes to confirm".
  - **Events:** a filterable table.
  - **Packs:** name, version, source, signature, active, reason, on/off via `guard.packs`, and a "Check for pack updates" button (`POST /api/v1/guard/check-packs`, added to Task 9's routes, which sends `CheckPacks`).
  - All device and process text is rendered as text.

- [ ] Step 1: failing component tests:
  - `inactive_rule_shows_reason` (RF5);
  - `block_choice_warns_confirm`;
  - `event_text_escaped` (an exe path `<img src=x>`);
  - `menu_entry`.
  - Playwright `guard.spec.ts`: page loads, add an alert rule, kill switch shown.
- [ ] Steps 2–4: TDD. Run the bundle check (≤ 440 KB) and the Playwright guard spec.
- [ ] Step 5: commit `feat(guard): Services › Runtime Guard page`.

### Task 11: End-to-end VM test

**Files:** create `nix/tests/guard.nix`; modify `flake.nix` (`checks.guard`, x86_64).

- [ ] Step 1: write the test. Router node with sensr (config: guard enabled, core pack on). Assert:
  - (a) every program is attached in `/api/v1/guard/status`;
  - (b) exec of `/tmp/x` gives an "exec outside /nix/store" alert event within 10 s;
  - (c) after committing a `Connect` block rule to the test node's IP, `curl` from the router fails, and the commit is pending confirm;
  - (d) the agent's own `nft`/`systemctl` (an apply after (c)) still works, the never-block check (RF1);
  - (e) touching `/boot/firmware/sensr/guard-off` and restarting sensr-guard makes the curl succeed;
  - (f) a non-guard `bpftool prog load` gives a `bpf` event (and EPERM once that rule is set to block);
  - (g) installing a pack with a bad signature is refused with the core pack still active;
  - (h) killing sensr-guard turns every rule inactive within 2 s, and it is back within 5 s;
  - (i) no failed units.
- [ ] Step 2: CI run → fix → PASS.
- [ ] Step 3: commit `test(guard): end-to-end VM test`.
