# Runtime guard (dynamic eBPF) — design

Status: draft for owner approval, 2026-11-25.

## Why

The owner wants Shirudo-style (github.com/shirudo-dev/shirudo) dynamic eBPF
on the router: programs loaded into the running kernel, and unloaded again,
with no reboot and no full release. "All of it" eventually (watching,
blocking, packet fast paths); **this design covers watching and blocking**.
Packet fast paths (XDP drops before conntrack, per-flow counters) are a later
project on the same platform.

The router is exactly the box that should be watched and locked down, and
reboots on it are risky (2026-11-23/24), so fixes that apply live matter.

## What exists today (verified on the router, kernel 7.3.4)

- `CONFIG_BPF_SYSCALL`, `BPF_JIT`, `BPF_LSM`, `DEBUG_INFO_BTF` (BTF at
  `/sys/kernel/btf/vmlinux`, so CO-RE programs load unchanged), `KPROBES`,
  `FTRACE`/`DYNAMIC_FTRACE`, `BPF_EVENTS`, `CGROUP_BPF`, XDP/tc.
- Active LSMs: `lockdown,capability,landlock,yama,bpf,ima` (BPF LSM is on).
- `unprivileged_bpf_disabled = 2`: only privileged processes load BPF.
- sensr has no eBPF code yet; docs/PLAN.md lists eBPF/XDP fast paths as a
  later goal.
- Not available: a TPM, and Shirudo's kernel patches (signed-BPF-only
  enforcement in the kernel). Those parts of Shirudo do not carry over.

## Goals

1. **`sensr-guard`**, a new service that loads, unloads and reports on eBPF
   programs while the router runs.
2. **Watching**: events for
   - process launches (path, parent, user);
   - outbound connections (process, destination, port);
   - new listening ports (process, address, port);
   - writes to protected paths (process, path);
   - privilege changes (setuid/setgid, capability gains);
   - kernel module loads;
   - BPF program loads by anything other than sensr-guard.
3. **Blocking**: any rule can block instead of alert (deny the exec, the
   connect, the bind/listen, the write, the module load, the BPF load).
4. **Packs (owner's choice A)**: signed bundles of BPF programs + default
   rules, published between full releases, verified against a public key in
   the image, switched on/off per pack in the UI (like IDS rulesets).
5. **Rules (owner's choice B)**: the owner's own watch/block rules, kept in
   the config, fed to the loaded programs as data (BPF maps). A change takes
   effect immediately, without new kernel code.
6. **Visibility**: a Runtime events page, events in the existing alerts flow,
   per-rule hit counters, the loaded programs and packs with their status.

## Non-goals (this project)

- Arbitrary user-uploaded BPF objects (option C): later, on the same signing.
- XDP/tc packet fast paths: the next project.
- In-kernel enforcement that root cannot bypass (needs Shirudo's kernel
  patches and a TPM); attestation.
- Shipping events to a SIEM (OTLP export): a later addition.

## Anti-goals

- **Locking the owner out of the router**, or blocking something the router
  needs to route (sensr-agent, sshd, sensr-api, systemd, DHCP/DNS daemons).
- **A rule that crashes or hangs the kernel.** Only verifier-accepted
  programs from signed packs load; user rules are data, never code.
- **SD-card wear or memory blow-up** from event floods.
- **Silent failure**: a rule that cannot be enforced (hook missing, program
  rejected) must show as not active, never as protected.

## Constraints

- Rust toolchain is stable (rust-toolchain.toml); no nightly. The BPF side
  must build in the Nix build with stable tools.
- Latest dependency versions; tests for every behaviour; no AI attribution.
- Pi 5 (aarch64, 16 GB in this house, but 2-8 GB Pis exist) on an SD card.
- sensr's config changes go through the agent (candidate/commit, with
  commit-confirm and automatic rollback).

## Approaches considered

Where the programs come from (decided by the owner):

- **A. sensr-made signed packs** — safest; you only get what sensr ships.
- **B. fixed programs driven by your rules** — rule changes are data, instant,
  can't crash the kernel.
- **C. upload any compiled BPF program** — most flexible, kernel code from
  anywhere; deferred.

**Chosen: A + B.** Packs are the delivery mechanism (programs + default
rules); the owner's rules configure the programs in the packs.

How the BPF programs are written (controller's call):

1. **C + clang (CO-RE, `vmlinux.h`), loaded from Rust with `aya`** — chosen:
   builds with stable tools in Nix (clang/llvm from nixpkgs), the standard
   CO-RE workflow, loads on any BTF kernel.
2. Rust BPF programs (`aya-ebpf`) — one language, but needs nightly Rust and
   `bpf-linker`, against the repo's stable-only toolchain.
3. libbpf/C userspace — a second language and FFI in the daemon.

## Design

### Components

- `crates/sensr-guard` — library + binary `sensr-guard`:
  - **loader**: opens pack objects with `aya`, attaches programs, owns the
    maps, detaches on unload;
  - **rules**: compiles the config's rules into map entries (atomic swap);
  - **events**: reads the BPF ring buffer, rate-limits, writes batched rows to
    `events.db`, forwards alert-worthy ones to the alert flow;
  - **packs**: fetches, verifies and stores packs;
  - control socket (JSON lines, like sensr-scan) for status/reload.
- `bpf/` — the C programs, `vmlinux.h` generated at build time from the
  kernel's BTF (nixpkgs `bpftools`), compiled with clang `-target bpf -O2 -g`.
- Config model `guard` in sensr-schema; applier renders
  `/run/sensr/guard/guard.json`.
- systemd unit `sensr-guard.service`: runs as root with the bounding set
  limited to `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE`
  (BPF LSM attach needs `CAP_SYS_ADMIN`); `ProtectSystem=strict`,
  `StateDirectory=sensr-guard`.

### Programs in the first pack (`core`)

| Program | Hook | Watches / blocks |
|---|---|---|
| exec | LSM `bprm_check_security` | process launches |
| connect | LSM `socket_connect` | outbound connections |
| listen | LSM `socket_bind` + `socket_listen` | new listening ports |
| file | LSM `file_open` (write modes) + `path_unlink`/`path_rename` | writes to protected paths |
| creds | LSM `task_fix_setuid`, `capable` (sampled) | privilege changes |
| module | LSM `kernel_read_file` / `kernel_module_request` | module loads |
| bpf | LSM `bpf` (`BPF_PROG_LOAD`, `BPF_LINK_CREATE`) | BPF loads by others |

Each program looks up the rule maps and either does nothing, emits an event
(alert), or returns `-EPERM` (block) — plus emits the event.

Process identity: the exe path (via `bpf_d_path` on the exe file in the exec
hook, cached per task in task storage) and the systemd unit (cgroup id ->
unit name, resolved in userspace for display; cgroup ids in maps for
matching).

### Rules (B)

Config: `guard.rules: ArrayField<GuardRule>`:

```
GuardRule {
  enabled, description,
  hook: exec | connect | listen | file_write | setuid | module | bpf,
  process: { exe_prefix?, unit? },          // who (any if empty)
  target:  { path_prefix? | cidr? + ports? | uid? },  // what
  action: alert | block,
}
```

- Compiled to maps: LPM tries for path prefixes and CIDRs, hash maps for
  units/ports/uids; each rule gets an id for counters.
- A rule whose hook's program is not loaded (pack off, hook missing, verifier
  rejection) is shown **inactive** with the reason (anti-goal: silent
  failure).
- **Safety**:
  - new rules default to `alert`; `block` is an explicit choice per rule;
  - a built-in **never-block** list that rules cannot override: PID 1,
    sensr-agent, sensr-guard, sensr-api, sshd, systemd-networkd/resolved,
    Kea, Unbound (block rules simply do not apply to them; alerts still do);
  - changing any rule's action to `block` goes through commit-confirm, so a
    lockout rolls back by itself;
  - **kill switch**: if `/boot/firmware/sensr/guard-off` exists at start,
    sensr-guard loads nothing that blocks (alerts only) and says so;
    `sensr guard off` (CLI) does the same live.

### Default rules shipped in the `core` pack (all `alert`)

- a process starts from outside `/nix/store` and `/run/current-system`;
- a new listening port opens (any process);
- a write under `/nix/store`, `/boot/firmware` (except the updater/bootlog),
  `/etc/sensr`;
- a kernel module loads after boot completed;
- any process other than sensr-guard loads a BPF program;
- a process gains uid 0 via setuid.
- Suggested block (shipped disabled): "only sensr-guard may load BPF".

### Packs (A)

- A pack: `manifest.json` (name, version, min sensr version, kernel/BTF
  requirements, programs, default rules) + `.o` objects, as a `.tar.zst`,
  plus a detached **Ed25519** signature (minisign format) over the archive.
- The `core` pack is built in CI on every release and published as a release
  asset; packs can also be published on their own between releases
  (`guard-packs.json` index next to `update-manifest.json`).
- The image carries the public key(s); unsigned or badly signed packs are
  refused, with the reason shown.
- sensr-guard keeps the last good version of each pack in its state directory
  and falls back to it if a new one fails to verify or to load.
- Pack updates: manual "Check for pack updates" plus an optional daily check
  (off by default), mirroring the system updater.

### Events and storage

- One BPF ring buffer (e.g. 1 MiB); userspace drains it, de-duplicates
  identical events within 10 s (with a count), and writes batches to
  `/var/lib/sensr-guard/events.db` once per 5 s at most.
- Per-rule and global caps (e.g. 100 events/s); overflow increments a dropped
  counter shown in the UI.
- Retention: 30 days or 200,000 rows (configurable).
- Alert-worthy events (any `block`, and rules marked notable) also appear in
  the existing Intrusion Detection alerts list as source "Runtime guard".

### UI

- **Services › Runtime Guard** (`/ui/guard`):
  - status: loaded packs/programs, kill-switch state, dropped events;
  - Rules: list with hit counters, add/edit (form), alert/block toggle (block
    asks for confirmation and uses commit-confirm);
  - Events: filterable table (hook, process, unit, target, action, time).
  - Packs: installed versions, signature status, enable/disable, check for
    updates.
- Host page: none in this project (the router itself is the subject).

### API and CLI

- `/api/v1/guard/{status,events,rules,packs}` + actions (reload, pack
  enable/disable, kill switch), privilege `page-services-guard`; read-only
  principals can't change anything.
- `sensr guard status|events|off|on`.

### Testing

- Unit: rule compilation to map entries, path/CIDR prefix logic, pack
  manifest parsing and signature verification (good, bad, wrong key),
  event de-duplication and rate limits, retention.
- BPF: programs compile in Nix; a NixOS VM test (x86_64; programs are CO-RE
  so the same objects are built per arch) that:
  - loads the core pack and checks each program attached;
  - starts a process from `/tmp` → alert event;
  - with a block rule on `connect` to a test IP → `connect()` fails `EPERM`,
    other destinations work;
  - a block rule whose target is sshd → not enforced (never-block list);
  - `guard-off` file → nothing blocks;
  - a bad-signature pack → refused, previous pack still active;
  - a non-guard process loading BPF → event (and blocked when that rule is on).
- aarch64: the same VM test on the aarch64 CI runner if available; otherwise a
  boot test that the objects load on the Pi kernel's BTF (CI nix-aarch64).

## Decisions from the design review

Answered from the router (2026-11-25):

- **Lockdown mode is `none`** (`/sys/kernel/security/lockdown`:
  `[none] integrity confidentiality`), so CO-RE kernel reads
  (`bpf_probe_read_kernel`) work. Pin it: the module sets `lsm=` (keeping
  `bpf`) and never sets `lockdown=confidentiality`; sensr-guard refuses to
  start (reports why) if lockdown is `confidentiality`.
- bpffs is mounted at `/sys/fs/bpf`.

Controller's calls (owner can override):

- **Programs are not pinned; the guard fails open.**
  - Programs and maps live as long as sensr-guard. A crash or restart leaves
    a short gap with no watching and no blocking. `Restart=always`
    (`RestartSec=1`), and the UI shows rules **inactive** while the daemon is
    down.
  - This follows the anti-goal (no lockout without recourse): a bad block
    rule disappears with the daemon, and commit-confirm's rollback plus a
    daemon restart always restore access.
- **Never-block works by systemd unit (cgroup), not by process.**
  - A listed unit's whole cgroup is exempt from blocks, so `nft`,
    `systemctl` and `switch-to-configuration` started by sensr-agent are
    covered.
  - Interactive SSH sessions live in `session-N.scope`, not in
    `sshd.service`, so an attacker's shell gets no exemption. sshd itself
    stays reachable.
  - The list: `init.scope`, `sensr-agent`, `sensr-guard`, `sensr-api`,
    `sshd`, `systemd-networkd`, `systemd-resolved`, `systemd-journald`,
    `sensr-kea-dhcp4`, `sensr-unbound`, `nix-daemon`, the sensr updater units
    (`sensr-update*`, `sensr-pi5-*`, `sensr-bootlog*`, `sensr-trial-*`) and
    `sensr-nic-recover`.
  - The list is compiled into the programs, not a map, so stale or missing
    map data can never lock anyone out.
- **The `core` pack is built into the image** and trusted because the image
  is (image integrity is the system update's business). Signatures apply to
  packs delivered between releases. On a fresh install the image's copy is
  the "last good" version.
- **Pack default rules live with the pack; the owner overrides them in the
  config.**
  - `guard.pack_rules: [{ pack, rule_id, enabled?, action? }]`.
  - Packs on and off (`guard.packs: [{ name, enabled }]`) and all rule
    changes are config changes, so they go through the agent's
    candidate/commit, commit-confirm and rollback.
  - Installing or updating a pack never edits the config.
- **Loader fallback:** if a spike shows aya cannot create C-defined
  `TASK_STORAGE` maps or attach sleepable LSM programs (`lsm.s/`, needed for
  `bpf_d_path`), use `libbpf-rs` for the loader instead. Hooks that still
  can't be attached are shown inactive with the reason.
- Module loads are watched via `kernel_read_file` (READING_MODULE) and
  `kernel_load_data`, not `kernel_module_request` (which only covers
  autoload).
- `vmlinux.h` is generated from the kernel package's `vmlinux` BTF at build
  time.
- The guard keeps its own `events.db`; the API merges guard events into the
  alerts view, rather than writing into sensr-insight's database.

- **Pack-signing key**: held as a GitHub Actions secret (owner: "try any one"; the image key list allows adding an offline owner key later). A leaked key is revoked by a release that drops it.

## Feasibility spike (2026-11-25)

A copy of the router's SD card (v0.1.28, kernel 7.3.4 Pi build) was booted
under QEMU/HVF. A C program compiled there with clang 19
(`-target bpf`, `vmlinux.h` from `bpftool btf dump`) and loaded with
`bpftool prog loadall ... autoattach`:

- `lsm.s/bprm_check_security` with `bpf_d_path`, a C-defined
  `BPF_MAP_TYPE_TASK_STORAGE` map and a ring buffer was accepted by the
  verifier. It reported every exec with its full path (`/tmp/evil-true`,
  `/nix/store/.../curl`).
- `lsm/socket_connect` returning `-EPERM` for 1.2.3.4 blocked that connect
  instantly, while 1.1.1.1 still worked.

The kernel side of the design works on the Pi kernel. Still open is whether
**aya** (not libbpf) can load the same objects; the plan's first task is that
spike, with the libbpf-rs fallback above.

## Left to the builder

- Exact map sizes, ring buffer size, event/rate caps and retention defaults
  within the stated bounds.
- The minisign tooling choice in CI (Rust `minisign-verify` crate in the
  daemon).
- Event table columns and UI layout details.
- How the cgroup-id → unit name cache is kept fresh.
