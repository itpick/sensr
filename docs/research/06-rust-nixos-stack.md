# 06 — Rust + NixOS stack for sensr

Research note, written 2026-11-15. Every version below was looked up that day
(crates.io API, repology, GitHub, channels.nixos.org, static.rust-lang.org); the
"checked" column in the pins table is the date the number was read, not a release
date. Re-run the lookups before trusting any number older than a month.

Scope: how sensr (a from-scratch Rust remake of OPNsense shipped as a NixOS image)
is put together. Six parts:

1. Lessons from the predecessor, `opnsense-pi`, and how sensr applies each.
2. OS base: NixOS channel, flake layout, images, atomic upgrades/rollback, and how
   the admin's runtime firewall config relates to the Nix closure.
3. Subsystem-by-subsystem Rust stack.
4. Dependency pins (versions, dates, health).
5. Dependency freshness policy.
6. What cannot be pure Rust yet, and the wrap-or-replace plan.

---

## 1. Lessons from opnsense-pi

`/Users/lucaspick/workspace/itpick/opnsense-pi` built flashable OPNsense 26.7
(FreeBSD 15.1) images for Raspberry Pi 4/5 from the community aarch64 VM images,
added Pi UEFI firmware, out-of-tree kernel modules, a first-boot hook, QEMU tests
and a GitHub release pipeline. Everything it learned the hard way is listed here
with the sensr consequence.

| # | Lesson (opnsense-pi) | Evidence | How sensr applies it |
|---|---|---|---|
| L1 | **Pin every input with a hash in one file.** `versions.env` holds URL + sha256 for the OPNsense image, Pi 4/5 UEFI zips, the kernel source ref, the kmod commit, and the plugin list; "bump a version and its sha256 together". | `versions.env`, `scripts/build-image.sh` | `flake.lock` is that file for Nix inputs and `Cargo.lock` for crates. Nothing is fetched at build time without a hash (Nix enforces it). Renovate bumps both (§5). The release manifest (`manifest.txt` in opnsense-pi) becomes `/etc/sensr/manifest.json` generated from the closure: nixpkgs rev, kernel, every daemon version, sensr git rev. |
| L2 | **First-boot settings live on the FAT boot partition**, because that is the one partition any laptop or a PXE installer can write. `config.xml` (applied once, renamed `.applied`), `drivers`, `ifnames`, `reboot-after-minutes`. | `overlay/usr/local/etc/rc.syshook.d/import/10-opnsense-pi` | Same contract, same partition: `/boot/firmware/sensr/` on the Pi (`/boot/sensr/` on the ESP for x86). A `sensr-firstboot.service` (Rust, part of the agent binary) runs before `network-pre.target`, imports `config.json`/`config.yaml` (sensr's typed config, §2.5) once and renames it `.applied`, reads `ifnames`, `reboot-after-minutes`, `diag`. The seed can also be an OPNsense `config.xml`: the importer (research doc 03) converts it. |
| L3 | **Pin NIC names by MAC, before anything configures interfaces.** USB NICs (`ue0`, `ue1`) attach in nondeterministic order so LAN/WAN swap between boots; the hook renames them by MAC in two passes via temporary names, and records the first boot's mapping if no file is given. | commit `cce5fb9`, `pin_ifnames` in the hook; `vm/test.sh` seeds swapped NICs to prove it | On Linux this is a solved problem: sensr writes `systemd.link` files (`[Match] MACAddress=` → `[Link] Name=lan0`) generated from the config, applied by udev before networking. The agent also keeps a MAC→logical-name table in the config so that `wan`/`lan` are stable names and the physical device is a detail. The first boot that finds unpinned NICs records them (same behaviour as the hook). Predictable names (`enp1s0`, `enx<mac>`) are the fallback, never `eth0`. |
| L4 | **A safety net for remote installs**: `reboot-after-minutes` reboots the box N minutes after every boot until the file is deleted, so a broken remote config cannot strand the device; trial boots save diagnostics to the ESP so even a box that never reaches the network leaves a post-mortem the PXE installer can read. | commit `fb73938`, `opnsense-pi-diag` | Two mechanisms replace it: (a) **systemd boot counting / automatic rollback** (§2.4) handles "the OS generation does not boot"; (b) a **config commit-confirm** in the agent handles "the config I just applied locked me out": every config apply is provisional for N minutes unless confirmed over the web UI/API, else the previous config is reapplied (Juniper `commit confirmed` semantics). `reboot-after-minutes` stays as a file on the boot partition for the installer case. `sensr diag` writes the same snapshot (`journalctl -b`, `ip -j`, `nft -j list ruleset`, dmesg, agent log) to `/boot/firmware/sensr/diag-<stage>.txt`. |
| L5 | **Hardware drivers were the whole problem on FreeBSD.** Pi 5 needed out-of-tree `rp1_eth`/`bcm2712`/`rpi5` modules compiled against the exact kernel, with symbol checks; RX stalled and needed two local patches (`rp1_eth-rx-recovery.patch`, `rp1_eth-start-rx-poll.patch`); RX is polled every 5 ms (~4 ms LAN latency); RTL8157 5 GbE USB NICs have no FreeBSD driver; Pi 4 has no ARMv8 crypto so VPNs are CPU-bound. | README "Board status", `patches/rpi5-kmods/`, commit `e0670f5` | **This is the reason sensr is Linux-based.** Checked today: the Raspberry Pi vendor kernel is `rpi-6.18.y` (nixos-hardware pins tag `stable_20261103`) and mainline 6.18+ drives the RP1 (`rp1_pci`, `pinctrl-rp1`, `clk-rp1`, Ethernet via `macb`) with interrupts, not polling; `r8152` in mainline has RTL8156/8156B and RTL8157 code paths (`r8157_rx_len`, `r8157_tx_csum` in `drivers/net/usb/r8152.c`). No out-of-tree modules, no patches. Pi 4's missing AES stays a fact: document ChaCha20-Poly1305 (WireGuard's default) as the Pi 4 VPN of choice and IPsec AES-GCM as "Pi 5 or x86". |
| L6 | **Suricata's Hyperscan is x86-only**; configs moved from x86 had `MPMAlgo hs` and Suricata refused to start on arm64, so the hook rewrites it to `ac`. | commit `cce5fb9` | nixpkgs builds Suricata 8.0.x against **vectorscan** (5.4.13 in unstable), the portable Hyperscan fork with NEON support, so `hs` works on aarch64. sensr still validates `mpm-algo` against the platform at config load and surfaces it in the UI instead of silently editing the config. |
| L7 | **Firmware/UEFI is a moving target on the Pi.** Pi 4 used pftf/RPi4 v1.53, Pi 5 used NumberOneGit/rpi5-uefi v0.1 (D0 boards, SD boot only); the Pi 5 UEFI had to be preset to "ACPI + Device Tree" by editing NVRAM in `RPI_EFI.fd` with `virt-fw-vars` so the device tree was available to `rp1_eth`; EEPROM had to be updated first; Pi 4 needed "Limit RAM to 3 GB" disabled by hand. | `uefi/pi5-vars.json`, commit `812e43d`, README "First boot" | NixOS on the Pi does not use UEFI at all: the Pi firmware (`raspberrypi/firmware` 1.20260915) boots a kernel directly or via U-Boot, device tree is native. sensr uses `nvmd/nixos-raspberrypi` (very active, pushed 2026-11-15) whose `kernel` bootloader mode supports multiple NixOS generations on the firmware partition, or `nixos-hardware`'s `raspberry-pi/5` profile + U-Boot extlinux. No NVRAM surgery. EEPROM update stays a documented first step (`rpi-eeprom` v2026.10.30-2712). |
| L8 | **Pi-shaped QEMU tests have limits and the README said so.** `virt` machine with Cortex-A76/A72 CPUs and the right RAM, serial console driven over a socket, tests for: GUI answers, plugin install + reboot, seed applied, ifnames swap, Suricata hs→ac, reboot-after-minutes. But: TCG makes performance numbers meaningless, no Pi NICs are modelled (virtio only), QEMU's A72 exposes crypto a real BCM2711 lacks, the Pi boot chain only runs on real boards. | `vm/run.sh`, `vm/test.sh`, `vm/console.py`, README "What the VM can and can't tell you" | Keep the honesty, use better tooling: NixOS VM tests (`nixosTest`, python driver, multiple machines on virtual networks) cover config-apply, firewall semantics, DHCP/DNS/VPN end-to-end between VMs, upgrade + rollback. The same `nixosTest` runs on aarch64 natively in CI (GitHub `ubuntu-24.04-arm` runners) instead of TCG. A hardware lab stage (two Pi 5s on the PXE server, §L10) runs the subset that needs real NICs: link detection, USB NIC reorder, throughput. |
| L9 | **Building on the target OS was a CI pain.** `customize.sh` had to run as root on FreeBSD aarch64 (UFS writes, the image's own `pkg` in a chroot), so CI ran a `vmactions/freebsd-vm` with NFS sync; builds took hours and three stages (raw → customize → compress). | `.github/workflows/release.yml`, commits `542d795`, `d91ae78` | Nix cross-compiles or builds natively on an arm64 runner; images are plain derivations (`nix build .#images.pi5`), no root, no chroot, no "writes UFS". One `nix build` produces the ISO, the Pi SD image and the qcow2. Caching via a binary cache (Cachix/attic) means a doc-only PR does not rebuild the kernel. |
| L10 | **PXE reimaging makes remote boards disposable.** `yieldllc/gitops/.../pxe`: a Pi whose EEPROM netboots asks TFTP for `<serial>/config.txt`; armed → busybox installer writes the image, verifies sha256, copies `--file` payloads onto the first partition (the opnsense-pi seed), reports done, disarms, reboots; unarmed → boots from SD. It also harvests the previous OS's diagnostics from the FAT partition. | pxe `README.md`, `reimage.sh --file opnsense-pi/config.xml=seed.xml` | sensr images keep the "first partition is FAT, seed files go there" contract so `reimage.sh --file sensr/config.yaml=...` works unchanged. Additionally, because NixOS supports `kexec`/`nixos-anywhere`, a running sensr can be re-imaged in place over SSH without PXE (`nixos-anywhere` 1.13.0 — note `nvmd/nixos-raspberrypi` says kexec is not supported on the Pi, so PXE remains the Pi path). |
| L11 | **Keep a manifest and a diag tool in the image.** `manifest.txt` listed every input; `opnsense-pi-diag` dumped kernel/ifaces/routes/modules to the ESP. | `scripts/customize.sh`, `opnsense-pi-diag` | `sensr version --json` prints the manifest; `sensr diag` is the same snapshot (also downloadable from the UI as a support bundle, with secrets redacted). |
| L12 | **Unofficial base = unsupported forever.** The images came from a community aarch64 build Deciso does not support; every OPNsense release risked breaking the boot hook (`rc.syshook.d/import` path discovered by grepping `/usr/local/etc/rc`). | README banner, commit `8396d4c` | sensr owns its whole stack; the only upstreams are nixpkgs, the kernel and a few daemons, all consumed through pinned, tested inputs. |
| L13 | **Release automation**: tag → build both boards → GitHub release with `.img.xz`, `.sha256`, manifest and default config; skip if the release exists; PRs keep images as artifacts for 7 days; Pages download page follows `releases/latest`. | `release.yml`, commit `72d3232` | Same shape: `vX.Y.Z` tag → `nix build` all image variants → GitHub + Forgejo releases with sha256 and manifest; PR builds publish artifacts; a download page points at `latest`. (Matches the Grown release process already in use.) |
| L14 | **Secondary NIC vendor drivers**: the `os-realtek-re` plugin (vendor `if_re.ko`) was preinstalled because FreeBSD's in-tree `re` is poor for modern Realtek PCIe NICs. | `PLUGINS="os-realtek-re"` | Linux `r8169` covers RTL8111/8168/8125 (2.5 GbE) in-tree; `r8126` (5 GbE RTL8126) is still out-of-tree in 6.18 — if sensr targets 5 GbE Realtek PCIe NICs on x86, nixpkgs has `linuxPackages.r8126` style out-of-tree modules, but this is the one place the L5 story is not finished. |

---

## 2. OS base

### 2.1 Which NixOS

Checked 2026-11-15:

| Channel | State | Notes |
|---|---|---|
| `nixos-26.05` ("Yarara") | **current stable**, released 2026-05-30, channel rev `f1e5c356…` | Kernel default moved 6.12 → **6.18**; systemd-based stage 1 (initrd) is the default; dbus-broker default; systemd 260.5; rustc **1.95.0** (too old for us, see §5). |
| `nixos-unstable` | tracks `26.11pre…` (rev `d5cc68339997` today) | systemd 262; rustc 1.99.1; has `boot.loader.systemd-boot.bootCounting` (not in 26.05). |
| `nixos-26.11` | **not released yet**; no `release-26.11` branch as of today. Expected ~2026-11-30 per the May/November cadence. | Will contain boot counting and kernel 6.18 LTS (or newer). |

Recommendation: **track `nixos-unstable` during development** (we need boot counting
and the newest kernels/daemons; sensr is itself unreleased), **then pin each sensr
release to the newest stable** (`nixos-26.11` once it ships, 26.05 if we release
before). Reason: stable gets security backports for seven months with low churn,
which matches "one firewall release every few weeks, patch releases in between".
Anything where stable lags upstream (OpenVPN 2.6.23 vs 2.7.9, Suricata 8.0.3 vs
8.0.8 in 26.05 today) is overridden in our overlay with `overrideAttrs { version;
src; }` — a Renovate rule bumps those (§5).

Toolchain: Rust **1.100.0** (stable, released 2026-11-12) via `oxalica/rust-overlay`
(or `fenix`), not nixpkgs' rustc, because nixpkgs stable is two to five releases
behind (1.95.0 in 26.05, 1.99.1 in unstable). Edition 2024. `rust-toolchain.toml`
pins the exact version and is the one file Renovate bumps when a new stable lands.

### 2.2 Flake layout

```
sensr/
  flake.nix                 inputs: nixpkgs (unstable now, release branch later),
                            nixos-hardware, nixos-raspberrypi (nvmd), disko,
                            rust-overlay, crane, treefmt-nix, git-hooks.nix,
                            sops-nix (CI secrets only), advisory-db (cargo-audit)
  flake.lock
  rust-toolchain.toml       channel = "1.100.0"
  Cargo.toml                workspace
  crates/
    sensr-config/           typed config model (serde + schemars), versioned, migrations
    sensr-agent/            the privileged daemon: applies config via netlink, supervises
                            wrapped daemons, exposes a local gRPC/Unix-socket API
    sensr-api/              axum HTTP/JSON + WebSocket backend (unprivileged, talks to agent)
    sensr-ui/               Leptos SSR + islands frontend (OPNsense-like layout, own CSS),
                            hydrated wasm served by sensr-api via leptos_axum
    sensr-cli/              `sensr` CLI (console menu, diag, version, config import)
    sensr-netlink/          thin wrappers over rtnetlink / nftables / wireguard netlink
    sensr-dhcp/, sensr-ra/, sensr-ddns/, sensr-monitor/ ...  Rust-native services
  nix/
    overlays/default.nix    pkgs.sensr-* (via crane), version overrides for daemons
    modules/                NixOS modules: services.sensr.*, hardware profiles
    images/                 iso-installer.nix, pi4.nix, pi5.nix, qcow2.nix, raw-efi.nix
    tests/                  nixosTest definitions (apply, rollback, dhcp, vpn, ha ...)
  docs/
```

Build graph: `crane` (v0.24.0) builds the Cargo workspace incrementally
(deps-only derivation cached separately), `rust-overlay` supplies 1.100.0 for
`x86_64-linux` and `aarch64-linux`, `treefmt-nix` + `git-hooks.nix` run
`rustfmt`/`clippy`/`nixfmt` pre-commit. Images are `nixosConfigurations.<name>
.config.system.build.images.<variant>` via nixpkgs' `image.modules` (26.05 has
`iso`, `iso-installer`, `sd-card`, `raw-efi`, `qcow`-style cloud variants:
amazon, azure, digital-ocean, hyperv, linode, oci, openstack, proxmox, vmware,
virtualbox, kexec).

### 2.3 Images

| Target | How | Boot | Status today |
|---|---|---|---|
| **x86_64 UEFI installer ISO** | `image.modules.iso-installer` + our module; installer = `disko` (v1.13.0) declarative partitioning driven by a Rust TUI (`ratatui` 0.30.2) that asks disk / LAN NIC / admin password, then `nixos-install --system <closure>` from the ISO's store (offline). | systemd-boot | Standard nixpkgs path; the ISO also offers "install over SSH" via `nixos-anywhere` 1.13.0. |
| **x86_64 raw-efi image** (dd-able, for appliances/PC Engines/Protectli) | `image.modules.raw-efi`; grows root on first boot (`boot.growPartition`). | systemd-boot | Standard. |
| **Raspberry Pi 5 SD/NVMe image** | `nvmd/nixos-raspberrypi` `raspberry-pi-5.base` + `sd-image`; vendor kernel `linuxPackages_rpi5` (rpi-6.18.y) + matching `raspberrypifw` 1.20260915 and wireless firmware; bootloader mode `kernel` (multi-generation). Alternative: `nixos-hardware/raspberry-pi/5` + `hardware.raspberry-pi.firmware` + U-Boot `generic-extlinux-compatible` (nixos-hardware notes U-Boot cannot drive USB/PCIe/RP1 on the Pi 5 yet, so USB/NVMe *boot* needs the firmware-direct `kernel` mode — another reason to prefer nvmd). | Pi firmware → kernel (or U-Boot) | nixpkgs **removed** `linux_rpi*` ("please change to use nixos-hardware"); both out-of-tree flakes are maintained (nixos-hardware pushed 2026-11-13, nvmd 2026-11-15). Mainline 6.18 also boots the Pi 5 (nixos-hardware handles the `linux` vs `linux-rpi` module-name differences), useful as a fallback. |
| **Raspberry Pi 4 SD image** | same flakes, `raspberry-pi-4.base` / `raspberry-pi/4`; `genet` Ethernet in-tree. | U-Boot extlinux (USB boot works on Pi 4) | Standard. |
| **qcow2 / cloud / VM** | `image.modules.qcow`-style (proxmox, openstack, hyperv, vmware, oci); plus a `nixosTest` VM for CI. | systemd-boot | Standard. |

All images carry the FAT first partition with `sensr/` seed folder (L2, L10) and
`sensr/README.txt` explaining the files.

### 2.4 Atomic upgrades and rollback

NixOS gives us A/B-equivalent semantics for free: every `nixos-rebuild switch`
(or `switch-to-configuration` on a prebuilt closure) is a new **generation**, the
bootloader lists all retained generations, and `nixos-rebuild --rollback` or
picking an older entry at boot restores the previous OS byte-for-byte. The
runtime state (`/var/lib/sensr`, leases, logs) is outside the closure and shared
across generations.

What we add:

1. **Boot counting** (`boot.loader.systemd-boot.bootCounting.enable = true; tries = 3;`,
   in nixos-unstable → 26.11). systemd-boot writes `+3` into new entry names,
   decrements per boot, `systemd-bless-boot.service` clears it once
   `boot-complete.target` is reached; an entry that hits 0 is skipped in favour of
   the previous generation (systemd "Automatic Boot Assessment"). sensr hooks its
   own health check into `boot-complete.target`: the agent must have applied the
   config and the management interface must answer, otherwise the generation is
   never blessed. On x86 that is the whole story.
2. **Pi**: no systemd-boot. The Pi firmware has its own A/B mechanism
   (`tryboot`: `reboot "0 tryboot"` boots `tryboot.txt`/the alternate partition
   once; `autoboot.txt` with `[tryboot]` filter; nixos-hardware's config.txt
   module already models `[tryboot]` filters). nvmd's `kernel` bootloader mode
   keeps multiple generations on the firmware partition (issue #60). Plan: the
   agent flips the Pi `tryboot` flag before rebooting into a new generation and
   commits it only after `boot-complete.target`; if the box comes back on the old
   generation, the UI shows "upgrade rolled back". Needs a small amount of
   first-party code (reading `/proc/device-tree/chosen/bootloader/tryboot`,
   writing `autoboot.txt`); nothing else in the Nix ecosystem does this today.
3. **Upgrade delivery**: pull a prebuilt closure (`nix copy --from https://cache…`
   or `nixos-rebuild switch --flake github:itpick/sensr/vX.Y.Z#<profile>` via
   `system.autoUpgrade`) — no evaluation on the box if we ship closures from the
   binary cache (Pi 4 with 2–8 GB RAM should not evaluate nixpkgs). The UI's
   "Update" page is a thin wrapper: check cache for newer tag → download → switch
   → reboot into counted entry.
4. **Config rollback is separate from OS rollback** (§2.5): the config store keeps
   history; "revert config" never touches the bootloader.

### 2.5 Runtime config vs the Nix closure

The question: the admin edits firewall rules in the web UI. Does that
(a) write a typed config that a Rust agent applies live via netlink, or (b)
generate Nix and run `nixos-rebuild`?

| | (a) Typed config + runtime agent | (b) Generate Nix + rebuild |
|---|---|---|
| Apply latency | ms–s (one nftables transaction, a few rtnetlink messages, `systemctl reload`) | 10 s–minutes (Nix eval + build of config files + activation); needs nix-daemon, store writes, RAM — bad on Pi 4 |
| Atomicity | nftables rulesets are transactional; the agent orders changes (interfaces → addresses → routes → nft → daemons) and reverts on failure; commit-confirm (L4) | Fully atomic at the generation level; rollback is a boot entry |
| Blast radius of a typo | Agent validates the typed model (schemars/garde) before touching anything; failed apply → previous state restored | Build failure → nothing applied (good); runtime failure (daemon won't start) → still a new generation that must be rolled back |
| Offline / bootstrap | Config is a file; first boot imports it (L2) | Needs a working Nix on the box or prebuilt closure per config → impossible for arbitrary per-device configs without a build server |
| Fits "all in Rust" | Yes: the model, validation, apply logic, diff, history are Rust | No: half the product logic becomes Nix modules |
| Fits GitOps / declarative users | Via a Nix module that *emits the same typed config file* (`services.sensr.config = { ... }`) → agent applies at boot; UI becomes read-only ("managed by Nix") | Native |
| Boot menu noise | None | A generation per rule change |
| Upstream precedent | OPNsense (config.xml + configd applies), VyOS (config → templates → reload), RouterOS | NixOS-only firewall configs (`networking.nftables.ruleset`) — fine for a personal box, not for a UI-driven product |

**Recommendation: hybrid, (a) by default.**

- The **OS closure is immutable** and contains: kernel, systemd, the sensr
  binaries, every wrapped daemon (Unbound/Kea/strongSwan/Suricata/…), their
  systemd units with `ExecReload`, and nothing config-specific.
- The **sensr config** is one typed, versioned document (Rust structs with
  `serde`, JSON Schema via `schemars` 1.2.3 for the UI and for validation,
  `semver`-numbered schema with migration functions). It lives in
  `/var/lib/sensr/config.db` (SQLite via `rusqlite` 0.43.0: current document +
  full history + who/when/diff, WAL, single file to back up) and is exported as
  `config.yaml`/`.json` for backups, seeds and Git.
- The **agent** (`sensr-agent`, runs as root with capabilities dropped to
  `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_NET_BIND_SERVICE` via `caps`) computes a
  diff between running state and desired state and applies it: netlink for
  links/VLANs/bridges/bonds/addresses/routes/rules/qdiscs, nftables netlink for
  the ruleset, WireGuard netlink for tunnels, and for wrapped daemons it renders
  their config into `/run/sensr/<daemon>/` and `systemctl reload|restart` via
  D-Bus (`zbus` 6.3.0). Every apply is a transaction with commit-confirm.
- The **Nix module** `services.sensr` exposes an optional `config` attribute (or
  `configFile`) for declarative users; when set, the agent treats the store path
  as the source of truth, the UI is read-only, and a config change *is* a
  `nixos-rebuild` — that is the (b) path, available but not required. Also handy
  for the `nixosTest` suite: tests are just Nix attrsets of sensr config.
- Things that legitimately *are* closure-level stay in Nix and are exposed in
  the UI as "requires OS update": kernel modules, optional packages (an IDS
  ruleset engine, a proxy), hardware profiles.

Why not pure (b): OPNsense's own strength is "edit, apply, see it in a second";
Nix evaluation on a Pi 4 is tens of seconds and gigabytes; per-device configs
would need a build farm or on-device builds; and the product logic would be
split across two languages, against the "all in Rust" goal. Why not pure (a):
declarative users and our own tests want to express a whole box in one file,
and the OS still needs generations for upgrades.

---

## 3. Subsystem-by-subsystem Rust stack

Versions are crates.io `max_stable_version` on 2026-11-15; "updated" is the date
of the latest publish. Full table in §4.

### 3.1 Packet filter — nftables

Options evaluated:

| Crate | Version | Updated | Approach | Verdict |
|---|---|---|---|---|
| `rustables` | 0.9.0 | 2026-09-21 | Pure-Rust nftables netlink (no libnftnl); GitLab rustwall | Pure Rust, but a small team; API churn between 0.x |
| `nftnl` + `mnl` (Mullvad) | 0.9.4 / 0.3.1 | 2026-08-11 / 2026-02-10 | Safe bindings to libnftnl/libmnl; used in production by Mullvad's firewall | C deps; expressions must be built by hand; mature |
| `nftables` (+ `nftables-async`) | 0.6.3 / 0.4.1 | 2025-08-15 / 2026-05-11 | Serde model of the libnftables JSON schema; shells out to `nft -j` | Complete expression coverage for free (anything `nft` can do), textual diff/dump trivial, upstream-stable schema; `nft` binary is a dependency; 3.2 M downloads |
| `nftables-nl`, `jip-nftables` | 0.5.0 / 0.1.0 | 2026-11-11 / 2026-04-18 | Young pure-netlink attempts | Too small today |

**Pick: `nftables` (JSON) for the ruleset, `nftnl`/`rustables` kept as the
escape hatch.** Reasoning: a firewall product needs *every* nftables feature
(sets with timeouts, maps, vmaps, flowtables for hardware offload, `ct`
helpers, `synproxy`, `meta`/`socket`, named counters/quotas/limits, NAT with
port ranges, `fib` checks for rpfilter, `osf`), and the JSON API is the only
Rust path with complete, upstream-maintained coverage. One `nft -j -f -` per
apply is a single atomic transaction. Dynamic set updates (blocklists, captive
portal sessions, gateway failover) go through the same path (`add element`)
or through `rustables` where sub-millisecond netlink matters. nftables userspace
is 1.1.7 (nixpkgs unstable 1.1.7). We also read back `nft -j list ruleset` to
detect drift. The pure-netlink route stays on the roadmap (§6) and `rustables`
is the candidate to graduate to it.

### 3.2 Interfaces, VLAN, bridges, bonding (LAGG), routing

**`rtnetlink` 0.24.0** (rust-netlink org; updated 2026-11-04) with
`netlink-packet-route` 0.34.0 / `netlink-packet-core` 0.9.0 / `netlink-sys` 0.9.0
— note all of rust-netlink published **1.0.0-rc2 today (2026-11-15)**; we start
on 0.24 and move to 1.0 when it lands (Renovate will tell us). It covers links
(create VLAN, bridge, bond, veth, dummy, VRF, macvlan, wireguard, gretap,
vxlan…), addresses, routes (tables, metrics, multipath, nexthop objects), rules
(policy routing for multi-WAN), neighbours, and **tc qdiscs/classes/filters**
(§3.11). `neli` 0.7.5 is the alternative generic netlink library; `rtnetlink`'s
typed packets are the better fit. `ethtool` 0.4.0 and `wl-nl80211` 0.9.0 (same
org) cover NIC offload settings and Wi-Fi. Stable names via generated
`systemd.link` (L3). Routes installed by the agent are tagged with a sensr
protocol number so they can be diffed against dynamic routing (§3.19).

### 3.3 WireGuard

Kernel WireGuard + generic netlink. Candidates:
`defguard_wireguard_rs` 0.12.5 (2026-11-04, active, supports kernel + userspace
backends, used by Defguard), `wireguard-control` 2.0.0 (2026-07-02, from
innernet), `nl-wireguard` 0.3.1 / `netlink-packet-wireguard` 0.5.1 (rust-netlink,
2026-11-04), `wireguard-uapi` 3.0.1 (2025-05-10). **Pick `defguard_wireguard_rs`**
for the high-level API (interface, peers, stats, keys) and
`netlink-packet-wireguard` when we need raw access from the same netlink socket
as `rtnetlink`. `boringtun` 0.7.1 (Cloudflare, userspace) only for platforms
without the kernel module — not our case. `wireguard-tools` 1.0.20260223 is not
needed at runtime (debug only).

### 3.4 IPsec

No credible pure-Rust IKEv2 stack exists for production. **strongSwan 6.1.0**
(2026-09-07; nixpkgs 6.1.0) via its VICI socket: `rsvici` 0.1.5 (2026-08-18,
tokio, 35 k downloads) and `serde_vici` 0.1.5 by the same author; `rustici` 1.1.1
(2026-02-25) is a second pure-Rust client; `strongswan`/`strongswan-sys` 0.1.0
(2026-09-14) embed charon via FFI — too new. **Pick `rsvici` + `serde_vici`**,
the agent generates `swanctl`-style connections and loads them over VICI
(load-conn/load-key/load-shared/initiate/terminate/list-sas) so no config file
is written at all. OPNsense does exactly this with PHP. strongSwan stays C (§6).

### 3.5 OpenVPN

OpenVPN 2.7.9 (2026-11-05; nixpkgs unstable **2.6.23**, must override). Managed
process + management interface: `openvpn-mgmt-codec` 0.8.0 (tokio-util codec,
2026-03-30). No Rust OpenVPN server exists (`openvpn-connect` 0.1.2 is client-only
FFI to OpenVPN 3 Core). OpenVPN gets DCO (kernel data channel offload,
`ovpn` module merged in Linux 6.16) which 2.7 uses — one more reason to pin 2.7.
Position it as legacy-compat; WireGuard is the default VPN.

### 3.6 DHCPv4/v6 server and client, router advertisements

- Protocol: **`dhcproto` 0.15.0** (BlueCat, 2026-05-19, 1 M downloads) —
  v4 and v6 encode/decode, options, relay agent info.
- Server: **`dora`** (BlueCat, built on dhcproto + sqlx/SQLite) is the only Rust
  DHCPv4 server with DDNS, client classes, static leases, ping-check, metrics,
  leases HTTP API — but: **no releases on GitHub or crates.io, last commit
  2026-01-29, "may contain bugs", DHCPv6 still "eventually"**. `rdhcpd` 0.16.3
  (2026-11-13, dual-stack, HA) is six stars and days old. **Plan: write
  `sensr-dhcp` on `dhcproto`** (v4 + v6 + PD + relay), using dora as the design
  reference; until it passes the conformance tests, ship **Kea 3.2.1** (ISC;
  nixpkgs 3.2.1) as the wrapped server, driven via its control socket JSON API
  (Kea ≈ OPNsense 26.x's default too). ISC DHCP is EOL and not an option.
- Client (WAN DHCP/DHCPv6-PD): `sensr-dhcp` client side on `dhcproto` +
  `dhcpv6-core` 0.1.0 (Fuchsia's DHCPv6 client state machine, 2026-08-12) as
  reference; fallback `systemd-networkd` (has a solid DHCPv4/v6-PD client and
  RA; ships in systemd 260/262) configured by the agent — this is the pragmatic
  day-one choice for WAN.
- Router advertisements: `sensr-ra` in Rust (raw ICMPv6 socket via `socket2`
  0.6.5; `ipv6-router-advertisement` 0.2.0 is a codec to borrow from), or
  systemd-networkd's `IPv6SendRA` until then. `radvd` 2.21 is the C fallback.

### 3.7 DNS resolver / forwarder / blocklists

**`hickory-dns` 0.26.3** (server, resolver, proto; 2026-09-10; 100 M+ downloads
on the resolver; formerly trust-dns): recursive resolver, forwarder, DoT/DoH/DoQ,
DNSSEC validation, authoritative zones (for local hostnames/DHCP registration),
pluggable `Authority` for blocklists (`forward` + a deny authority with
CNAME/NXDOMAIN/sinkhole semantics). This is the Rust replacement for both
Unbound and dnsmasq roles. Caveat: hickory's recursive resolver is younger than
Unbound 1.26.2 (2026-10-21) — ship **Unbound as an optional wrapped resolver**
for users who want it (DNSBL via `unbound` views/RPZ), with `sensr-dns` on hickory
as default. Blocklist formats (hosts, domain lists, AdGuard, RPZ) parsed in Rust;
updates on a `tokio-cron-scheduler` 0.15.1 schedule.

### 3.8 NTP

**`ntpd` 1.9.0** (ntpd-rs, Pendulum/Tweede golf, 2026-06-12; NTPv4 client+server,
NTS, NTPv5 draft, memory-safe, used by Let's Encrypt). 2.0.0-alpha
(2026-11-13) reworks config format and sync algorithm — stay on 1.9 until 2.0
final. nixpkgs packages `ntpd-rs` and has a module. chrony 4.9 not needed.

### 3.9 IDS/IPS

**Suricata 8.0.8** (2026-10-29; nixpkgs unstable 8.0.7, 26.05 8.0.3) wrapped: AF_PACKET
IDS or NFQUEUE IPS mode, EVE JSON over a Unix socket consumed by the agent
(`serde_json` streaming → SQLite/`redb` alert store + UI live view), rule
management (ET Open, Abuse.ch, custom) by a Rust downloader replacing
`suricata-update`. Suricata 8 itself is ~half Rust internally (app-layer parsers)
and requires cargo to build; pattern matching via **vectorscan** on arm64 (L6).
No pure-Rust IDS exists with a Suricata-compatible rule engine; see §6.

### 3.10 Traffic shaping

tc via `rtnetlink` (qdisc/class/filter messages in `netlink-packet-route`):
CAKE per interface for the common "fix bufferbloat" case, HTB/FQ-CoDel trees
with `nft` marks → `tc filter … handle <mark> fw` for OPNsense-style pipes/queues
(or `nft` `meta priority` to classify directly). `netlink-tc` 0.0.4 (2023) is
dead; don't use. We may shell to `tc -j` for qdisc *statistics* initially (JSON
output is stable), same pattern as §3.1.

### 3.11 Flow export (NetFlow v9 / IPFIX)

Export is the hard half: nothing packaged does "observe conntrack → emit IPFIX".
Design: a `sensr-flow` exporter that subscribes to conntrack events
(`conntrack` 0.1.5 crate, 2025-12-03, libnetfilter_conntrack binding — or
`neli`-based NFNETLINK_CONNTRACK directly) and encodes IPFIX/NetFlow v9 with
**`netgauze-flow-pkt` 0.14.0** (NetGauze, 2026-11-10, IANA IE code generation) or
`netflow_generator` 0.2.8. `netflow_parser` 1.0.6 (2026-07-23) handles the
collector/"Insight" side if sensr also ingests flows for its own reporting.
Fallback: `softflowd`/`pmacct` wrapped. Kernel alternative: `nf_flow`? no —
conntrack events are the right source for a NAT box because they carry both
pre- and post-NAT tuples.

### 3.12 High availability

- **VRRP**: Holo (`holo-routing/holo` v0.9.0, 2026-02-21, MIT, Rust) implements
  VRRPv2/v3 (RFC 3768/5798) alongside BGP/OSPF/IS-IS/RIP/BFD/LDP with YANG config
  and gRPC — the natural Rust replacement for both keepalived and FRR (§3.19).
  `highland-daemon` 0.2.2 (2026-11-12, VRRPv3 + health checks) and `wren-vrrp`
  0.3.1 are tiny; keepalived 2.4.3 is the C fallback. **Pick Holo**, wrapped as a
  daemon the agent drives over gRPC (`tonic` 0.14.9 / `prost` 0.14.6). CARP
  compatibility is not possible (CARP is BSD-only); document VRRP as the
  replacement.
- **State sync**: `conntrackd` (conntrack-tools 1.4.9, C) for connection-table
  replication — keep it wrapped (§6). pfsync has no Linux equivalent beyond this.
- **Config sync**: sensr-native, the typed config pushed peer-to-peer over mTLS
  (`rustls` 0.23.46, `rcgen` 0.14.10 device certs) — like OPNsense XMLRPC sync but
  with the JSON document and schema version checks.

### 3.13 Web backend

**`axum` 0.8.9** on **`tokio` 1.54.1**, `tower` 0.5.3, `tower-http` 0.7.1
(compression, CORS, trace, static files), `hyper` 1.12.0, TLS via
`axum-server` 0.9.2 + `rustls` 0.23.46 (0.24 is still `-dev`), sessions
`tower-sessions` 0.15.0, auth `axum-login` 0.18.0, cookies `tower-cookies`
0.11.0, WebSocket (`tokio-tungstenite` 0.30.0 through axum's `ws`) for live
logs/graphs, OpenAPI via **`utoipa` 6.0.0** (so the CLI, Terraform/Pulumi
providers and the OPNsense-API-compat layer share one spec), validation `garde`
0.23.0, templates not needed (SPA). The API process is unprivileged and talks to
`sensr-agent` over a Unix socket (`tonic` gRPC or plain JSON framing). The
OPNsense API compatibility shim (`/api/<module>/<controller>/<command>`) is a
router layer in the same process — see research doc 03.

### 3.14 Frontend ("all in Rust")

**Decision (user/lead, 2026-11-15): the UI looks like OPNsense — left sidebar
menu tree, top bar, the same page → form → grid structure — so OPNsense admins
feel at home, but is built with Leptos (latest), SSR + hydration with islands,
fine-grained signals, and types shared with the axum backend through server
functions. Own CSS; no OPNsense theme assets, logos or copied markup.**

Candidates compared:

| Option | Version (stable / pre) | Updated | Notes |
|---|---|---|---|
| **Leptos** | 0.8.23 / 0.9.0-rc1 | 2026-10-31 | Fine-grained signals (`reactive_graph` 0.2.16), SSR + hydration + islands, `server_fn` 0.8.13 shares types/functions with axum, largest Rust web ecosystem (6.2 M downloads; `leptos-use` 0.20.0, `leptos_i18n` 0.6.3). |
| Dioxus | 0.7.10 / 0.8.0-alpha.3 | 2026-10-16 | React-like VDOM with signals; strongest on desktop/mobile; hot-reload. |
| Sycamore | 0.9.4 / 0.10.0-beta.1 | 2026-11-09 | Fine-grained like Leptos, small community (322 k downloads). |
| Yew | 0.23.0 | 2026-03-10 | VDOM, slower cadence, no SSR story comparable to Leptos. |
| TypeScript SPA | — | — | Richest component libs; violates "all in Rust". Rejected. |

Pinned versions (crates.io, 2026-11-15): **`leptos` 0.8.23, `leptos_router`
0.8.17, `leptos_axum` 0.8.10, `leptos_meta` 0.8.7, `server_fn` 0.8.13,
`cargo-leptos` 0.3.12 (2026-11-09)**; all core crates have **0.9.0-rc1**
published 2026-10-31 — start on 0.8.x, migrate to 0.9 the week it goes final
(the Renovate "watch" issue, §5.6). Companions: `wasm-bindgen` 0.2.130,
`web-sys` 0.3.107, `wasm-bindgen-futures` 0.4.80, `gloo` 0.13.0, `leptos-use`
0.20.0 (debounce, storage, websocket, intersection observer), binaryen
`wasm-opt` 133 (nixpkgs unstable 133; the `wasm-opt` crate 0.116.1 is stale,
use the binary from nixpkgs). Build with `cargo-leptos` (not `trunk`), which
does the SSR server + hydration wasm split, `wasm-opt -Oz`, and hashed file
names in one tool.

Performance rationale:

- **js-framework-benchmark**: Leptos consistently sits in the top group of all
  frameworks (within a few percent of vanilla JS and alongside SolidJS and
  Svelte on the keyed-row benchmarks) because fine-grained reactivity updates
  DOM nodes directly without a virtual DOM diff. Dioxus (VDOM + signals) and
  Yew (VDOM) are measurably slower on the "partial update / select row / swap
  rows" cases that are exactly what a firewall grid does (toggle one rule,
  reorder, inline-edit). Sycamore is in the same fine-grained class as Leptos
  but with a far smaller ecosystem. Re-check the current run at
  krausest/js-framework-benchmark before citing numbers in user-facing docs; the
  ranking has been stable for three years.
- **First paint**: SSR means the OPNsense-style page (sidebar, top bar, form
  skeleton, first page of a grid) arrives as HTML and is usable before the wasm
  loads — important on a slow WAN admin session or a Pi 4 serving the page.
- **Wasm bundle size** (the honest weak point of Rust UIs; a naive Leptos app is
  1–3 MB):
  - **Islands** (`#[island]`): only interactive components (grids, forms,
    live graphs) ship wasm; static chrome (menu tree, breadcrumbs, help text) is
    server-rendered HTML with zero client code. Target: <400 KB brotli for the
    base island bundle.
  - `wasm-opt -Oz` + `opt-level = "z"`, `lto = "fat"`, `codegen-units = 1`,
    `panic = "abort"`, `strip = true` in the `[profile.wasm-release]`
    `cargo-leptos` uses; `wasm-bindgen` `--reference-types`.
  - **Code splitting / lazy routes**: Leptos 0.8 has lazy-loaded routes
    (`#[lazy]` / `lazy_route`) so the IDS, VPN, and reports pages load their
    wasm on first visit; 0.9 improves this further (one of the reasons to move
    quickly).
  - Keep the dependency diet: no `regex`/`chrono` in the client crate (use
    `jiff` with minimal features or server-side formatting); feature-gate
    `sensr-config` so the wasm build compiles only the model + validators.
  - Serve with `tower-http` brotli/zstd precompression and long-lived immutable
    cache headers (hashed file names), so the bundle is downloaded once per
    release.
- **Shared types**: `sensr-config` (serde + schemars + garde) compiles to both
  targets, so the browser validates with the same rules the agent applies and
  server functions take/return the real config structs — no OpenAPI codegen
  layer between UI and backend (the `utoipa` spec in §3.13 remains for third
  parties).

Replicating OPNsense's UI as Leptos components (own CSS, same ergonomics):

| OPNsense element | Leptos component | Notes |
|---|---|---|
| Left menu tree (System / Interfaces / Firewall / VPN / Services / …) | `<MenuTree>` server-rendered from a menu definition shared with the API's route table; `<A>` from `leptos_router`; open/active state derived from `use_location()`. | Not an island — pure SSR HTML + CSS for collapse; a tiny island only for the search-as-you-type filter at the top. |
| Top bar (hostname, logout, help toggle, breadcrumbs) | `<TopBar>` SSR + one island for the session/notification badge (WebSocket via `leptos-use`). | |
| Form pages ("General settings" tabs, field + help text, advanced toggle) | `<SettingsForm<T>>` generic over a config struct; renders from `schemars` metadata (labels, help, enum options, validation) so most forms are declared, not hand-written; `<FormField>`, `<HelpText>`, `<AdvancedToggle>`. | Server function `save_<section>(T) -> Result<ApplyReport>`; errors map back to fields. |
| Bootgrid tables (search, paging, column chooser, inline enable/disable toggle, drag-order for rules, row actions edit/clone/delete) | `<Grid<T>>` island: `RwSignal<GridState>` (query, sort, page, page size, visible columns, selection) → `Resource` calling a server fn `list_<kind>(GridQuery) -> Page<T>`; `<For>` keyed on row id for fine-grained row updates; `<ToggleCell>` calls `set_enabled(id, bool)` and updates the row signal optimistically; `<RowActions>`; drag reordering via `leptos-use` `use_sortable`/pointer events writing a `sequence` field. | Column chooser and page size persisted per grid in `localStorage` (`use_local_storage`). Server-side paging/search so a 10 k-rule grid stays fast. |
| Modal edit dialogs | `<Dialog>` island with `<SettingsForm<T>>` inside; URL-addressable (`?edit=<id>`) so deep links work. | |
| "Apply changes" banner | `<ApplyBanner>` island fed by a server-sent `pending_changes` signal; triggers the agent's commit-confirm (§2.5). | |
| Dashboard widgets | Islands per widget; charts via a thin `web-sys` wrapper over uPlot (JS library, not app code) or `plotters` to canvas for zero JS. | |
| Live log viewers (firewall log, system log) | `<LiveLog>` island on a WebSocket stream of journald/nft log JSON. | |
| Help text / i18n | `leptos_i18n` 0.6.3; strings keyed like OPNsense's for easy mapping. | |

CSS: our own design tokens (CSS variables), a dense "admin console" look that
mirrors OPNsense's layout proportions and Bootstrap-like form density, but no
Bootstrap, no copied theme files, no OPNsense logo. Light/dark via
`prefers-color-scheme`.

Risks: Leptos 0.9 migration (planned); hiring/learning curve vs TS; wasm size
if islands discipline slips (the nightly CI prints bundle size and fails above
a budget).

### 3.15 Auth

`argon2` 0.6.0 (Argon2id, RustCrypto, 2026-08-27), `totp-rs` 6.0.0 (2026-08-06),
`openidconnect` 4.1.0 (2026-10-31; OIDC login against Zitadel/Keycloak/Entra),
`webauthn-rs` 0.6.2 (Kanidm, 2026-10-31; passkeys), `jsonwebtoken` 12.0.0
(2026-11-13; API tokens), `ldap3` 0.12.1 (2025-09-18; LDAP/AD groups — quiet but
complete), `radius` 0.4.0 (2024-01-15; RADIUS client for captive portal/VPN auth —
old, may need a fork or our own on `tokio` — RADIUS is a tiny protocol),
`secrecy` 0.10.3 / `zeroize` 1.9.1 for key material, `governor` 0.10.4 for
login rate limiting. Console/SSH auth stays PAM/sshd (NixOS), with the sensr
admin users projected into `users.users` only for the recovery account.

### 3.16 Config storage, backups

`serde` 1.0.229 + `serde_json` 1.0.154 + `toml` 1.2.1 (edition files), schema
`schemars` 1.2.3 + `jsonschema` 0.61.2 (validation of imported documents),
history in **`rusqlite` 0.43.0** (bundled SQLite, 2026-11-15) with
`rusqlite_migration` 2.7.0; `redb` 4.6.0 (pure-Rust embedded KV, 2026-11-13) for
hot runtime state (leases, DHCP, flows) where SQL is not needed. Backups:
`tar` 0.4.46 + `zstd` 0.14.4, encrypted with **`age`** 0.12.1 (rage; passphrase
or recipient keys), optional push to S3/WebDAV/Nextcloud/Git via `reqwest`
0.13.5 (rustls) — mirrors OPNsense's Nextcloud/Git backup plugins. `blake3`
1.8.7 for content hashes.

### 3.17 Metrics, logging

`tracing` 0.1.44 + `tracing-subscriber` 0.3.23 + `tracing-journald` 0.3.2 (all
daemons log structured to journald; the UI reads `journalctl -o json` via
`zbus`/`sd-journal`), `tracing-opentelemetry` 0.34.0 + `opentelemetry-otlp`
0.33.1 for shipping to a collector. Metrics: **`prometheus-client`** 0.26.0
(official client_rust, 2026-11-11, OpenMetrics) over `prometheus` 0.14.0 (tikv,
last release 2025-03-27). `sysinfo` 0.40.3 / `procfs` 0.18.0 for host stats
(CPU, memory, temps, disk). Round-robin graphs: store samples in SQLite with
downsampling jobs (RRDtool replacement in Rust is ~300 lines) and render in the
UI. Syslog export to remote collectors (RFC 5424/TLS) is a small Rust shipper.

### 3.18 Certificates / ACME

`rcgen` 0.14.10 (device/CA/client certs, 2026-08-28), `x509-parser` 0.18.1,
`instant-acme` 0.8.5 (ACME client, djc, 2026-02-24) for Let's Encrypt with
HTTP-01/DNS-01 (DNS-01 via the same provider plugins as DDNS §3.25), `pem` 4.0.0,
`webpki-roots` 1.0.12 / `rustls-platform-verifier` 0.7.1. `rustls-acme` 0.15.4
is an alternative that integrates with axum directly for the admin UI cert.
Replaces OPNsense's os-acme-client (acme.sh) in Rust.

### 3.19 Dynamic routing

**Holo** (§3.12) for BGP/OSPFv2/v3/RIP/IS-IS/BFD — it is the Rust FRR. Where
Holo lacks something (route maps are evolving; no PIM yet), **FRR 10.7.1**
(nixpkgs 10.7.1) is the wrapped fallback, driven via `vtysh -c`/its JSON
output. Both are optional packages selected in the Nix closure (closure-level
choice, §2.5).

### 3.20 Captive portal

Pure Rust: axum on the portal vhost, nftables sets of authorized MAC/IP
(`add element … { timeout }`) for the allow list, vouchers/RADIUS/local users,
accounting via conntrack byte counters per `ct mark` or nft counters. No
external component. HTTPS interception is not possible; the portal relies on
captive-portal detection URLs (RFC 8908 API served by axum, `DHCP option 114`).

### 3.21 Proxy / reverse proxy / load balancer

- **Pingora 0.9.1** (Cloudflare, 2026-11-03, 27.9 k stars) is a *library*: we
  can build sensr-proxy (reverse proxy, TLS termination, load balancing, ACME
  via §3.18, caching) as a Rust service — this replaces the HAProxy and
  nginx/Caddy plugins. Nothing else in Rust is as proven at scale. (Alternative
  framework-free: `axum` + `hyper` client, but Pingora's LB/health-check/connection
  reuse is the point.)
- Forward/caching proxy with content filtering (Squid 7.8; nixpkgs 7.6): no Rust
  equivalent with ICAP/auth/cache maturity. Wrap Squid as an optional package or
  simply drop the feature in v1 — most OPNsense users have moved to DNS-level
  filtering (§3.7). HAProxy 3.4.7 stays available as a wrapped option until
  sensr-proxy has parity.

### 3.22 GeoIP

`maxminddb` 0.33.0 (2026-11-12) reading MaxMind GeoLite2 / DB-IP mmdb; the agent
materializes country → nftables set elements (interval sets), refreshed weekly.

### 3.23 SNMP

`snmp2` 0.5.3 (2026-11-02) and `async-snmp` 0.18.1 are **clients**. Agents:
`snmp_rust_agent` 0.4.0 (2025-10-17, SNMPv3 framework, 2.8 k downloads) is the
only Rust agent — immature. **Wrap net-snmp 5.9.5.2** (`snmpd` with AgentX) and
write a small Rust AgentX subagent later for sensr-specific MIBs; or decide SNMP
is read-only legacy and point users at Prometheus. `rasn-snmp` 0.30.0 provides
the ASN.1 codec if we write our own v2c/v3 responder (the protocol is small).

### 3.24 LLDP

`lldp`/`lldpcli` 0.0.0 are placeholders. **Wrap `lldpd` 1.0.23** (nixpkgs 1.0.22)
and read it through `rlldpctl` 1.0.2 (pure-Rust client for lldpd's control
socket, 2026-09-11) or `lldpcli -f json`. An LLDP transmitter/receiver in Rust
over `AF_PACKET` (`rawether` 0.2.0 or `socket2`) is a weekend project if we want
to drop lldpd; `packet-dissector-lldp` 0.6.3 has the TLV codec.

### 3.25 UPnP IGD / NAT-PMP / PCP

`igd-next` 0.18.0 and `natpmp` 0.5.0 are **clients**. Server side (what a
router needs): write `sensr-pcp` — PCP (RFC 6887) + NAT-PMP are simple UDP
protocols; UPnP IGD needs SSDP + a SOAP endpoint (axum). Mapping → nftables
`dnat` map elements with timeouts. Until then wrap **miniupnpd 2.3.11** (nixpkgs
2.3.10) which supports nftables natively.

### 3.26 Dynamic DNS

Rust-native `sensr-ddns`: provider plugins (Cloudflare, Route53, Hetzner,
deSEC, DuckDNS, No-IP, RFC 2136 via `hickory-proto` UPDATE, …) on `reqwest`
0.13.5; `dns-update-lite` 0.5.9 (2026-08-25, RFC 2136 + cloud) can be a dependency
or a reference. Interface-address change events come from the rtnetlink
subscription the agent already holds. Replaces ddclient/os-ddclient.

### 3.27 Gateway monitoring (dpinger replacement)

`surge-ping` 0.9.1 (2026-09-16, 4.6 M downloads, tokio ICMP v4/v6) — one task per
gateway sending at the configured interval, computing RTT/loss/jitter over a
sliding window, with thresholds → events → policy-routing table swaps and
nftables set updates for multi-WAN failover, all in the agent. `tokio-icmp-echo`
0.4.3 is the alternative. Also HTTP(S)/TCP/DNS probes via `reqwest`/`hickory` for
"the ISP answers ping but not the web" cases, which dpinger cannot do.

### 3.28 Wi-Fi (Pi has it)

`hostapd` 2.12 wrapped (nixpkgs 2.12, `services.hostapd`); `wl-nl80211` 0.9.0 for
scan/status. No Rust AP daemon exists and WPA3/802.11ax state machines are not
worth rewriting.

### 3.29 Misc plumbing

`clap` 4.6.7 (CLI), `anyhow` 1.0.104 / `thiserror` 2.0.21, `nix` 0.32.0 and
`rustix` 1.1.6 (syscalls, namespaces, capabilities), `caps` 0.5.6, `zbus` 6.3.0
(systemd D-Bus: start/stop/reload units, journal), `sd-notify` 0.5.0
(`Type=notify`, watchdog), `notify` 8.2.2 (file watching for seed files),
`jiff` 1.0.0 (dates; BurntSushi, 1.0 on 2026-11-15) over `chrono`, `ipnet`
2.12.2, `etherparse` 0.21.0 / `pcap` 2.5.0 (packet capture UI feature; `tcpdump`
stays available), `aya` 0.16.0 (eBPF — future: XDP DDoS drop, per-flow byte
counters without conntrack), `ratatui` 0.30.2 (console menu like OPNsense's
option 1–13 menu), `russh` 0.65.1 only if we embed an SSH server for the API
(we won't; OpenSSH via NixOS), `lettre` 0.11.23 (alert emails), `rust-embed`
8.14.0 (embed the wasm bundle in the API binary), `minijinja` 3.1.0 (render
daemon config files: Kea, Unbound, Suricata, hostapd, strongSwan), `moka` 0.12.16
(caches), `arc-swap` 1.9.5 (hot-swapping the running config snapshot),
`cargo-nextest` 0.9.152 (test runner).

---

## 4. Dependency pins

### 4.1 Platform

| Component | Latest upstream | In nixpkgs (unstable / 26.05) | Checked | Health / note |
|---|---|---|---|---|
| NixOS stable | **26.05** (2026-05-30) | — | 2026-11-15 | 26.11 due ~2026-11-30; no `release-26.11` branch yet |
| nixos-unstable | 26.11pre1119549.d5cc68339997 | — | 2026-11-15 | has `systemd-boot.bootCounting` |
| Nix | 2.35.6 | 2.35.6 / 2.34.9 | 2026-11-15 | 2.36pre in unstable |
| Rust stable | **1.100.0** (2026-11-12) | 1.99.1 / 1.95.0 | 2026-11-15 | use `rust-overlay`/`fenix`; nixpkgs lags |
| Linux stable / LTS | 7.3.4 / 6.18.63 (LTS) | default kernel 6.18 in 26.05; `linux_7_3` present in unstable | 2026-11-15 | x86 images: 6.18 LTS (`linuxPackages_6_18`); Pi: vendor rpi-6.18.y |
| Raspberry Pi kernel | `rpi-6.18.y` (default branch), nixos-hardware tag `stable_20261103` | via nixos-hardware / nvmd (nixpkgs removed `linux_rpi*`) | 2026-11-15 | both flakes pushed within 2 days |
| Raspberry Pi firmware | 1.20260915 | 1.20260915 unstable (26.05: 1.20250430) | 2026-11-15 | nvmd ships matched firmware |
| rpi-eeprom | v2026.10.30-2712 | — | 2026-11-15 | document "update EEPROM first" |
| systemd | 262.2 | 262 / 260.5 | 2026-11-15 | boot counting needs ≥ 240 (fine) |
| nixos-hardware | master (pushed 2026-11-13) | — | 2026-11-15 | |
| nvmd/nixos-raspberrypi | main (pushed 2026-11-15), 694 stars | — | 2026-11-15 | cachix binary cache available |
| disko | v1.13.0 (2026-01-20) | — | 2026-11-15 | |
| nixos-anywhere | 1.13.0 (2025-11-13) | — | 2026-11-15 | no kexec on Pi |
| nixos-images | tag nixos-26.05 | — | 2026-11-15 | netboot/kexec images, reference for our builder |
| nixos-generators | 1.8.0 — **archived** (2026-01-30) | — | 2026-11-15 | superseded by nixpkgs `image.modules`; do not use |
| lanzaboote | v1.2.0 (2026-09-26) | — | 2026-11-15 | Secure Boot for x86 later |
| crane | v0.24.0 (2026-08-21) | — | 2026-11-15 | |
| rust-overlay | snapshot/2026-03-11 tag, pushed 2026-11-15 (daily auto-updates) | — | 2026-11-15 | |
| nixos-facter | v0.4.4 | — | 2026-11-15 | hardware detection for installer |
| Renovate | 44.240.0 (2026-11-16) | — | 2026-11-15 | nix + cargo + github-actions managers |

### 4.2 Wrapped external daemons

| Daemon | Latest upstream | nixpkgs unstable / 26.05 | Checked | Plan |
|---|---|---|---|---|
| nftables (userspace) | 1.1.7 | 1.1.7 / 1.1.6 | 2026-11-15 | required (JSON API) |
| iproute2 | 7.3.0 | 7.2.0 / 7.0.0 | 2026-11-15 | debug + `tc -j` stats |
| Suricata | 8.0.8 (2026-10-29) | 8.0.7 / 8.0.3 | 2026-11-15 | wrap; override to latest |
| vectorscan | 5.4.14 | 5.4.13 / 5.4.12 | 2026-11-15 | Suricata MPM on arm64 |
| strongSwan | 6.1.0 (2026-09-07) | 6.1.0 / 6.1.0 | 2026-11-15 | wrap via VICI |
| OpenVPN | 2.7.9 (2026-11-05) | **2.6.23** / 2.6.19 | 2026-11-15 | override to 2.7 (DCO) |
| Kea | 3.2.1 | 3.2.1 / 3.0.3 | 2026-11-15 | wrap until sensr-dhcp passes |
| Unbound | 1.26.2 (2026-10-21) | 1.26.2 / 1.25.1 | 2026-11-15 | optional resolver |
| ntpd-rs | 1.9.0 (2026-06-12); 2.0.0-alpha.20261113 | packaged | 2026-11-15 | Rust; default NTP |
| Holo | v0.9.0 (2026-02-21), pushed 2026-11-14 | not in nixpkgs → package it (crane) | 2026-11-15 | Rust; VRRP + routing |
| FRR | 10.7.1 (2026-08-31) | 10.7.1 / 10.4.1 | 2026-11-15 | optional fallback |
| keepalived | 2.4.3 | 2.4.3 / 2.3.4 | 2026-11-15 | fallback only |
| conntrack-tools | 1.4.9 | 1.4.9 / 1.4.8 | 2026-11-15 | conntrackd for HA |
| HAProxy | 3.4.7 | 3.4.7 / 3.3.17 | 2026-11-15 | optional until sensr-proxy (Pingora) |
| Squid | 7.8 | 7.6 / 7.3 | 2026-11-15 | optional / maybe drop |
| hostapd | 2.12 | 2.12 / 2.11 | 2026-11-15 | Wi-Fi AP |
| lldpd | 1.0.23 | 1.0.22 / 1.0.20 | 2026-11-15 | wrap |
| net-snmp | 5.9.5.2 | 5.9.5.2 / 5.9.4 | 2026-11-15 | wrap (optional) |
| miniupnpd | 2.3.11 | 2.3.10 / 2.3.9 | 2026-11-15 | wrap until sensr-pcp |
| radvd | 2.21 | 2.21 / 2.21 | 2026-11-15 | fallback for RA |
| wireguard-tools | 1.0.20260223 | same | 2026-11-15 | debug only |
| chrony | 4.9 | 4.9 / 4.8 | 2026-11-15 | not used (ntpd-rs) |
| dnsmasq | 2.93 | 2.93 / 2.92 | 2026-11-15 | not used (hickory) |
| OpenSSL | 3.5.9 LTS (4.1.0 latest) | 3.5.9 default | 2026-11-15 | only via C daemons; Rust uses rustls |

### 4.3 Rust crates (max stable version on crates.io, 2026-11-15)

| Area | Crate | Version | Last publish | Health |
|---|---|---|---|---|
| nftables | `nftables` | 0.6.3 | 2025-08-15 | 3.2 M dl; repo pushed 2026-05; stable JSON schema, slow but fine |
| | `nftables-async` | 0.4.1 | 2026-05-11 | 1.8 M dl |
| | `rustables` | 0.9.0 | 2026-09-21 | pure Rust, small team (escape hatch) |
| | `nftnl` / `mnl` | 0.9.4 / 0.3.1 | 2026-08-11 / 2026-02-10 | Mullvad, production |
| netlink | `rtnetlink` | 0.24.0 (1.0.0-rc2 out) | 2026-11-04 | rust-netlink org, 29 M dl, very active |
| | `netlink-packet-route` | 0.34.0 (1.0.0-rc2) | 2026-11-15 | |
| | `netlink-packet-core` / `netlink-sys` / `genetlink` | 0.9.0 / 0.9.0 / 0.3.1 (1.0.0-rc2) | 2026-11-15 | |
| | `ethtool` / `wl-nl80211` | 0.4.0 / 0.9.0 | 2026-11-04 | |
| | `neli` | 0.7.5 | 2026-10-20 | alternative |
| WireGuard | `defguard_wireguard_rs` | 0.12.5 | 2026-11-04 | active (Defguard) |
| | `netlink-packet-wireguard` / `nl-wireguard` | 0.5.1 / 0.3.1 | 2026-11-04 | rust-netlink |
| | `wireguard-control` | 2.0.0 | 2026-07-02 | innernet; alt |
| | `boringtun` | 0.7.1 | 2026-05-01 | userspace only |
| IPsec | `rsvici` / `serde_vici` | 0.1.5 / 0.1.5 | 2026-08-18 / 2025-12-18 | small, works; `rustici` 1.1.1 alt |
| OpenVPN | `openvpn-mgmt-codec` | 0.8.0 (1.0.0-rc.4) | 2026-03-30 | small |
| DHCP | `dhcproto` | 0.15.0 | 2026-05-19 | BlueCat, 1 M dl, pushed 2026-11-10 |
| | `dora` (server) | unreleased, git | last commit 2026-01-29 | reference only; **stale** |
| | `dhcpv6-core` | 0.1.0 | 2026-08-12 | Fuchsia extraction; reference |
| RA | `ipv6-router-advertisement` | 0.2.0 | 2026-10-31 | tiny codec |
| DNS | `hickory-server` / `-resolver` / `-proto` | 0.26.3 | 2026-09-10 | 100 M+ dl, pushed 2026-11-14 |
| NTP | `ntpd` | 1.9.0 | 2026-06-12 | 2.0 alpha in progress |
| Flow | `netgauze-flow-pkt` | 0.14.0 | 2026-11-10 | IPFIX/NFv9 encode/decode |
| | `netflow_parser` | 1.0.6 | 2026-07-23 | 805 k dl |
| | `conntrack` | 0.1.5 | 2025-12-03 | libnetfilter_conntrack binding; thin |
| HA | Holo (git, not on crates.io) | v0.9.0 | 2026-02-21 | VRRP/BGP/OSPF/IS-IS/RIP/BFD |
| | `highland-daemon` | 0.2.2 | 2026-11-12 | 1 star; watch only |
| Web | `axum` / `axum-extra` | 0.8.9 / 0.12.6 | 2026-04-14 | |
| | `tokio` | 1.54.1 | 2026-10-21 | |
| | `tower` / `tower-http` | 0.5.3 / 0.7.1 | 2026-01-12 / 2026-08-31 | |
| | `hyper` | 1.12.0 | 2026-10-06 | |
| | `axum-server` | 0.9.2 | 2026-11-11 | TLS listener |
| | `tower-sessions` / `axum-login` / `tower-cookies` | 0.15.0 / 0.18.0 / 0.11.0 | 2026-02-01 / 2025-07-20 / 2025-01-01 | ok; cookies crate quiet |
| | `tokio-tungstenite` | 0.30.0 | 2026-07-11 | |
| | `utoipa` | 6.0.0 | 2026-09-22 | OpenAPI |
| | `garde` / `validator` | 0.23.0 / 0.21.0 | 2026-05-23 / 2026-07-27 | pick garde |
| | `reqwest` | 0.13.5 | 2026-09-08 | rustls feature |
| | `tonic` / `prost` | 0.14.9 / 0.14.6 | 2026-10-29 / 2026-11-12 | agent↔api, Holo gRPC |
| Frontend | `leptos` / `leptos_router` / `leptos_axum` / `leptos_meta` / `server_fn` | 0.8.23 / 0.8.17 / 0.8.10 / 0.8.7 / 0.8.13 (all 0.9.0-rc1) | 2026-10-31 | decided framework (§3.14) |
| | `leptos-use` / `leptos_i18n` | 0.20.0 / 0.6.3 | 2026-10-20 / 2026-11-09 | |
| | `sycamore` (alt) | 0.9.4 (0.10.0-beta.1) | 2026-11-09 | |
| | `cargo-leptos` (`trunk` 0.22.1 not used) | 0.3.12 | 2026-11-09 | + binaryen wasm-opt 133 from nixpkgs |
| | `wasm-bindgen` / `web-sys` / `wasm-bindgen-futures` / `gloo` | 0.2.130 / 0.3.107 / 0.4.80 / 0.13.0 | 2026-10-30 … 2026-11-15 | |
| | `dioxus` (alt) | 0.7.10 (0.8.0-alpha.3) | 2026-10-16 | |
| Auth | `argon2` | 0.6.0 | 2026-08-27 | RustCrypto |
| | `totp-rs` | 6.0.0 | 2026-08-06 | |
| | `openidconnect` / `oauth2` | 4.1.0 / 5.0.0 | 2026-10-31 / 2025-01-21 | |
| | `webauthn-rs` | 0.6.2 | 2026-10-31 | Kanidm |
| | `jsonwebtoken` | 12.0.0 | 2026-11-13 | |
| | `ldap3` | 0.12.1 | 2025-09-18 | quiet, complete |
| | `radius` | 0.4.0 | 2024-01-15 | **stale**; may fork/own |
| | `secrecy` / `zeroize` | 0.10.3 / 1.9.1 | 2024-10-09 / 2026-10-06 | |
| | `governor` | 0.10.4 | 2025-12-16 | |
| Config/store | `serde` / `serde_json` / `toml` | 1.0.229 / 1.0.154 / 1.2.1 | 2026-07 … 2026-11 | |
| | `schemars` / `jsonschema` | 1.2.3 / 0.61.2 | 2026-10-12 / 2026-11-12 | |
| | `rusqlite` / `rusqlite_migration` | 0.43.0 / 2.7.0 | 2026-11-15 / 2026-11-10 | bundled SQLite |
| | `redb` | 4.6.0 | 2026-11-13 | pure-Rust KV |
| | `semver` | 1.0.28 | 2026-04-04 | schema versions |
| | `arc-swap` / `moka` | 1.9.5 / 0.12.16 | 2026-11-09 / 2026-08-09 | |
| Backup | `age` | 0.12.1 | 2026-07-14 | rage |
| | `tar` / `zstd` / `blake3` | 0.4.46 / 0.14.4 / 1.8.7 | 2026-05 … 2026-11 | |
| Metrics/log | `tracing` / `tracing-subscriber` / `tracing-journald` / `tracing-appender` | 0.1.44 / 0.3.23 / 0.3.2 / 0.2.5 | 2025-12 … 2026-04 | |
| | `tracing-opentelemetry` / `opentelemetry` / `opentelemetry-otlp` | 0.34.0 / 0.33.1 / 0.33.1 | 2026-09-23 / 2026-10-09 | |
| | `prometheus-client` | 0.26.0 | 2026-11-11 | official |
| | `sysinfo` / `procfs` | 0.40.3 / 0.18.0 | 2026-11-11 / 2025-08-30 | |
| Certs/ACME | `rustls` / `tokio-rustls` | 0.23.46 (0.24.0-dev.3) / 0.26.6 | 2026-11-12 / 2026-09-28 | |
| | `rcgen` / `x509-parser` / `pem` | 0.14.10 / 0.18.1 / 4.0.0 | 2026-08-28 / 2026-02-05 / 2026-07-28 | |
| | `instant-acme` / `rustls-acme` | 0.8.5 / 0.15.4 | 2026-02-24 / 2026-08-11 | |
| | `webpki-roots` / `rustls-platform-verifier` | 1.0.12 / 0.7.1 | 2026-11-10 / 2026-09-24 | |
| Proxy | `pingora` | 0.9.1 | 2026-11-03 | Cloudflare |
| GeoIP | `maxminddb` | 0.33.0 | 2026-11-12 | |
| SNMP | `snmp2` / `async-snmp` / `rasn-snmp` | 0.5.3 / 0.18.1 / 0.30.0 | 2026-11-02 / 2026-08-19 / 2026-11-02 | clients + codec |
| | `snmp_rust_agent` | 0.4.0 | 2025-10-17 | immature agent |
| LLDP | `rlldpctl` | 1.0.2 | 2026-09-11 | lldpd client |
| UPnP/NAT-PMP | `igd-next` / `natpmp` | 0.18.0 / 0.5.0 | 2026-10-04 / 2024-11-06 | clients only |
| DDNS | `dns-update-lite` | 0.5.9 | 2026-08-25 | |
| Monitoring | `surge-ping` | 0.9.1 | 2026-09-16 | 4.6 M dl |
| | `tokio-icmp-echo` | 0.4.3 | 2025-05-03 | alt |
| Packets | `etherparse` / `pcap` / `pnet` | 0.21.0 / 2.5.0 / 0.35.0 | 2026-07-21 / 2026-08-15 / 2024-05-30 | pnet stale |
| eBPF | `aya` | 0.16.0 | 2026-10-28 | future |
| System | `nix` / `rustix` / `libc` | 0.32.0 / 1.1.6 / 0.2.191 (1.0.0-alpha.5) | 2026-11-14 / 2026-10-27 / 2026-10-16 | |
| | `caps` | 0.5.6 | 2025-10-17 | |
| | `zbus` | 6.3.0 | 2026-11-13 | systemd D-Bus |
| | `sd-notify` / `libsystemd` | 0.5.0 / 0.7.2 | 2026-03-09 / 2025-04-30 | |
| | `socket2` | 0.6.5 | 2026-07-13 | |
| | `notify` | 8.2.2 (9.0.0-rc.9) | 2026-11-15 | |
| | `tokio-cron-scheduler` / `cron` | 0.15.1 / 0.17.0 | 2025-10-28 / 2026-06-18 | |
| CLI/TUI | `clap` / `ratatui` / `rpassword` | 4.6.7 / 0.30.2 / 7.5.5 | 2026-09-14 / 2026-06-19 / 2026-11-10 | |
| Misc | `anyhow` / `thiserror` | 1.0.104 / 2.0.21 | 2026-07-18 / 2026-09-23 | |
| | `jiff` / `chrono` | 1.0.0 / 0.4.45 | 2026-11-15 / 2026-06-04 | pick jiff |
| | `ipnet` | 2.12.2 | 2026-09-06 | |
| | `uuid` / `ulid` | 1.29.2 / 3.0.0 | 2026-11-09 / 2026-07-16 | |
| | `minijinja` | 3.1.0 | 2026-11-07 | daemon config templates |
| | `rust-embed` | 8.14.0 | 2026-11-11 | |
| | `lettre` | 0.11.23 | 2026-08-03 | |
| | `bytes` / `tokio-util` / `futures` | 1.12.1 / 0.7.20 / 0.3.34 | 2026-07 … 2026-11 | |
| | `regex` / `base64` / `hex` | 1.13.1 / 0.23.1 / 0.4.3 | 2026-07-15 / 2026-08-04 / 2021 | hex is tiny & done |
| Crypto | `sha2` / `hmac` / `hkdf` / `aes-gcm` / `chacha20poly1305` | 0.11.1 / 0.13.0 / 0.13.0 / 0.11.1 / 0.11.0 | 2026 | RustCrypto |
| | `ed25519-dalek` / `x25519-dalek` | 3.0.0 / 3.0.0 | 2026-07-06 | |
| | `rand` | 0.10.4 | 2026-11-15 | |
| Tooling | `cargo-deny` | 0.20.2 | 2026-07-09 | |
| | `cargo-audit` | 0.23.0 | 2026-11-10 | |
| | `cargo-outdated` | 0.19.0 | 2026-04-14 | |
| | `cargo-edit` (`cargo upgrade`) | 0.13.14 | 2026-10-21 | |
| | `cargo-machete` | 0.9.2 | 2026-04-15 | unused deps |
| | `cargo-semver-checks` | 0.51.0 | 2026-10-03 | for our published crates |
| | `cargo-nextest` | 0.9.152 | 2026-11-13 | |

Health flags worth acting on: `dora` (stale, unreleased → reference only),
`radius` (2024 → own implementation or fork), `pnet` (2024 → use `etherparse`
+ `socket2`), `prometheus` (tikv, 2025 → use `prometheus-client`), `nftables`
JSON crate (quiet but tracking a stable upstream schema; acceptable), `ldap3`
(2025, feature-complete), `tower-cookies` (2025), `natpmp` (2024, client only
anyway). Everything else published within the last ~6 months.

---

## 5. Dependency freshness policy

Goal: "latest version of every dependency" as an enforced property, not an
aspiration.

1. **MSRV = latest stable, always.** `rust-toolchain.toml` pins `1.100.0`;
   `Cargo.toml` `rust-version` = the same; a Renovate rule (`rust-toolchain`
   manager) opens the bump PR the day a new stable ships (six-week cadence, next
   1.101.0 ≈ 2026-12-24). `rust-overlay` is updated daily by its bot, so the
   flake input bump carries the toolchain. We do not promise an MSRV to
   downstream — sensr is an application.
2. **Renovate** (44.x, self-hosted on Forgejo or Mend app on GitHub) with
   managers: `cargo` (lockfile maintenance *and* `Cargo.toml` range bumps,
   `rangeStrategy: bump` so `Cargo.toml` always names the newest minor),
   `nix` (flake.lock inputs — nixpkgs, nixos-hardware, nixos-raspberrypi,
   crane, rust-overlay, disko, advisory-db), `github-actions`, `regex` for
   `overrideAttrs` version/hash pairs in `nix/overlays/` (Renovate's
   `customManagers` + `nix-update`/`nix-prefetch` post-upgrade task recomputes
   the sha256), and `pre-commit`. Grouping: all patch bumps weekly in one PR,
   minors individually, majors individually with `cargo semver-checks` output in
   the PR body. Automerge for patch/minor when CI (unit + nixosTest smoke) is
   green; majors need a human.
3. **flake.lock cadence**: nixpkgs input bumped **weekly** on `nixos-unstable`
   during development (automerge if the VM test matrix passes); on the release
   branch, **daily** `nixos-26.xx` bumps (they are security backports) with
   automerge. Every merged bump runs the full image build so a nixpkgs breakage
   is caught at bump time, not at release time.
4. **Security**: `cargo audit` (0.23.0; advisory-db as a flake input so audits are
   reproducible and offline) and `cargo deny check` (0.20.2: `advisories`,
   `bans` — duplicate versions warn, `licenses` — allow MIT/Apache-2.0/BSD/ISC/
   MPL-2.0/Zlib/Unicode, deny GPL in Rust deps since we're MIT-licensed, `sources`
   — crates.io only, plus explicitly allowed git deps like Holo) on every PR and
   nightly. Nightly also runs `vulnix`/`nix-security-tracker`-style scans of the
   closure for CVEs in C daemons (Suricata, strongSwan, OpenVPN, Kea, FRR).
5. **CI fails on outdated deps**: a nightly job runs
   `cargo outdated --exit-code 1 --root-deps-only` (0.19.0) and
   `cargo upgrade --dry-run --incompatible` (cargo-edit 0.13.14) and a small Rust
   script that compares every `overrideAttrs` version in `nix/overlays/` and
   every flake input's revision age (via `nix flake metadata --json`) against
   upstream (crates.io/GitHub/repology APIs, same lookups as this document). It
   fails the nightly if anything is more than **14 days** behind a stable
   release, or any flake input is more than 14 days old — a failing nightly is a
   ticket, and the Renovate PR is usually already open. `cargo machete` catches
   dead dependencies.
6. **Prereleases**: never auto-adopted (`ignoreUnstable: true`), but tracked:
   rust-netlink 1.0.0-rc2, leptos 0.9.0-rc1, rustls 0.24-dev, ntpd-rs 2.0 alpha,
   libc 1.0 alpha, notify 9 rc all get a "watch" issue so the migration is
   planned, not discovered.
7. **Release gating**: a release tag requires `cargo audit`/`deny` clean, zero
   open Renovate PRs older than 14 days (or an explicit `deps-deferred:` label
   with a reason), and the manifest (`sensr version --json`) committed into the
   release notes so users can diff daemon versions between releases.
8. **Reproducibility**: `Cargo.lock` committed; crane builds from the lock via
   `cargoVendorDir` so Nix and cargo agree bit-for-bit; images carry
   `nixpkgs.rev` and `sensr.rev` in `/etc/os-release` (`BUILD_ID`,
   `VARIANT_ID`).

---

## 6. What cannot be pure Rust yet

Honest list, with the wrap-or-replace plan:

| Component | Why not Rust (today) | Day-one | Plan |
|---|---|---|---|
| **Linux kernel** (netfilter/nftables, routing, WireGuard, conntrack, tc, drivers) | It is the point of a Linux base; Rust-for-Linux covers some drivers but nothing we'd replace. | Wrap (it's the OS). | Not a goal. Rust userspace talks netlink. |
| **nftables userspace (`nft`)** | Only complete ruleset compiler/JSON API; Rust pure-netlink crates don't cover every expression. | `nft -j` via `nftables` crate. | Graduate hot paths (set elements) to `rustables`/netlink; revisit a full pure-Rust ruleset path when `rustables` or `nftables-nl` covers flowtables/synproxy/vmaps. |
| **Suricata** (C, ~50 % Rust internally) | No Rust IDS with a Suricata-rule engine, Hyperscan-class MPM, or app-layer coverage. | Wrap (EVE socket, rule updater in Rust). | Stay wrapped indefinitely; contribute upstream (their Rust surface grows each release). |
| **strongSwan** (C) | No production IKEv2/ESP control plane in Rust; kernel does ESP anyway. | Wrap via VICI (`rsvici`). | Track the `strongswan` embedded-charon crate and any Rust IKEv2 effort; low priority — WireGuard is the default VPN. |
| **OpenVPN** (C) | No Rust server; protocol is large and ossified. | Wrap 2.7 (DCO) via management socket. | Keep as legacy; never rewrite. |
| **Kea** (C++) | `dora` stale, others infant. | Wrap via control socket. | **Replace** with `sensr-dhcp` on `dhcproto` once it passes a conformance suite (v4 first, then v6/PD) — realistic within v1.x. |
| **Unbound** (C) | hickory's recursor is younger. | Optional; hickory default. | hickory is the default from day one; Unbound stays optional for people who insist. |
| **FRR** (C) | Holo lacks some policy/route-map features and PIM. | Optional wrapped; Holo default for BGP/OSPF/VRRP. | **Replace**: contribute gaps to Holo. |
| **keepalived** (C) | Holo has VRRP. | Not shipped unless Holo VRRP shows problems. | — |
| **conntrackd** (C) | No Rust conntrack-sync implementation. | Wrap. | Write `sensr-ctsync` later (conntrack netlink events → multicast/TCP replication) — moderate effort, nothing exotic. |
| **hostapd / wpa_supplicant** (C) | No Rust AP/802.11 state machines. | Wrap. | Never rewrite. |
| **lldpd** (C) | Trivial to rewrite but low value. | Wrap. | Replace with a ~500-line Rust TX/RX when convenient. |
| **net-snmp** (C) | No Rust SNMP agent. | Wrap, optional. | Either own v2c/v3 responder on `rasn-snmp` or declare SNMP legacy. |
| **miniupnpd** (C) | No Rust IGD/PCP server. | Wrap. | **Replace** with `sensr-pcp` (PCP/NAT-PMP first, SSDP/IGD second). |
| **Squid / HAProxy** (C) | Pingora is a library, not a product; forward-proxy/ICAP has no Rust story. | HAProxy optional; Squid optional-or-dropped. | `sensr-proxy` on Pingora replaces HAProxy; drop Squid unless demand. |
| **systemd / udev / networkd** (C) | The init system. We *use* networkd for WAN DHCP client/RA initially. | Wrap. | Replace networkd use with `sensr-dhcp` client + `sensr-ra`; systemd itself stays. |
| **OpenSSL** (C) | Only inside the C daemons above. | Transitive. | Rust side is rustls-only; shrinks as daemons are replaced. |
| **Charts in the browser** | Rust canvas charting is possible (`plotters`) but JS libs are better. | Thin `web-sys` wrapper over a JS chart lib. | Acceptable exception; not application code. |

Everything else — agent, API, UI, config model, DHCP (planned), DNS, NTP, VRRP
and routing (Holo), WireGuard control, gateway monitoring, flow export, ACME,
DDNS, captive portal, GeoIP, backups, metrics, console TUI, installer TUI — is
Rust from day one.
