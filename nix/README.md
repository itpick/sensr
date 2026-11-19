# nix/

| Path | What |
|---|---|
| `overlays/default.nix` | `pkgs.sensr` (the workspace, crane) and `pkgs.sensr-kea` (Kea without kea-shell/Python) |
| `modules/sensr.nix` | `services.sensr`: agent, API, daemon units, selftest, `/etc/sensr/version.json` |
| `modules/updates.nix` | `services.sensr.updates`: manifest check, closure import, `switch-to-configuration`, timer and the request/status files the System › Updates page uses |
| `images/common.nix` | what every image shares (panic/watchdog policy, no baked-in login, perlless) |
| `images/qcow.nix` | `nix build .#images.qcow`: x86_64 UEFI qcow2, systemd-boot with boot counting |
| `images/iso.nix` | `nix build .#images.iso`: x86_64 UEFI/BIOS live installer, `nixos-install` from the ISO store |
| `tests/boot-first-run.nix` | `checks.x86_64-linux.boot-first-run`: units, selftest rows, hardening |
| `tests/qcow-boot.nix` | `checks.x86_64-linux.qcow-boot`: boots the real qcow2 three times, records boot seconds |
| `tests/slice.nix` | `checks.x86_64-linux.slice` (sensr) and `slice-reference` (hand-written oracle): the routing vertical slice with 6 VMs |
| `tests/slice/` | the slice's addressing plan (`net.nix`) and the oracle router (`reference-router.nix`) |
| `pi5/trial-install.sh` | `sensr-pi5-trial-install`: one tryboot trial of sensr on a Pi 5 running another OS, from NVMe/USB or (OS on NVMe) the SD card; log partition; commit/uncommit |
| `pi5/trial-health.sh` | `sensr-trial-health`: a trial boot's self-health gate (reboot to the previous OS on failure), confirm, UDP journal stream |
| `tests/pi5-trial-install.nix` | `checks.x86_64-linux.pi5-trial-install`: both layouts on disk images, a model of the firmware's documented boot selection, the health gate |
| `pending.nix` | which assertions wait on crates that have not landed |

## Contract between the module and the Rust crates

The module provides this; the crates may rely on it. Change both together.

| Item | Value |
|---|---|
| Binaries | `sensr-agent`, `sensr-api`, `sensr` (the CLI; the overlay links `sensr` to `sensr-cli` until the crate names its binary) |
| Agent | root, `ProtectSystem=strict`, capabilities `NET_ADMIN NET_RAW NET_BIND_SERVICE SYS_ADMIN CHOWN FOWNER KILL`, writable: `/var/lib/sensr` (0700), `/run/sensr` (0755, kept across restarts), `/run/systemd/network`, the seed dir, `/boot/firmware`. `Type=notify`, `WatchdogSec=30s`; started with `--socket /run/sensr/agent.sock --socket-mode 660 --socket-gid 730 --state-dir /var/lib/sensr --trust-uid 731` (`--seed <configFile>` in declarative mode) |
| Agent env | `SENSR_AGENT_SOCKET=/run/sensr/agent.sock`, `SENSR_RUNTIME_DIR=/run/sensr`, `SENSR_STATE_DIR=/var/lib/sensr`, `SENSR_SEED_DIR` (`/boot/sensr`, Pi `/boot/firmware/sensr`), `SENSR_NETWORKD_DIR=/run/systemd/network`, `SENSR_CONFIG_FILE` (declarative mode only) |
| Socket | the agent creates `$SENSR_AGENT_SOCKET` and makes it `0660 root:sensr` |
| API | user `sensr-api` (uid 731, the agent's trusted uid), supplementary group `sensr` (gid 730), `CAP_NET_BIND_SERVICE` only, cannot see `/var/lib/sensr`; env `SENSR_AGENT_SOCKET`, `SENSR_API_LISTEN` (default `[::]:443`) |
| Kea | agent writes `/run/sensr/kea/kea-dhcp4.conf`, then starts or reloads `sensr-kea-dhcp4.service` (the unit runs `kea-dhcp4 -t` first; reload is SIGHUP). Leases: `/var/lib/kea` |
| Unbound | agent writes `/run/sensr/unbound/unbound.conf`, then starts or reloads `sensr-unbound.service` (`unbound-checkconf` first; reload is SIGHUP) |
| networkd | agent writes `.network`/`.netdev` files to `/run/systemd/network` and runs `networkctl reload` |
| nftables, WireGuard | in the agent's `PATH` (`nft`, `wg`, `ip`, `conntrack`); modules preloaded |
| Selftest | `sensr-selftest.service` writes `/run/sensr-selftest/result.json` and gates `boot-complete.target` |

## Running the checks

```sh
nix build -L .#checks.x86_64-linux.boot-first-run   # needs KVM
nix build -L .#checks.x86_64-linux.qcow-boot
nix build -L .#checks.x86_64-linux.slice-reference   # proves the slice's assertions
nix build -L .#checks.x86_64-linux.slice             # the same assertions against sensr
nix build .#images.qcow
```

## Turning on a slice assertion

When a crate lands, flip its flag in `pending.nix` in the same PR. `slice`
then asserts what `slice-reference` already proves: the reference router
(`tests/slice/reference-router.nix`) is the expected outcome of importing
`home-router.xml`, so a difference between the two is a sensr bug (or a
mistake in the oracle, fixed in the same PR with the reason).
