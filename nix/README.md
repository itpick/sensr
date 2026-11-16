# nix/

| Path | What |
|---|---|
| `overlays/default.nix` | `pkgs.sensr` (the workspace, crane) and `pkgs.sensr-kea` (Kea without kea-shell/Python) |
| `modules/sensr.nix` | `services.sensr`: agent, API, daemon units, selftest, `/etc/sensr/version.json` |
| `images/common.nix` | what every image shares (panic/watchdog policy, no baked-in login, perlless) |
| `images/qcow.nix` | `nix build .#images.qcow`: x86_64 UEFI qcow2, systemd-boot with boot counting |
| `tests/boot-first-run.nix` | `checks.x86_64-linux.boot-first-run`: units, selftest rows, hardening |
| `tests/qcow-boot.nix` | `checks.x86_64-linux.qcow-boot`: boots the real qcow2 three times, records boot seconds |
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
nix build .#images.qcow
```
