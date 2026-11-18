<p align="center"><img src="docs/logo.svg" alt="sensr" width="220"></p>

<p align="center"><img src="docs/ui-dashboard.png" alt="sensr web UI: dashboard with system information, CPU and memory, interfaces, gateways and traffic graphs" width="880"></p>

A firewall and router OS written in Rust on NixOS. The goal is feature parity with
[OPNsense](https://opnsense.org/), including its Business Edition features, plus
atomic upgrades, rollback and a typed, tested configuration model.

**Status: in development.** No images have been released yet. Start with the plan in [`docs/PLAN.md`](docs/PLAN.md).
If you need a router today, use [opnsense-pi](https://github.com/itpick/opnsense-pi) or [vyos-pi](https://github.com/itpick/vyos-pi).

**Install page:** https://itpick.github.io/sensr/ (images are listed there once released)

**Related projects:**
- [opnsense-pi](https://github.com/itpick/opnsense-pi) ([download page](https://itpick.github.io/opnsense-pi/)): OPNsense images for Raspberry Pi 4/5
- [vyos-pi](https://github.com/itpick/vyos-pi) ([download page](https://itpick.github.io/vyos-pi/)): VyOS images for Raspberry Pi 4/5
- [OPNsense vs VyOS on the Pi 5](https://github.com/itpick/vyos-pi/blob/main/docs/comparison/pi5-iperf-vyos-vs-opnsense.md): side-by-side speed and boot-time results
- [Performance evaluation](docs/research/07-performance-evaluation.md): OPNsense, VyOS and a NixOS + Rust prototype compared on forwarding, boot and config apply

## Why

[opnsense-pi](https://github.com/itpick/opnsense-pi) showed what it costs to run OPNsense
on hardware FreeBSD barely supports. The Pi 5 needed out-of-tree Ethernet drivers with
receive-path patches, and 5 GbE USB NICs had no driver at all. Linux supports that
hardware in the mainline kernel. NixOS adds reproducible images and generation-based
rollback. OPNsense's own issue tracker shows the rest: most recurring bugs are
config-apply races, migrations and upgrade regressions, and typed Rust and a declarative
OS can design those out.

## Research (written with Fable)

| Doc | What it covers |
|---|---|
| [01 Feature inventory](docs/research/01-feature-inventory.md) | Every documented OPNsense feature and plugin, with stable IDs and the sensr backing for each |
| [02 Architecture](docs/research/02-architecture.md) | How OPNsense works, what to keep, what to redesign, and the crate map |
| [03 Test parity](docs/research/03-test-parity.md) | All 408 OPNsense tests and checks (T-0001 to T-0408), each mapped to a sensr test |
| [04a Core issues](docs/research/04a-issues-core.md) | All 7,984 opnsense/core issues: open, declined, most wanted, recurring bug classes |
| [04b Plugin issues](docs/research/04b-issues-plugins.md) | All 3,230 opnsense/plugins issues, plugin health, and a tier for each plugin |
| [05 Business features](docs/research/05-business-features.md) | Business Edition and its add-ons, competitor features, and the BIZ-001 to BIZ-032 plan |
| [06 Rust + NixOS stack](docs/research/06-rust-nixos-stack.md) | Lessons from opnsense-pi, OS base, a crate for each subsystem with its latest version, and the dependency freshness policy |

## Layout

```
crates/   Rust workspace (sensr-schema, -config, -rules, -import-opnsense, -agent, -api, -ui, -cli)
docs/     plan, research, install page (GitHub Pages)
flake.nix NixOS modules, images and VM tests (being built out)
```

## Build

```sh
cargo check --workspace   # uses the toolchain pinned in rust-toolchain.toml (1.100.0)
nix develop               # dev shell with cargo-deny, cargo-audit, cargo-leptos, qemu
```

## Dependencies

Every dependency is at its newest stable release, and CI enforces it. Renovate opens the
bumps, and the nightly job fails if any direct dependency or flake input falls more than
14 days behind (see [06 §5](docs/research/06-rust-nixos-stack.md#5-dependency-freshness-policy)).

## License

Dual-licensed: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

sensr is an independent project. It is not affiliated with Deciso B.V., and it contains
no OPNsense code. OPNsense® is a trademark of Deciso B.V. and appears here only to
describe compatibility.
