# 07 — Performance evaluation: would sensr be faster, leaner, lighter?

Research note, measured 2026-11-15/16 on `nixtop`. Scripts, raw results and the
throwaway Rust prototype live in [`bench/`](../../bench/); every number below
comes from `bench/results/*.jsonl`, reduced by `bench/run/summarize.py` into
`bench/results/summary/` (medians, min–max in parentheses).

> **The question.** Is there evidence that a Rust remake of OPNsense on NixOS
> brings *significant* speed, efficiency or lightweightness gains, and if so
> where do they come from?
> **(A)** the data plane: FreeBSD pf vs Linux nftables. That is a kernel
> question, not a Rust one.
> **(B)** the OS base: FreeBSD/OPNsense vs a minimal NixOS.
> **(C)** the control plane: PHP/Python configd stack vs a Rust daemon.

## TL;DR

- **Yes, there are large gains, but most of them come from Linux, not from
  Rust.** VyOS, a Python-managed Linux router, matches NixOS on the data
  plane.

  | Data plane, as shipped | OPNsense | Linux (NixOS or VyOS) |
  |---|---|---|
  | TCP forwarding, 8 streams | 3.1 Gbit/s | 25–26 Gbit/s |
  | Ping p50 under load | 15 ms | 1.6–1.9 ms |
  | New connections/s | 2.3k | ~20k |

  - Remove the cause and the throughput gap vanishes: Linux with GRO/GSO/TSO
    off forwards 3.3 Gbit/s, the same as OPNsense.
  - OpenBSD's pf on the same host does 18.7 Gbit/s, so the bottleneck is
    FreeBSD's virtio forwarding path (OPNsense must ship offloads off;
    switching them on breaks forwarding), not pf.
  - Latency comes from Linux's default fq_codel; connection rate from pf's
    closed-state reuse vs conntrack.
  - Caveat: measured on virtio. Real NICs must confirm the throughput part.
- **The OS base (B) gives modest gains.**
  - Idle RAM 550 → 281 MiB, boot to forwarding 14.5 → 12.4 s, disk 2.1 →
    1.5 GiB (NixOS closure untrimmed).
  - Compressed images are the same size: 487 vs 491 MB.
  - A heavy Linux userland erases this: VyOS needs 637 MiB and 31 s, and 2 min
    with a 1,000-rule config.
- **The control plane (C) is where a lean Rust daemon wins outright**
  (prototype estimates):

  | | Rust prototype | OPNsense | VyOS (same kernel) |
  |---|---|---|---|
  | One-rule apply, 50 rules | 16 ms | 0.36 s | 2.2 s |
  | One-rule apply, 1,000 rules | 0.12 s | 1.6 s | 26 s |
  | 10k-entry table replace | 0.05 s | 1.05 s | 8.5 min |
  | API reads | 0.3 ms | 55–300 ms | 0.45–15 s |
  | Management memory | 2–10 MiB | ~950 MiB summed RSS | 378 MiB |

  These matter for automation, large/dynamic tables and low-RAM boards. For a
  person clicking "Apply" on one home router they mostly don't.
- **Verdict:** on performance/efficiency grounds the evidence supports the
  plan's Linux/NixOS/nftables base and a single-process, render-and-swap
  agent. It does **not**, by itself, justify a full Rust rewrite of
  OPNsense's feature surface. NixOS + nftables + a small Rust agent captures
  nearly all of the measured gains; the rest of the remake has to be
  justified on its other grounds (Pi 5 drivers, safety of apply, typed
  config).


---

## 1. Method

### 1.1 Lab

| | |
|---|---|
| Host | `nixtop`: AMD Ryzen 7 7840U (8 cores / 16 threads, SMT siblings *n* and *n+8*), 30 GB RAM, NixOS 26.11.20261008.e7439b6, kernel 6.18.55, QEMU 11.1.1, libvirt 12.7.0, KVM |
| Topology | `client 192.168.1.100 ─[sensrbench-lan]─ ROUTER ─[sensrbench-wan]─ server 10.99.0.10`, outbound NAT on the router. Both libvirt networks are isolated (no forwarding); the host holds .254 on each bridge for management only |
| Router VM | 2 vCPU pinned to host CPUs 2,3 (emulator + vhost threads on 10,11), 2 GiB, q35, `host-passthrough`, virtio-blk, 2 × virtio-net with vhost. Same MACs/NIC order for every variant (NIC0 = LAN, NIC1 = WAN) |
| Endpoints | NixOS minimal (same image, role by MAC), 3 vCPU each (client 4,5,12 / server 6,7,14, emulator 13 / 15), 2 queues, iperf3 3.x, wrk, nginx |
| Repeats | 5 runs per test (boots: 5, idle snapshots: 1–2), reported as median (min–max). Host load average and the CPU use of the pre-existing `rocky-rel` VM (not ours, untouched, floating over all CPUs) are logged with every sample. During data-plane tests the host 1-min load average (which includes our own busy VM threads) had a median of 6.8 and a max of 12.9 on 16 threads; `rocky-rel` used a median of 11 % (4–23 %) of one CPU |

### 1.2 Routers under test

| Variant | Version | Data plane | Control plane | Notes |
|---|---|---|---|---|
| **OPNsense** | 26.7 nano amd64 (FreeBSD 15.1-RELEASE-p1), sha256 + signature verified | pf | lighttpd + php-cgi + configd (Python) | configured through its own API (50 rules, 7 aliases, automatic outbound NAT; large: 1,000 rules + 10k-entry alias) |
| **OpenBSD** | 8.0 GENERIC.MP amd64 (build 2026-10-07), sha256 + signify verified | pf | none (pf.conf + pfctl) | autoinstall-style serial install, sets minus X/games; unbound + dhcpd on LAN; `net.inet.ip.forwarding=1`, everything else as shipped |
| **VyOS** | rolling 2026.11.16-0022 (generic amd64 ISO, minisign verified; LTS needs a subscription), kernel 6.18.62-1-vyos | nftables | vyos-1x (Python) commit + HTTP API (Python/uvicorn behind nginx) | same rules as `set firewall ipv4 …`, network/address/port groups, source NAT masquerade, Kea DHCP, DNS forwarding (PowerDNS recursor) |
| **NixOS** | minimal profile, same nixpkgs as the host, kernel 6.18.55 | nftables | the Rust prototype as a systemd service (stand-in for sensr's agent) | unbound + Kea on LAN (OPNsense ships a resolver + DHCP), sshd. `nftables flowtable` and "no GRO/GSO/TSO" as extra variants |
| **Rust prototype** | `bench/prototype/` (axum 0.8, serde_json; static musl build) | — | renders the whole policy as nftables JSON and applies atomically with `nft -j -f -`; serves rule search from memory | **prototype estimate**, ~400 lines, no validation, no persistence |

All four routers enforce *the same* synthetic home-router policy, generated by
`bench/gen/gen_rules.py` from one rule list (order, matches, actions): DNS/NTP/DHCP
to the router, admin hosts, a blocklist alias, IoT and kids device groups with
port aliases, per-host exceptions, "LAN to any" last, a few WAN rules, default
deny, NAT on WAN. The benchmark flows match none of the specific rules, so every
new connection walks the whole list before the final pass. Large variant: the
same plus 950 per-host rules (1,000 total) and a 10k-entry blocklist table.

### 1.3 Fairness and "as shipped"

- Every router runs **as shipped** apart from what the topology needs. Offloads
  are the vendor default:
  - OPNsense ships the three "Disable hardware checksum/TSO/LRO offload" boxes
    ticked **and** the loader tunables `hw.vtnet.csum_disable=1`,
    `hw.vtnet.lro_disable=1`, so vtnet negotiates no CSUM/TSO/LRO feature.
  - OpenBSD 8.0's `vio(4)` negotiates TSO and LRO by default.
  - Linux `virtio_net` has GRO/GSO/TSO on (NixOS and VyOS).
- "Tuned" variants are labelled as such: OPNsense with offloads enabled at boot
  (both with and without LRO), Linux with GRO/GSO/TSO off, the Linux flowtable,
  and 2 virtio queue pairs instead of 1 (`q2`).
- Router CPU is measured three ways per test:
  - *guest busy %*: the router's own counters (`/proc/stat`, `kern.cp_time`),
    100 % = both vCPUs.
  - *host vCPU %*: libvirt `cpu.time` minus KVM halt-polling.
  - *vhost %*: host CPU of the router's vhost-net workers.

  The host views are the comparable ones. Linux guests use `cpuidle-haltpoll`,
  which looks idle inside the guest but burns host CPU, so Linux's guest busy %
  understates its cost.
- Boot times run from `virsh start` on a fresh qcow2 overlay, with the endpoints
  already up:
  - *forwarding*: first client→server ping answered through the router, 50 ms
    probe interval.
  - *SSH*: SSH accepts the key.
  - *mgmt API*: OPNsense `/api/core/firmware/status`, VyOS `/retrieve`, the
    prototype's `/api/health` → 200.

  Serial milestones are timestamped on arrival at the host. Loader timeouts are
  as shipped: OPNsense `autoboot_delay=3`, NixOS GRUB 5 s, OpenBSD 5 s.

### 1.4 Known limits of this lab

- **Small-packet ceiling.** Docker on the host loads `br_netfilter`, so every
  frame crossing the lab bridges also traverses the host's netfilter hooks.
  Together with iperf3 as the generator, this caps the lab at roughly
  250–300 kpps for every router (kernel pktgen did no better). Small-packet
  results therefore say "keeps up with ~280 kpps or not", not "maximum pps".
  The host is not ours to reconfigure.
- **Virtio, not real NICs.** Linux's large-TCP advantage comes from forwarding
  GRO-aggregated 64 KB super-packets over virtio (section 2.1). On real
  hardware, the gap depends on the NIC driver's LRO/GRO/TSO support under
  forwarding. It must be re-checked on the target boards (Pi 5 RP1 + RTL8156
  USB, an x86 box with i226).
- **One synthetic policy.** Rule-count effects are measured at 50 and 1,000
  rules, not at every size.
- **Errata, all fixed and rerun before these tables** (superseded raw rows are
  kept in `bench/results/superseded-*.jsonl` / `controlplane-superseded.jsonl`):
  - an "offload-on" OPNsense run that only flipped `ifconfig` flags (no
    effect: negotiation happens at boot);
  - a FreeBSD `ps -o` parsing bug (POSIX header semantics) that zeroed
    OPNsense process counts;
  - a Python scoping bug in the boot API probe;
  - an OpenBSD apply test that failed silently (shell expansion);
  - 10 ms BSD timer resolution;
  - a first VyOS large-config load that raced VyOS's own boot-time commit and
    never took effect.

---

## 2. Results

### 2.1 (A) Data plane

**TCP forwarding through NAT + 50-rule policy, Gbit/s** (iperf3 10 s, 5 runs;
`up` = client→server, `down` = `-R`; 1 virtio queue pair unless noted):

| Router / variant | 1 stream up | 1 stream down | 8 streams up | 8 streams down | host CPU per Gbit/s (vCPU+vhost, 8 up) |
|---|---|---|---|---|---|
| OPNsense, as shipped | 3.15 (2.71–3.20) | 3.13 (2.91–3.23) | 3.11 (2.89–3.22) | 2.96 (2.87–3.16) | 75 % |
| OPNsense, csum+TSO on, LRO off (tuned) | 3.10 (3.08–3.18) | 3.16 (3.07–3.33) | 3.12 (3.08–3.26) | 3.23 (2.95–3.26) | 76 % |
| OPNsense, csum+TSO+LRO on (tuned) | **0.00** | **0.00** | **0.03** | **0.04** | — (forwarding breaks) |
| OPNsense, 2 queues | 2.95 (2.75–3.02) | 2.76 (2.76–2.91) | 3.75 (3.62–3.81) | 3.74 (3.58–3.75) | 89 % |
| OpenBSD 8.0 pf, as shipped | 23.8 (20.5–30.8) | 23.3 (20.7–28.1) | 18.7 (18.2–20.2) | 18.2 (17.1–20.2) | 15 % |
| OpenBSD, 2 queues | 28.3 (26.5–29.7) | 28.5 (22.9–31.5) | 24.0 (23.9–24.1) | 24.0 (23.3–24.1) | 15 % |
| NixOS nftables, as shipped | 29.8 (27.7–31.0) | 31.1 (20.7–31.8) | 25.7 (25.3–26.3) | 25.3 (24.8–26.0) | 12 % |
| NixOS, GRO/GSO/TSO **off** | 3.30 (3.27–3.38) | 3.27 (3.16–3.28) | 3.27 (3.07–3.33) | 3.13 (2.98–3.20) | 63 % |
| NixOS, flowtable | 27.6 (24.4–30.7) | 28.1 (23.6–29.7) | 26.0 (24.6–26.6) | 24.8 (24.3–27.0) | 12 % |
| NixOS, 2 queues | 31.4 (29.5–31.7) | 30.6 (25.7–31.4) | 29.2 (27.7–29.6) | 27.3 (26.6–28.5) | 10 % |
| NixOS, flowtable, 2 queues | 30.9 (30.8–31.8) | 29.7 (21.4–30.8) | 29.7 (28.7–30.3) | 29.9 (29.2–30.2) | 10 % |
| VyOS, as shipped | 28.4 (26.7–30.6) | 30.2 (26.3–30.8) | 25.9 (25.2–26.4) | 25.8 (25.0–26.0) | 12 % |
| VyOS, 2 queues | 31.5 (28.3–33.0) | 31.0 (27.3–32.3) | 26.0 (25.4–26.6) | 26.4 (25.9–27.3) | 13 % |

The 1,000-rule + 10k-table variants forward established TCP at the same rate as
the 50-rule ones: OPNsense 3.13 / 3.08, OpenBSD 22.0 / 18.8, NixOS 29.0 / 25.6,
VyOS 31.1 / 26.9 Gbit/s (1 / 8 streams). Established flows hit the state table
or conntrack, never the rule list.

What this shows:
- **The ~8–10× TCP gap is offload handling, not pf vs nftables.** Linux with
  GRO/GSO/TSO off forwards 3.1–3.3 Gbit/s, the same as OPNsense. The difference
  is that Linux (and OpenBSD 8.0's `vio`) forwards aggregated 64 KB
  super-packets. Per packet, Linux is still somewhat cheaper: 63 % vs 75 % host
  CPU per Gbit/s at the same packet rate.
- **OPNsense cannot simply switch this on.** With checksum offload + LRO
  enabled at boot, FreeBSD/vtnet forwarding collapses to ~0.04 Gbit/s with heavy
  retransmits. Without LRO it stays at 3.1 Gbit/s. OPNsense's offload-off
  defaults are therefore correct for FreeBSD, not timid.
- **OpenBSD pf reaches 18–28 Gbit/s on the same hypervisor.** pf as a filter is
  not the bottleneck; FreeBSD's virtio forwarding path is.
- **The flowtable fast path adds nothing measurable here.** Throughput is
  within the noise and host CPU per Gbit/s is the same. With GRO, the netfilter
  hooks are already a small share of the cost. XDP was not measured: nothing in
  the plan needs it before Phase 4, and virtio-net XDP would not predict real
  NICs.
- **Multiqueue helps every OS with 8 streams:** OPNsense +20 %, OpenBSD +28 %,
  NixOS +14 %.

**Small packets** (iperf3 UDP, 4 streams, unlimited rate; the lab tops out
around 250–300 kpps, see 1.4):

| Router | 64 B recv kpps (loss) 1 queue | 64 B recv kpps (loss) 2 queues | 512 B recv kpps (loss) 1 queue |
|---|---|---|---|
| OPNsense | 253 (12.6 %) | 259 (0.0 %) | 240 (14.5 %) |
| OpenBSD | 170 (37.6 %) | 272 (5.1 %) | 166 (37.0 %) |
| NixOS | 264 (11.1 %) | 256 (0.1 %) | 242 (18.8 %) |
| NixOS flowtable | 247 (12.2 %) | 277 (0.2 %) | 220 (22.1 %) |
| VyOS | 253 (13.7 %) | 277 (1.5 %) | 219 (28.2 %) |

Within this ceiling, OPNsense, NixOS and VyOS keep up equally; with 2 queues
all three are loss-free. OpenBSD with one queue is the only router that falls
behind. No pf-vs-nftables per-packet difference can be resolved at this rate.

**Latency** (ping every 10 ms, 1,000 probes; "under load" = during an 8-stream
TCP run):

| Router | idle p50 / p99 ms | under load p50 / p99 ms (1 queue) | under load p50 / p99 ms (2 queues) |
|---|---|---|---|
| OPNsense | 0.35 / 1.88 | 15.3 / 19.2 | 24.3 / 33.2 |
| OpenBSD | 0.31 / 1.42 | 9.5 / 14.5 | 9.3 / 11.3 |
| NixOS | 0.29 / 1.25 | 1.6 / 6.1 | 3.5 / 8.3 |
| NixOS, GRO off (same 3.3 Gbit/s as OPNsense) | 0.28 / 1.40 | 1.5 / 4.1 | — |
| VyOS | 0.27 / 1.40 | 1.9 / 7.5 | 4.1 / 9.2 |

Idle latency is identical. Under load, the Linux routers queue ~10× less, even
at OPNsense's throughput (GRO off: 1.5 ms vs 15.3 ms). That is Linux's default
`fq_codel` qdisc and BQL, a kernel default, not a Rust effect. OPNsense can get
close with a manually configured FQ-CoDel shaper; it isn't on by default.

**New connections per second** (wrk, `Connection: close`, 48 concurrent, 10 s):

| Router | 50 rules | 1,000 rules + 10k table | router host vCPU % (50 rules) |
|---|---|---|---|
| OPNsense | 2,350 (2,321–2,774) | 1,489 (738–2,706) | 30 % |
| OpenBSD | 1,290 (1,276–1,419) | 928 (208–1,403) | 10 % |
| NixOS | 20,820 (19,404–22,323) | 11,699 (11,622–11,805) | 99 % |
| NixOS flowtable | 19,582 | 11,763 | 99 % |
| VyOS | 19,886 (18,774–20,616) | 14,027 (13,985–14,137) | 109 % |

Why the pf routers are 8–15× lower here although their CPU is mostly idle
(`bench/run/diag.py`, `results/diag.jsonl`):

- **One connection at a time, all four are equal.** curl ×200, connect p50 /
  total p50: OPNsense 0.35 / 0.66 ms, OpenBSD 0.37 / 0.69 ms, NixOS 0.31 /
  0.58 ms, VyOS 0.40 / 0.72 ms.
- **Under concurrency the BSDs fall behind.** OPNsense goes from 2.8k to 3.9k
  conn/s between 48 and 256 concurrent connections, and OpenBSD drops from 1.4k
  to 0.6k. Linux rises to 26.8k.
- **pf counts SYNs hitting lingering states.** During one 10 s run, pf logs ~440–480
  `state-mismatch` events: SYNs that collide with lingering closed states
  (`tcp.closed` 90 s) when the client recycles source ports. Each one costs that
  connection a 1 s SYN retransmit.
- **Linux conntrack lets a new SYN reopen a TIME_WAIT entry,** so it is only
  CPU-bound: ~1 vCPU busy.

This is a state-machine semantic difference in the kernels (A). It matters for
heavy connection churn from few clients (load tests, some P2P/IoT patterns),
not for typical home traffic. The 1,000-rule policy costs nftables ~30–45 % of
its connection rate (NixOS 20.8k → 11.7k, VyOS 19.9k → 14.0k), because new
flows walk the chain linearly. pf's numbers are dominated by the state-reuse
effect, so its rule-count sensitivity cannot be read from this test. If sensr
wants large rule lists to stay cheap, its rule compiler should emit verdict
maps or sets rather than one linear chain.

### 2.2 (B) OS base: footprint and boot

| | OPNsense 26.7 | OpenBSD 8.0 | NixOS minimal (sensr-like) | VyOS rolling |
|---|---|---|---|---|
| Distribution artefact | nano image 491 MB (.bz2), 3.0 GiB raw | install80.img 839 MB (all sets) | built locally: 487 MB as .bz2 (427 MB zstd -19), 3.0 GiB raw, closure 915 MiB, untrimmed: python3 137 MiB, perl 55 MiB, Kea 43 MiB ride along | ISO 642 MB |
| Installed, disk used | 2,104 MiB (large: 2,286) | 2,046 MiB (/usr 1,907 MiB, incl. the compiler set the installer selects by default; a base-only router install would be roughly half) | 1,528 MiB | 732 MiB (large: 755) |
| Idle memory used, 5 min after boot (total − available) | **550 MiB** (large: 629) | **285 MiB** | **281 MiB** | **637 MiB** (large: 774) |
| Processes: total / userland | 75 / 57 | 34 / 34 (kernel threads not listed) | 130 / 23 (107 kernel threads) | 140 / 55 |
| Management stack, summed RSS¹ | 952 MiB: php-cgi pool 800, php 56, configd 54, lighttpd 11, … | — | 5.4 MiB (prototype, 50 rules; streaming build 1.7 MiB) | 378 MiB: Python daemons 278, vyos-http-api 84, nginx 16 |
| Boot → kernel on serial | 7.5 s | 5.9 s | 7.5 s² | 6.9 s |
| Boot → **first packet forwarded** | 14.5 s (large: 17.7) | 14.8 s | **12.4 s** | 30.7 s (large: **120.6 s**) |
| Boot → SSH | 15.3 s | 21.5 s | 13.6 s | 37.6 s (large: 231 s) |
| Boot → management API 200 | 15.4 s (large: 19.4) | n/a (no API) | **13.0 s** | 39.4 s (large: >600 s, probe gave up) |

¹ Summed RSS double-counts shared pages (16 php-cgi workers share most of
theirs). "Idle memory used" is the honest system-wide figure.
² First serial byte: NixOS's GRUB draws its 5 s menu on VGA only, so the kernel
is the first thing on the serial line. Kernel → forwarding is ~5 s on NixOS vs
~7 s on OPNsense.

### 2.3 (C) Control plane

**One-rule change, end to end until the rule is active in the kernel**
(verified in `pfctl -sr` / `nft list`):

| Path | 50 rules | 1,000 rules + 10k table | 10,000 rules |
|---|---|---|---|
| OpenBSD `pfctl -f` (raw kernel tool, no management layer) | 0.015 s | 0.062 s | — |
| `nft -f` whole ruleset (raw, text) | 0.013 s | 0.066 s | — |
| **OPNsense** API `add_rule` + `filter/apply` (configd → rc.filter_configure → pfctl) | 0.36 s (0.34–0.49) | 1.58 s (1.32–1.73) | — |
| **VyOS** `configure; set …; commit` | 2.23 s (commit 1.86) | **26.4 s** (commit 26.0) | — |
| VyOS HTTP API `/configure` (set + commit) | 2.69 s | 40.5 s (40.5–41.4) | — |
| **Rust prototype** POST `/api/rules` → render all → `nft -j -f` | **0.016 s** | **0.124 s** | 0.757 s |

**Table/alias replacement** (blocklist with 1k / 10k / 100k entries):

| Path | 1k | 10k | 100k |
|---|---|---|---|
| FreeBSD `pfctl -T replace` (raw) | 0.006 s | 0.013 s | 0.076 s |
| OpenBSD `pfctl -T replace` (raw) | 0.014 s | 0.042 s | 0.319 s |
| Linux `nft -f` flush set + add elements (raw, text) | 0.017 s | 0.046 s | 0.594 s |
| **OPNsense** alias API `set_item` + `alias/reconfigure` | 0.86 s | 1.05 s | 1.08 s |
| **VyOS** delete + `set … network-group` + commit | 41.7 s (commit 5.0) | 508 s (commit 32.5) | **> 600 s, gave up while staging** |
| **Rust prototype**: render JSON + `nft -j -f` (atomic) | 0.017 s | 0.050 s | 0.651 s |

**API read latency** (rule search, 50 sequential requests, p50 / p95):

| | 50 rules | 1,000 rules |
|---|---|---|
| OPNsense `firewall/filter/search_rule` | 55 / 63 ms | 300 / 454 ms |
| VyOS `/retrieve showConfig`, one rule | 455 / 482 ms | **8,017 / 8,095 ms** |
| VyOS `/retrieve showConfig`, whole forward chain | 731 / 759 ms | **15,521 / 15,609 ms** |
| Rust prototype `/api/rules/search` (10k rules: 0.43 / 0.66 ms) | 0.25 / 0.34 ms | 0.34 / 0.48 ms |

**Bulk configuration through the product's own interface:**
- OPNsense: adding 1,000 rules one by one via the API took 202 s. Per-rule cost
  grows from 29 ms to ~200 ms because every add re-serialises config.xml.
- VyOS: loading the 1,000-rule + 10k-entry config took 17 min (≈15 min staging
  17k `set` commands, then a 121 s commit).
- Rust prototype: renders 1,000 rules + 10k entries in 0.06 s, applies in 0.07 s.

**Management memory:**
- OPNsense: 952 MiB summed RSS, 550 MiB system-wide.
- VyOS: 378 MiB.
- Prototype, streaming build: 1.7 MiB at 50 rules, 3.3 MiB at 1,000, 10.2 MiB at
  10,000. It stays flat across repeated applies.
- The first, naive prototype build put each ruleset into a `serde_json::Value`
  DOM: 45 MiB at 1,000 rules and 337 MiB at 10,000, growing to ~1 GiB after a
  few applies (allocator retention). So the implementation choice matters as
  much as the language.

**GUI weight (OPNsense):**
- Dashboard: 117 KiB HTML + 39 JS/CSS assets = 2.2 MiB; 0.12 s to fetch
  everything on the LAN.
- Firewall rules page (MVC): 269 KiB HTML + 25 assets = 1.5 MiB, 0.08 s. The
  rules are fetched separately through the API (the 55–300 ms above).
- OpenBSD and VyOS have no GUI. sensr's planned Leptos SSR UI does not exist
  yet, so there is no number to compare. A server-rendered page plus a WASM
  island bundle in the low hundreds of KiB is plausible but **not measured**.

**Prototype render vs `nft`:**
- At 10k rules the static-musl prototype spends 0.44 s rendering 5.3 MiB of
  JSON (musl's allocator; a glibc build of the DOM variant took 0.25 s).
- `nft -j -f` spends 0.37 s parsing and committing it.
- At 1,000 rules: render 0.06 s, apply 0.07 s; nft's own text parser needs
  0.066 s for the same ruleset.
- The kernel transaction, not Rust, sets the floor.

---

## 3. Which gains come from where

Comparing **VyOS** (Linux nftables + a heavy Python control plane) with
**NixOS + the Rust prototype** (same kernel data plane, minimal OS, tiny
control plane) isolates what Rust/minimalism buys. Comparing **OPNsense** with
**OpenBSD** separates "pf the filter" from "FreeBSD + OPNsense the system".

| Metric | OPNsense → NixOS+Rust | Where it comes from | Evidence |
|---|---|---|---|
| Large-flow TCP forwarding | 3.1 → 25.7 Gbit/s (8 streams), ~6× less host CPU per Gbit/s | **A: Linux kernel** (GRO/GSO forwarding over virtio). Not pf vs nft, not Rust | VyOS gets the same 25.9; Linux with GRO off drops to OPNsense's 3.3; OpenBSD pf gets 18.7 |
| Latency under load | 15 ms → 1.6 ms p50 | **A: Linux default qdisc** (fq_codel, BQL) | identical at equal throughput (GRO off: 1.5 ms); VyOS 1.9 ms |
| Small-packet rate | no difference within the lab's ~280 kpps ceiling | — | all three Linux/FreeBSD routers keep up |
| New connections/s under churn | 2.3k → 20.8k | **A: kernel state-machine semantics** (pf `tcp.closed` state reuse vs conntrack) | VyOS 19.9k; sequential connection latency identical on all |
| Idle RAM | 550 → 281 MiB | **B: OS base** + **C: control plane** | OpenBSD (no GUI) 285 MiB; VyOS 637 MiB, of which ~380 MiB is its Python management stack |
| Disk | 2,104 → 1,528 MiB | **B**, and the NixOS closure is not trimmed (Python, Perl ride along) | VyOS 732 MiB squashfs shows Linux can be smaller |
| Boot → forwarding / API | 14.5 / 15.4 s → 12.4 / 13.0 s | **B**, modest | VyOS 30.7 / 39.4 s (small), 121 s / >600 s (large config) |
| One-rule apply | 0.36 s → 0.016 s (50 rules); 1.58 → 0.12 s (1,000) | **C: control plane**. The kernel tools take 13–66 ms either way | VyOS 2.2 s / 26.4 s on the same nftables kernel |
| Alias/table replace, 100k | 1.08 s → 0.65 s | **C** at small sizes; at 100k the kernel dominates and FreeBSD's `pfctl -T` (76 ms) beats nft (594 ms) | VyOS: >600 s |
| API read latency | 55–300 ms → 0.3 ms | **C** | VyOS 455 ms – 15.5 s |
| Management memory | ~950 MiB summed RSS / ~270 MiB extra system-wide → 2–10 MiB | **C** (PHP-FPM-style worker pool vs one process) | VyOS 378 MiB |

## 4. Pi 5 shape (emulated)

**Setup.** This reuses opnsense-pi's Pi 5 VM profile: QEMU `virt`,
`cortex-a76` × 4, 4 GiB, UEFI from QEMU's own `edk2-aarch64-code.fd`, virtio
NICs on the same isolated bridges. It runs under **TCG emulation on the x86
host**. The Raspberry Pi firmware/UEFI blobs and the RP1 hardware can't run in
QEMU, so this measures the operating-system images, not the board.

| Image | Details |
|---|---|
| OPNsense | community *serial* aarch64 image pinned in opnsense-pi `versions.env` (`OPNsense-26.7-ufs-serial-vm-aarch64.qcow2.bz2`, sha256 `564a17e6…` verified), bootstrapped exactly like x86 (config.xml + API) |
| NixOS | the same `router.nix` as x86, for `aarch64-linux`. nixtop has no aarch64 binfmt/builder and no sudo, so the official aarch64 minimal installer ISO (sha256 verified) booted in the VM: the host pushed the evaluated `.drv` closure in with `nix copy`, and the VM substituted the rest from cache.nixos.org through an SSH reverse tunnel (the lab bridge stays isolated). The Rust prototype is the same source, cross-compiled static (musl) |
| VyOS arm64 | no free prebuilt arm64 image is published (the rolling nightly releases carry only `generic-amd64`). Marked **pending the `vyos-pi` build** |
| OpenBSD arm64 | optional; skipped |

Validity:
- **Footprint numbers are valid**: image size, idle RAM, process count.
- **Boot and control-plane times are relative indicators only.** TCG is
  ~10–25× slower than the x86 runs and slower than a real Cortex-A76.
- **No throughput, pps or latency numbers** are reported, because they would
  say nothing about Pi 5 hardware.
- The large OPNsense variant was not built on this track: adding 1,000 rules
  through the API at ~0.5 s+ per rule under TCG would take over an hour.

| Pi 5 shape, emulated | OPNsense 26.7 aarch64 | NixOS aarch64 (+ Rust prototype) |
|---|---|---|
| Installed, disk used | 1,983 MiB | 1,693 MiB |
| Idle memory used (of 4 GiB) | **617 MiB** | **298 MiB** |
| Processes total / userland | 66 / 49 | 127 / 23 |
| Management stack, summed RSS | 936 MiB | 1.5 MiB (prototype) |
| Boot → forwarding / SSH / API *(relative)* | 69 / 74 / 80 s | 83 / 88 / 88 s (1 clean boot; see note) |
| One-rule apply *(relative)* | 2.2 s (x86: 0.36 s) | 0.23 s at 50 rules, 3.2 s at 1,000 (prototype; render 2.1 s of it) |
| Table replace 1k / 10k / 100k, raw kernel tool *(relative)* | 0.11 / 0.17 / 1.03 s (`pfctl -T replace`) | 0.14 / 0.54 / 4.9 s (`nft -f`) |
| Table replace via the management layer *(relative)* | 14.0 / 10.9 / 15.8 s (alias API + reconfigure) | 0.14 / 0.80 / 8.2 s (prototype render + `nft -j -f`) |
| API rule search *(relative)* | 632 ms | 6–9 ms |
| Initial policy load via API (50 rules) *(relative)* | 519 ms per rule, filter apply 5.7 s | n/a (policy is in the image) |

Notes on the NixOS aarch64 numbers:
- **Boot.** Only 2 of 5 boots came up cleanly. The failures stopped in the
  initrd, at "Find NixOS closure" or at "Mountpoints Configured in the Real
  Root" for the vfat ESP. This looks like a timing race that TCG's slowness
  exposes, but it is still a finding against this image config. `/boot`
  should be `nofail` with a device timeout, and sensr's Pi image must boot
  reliably on hardware anyway.
- **Boot to forwarding** under TCG was slower than OPNsense (83 s vs 69 s),
  the reverse of x86 (12.4 vs 14.5 s). NixOS's generic initrd + udev is more
  CPU-heavy, and TCG punishes CPU-heavy boots. This is a relative indicator
  only.
- **Prototype render cost.** The static-musl prototype spends most of its
  1,000-rule apply rendering (allocation-heavy JSON building, ~40× slower
  under TCG than on x86). A real agent should serialise typed structs
  directly.
- **Raw table loads:** FreeBSD's `pfctl -T replace` again beats `nft` (1.0 s
  vs 4.9 s at 100k).

What a real-board run must confirm:
- **Forwarding with real NIC drivers.** Pi 5 RP1 `macb` on Linux vs
  opnsense-pi's polled `rp1_eth`, RTL8156/8157 over USB (`r8152` vs FreeBSD's
  `ure`/none), with and without offloads. This is where the x86 "8×" could
  shrink or grow.
- **Small-packet pps** on the Cortex-A76, outside a TCG/br_netfilter lab.
- **Thermals and power under sustained forwarding.**
- **Boot from the Pi firmware** (not UEFI) for the NixOS image.

### VyOS on Raspberry Pi 5

*The question: "would VyOS be a sufficient router to install on a Pi 5?"*

1. **Kernel and Pi 5 hardware.**
   - VyOS rolling runs kernel **6.18.62** (confirmed on the x86 image:
     `6.18.62-1-vyos`).
   - Its arm64 `vyos_defconfig` does **not** enable `BCMGENET`, `MACB`/RP1
     support, or the Pi SD/MMC controllers. The Pi 5's on-board Ethernet (RP1
     → `macb`) and its SD card are therefore unusable with the stock arm64
     kernel config.
   - Booting needs either the Pi firmware loading a kernel + `bcm2712`
     device tree directly (which VyOS's GRUB/EFI image layout doesn't do), or
     UEFI (`rpi5-uefi`, D0 boards, SD boot only, "ACPI + Device Tree" preset as
     in opnsense-pi).
   - Either way it needs a custom kernel, which is exactly what the separate
     `vyos-pi` project is building.
2. **USB NICs.** `USB_RTL8152=m` is enabled, so RTL8156/8157 USB NICs (the
   `r8152` driver; RTL8157 support depends on the kernel's r8152 revision) are
   the realistic Pi 5 LAN/WAN with a stock VyOS kernel.
3. **Feature gaps vs the opnsense-pi daily-driver set.** Checked in the VyOS
   image's config templates and binaries:

   | Feature | VyOS rolling |
   |---|---|
   | WAN DHCPv4/v6 + prefix delegation | yes (`dhcpv6-options pd`) |
   | LAN on USB NICs | yes (`r8152`) |
   | Kea DHCP | yes (`kea-dhcp4`/`kea-dhcp6`) |
   | DNS | PowerDNS recursor, not Unbound: forwarding/recursion yes; no Unbound-style DNSBL/blocklist UI |
   | WireGuard | yes |
   | Suricata IDS | yes (`service suricata` + `/usr/bin/suricata`) |
   | NetFlow | yes (`system flow-accounting`) |

   It has no web GUI, so configuration is CLI/API only.
4. **Performance/efficiency, from the x86 track.**
   - Same Linux data plane as sensr, so the same forwarding and latency
     results.
   - But it is the heaviest image measured: 637 MiB idle with a 378 MiB
     Python management stack, 31 s to forward from boot, and 2 min with a
     1,000-rule config.
   - At 1,000 rules + a 10k group: 26 s per one-rule commit, 8 s per API read,
     8.5 min to replace a 10k-entry group.

**Verdict:** functionally VyOS covers the opnsense-pi feature set except
Unbound-style DNS blocklists and a GUI. On a Pi 5 it is **not usable out of
the box**: no RP1/SD support and no Pi boot path. With the `vyos-pi` kernel it
would be a capable CLI router for small, mostly static configurations. Its
commit/API latency and ~640 MiB idle footprint make it a poor base for large or
frequently changing rule sets. Measurements on an emulated Pi are pending the
`vyos-pi` build.


## 5. Conclusion

**Is the remake worth it on performance, efficiency or lightness grounds?**
Partly. The large gains are real, but most of them come from Linux, and you
can get them without rewriting the control plane in Rust. Where Rust does help,
the effect is big in ratio and small in absolute terms for one home router.

1. **The data-plane gains (A) argue for Linux, not for Rust.**
   - ~8× TCP forwarding on virtio, ~10× lower latency under load, and ~9×
     connection rate under churn.
   - VyOS, a Python-managed Linux router, gets every one of these numbers.
   - The raw filter isn't the cause: OpenBSD's pf forwards 18–28 Gbit/s on the
     same host, and pf beats nft at table loading.
   - The drivers are Linux's GRO/offload forwarding path, its default
     `fq_codel`, and conntrack's TIME_WAIT reuse.
   - Caveat: measured on virtio. Real NICs (RP1 `macb`, `r8152`, i226) must
     confirm the offload part before anyone quotes "8×".
   - The plan's choice of NixOS + nftables is the part that delivers this.
     Flowtables gave nothing measurable here. XDP/eBPF fast paths (Phase 4)
     are unproven and not needed for these numbers.
2. **The OS base (B) gives modest wins.**
   - Idle RAM: 550 → 281 MiB. Boot to forwarding: 14.5 → 12.4 s.
     Disk: 2.1 → 1.5 GiB, and that NixOS closure isn't trimmed yet.
   - Pleasant, not decisive: a 4–16 GB Pi 5 doesn't care about 270 MiB.
   - VyOS shows the opposite risk: a Linux base with a heavy userland can be
     *heavier* than OPNsense (637 MiB, 31 s to forward, 2 min with a big
     config).
3. **The control plane (C) is where Rust/minimalism wins outright.** Against
   VyOS on the *same kernel*:

   | Metric | VyOS | Rust prototype |
   |---|---|---|
   | One-rule apply, 50 rules | 2.2 s | 0.016 s |
   | One-rule apply, 1,000 rules | 26 s | 0.12 s |
   | 10k-entry group replace | 8.5 min | 0.05 s |
   | API reads | 0.45–8 s | 0.3 ms |
   | Management memory | 378 MiB | 2–10 MiB |

   Against OPNsense: 20–30× faster applies, 200–1,000× faster API reads,
   ~100× less management memory.

   For a human clicking "Apply", 0.36 s vs 0.016 s doesn't matter. It matters
   for:
   - automation and fleets: OPNsense's API took 202 s to add 1,000 rules;
   - big dynamic tables (blocklists);
   - boot-to-ready with large configs;
   - low-RAM boards.

   These are prototype lower bounds. A real agent with validation, a config
   store, commit-confirm and a UI will cost more. It should stay well under
   VyOS's numbers *if* it keeps the prototype's design: one process,
   in-memory typed config, render-all-then-atomic-swap, streaming serialisation.
   The naive DOM build used 337 MiB at 10k rules, so the design matters more
   than the language.
4. **What the plan should take from this.**
   - The performance case supports §1's choice of Linux/NixOS/nftables and
     §2.3's lean process model (agent + API, no PHP/Python worker pools,
     atomic `nft -j -f`).
   - It does **not** by itself justify a 464-feature, from-scratch rewrite.
   - A cheaper path to most of the same numbers exists: NixOS + nftables + a
     small Rust agent. The UI, `sensr-compat` and feature parity don't add
     speed.
   - Those remain justified (or not) on the plan's other grounds: Pi 5/USB NIC
     drivers, atomic apply / commit-confirm safety, typed config. Speed
     shouldn't be the headline argument.
   - Two concrete design notes:
     - Compile large rule sets into nft verdict maps/sets: a linear chain cost
       NixOS 44 % of its connection rate at 1,000 rules.
     - Keep `fq_codel`/CAKE on by default.


## 6. Reproduce

Everything runs on an x86_64 Linux KVM host with libvirt and Nix, as a
non-root user in the `libvirtd`/`kvm` groups. Paths default to
`/mnt/vms/sensr/bench`.

```sh
# 0. inputs (verified downloads) and images
python3 bench/gen/gen_rules.py bench/generated        # policy for all routers
nix build ./bench#router ./bench#endpoint            # NixOS images (qcow2)
#    OPNsense nano / OpenBSD install80.img / VyOS ISO: URLs + checksums in this doc, 1.2
virsh net-define bench/libvirt/net-{lan,wan}.xml     # isolated bridges
python3 bench/gen/opn_bootstrap.py …                 # OPNsense: SSH, WAN, gateway
python3 bench/run/opn_api.py load small|large        # OPNsense rules via its API
python3 bench/run/obsd_install.py                    # OpenBSD unattended install + pf.conf
python3 bench/run/vyos_install.py                    # VyOS install + set commands
# 1. runs
python3 bench/run/run_x86.py --stages dataplane,footprint,control
python3 bench/run/diag.py && python3 bench/run/diag.py connlat
python3 bench/run/pi5.py prep-opn && python3 bench/run/pi5_nixos.py
python3 bench/run/pi5.py measure opn 3 && python3 bench/run/pi5.py measure nixr 3
python3 bench/run/summarize.py bench/results bench/results/summary
```

`bench/run/queue_*.sh` are the exact sequences used for this report, including
the reruns listed in 1.4. The Rust prototype source is in `bench/prototype/`.
It was written for this measurement only and is not sensr code.

