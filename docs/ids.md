# Intrusion detection and prevention (Suricata)

sensr runs Suricata from the `ids` section of the configuration (Services ›
Intrusion Detection). The agent renders everything into `/run/sensr/suricata`
and drives four units: `sensr-suricata` (the engine), `sensr-suricata-update`
(rule downloads with `suricata-update`, daily via its timer), and two small
helpers (`-reload`, `-update-trigger`) so an apply never waits for a download.

## What differs from OPNsense, and why

| | OPNsense | sensr |
|---|---|---|
| HOME_NET | a fixed list, RFC 1918 by default | the list **plus every interface's networks and the WAN's current address(es)** (`home_net_auto`, on by default), rewritten when the WAN lease changes |
| IPS | netmap (emulated on the Pi's RP1 NIC) or divert | nftables NFQUEUE in the forward path, **fail-open** (`queue bypass`), flows past the stream depth bypassed in the kernel |
| Connections open when IPS starts | dropped (`stream_midstream`) | picked up (`stream.midstream: true`) |
| Chatty signatures | every STUN packet of a video call alerts | default suppression list (`default_suppressions`) |
| Rule updates | a cron job that may be off (it was on the owner's router: no rule was ever loaded) | downloaded when the rule lists change, then daily; retried every 2 minutes on failure |

### HOME_NET

On the WAN, after NAT, both ends of every outbound flow are public addresses.
With an RFC 1918-only HOME_NET no `$HOME_NET -> $EXTERNAL_NET` rule can match:
on 2026-11-16 the owner's router raised **zero** alerts for 15 probes with
33 k rules loaded (OPNsense) and only the one `any -> any` rule fired with 53 k
rules (VyOS). Adding the WAN /32 made 10 of 15 alert. sensr adds it
automatically and follows lease changes (the agent checks addresses every 2 s
and reloads the rules, without a restart).

In prevent mode the queue sits in the forward path, before source NAT on the
way out and after it is undone on the way back, so Suricata sees the LAN
addresses anyway.

## Modes

- **detect** (default): af-packet capture on `ids.interfaces`, alerts only.
- **prevent**: forwarded packets entering or leaving `ids.interfaces` are
  queued to Suricata (nftables table `inet sensr_ips`, priority 10, after the
  filter, so only traffic the firewall passes is inspected). `drop` rules
  block. With `ips.fail_open` (default) a stopped or restarting engine lets
  traffic through; a memcap or parser exception passes the flow
  (`exception-policy: ignore`). Flows Suricata stops inspecting (after 1 MiB
  of stream, or a `pass`/`bypass` rule) get mark `0x01000000`, which is copied
  to the connection so its later packets skip the queue: bulk downloads cost
  almost nothing after their first megabyte.

## Rules

- `sources`: ET Open (default) and/or URLs (`.rules` files or archives).
- `profile`:
  - `home` (default): a curated ET Open subset (exploits, malware, C2,
    compromised hosts, attack responses, scans, coin miners, DNS, phishing,
    worms, the IP reputation lists). Roughly a third of ET Open.
  - `all`: every file the sources ship.
  - `custom`: exactly `rule_files` (an OPNsense import lands here, with the
    files that were enabled).
- `policies`: change the action of rules by ruleset or by metadata
  (`signature_severity Major`), not both at once.
- `rule_overrides`: per-sid enable/disable and alert/drop.
- `user_rules`: address or TLS-fingerprint rules (OPNsense user-defined rules).

## Suppressions

`default_suppressions` (on) silences signatures a household triggers all day
for no reason: ET INFO STUN binding requests/responses (2016149, 2016150,
2033077, 2033078: about 150 alerts a minute from video calls on the owner's
network), GPL CHAT Jabber, ET INFO Go-http-client, and Suricata's own stream
and app-layer events (2210044, 2210050, 2210054, 2260000, 2260001, 2260003).
The full list with reasons is `DEFAULT_SUPPRESSIONS` in
`crates/sensr-schema/src/models/ids.rs`.

Add your own in `ids.suppressions` (or from an alert in the UI), optionally
limited to a source or destination network. A suppressed rule still runs and
still drops in prevent mode; disable it (`rule_overrides`) to save the CPU.

## Tuning for a Raspberry Pi 5

Measured on the owner's Pi 5 (16 GB) on 2026-11-16, through NAT, with public
iperf3 servers (`itpick/vyos-pi` `docs/comparison/`):

| setup | throughput | CPU | packets missed |
|---|---|---|---|
| no IDS | 590-790 Mbit/s (server-limited) | one core busy with interrupts (core 0) | - |
| IDS, af-packet, 4 workers, 53 k rules (all ET Open) | unchanged | up to 2.2 cores for Suricata, 78 % of the box | **10 %** at ~600 Mbit/s |
| IDS, OPNsense pcap, 1 worker, 33 k rules | unchanged | busiest core 95 % | 13 % |
| IPS, NFQUEUE (VyOS), 53 k rules | **~370 Mbit/s** | 2.7 cores, busiest at 100 % | - |
| IPS, netmap (OPNsense) | ~260 Mbit/s down, ~190 up | 41 % (netmap-limited) | - |

sensr's defaults follow from that:

| setting | default | why |
|---|---|---|
| `profile` | `home` | rule count is the biggest lever: fewer rules, fewer misses |
| `tuning.workers` | CPUs − 1 (3 on a Pi 5), split across the interfaces | leaves CPU 0 to the NIC interrupts |
| `tuning.pin_workers` | on | workers on CPUs 1..n, management on 0 |
| `tuning.ring_size` | 16384 packets per worker (af-packet, tpacket v3, 1 MiB blocks) | absorbs bursts; about 32 MiB per worker |
| `tuning.detect_profile` | `medium` | `high` trades memory for speed; fine with 4 GB or more |
| `tuning.pattern_matcher` | auto (Hyperscan/Vectorscan when built in) | |
| prevent mode | stream bypass after 1 MiB | the IPS cost is per inspected packet: bypassing bulk flows is what keeps throughput up |

To go further: inspect only the LAN interfaces (pre-NAT, no WAN noise),
switch off rule files you do not need (`custom`), or disable rules you have
suppressed. Suricata's counters: `suricatasc -c dump-counters
/run/suricata/suricata-command.socket` (`capture.kernel_drops`, `ips.*`).

## Files and units

| path | what |
|---|---|
| `/run/sensr/suricata/suricata.yaml` | engine config (restart on change) |
| `/run/sensr/suricata/vars.yaml` | HOME_NET (rule reload on change) |
| `/run/sensr/suricata/threshold.config` | suppressions (rule reload) |
| `/run/sensr/suricata/local.rules` | user rules (rule reload) |
| `/run/sensr/suricata/{update.args,enable,disable,drop,modify}.conf` | suricata-update input (download on change) |
| `/run/systemd/system/sensr-suricata-update.timer.d/50-sensr.conf` | update schedule (`ids.updates`) |
| `/var/lib/suricata/rules/` | downloaded rules, one file per ruleset |
| `/var/log/suricata/eve.json` | alerts (and drops, stats) |

The end-to-end VM test is `nix build .#checks.x86_64-linux.ids`
(`nix/tests/ids.nix`).
