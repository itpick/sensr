# 01 — OPNsense feature inventory (master checklist for sensr)

Status: research baseline, 2026-11-15. Sources: OPNsense `docs` (docs/source/manual, manual/how-tos, vendor/, be.rst, plugins.rst, third_party_plugins.rst, troubleshooting/, hardware/, development/), `core` at commit 8b88393 (26.7 series: MVC `Menu.xml`, `ACL.xml`, model XMLs, legacy `src/www/*.php`, `plugins.inc.d`, configd `actions.d`), `plugins` (102 plugin Makefiles + their `Menu.xml`/model XMLs), and `changelog` (community 26.1–26.7.9, business 26.4/26.10).

Nothing in this document is copied from OPNsense source; it describes behaviour and settings so sensr can reimplement them independently.

## 0. How to read this document

### 0.1 Columns

| Column | Meaning |
|---|---|
| **ID** | Stable identifier. Later plan docs reference these; never renumber, only append. Format `AREA-NNN` or `AREA-SUB-NNN`. |
| **Feature** | Name as OPNsense users know it (menu path in parentheses where useful). |
| **Scope / settings** | Sub-features, tabs, and the options that matter. Option lists come from the model XML `OptionValues` where the docs were vague. |
| **OPNsense backs it with** | The FreeBSD or third-party component that does the work. |
| **Tier** | `core` · `plugin` (official community plugin repo, maintained by OPNsense team or contributors; "tier 2/3" per plugin Makefile where set) · `BE` (Business Edition only) · `vendor` (third-party commercial) · `legacy` (still shipped, moving to a plugin or deprecated). |
| **sensr approach** | Linux/NixOS/Rust equivalent that would back the feature. |
| **Class** | `N` native Rust (we write it) · `D` Rust-managed external daemon (we render config, supervise, parse status) · `K` kernel feature driven via netlink/sysfs/ioctl from Rust · `X` out of scope (see §19). Mixed entries are written `N+K` etc. |

### 0.2 Area prefixes

| Prefix | Area | Prefix | Area |
|---|---|---|---|
| `GUI` | Lobby, dashboard, GUI framework | `DNS` | DNS services (Unbound, dnsmasq-DNS, forwarding, blocklists) |
| `SYS-AUTH` | Users, groups, privileges, auth servers | `RA` | Router advertisements |
| `SYS-CFG` | Configuration, backups, wizard | `CP` | Captive portal |
| `SYS-FW` | Firmware, packages, plugins | `IDS` | Intrusion detection/prevention |
| `SYS-GW` | Gateways, gateway groups, multi-WAN | `MON` | Monit |
| `SYS-HA` | CARP/pfsync/XMLRPC HA | `NTP` | Time |
| `SYS-RT` | Static routes | `VPN-IPSEC`, `VPN-OVPN`, `VPN-WG` | VPN |
| `SYS-SET` | Settings (admin, general, misc, tunables, logging, cron) | `RTG` | Dynamic routing (FRR) |
| `SYS-TRUST` | CAs, certificates, CRLs, TLS policy | `REP` | Reporting |
| `SYS-DIAG` | System diagnostics | `PLG-<cat>` | Plugins by repo category |
| `SYS-SNAP` | ZFS snapshots | `BE` | Business Edition |
| `IF` | Interfaces, devices, VIPs, wireless, neighbors | `VND` | Third-party vendor integrations |
| `FW` | Firewall rules, aliases, categories, groups, schedules, settings, normalization, logs, diagnostics | `PLAT` | Installation, images, hardware, cloud, CLI tools, troubleshooting |
| `NAT` | NAT (DNAT, SNAT, 1:1, NPTv6, reflection) | `ARCH` | Architecture concepts to reproduce (configd, config store, models, API, ACL, menus, templates) |
| `SHP` | Traffic shaper | | |
| `DHCP` | DHCP servers and relay | | |

### 0.3 Default sensr backing choices referenced throughout

| OPNsense component | sensr default | Class | Notes |
|---|---|---|---|
| pf (filter, NAT, tables, scrub, states, pflog) | nftables via netlink (`nftnl`/`rustables` crates), conntrack via `nf_conntrack` netlink, logging via `nfnetlink_log` | N+K | Native Rust rule compiler emits one atomic nft ruleset; no `nft` CLI dependency. |
| pfsync | conntrackd (state sync) | D | Rust-managed; later candidate for native conntrack netlink replication. |
| CARP | VRRPv3 in Rust (native) with keepalived as fallback | N (D fallback) | Native VRRP is small; needed for CARP maintenance mode semantics, demotion, unicast peers. |
| ipfw/dummynet | tc (HTB/HFSC/FQ-CoDel/CAKE) via rtnetlink | N+K | Shaper pipes → classes, queues → child classes/qdiscs, rules → nft marks + tc filters. |
| ifconfig/devd/rc network | rtnetlink (`netlink-packet-route`), `wireless-netlink` (nl80211) | N+K | Rust owns interface lifecycle. |
| dhclient / dhcp6c / rtsold | native Rust DHCPv4/DHCPv6/RS clients | N | Required for send/request option fidelity (ISP how-tos). |
| mpd5 (PPPoE/PPP/L2TP/PPTP) | pppd + rp-pppoe kernel mode (D), later native PPPoE in Rust | D→N | Kernel `pppoe`/`pppox`; `pppd` managed by Rust. |
| hostapd / wpa_supplicant | hostapd (D) | D | nl80211 drivers. |
| unbound | unbound (D) first; hickory-dns resolver optional later | D | Blocklists, overrides, DoT, stats parsed natively. |
| dnsmasq | native Rust DNS-forwarder+DHCP (N) or dnsmasq (D) | N (D fallback) | Decision point; see DHCP section. |
| kea-dhcp4/6, kea-dhcp-ddns | native Rust DHCP server (N) | N | Kea config surface is reproduced, not Kea itself. |
| isc-dhcpd | none | X | EOL upstream. |
| dhcrelay | native Rust relay | N | |
| radvd | native Rust RA daemon | N | |
| strongSwan (swanctl/charon) | strongSwan (D) via VICI socket | D | VICI gives connections/SAD/SPD/leases without parsing text. |
| OpenVPN | OpenVPN 2.6 (D) with `ovpn-dco` kernel module | D+K | Management socket for status/kill. |
| WireGuard (wg kmod) | kernel WireGuard via `wireguard-uapi`/netlink | N+K | No external daemon. |
| Suricata | Suricata (D) in AF_PACKET/NFQUEUE/XDP modes | D | NFQUEUE replaces divert-to; AF_PACKET/XDP replaces netmap. |
| Squid / c-icap / ClamAV | Squid, c-icap, ClamAV (D) | D | |
| HAProxy / nginx / Caddy / relayd | HAProxy, nginx, Caddy (D); relayd → HAProxy TCP mode | D | |
| FRR | FRR (D) via vtysh/northbound | D | |
| lighttpd (web GUI) | axum/hyper HTTPS server in Rust | N | |
| configd (Python) + templates (Jinja2) | Rust service broker + typed config renderers | N | See ARCH section. |
| syslog-ng | native Rust log router (journald reader + RFC5424/TLS forwarder) | N | |
| flowd/netflow (samplicate) | native NetFlow v5/v9 + IPFIX exporter from conntrack/AF_PACKET sampling | N | |
| RRD (system health) | native time-series (embedded, e.g. SQLite/own ring files) | N | |
| ZFS boot environments (`bectl`) | NixOS generations (+ ZFS snapshots when root is ZFS) | N+K | Snapshots menu maps to generations + optional zfs snapshot. |
| pkg / opnsense-update | Nix store, `nixos-rebuild`-equivalent orchestrated by Rust | N | Flavours/mirrors → channels/caches. |
| monit | native Rust monitor (process/host/file/resource tests, mail/exec actions) | N | |
| ntpd | chrony (D) | D | Chrony NTS covers plugin os-chrony too; GPS/PPS via chrony refclock. |
| OpenSSL cert manager (PHP) | `rcgen`/`x509-parser`/`rustls-pki` in Rust | N | |

## 1. Interfaces (`IF`)

Sources: interfaces.rst, other-interfaces.rst, interfaces_overview.rst, interfaces_settings.rst, hostwatch.rst, neighbors.rst, firewall_vip.rst, wireless.rst, ipv6.rst, diagnostics_interfaces.rst, how-tos (vlan_and_lagg, lan_bridge, vxlan_bridge, transparent_bridge, interface_wireless_internal, cellular, IPv6 ISP guides, pppoe_isp_setup, guestnet); core `Interfaces/*.xml`, legacy `interfaces.php`, `interfaces_ppps*.php`, `status_wireless.php`.

### 1.1 Assignments and per-interface configuration

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| IF-001 | Interface assignments grid (Interfaces › Assignments) | Assign device → logical interface (`wan`, `lan`, `optN`); add/edit/delete; pending changes queued until global Apply; Description and Lock save immediately; advanced-mode toggle; each device assignable once. | MVC `NetworkInterface` model + `interfaces_configure()` | core (MVC since 26.7) | Rust interface manager with a staged-config model; apply = diff + rtnetlink transaction. | N+K |
| IF-002 | Basic config | Identifier (read-only), Enabled, Lock (prevent deletion), Description. | config.xml `interfaces/<id>` | core | Typed config schema. | N |
| IF-003 | Device config | Device, Promiscuous mode, MAC spoof, MTU (empty = device default), MSS clamp (header size subtracted). | ifconfig | core | rtnetlink link attrs; MSS → nft `tcp option maxseg size set` on that interface. | K+N |
| IF-004 | Hardware settings | Media (speed/duplex), "Overwrite global settings", per-interface disable of CRC/TSO/LRO, VLAN hardware filtering (0/1/2). | ifconfig capability flags | core | ethtool-netlink (`ETHTOOL_MSG_FEATURES_SET`, link modes). | K |
| IF-005 | Generic config | Block private networks (RFC1918, loopback, link-local, CGNAT 100.64/10), Block bogon networks (bogons table updated monthly/weekly/daily). | pf tables + automatic rules | core | nft sets `bogons`, `bogonsv6`, `private`; auto rules in sensr rule compiler; bogon fetcher. | N |
| IF-006 | IPv4 type: none / static / DHCP / PPP-device | Static: address CIDR + gateway rule (generates reply-to and automatic SNAT). DHCP: alias address/subnet, Reject leases from, Hostname, Honour MTU (advanced), VLAN priority (802.1p), Send options, Request options (one per line, dhclient syntax). PPP/PPPoE/PPTP/L2TP via Point-to-Point device. | dhclient, mpd5 | core | Native Rust DHCPv4 client with raw send/request option support (required by ISP how-tos: Orange, SFR, Sky); gateway rule generation in rule compiler. | N |
| IF-007 | IPv6 type: none / static / DHCPv6 / link-local / SLAAC / 6rd / 6to4 / Identity Association / Track Interface (legacy) / PPPoEv6 | DHCPv6: VLAN priority, Prefix delegation size (/48…/64 or none), Request prefix only, Information only, Request DNS, Send prefix hint, Rapid commit, prefix ID, interface ID, prefix IAID, Send/Request options. 6rd: prefix, border relay, IPv4 prefix length, v4 address override. Identity Association / Track: parent interface, Assign prefix ID (hex), Reserved prefix range, interface ID, IAID, Manual configuration. Link-local: no RA processing. SLAAC: RA processed. | dhcp6c, rtsold, kernel accept_rtadv, stf(4) for 6to4/6rd | core (Track = legacy) | Native Rust DHCPv6 client (IA_NA/IA_PD, PD sub-assignment, raw options); kernel `sit` for 6rd/6to4; RA handling via kernel `accept_ra` + Rust RS sender. Track Interface semantics kept as "Identity Association" only. | N+K |
| IF-008 | Dynamic gateway policy | Gateway without next-hop for tunnels/PtP/VPN client interfaces. | gateway handling | core | Gateway model flag; rtnetlink routes with `dev` only. | N |
| IF-009 | Legacy `interfaces.php` page | Still reachable by URL; supports advanced/file-override DHCP modes dropped by MVC dialog; planned to move to plugin in 27.1. | PHP | legacy | Not reproduced; MVC dialog semantics only. | X |
| IF-010 | Interfaces › Overview | Per-interface addresses, status, link, details (extended ifconfig view); DHCP lease reload/release buttons; separate IPv4/IPv6 link types (26.10). | ifconfig, dhclient | core | rtnetlink dump + client state. | N |
| IF-011 | Interfaces › Settings (global) | Disable hardware CRC/TSO/LRO (default checked); VLAN hardware filtering mode; ARP handling (suppress log of ARP movements / wrong-interface); Turn off IPv6 (adds floating block rule); DHCPv6 client: prevent release, log level, explicit DUID (with "insert existing DUID" helper), RA timeout. | sysctl, ifconfig, dhcp6c | core | ethtool-netlink defaults; sysctl `net.ipv6.conf.all.disable_ipv6`; DUID persisted in state dir. | K+N |

### 1.2 Devices (Interfaces › Devices)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| IF-DEV-001 | Bridge | Members; enable link-local; (R)STP: protocol rstp/stp, STP ports, maxage, fwdelay, holdcnt; cache size (maxaddr), cache expire (timeout); span, edge, auto-edge, PTP, auto-PTP, sticky (static), private ports. Filtering tunables `pfil_member`/`pfil_bridge`. | if_bridge(4) | core | Linux bridge via rtnetlink (`IFLA_BR_*`, per-port `IFLA_BRPORT_*`: stp, isolated=private, hairpin, mirror via tc for span). Filtering on bridge via nft `bridge` family or `br_netfilter`. | K+N |
| IF-DEV-002 | GIF (IPv6-in-IPv4 / IPv4-in-IPv6) | Parent, remote address, tunnel local/remote, Disable ingress filtering, ECN friendly, noclamp (26.10), route caching. | gif(4) | core | `sit`/`ip6tnl` tunnels via rtnetlink. | K |
| IF-DEV-003 | GRE | Parent, remote, tunnel local/remote addresses. Multicast with igmpproxy/pimd. | gre(4) | core | `gre`/`ip6gre` via rtnetlink. | K |
| IF-DEV-004 | LAGG | Members, primary member, proto none/lacp/failover/fec/loadbalance/roundrobin, LACP fast timeout, use flowid, hash layers l2/l3/l4, LACP strict, MTU. Members must be unassigned. | lagg(4) | core | Linux `bond` (802.3ad, active-backup, balance-xor, balance-rr) via rtnetlink; `fec` → balance-xor. | K |
| IF-DEV-005 | Loopback | Numbered `loN`, description. Used for service binding, router IDs, NAT64 DNS tricks. | lo(4) | core | `dummy` interfaces via rtnetlink. | K |
| IF-DEV-006 | TAP | Auto-named `tapNN`, description; bridge to LAN for VMs. | tap(4) | core | `tuntap` via rtnetlink/ioctl. | K |
| IF-DEV-007 | VLAN / QinQ | Device name (`vlanX.Y` or `qinq…`), parent, tag 1–4094, PCP priority, description; QinQ by stacking. Parent may stay unassigned. | vlan(4), 802.1ad | core | `vlan` link (802.1Q/802.1ad) with egress-qos-map for PCP. | K |
| IF-DEV-008 | VXLAN | VNI, local source (must be existing static address), local/remote port, remote address (P2P) or multicast group + device. | vxlan(4) | core | `vxlan` link via rtnetlink. | K |
| IF-DEV-009 | Point-to-Point: PPP (modem) | Link interfaces (multi-link), service provider picker (country/provider/plan DB), username/password, phone number, APN, APN number, SIM PIN, PIN wait, init string, connection timeout, uptime logging, dial on demand, idle timeout, VJ compression, TCPmssFix, ShortSeq, ACFComp, ProtoComp. | mpd5, u3g(4), cuaU* | core (legacy PHP page) | `pppd` + ModemManager-free AT chat in Rust (or `chat`); serial via `/dev/ttyUSB*`; provider DB copied from mobile-broadband-provider-info (GPL data, separate). | D+N |
| IF-DEV-010 | Point-to-Point: PPPoE | Parent (single), username, password, service name, Host-Uniq; inherits PPP advanced options; RFC4638 MTU 1508 tip; PPPoEv6 type. | mpd5 | core (legacy page) | Kernel `pppoe` (rp-pppoe plugin for pppd) managed by Rust; LCP log surfaced. | D+K |
| IF-DEV-011 | Point-to-Point: PPTP / L2TP (client) | Link interface, username/password, server; inherits PPP options. | mpd5 | core (legacy) | L2TP via `xl2tpd`/kernel l2tp (D); PPTP via `pptp-linux` (D). Low priority (insecure). | D |
| IF-DEV-012 | Wireless devices (Interfaces › Wireless › Devices) | Clone per physical radio: mode bss/adhoc/hostap; standard (auto, 11a/b/g/n/ac…); pure g/n; protection mode off/cts/rtscts; txpower; channel; diversity; tx/rx antenna; regdomain/country/location; SSID; WME; hide SSID; WEP keys; WPA: auth algs, WPA mode 1/2/3, key mgmt PSK/EAP, EAP method PEAP/TLS/TTLS, phase2 MD5/MSCHAPv2, CA/client cert, pairwise CCMP/TKIP, group/GMK rekey, identity, passphrase, strict rekey, IEEE802.1X; RADIUS primary/secondary server/port/secret; AP bridge; RSN preauth. Status page `status_wireless.php` (scan). "Results may vary", no 802.11ac. | wlan(4), hostapd, wpa_supplicant | core (MVC since 26.7.4) | hostapd (AP) / wpa_supplicant (BSS) managed by Rust; nl80211 for scan/regdomain; 802.11ax possible on Linux. | D+K |

### 1.3 Virtual IPs (Interfaces › Virtual IPs)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| IF-VIP-001 | IP Alias | Extra address on interface; answers ARP/ping; may join a CARP VHID; Type Network/Single (NAT expansion); gateway (ppp/tun); disable expansion; deny service binding; nosync. | ifconfig alias | core | rtnetlink address add with `IFA_F_*` flags; "deny service binding" is a sensr-side flag for listeners. | K+N |
| IF-VIP-002 | CARP VIP | VHID 1–255 (unassigned-VHID picker), password, advbase/advskew, peer IPv4/IPv6 (unicast, 24.7+), virtual MAC `00:00:5e:00:01:XX`, multicast 224.0.0.18/ff02::12; hash of address set shared with IP aliases on same VHID. | carp(4) | core | Native Rust VRRPv3 (RFC 5798) daemon: multicast/unicast, skew→priority mapping, virtual MAC via macvlan; one VRRP router per VHID with the alias set as its VIPs. | N+K |
| IF-VIP-003 | Proxy ARP | Answer ARP for addresses without binding them. | choparp | core | Native Rust proxy-ARP responder (AF_PACKET) or kernel `proxy_arp` + static neighbor `pub` entries via rtnetlink. | N/K |
| IF-VIP-004 | VIP status page | VHID state INIT/BACKUP/MASTER/DISABLED, "Temporarily disable CARP", persistent "Enter maintenance mode" (survives reboot), pfsync nodes. | carp, sysctl demotion | core | VRRP daemon status API; maintenance = priority demotion persisted in state. | N |
| IF-VIP-005 | CARP demotion controls | `net.inet.carp.senderr_demotion_factor`, demotion reset, preempt (in HA settings), `net.inet.carp.log`. | sysctl | core | VRRP daemon tracking scripts / interface-error demotion; log level knob. | N |

### 1.4 Hostwatch, neighbors, diagnostics

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| IF-HW-001 | Hostwatch settings | Enable, interfaces (Ethernet only), promiscuous, verbose, IPv4/IPv6 expire (≥3600 s), ignore networks. | hostwatch daemon (ARP/NDP sniffer) | core | Native Rust AF_PACKET sniffer for ARP/ND + persistent neighbor DB (sled/SQLite). | N |
| IF-HW-002 | Hostwatch hosts view | Last seen, hostname (rDNS), state/traffic statistics (from pf states), fallback to kernel ARP/NDP tables, sorted by last_seen. | hostwatch + pf | core | Join neighbor DB with conntrack stats. | N |
| IF-HW-003 | Hostwatch consumers | Captive portal IPv6 collection, MAC aliases → IP resolution, Kea PD route installation (link-local lookup). | internal API | core | Internal event bus topic `neighbor.{new,moved,expired}`. | N |
| IF-HW-004 | Hostwatch log | New station / movement events (flapping = conflict). | syslog | core | journald structured events. | N |
| IF-NB-001 | Neighbors (static ARP/NDP) | MAC, IP, description; read-only entries from DHCP origin. | arp(8)/ndp(8) | core | rtnetlink `RTM_NEWNEIGH` permanent entries. | K |
| IF-DIAG-001 | ARP table | IP, MAC, OUI manufacturer, interface, hostname (from DHCP leases). | arp | core | rtnetlink neigh dump + OUI DB. | N |
| IF-DIAG-002 | NDP table | IPv6, MAC, manufacturer, interface. | ndp | core | rtnetlink neigh dump (AF_INET6). | N |
| IF-DIAG-003 | DNS lookup | Forward/reverse lookups via system resolvers. | drill/host | core | hickory-resolver. | N |
| IF-DIAG-004 | Netstat | Tabs Interfaces, Protocol, Sockets, Netisr, Memory (mbuf), Bpf. | netstat/sockstat | core | `/proc/net/*`, sock_diag netlink; Netisr/mbuf tabs replaced by softnet_stat / slab info. | N |
| IF-DIAG-005 | Packet capture | Multi-interface (one capture per interface), promiscuous, family any/ip/ip6/arp, invert protocol, protocol, host expression (not/MAC/CIDR), invert port, port, snaplen, count, description; background jobs; stop/restart/remove; download zip (pcap + options JSON); view at 3 detail levels while running. | tcpdump | core | Native `pcap`/AF_PACKET capture with BPF compiled from a small expression grammar; pcapng writer; decoded view via `pnet`/`etherparse`. | N |
| IF-DIAG-006 | Ping | Host, family, source address, payload size, do-not-fragment, description; background jobs; result fields send/received/min/max/avg/loss/last_error. | ping | core | `surge-ping` or raw ICMP sockets. | N |
| IF-DIAG-007 | Port probe | TCP connect test to host:port with source. | nc | core | tokio TCP connect. | N |
| IF-DIAG-008 | Traceroute | Host, family, protocol UDP/ICMP, source; results include ASN. | traceroute | core | Native UDP/ICMP traceroute; ASN via Team Cymru DNS or local MaxMind/IPinfo ASN DB. | N |

### 1.5 Interface setup patterns from how-tos (behaviours sensr must support)

| ID | Pattern | Requirements it implies |
|---|---|---|
| IF-PAT-001 | VLAN trunk + LACP to managed switch | Unassigned parent allowed; sacrificial native VLAN; parent assignable without IP for speed override. |
| IF-PAT-002 | LAN bridge of spare NICs | Members set to none/none; bridge filtering mode tunables; link-local toggle. |
| IF-PAT-003 | VXLAN L2 extension over IPsec/WireGuard between loopbacks | Loopback /32s, VXLAN without IP, bridge with LAN, MTU/MSS tuning. |
| IF-PAT-004 | Transparent filtering bridge + IPS | Unnumbered bridge, management port, IPS on physical member not bridge; incompatible with shaper. |
| IF-PAT-005 | Internal Wi-Fi AP with 802.1X via FreeRADIUS | hostapd EAP → RADIUS at localhost. |
| IF-PAT-006 | Cellular PPP WAN | AT port discovery, PIN handling, APN, provider DB. |
| IF-PAT-007 | ISP-specific DHCP option spoofing (Orange FR, SFR/RED, Sky UK, Zen, DT, Fritz!Box) | dhcp-class-identifier, user-class, option-90/option-125 hex, client-id, request-option lists, DUID `00:03:00:01:MAC`, VLAN PCP 6 on DHCP/DHCPv6, DHCPv6 raw-options 6/15/16/11, IAID control, "Request prefix only", "Send prefix hint", Prevent release. |
| IF-PAT-008 | HE.net tunnelbroker | GIF + static /64s + RA assisted + ddclient `he-net-tunnel`. |
| IF-PAT-009 | IPTV multicast (DT Magenta, Orange TV) | igmpproxy upstream/downstream, "allow options" on rules, dummy IP on second VLAN. |
| IF-PAT-010 | PPPoE on ISP VLAN | VLAN unassigned under PPPoE device; LCP log view. |
| IF-PAT-011 | Guest network | OPT interface + DHCP + isolation rules + captive portal + shaper + vouchers. |

## 2. Firewall (`FW`)

Sources: firewall_generic.rst, aliases.rst, firewall_categories.rst, firewall_groups.rst, firewall.rst, firewall_settings.rst, firewall_scrub.rst, logging_firewall.rst, diagnostics_firewall.rst, how-tos (carp, fwcategory, drop, security-zones); core `Firewall/Filter.xml`, `Alias.xml`, `Category.xml`, `Group.xml`, `firewall_schedule*.php`, `firewall_rule_lookup.php`.

### 2.1 Rules

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| FW-001 | Stateful rule engine model | Actions pass/block (silent)/reject (TCP RST, ICMP unreachable)/match; `quick` first-match vs last-match; default deny; NAT before filter; processing order: system → floating (prio 200000) → interface groups (300000) → interface (400000) → system tail; sort order `prio.sequence`; direction in/out/any; rule types derived (single interface = interface rule, group, multi/inverted = floating). | pf | core | Rust rule compiler producing an nftables ruleset: one `inet filter` table with chains per interface/direction; `quick` → `accept/drop` terminal verdicts, non-quick → mark-and-continue with final verdict chain; policy state via conntrack `ct state`. | N+K |
| FW-002 | Firewall Rules (MVC, Firewall › Rules) | Interface filter (floating/group/single; LAN view shows all affecting rules), category multi-filter (pre-fills new rules), tree view by category, Inspect (automatic rules + cached statistics, search IPs inside aliases), move/edit/copy/delete, "Move rule before this rule", API. | MVC `Filter.xml` | core | Same UI semantics; stats from nft counters per rule (`counter` + comment = rule UUID). | N |
| FW-003 | Rule – Organisation tab | Enabled, sort order, sequence (non-unique allowed), categories, No XMLRPC sync, description. | | core | Config schema. | N |
| FW-004 | Rule – Interface tab | Invert interface, interface(s)/groups, Invert origin, Interface (origin = where packet first received; for out-direction and zone rules). | pf `received-on` | core | nft `iifname`/`meta iifname` for origin on output chain. | N |
| FW-005 | Rule – Filter tab | Quick, action, Allow options (IPv4 options / IPv6 routing headers), direction, version inet/inet6/inet46, protocol (full list), ICMP type (common/deprecated), ICMPv6 type list, invert source, source (alias/host/net/any/This Firewall/[if] net/[if] address/VIPs), source port, invert destination, destination, destination port, log, TCP flags set/out-of, TCP flags any, schedule, divert-to. | pf | core | nft match expressions; "This Firewall" → dynamic set of local addresses; `[if] net` → set maintained from rtnetlink; divert-to → NFQUEUE num. | N |
| FW-006 | Rule – Stateful tab | State type keep/sloppy/modulate/synproxy/none; state policy if-bound/floating; NO pfsync; TCP established timeout; UDP first/single/multiple timeouts; adaptive start/end; max states; max src nodes; max src states; max src conn; max new conn rate (count/seconds); overload table (default `virusprot` + floating block rule). | pf state options | core | conntrack zones/timeouts via `ct timeout` objects; sloppy ≈ `ct state` loose (`nf_conntrack_tcp_loose`); synproxy via nft `synproxy`; conn limits via nft `ct count`/`meter`/`limit rate`; overload → add to nft set with timeout. | N+K |
| FW-007 | Rule – Rate limiting | Max packet rate (packets/seconds). | pf `max-pkt-rate` | core | nft `limit rate … over` per rule. | N |
| FW-008 | Rule – Traffic shaping [experimental] | Shaper pipe/queue for direction and reverse. | ipfw/dummynet via pf tags | core | nft `meta mark set` → tc filter on class. | N+K |
| FW-009 | Rule – Source routing | Gateway (policy routing to gateway or group), Disable reply-to, Reply-to (default/specific gateway). | pf route-to/reply-to | core | nft fwmark → policy routing tables (`ip rule fwmark`), one table per gateway/group; reply-to via conntrack mark saved on state and `ip rule` for replies. | N+K |
| FW-010 | Rule – Priority tab | Match priority (802.1p PCP 0–7), set priority, set priority low-delay, match TOS/DSCP, scrub set TOS. | pf prio/set prio, vlan PCP | core | nft `vlan pcp` match/set, `ip dscp` match/set. | N |
| FW-011 | Rule – Internal tagging | Set local tag (sticky, one at a time), Match local tag. | pf tag/tagged | core | nft `meta mark`/`ct mark` bitfield reserved for tags. | N |
| FW-012 | Rule – Audit | Created/updated user, time, description, note. | JsonAudit | core | Config change audit trail. | N |
| FW-013 | Legacy Firewall Rules pages (`os-firewall-legacy`) | Static PHP rule pages + legacy Outbound NAT page; Source OS (pf.os fingerprint), multiple sources/destinations per rule, eye-button stats; migration assistant to MVC. | PHP | legacy plugin (26.7) | Not reproduced; migration importer from OPNsense config.xml can translate legacy rule XML into sensr rules. | X (importer N) |
| FW-014 | Automatic rules | Anti-lockout (GUI/SSH on LAN), SSH lockout table, virusprot overload, bogons/private blocks, DHCP/DHCPv6/RFC4890 ICMPv6, port 0 block, CARP, IPsec, OpenVPN, captive portal, dnsmasq/kea `fwrules`, static route filtering, force-gateway floating rule; visible via Inspect. | pf.inc | core | Rule compiler "system rules" stage, each toggleable per Firewall Settings. | N |
| FW-015 | Schedules (Firewall › Schedules) | Named schedules: month/day/weekday/time ranges; attach to rule; "Schedule states" setting keeps/kills states on expiry. | PHP `firewall_schedule*.php` + cron re-evaluation | core (legacy PHP) | Native scheduler toggles rule membership in nft sets (`meta time`/`meta hour`/`meta day` where possible, else timer). | N |
| FW-016 | Rule lookup (`firewall_rule_lookup.php`) | Jump from log `rid` to rule. | PHP | core | Rule UUID in nft comment ↔ log. | N |
| FW-017 | Floating/group/interface rule semantics in multi-WAN | Group rules on WAN-type interfaces skip reply-to. | pf | core | Compiler rule. | N |

### 2.2 Aliases (Firewall › Aliases)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| FW-AL-001 | Alias grid | Search, filter by type/category, internal aliases shown, Loaded#/Last updated, table-usage bar, export/import JSON, flush, statistics toggle (`counters`), categories, description. | pf tables | core | nft named sets (`type ipv4_addr/ipv6_addr flags interval`), per-set counters via `counter` in rules; usage bar from `nf_tables` set size. | N+K |
| FW-AL-002 | Type Hosts | IPs, ranges `a-b`, FQDNs (re-resolved every 300 s default), `!` exclusions. | pf table + resolver | core | Rust resolver loop updating sets atomically. | N |
| FW-AL-003 | Type Networks | CIDR, `!` exclusions, wildcard masks. | pf | core | nft interval sets (wildcard masks need expansion). | N |
| FW-AL-004 | Type Ports | Ports and ranges; part of rule, not a table. | pf | core | nft `inet_service` sets. | N |
| FW-AL-005 | Type MAC addresses | Full or partial (OUI) MAC; resolved to IPs via hostwatch/ARP/NDP periodically. | hostwatch | core | Neighbor DB → set refresh. | N |
| FW-AL-006 | Type URL (IPs) | Fetch once; auth type Basic/Bearer/Header with username/password; cert check toggle. | fetch + jq | core | reqwest fetcher. | N |
| FW-AL-007 | Type URL Table (IPs) | Refresh frequency (days/hours), same auth; file format one IP/line, comment prefixes. | fetch | core | Same. | N |
| FW-AL-008 | Type URL Table in JSON format | jq-style path expression (e.g. `cidr`, `.prefixes[].ip_prefix`). | jq | core | `jaq` crate (jq in Rust). | N |
| FW-AL-009 | Type GeoIP | Countries/regions, toggle-all per region; source URL in GeoIP settings tab (IPinfo gz CSV or MaxMind zip); BE auto-downloads from OPNsense mirrors; raise max table entries. | GeoIP CSV import | core (auto-DB = BE) | Native CSV/MMDB importer; interval sets per country. | N |
| FW-AL-010 | Type Network group | Combines network aliases, with exclusions. | pf | core | Set union at compile time. | N |
| FW-AL-011 | Type Dynamic IPv6 Host | `::suffix` + interface prefix; updates on prefix change; multiple suffixes. | rc scripts | core | Prefix-change event → set update. | N |
| FW-AL-012 | Type BGP ASN | ASN → prefixes. | RIPE/whois fetch | core | Fetch from RIPEstat/bgpview API. | N |
| FW-AL-013 | Type OpenVPN group (authgroup) | Group → tunnel IPs of logged-in users; CN must equal username. | OpenVPN status | core | OpenVPN management socket events → set. | N |
| FW-AL-014 | Type Internal (automatic) | `__`-prefixed, e.g. interface nets, captive portal zones. | pf.inc | core | Compiler-owned sets. | N |
| FW-AL-015 | Type External (advanced) | Placeholder filled via API/plugins/pfctl; non-persistent across reboot. | pfctl | core | Writable set via API; optional persist flag (improvement). | N |
| FW-AL-016 | Alias nesting and exclusions | Host/network aliases contain aliases; negation inside alias or group. | pf table negation | core | Compile-time flattening with exclusion diff (nft has no negated set elements). | N |
| FW-AL-017 | Alias util API | `alias_util add/delete/flush/list`, find references, quick add/delete in Diagnostics › Aliases. | API | core | REST endpoints. | N |
| FW-AL-018 | Spamhaus DROP recipe | JSON URL table aliases + block rules (how-to drop.rst). | | core | Documented recipe. | N |

### 2.3 Categories, groups, zones

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| FW-CAT-001 | Categories | Name, color, automatic (auto-delete when unused); multi-select on rules/aliases/NAT; filter across pages. | config | core | Tags in config schema. | N |
| FW-GRP-001 | Interface groups (Firewall › Groups) | Name (OS naming limits), members, "no GUI groups", sequence, description; group rules processed before interface rules; automatic `<GROUP> net` alias. | pf interface groups | core | Logical group → list of ifnames in nft `iifname` set; auto sets. | N |
| FW-ZONE-001 | Security zones pattern | Zone groups (Trust/Untrust/DMZ/Guest/Wifi); network-dependent model (multi-value src/dst `ZONE net`) vs network-independent (state none inbound + outbound rules with Interface (origin) + final reject with inverted origin). | pf | core | Supported by FW-004/FW-006. | N |

### 2.4 Settings (Firewall › Settings › Advanced) and normalization

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| FW-SET-001 | NAT reflection options | Reflection for DNAT (port forwards), reflection for 1:1, automatic SNAT for reflection (hairpin). Discouraged; manual rules advised. | pf rdr/nat | core | Compiler option generating hairpin rules in nft `prerouting`/`postrouting`. | N |
| FW-SET-002 | Bogon update frequency | monthly/weekly/daily. | cron | core | Scheduler job. | N |
| FW-SET-003 | Gateway monitoring: skip rules when gateway down | Instead of default gateway fallback. | pf.inc | core | Compiler flag. | N |
| FW-SET-004 | Multi-WAN options | Sticky connections (+ source tracking timeout), shared forwarding (`pf_share_forward`), disable force gateway. | pf | core | Sticky → conntrack-based source map (nft `ct mark`), per-source hash in `numgen`/`jhash`; force-gateway → output policy routing. | N+K |
| FW-SET-005 | Schedule states | Keep states on schedule expiry. | pf | core | Scheduler option. | N |
| FW-SET-006 | Logging defaults | Log default block, default pass, automatic SNAT, bogons, private networks; debug level none/urgent/misc/loud. | pflog | core | `log group N` in nft + nfnetlink_log reader. | N |
| FW-SET-007 | Miscellaneous | Optimization normal/high-latency/aggressive/conservative; bind states to interface (state_policy); disable firewall (also NAT); adaptive timeouts start/end; max states; max fragments; max table entries; static route filtering (bypass same-interface); disable reply-to; disable anti-lockout; aliases resolve interval; check cert of alias URLs; keep counters on reload; no SSH lockout; no virusprot; no RFC4890 ICMPv6 rules; no port-0 block; disable IPv6 handling. | pf.conf `set …`, sysctl | core | conntrack sysctls (`nf_conntrack_max`, timeouts, `nf_conntrack_tcp_be_liberal`), nft set size limits, fragment settings via `ipfrag_*`. | K+N |
| FW-SET-008 | Anti-DDoS syncookies | never/always/adaptive (start/end % of state table). | pf syncookies | core | nft `synproxy` global chain or `tcp_syncookies` + `synproxy` with conntrack threshold watcher. | N+K |
| FW-SCRUB-001 | Normalization defaults | All interfaces scrub `fragment reassemble`; `max-mss` from interface MSS; "Disable interface scrub"; scrub no-DF, random-id. | pf scrub | core | Linux always reassembles for conntrack; MSS clamp via nft; DF clear via nft `ip frag-off set`; random id n/a (Linux randomises). | N+K |
| FW-SCRUB-002 | Custom normalization rules | Same matching as filter; options max mss, TOS/DSCP, min TTL, do-not-fragment, random ID; first match wins; user rules before interface defaults. | pf scrub | core | nft `mangle` chain: `tcp option maxseg size set`, `ip dscp set`, `ip ttl set`. | N |

### 2.5 Firewall logs and diagnostics

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| FW-LOG-001 | Live view | Realtime stream; filter builder (field/operator contains/is/is not/does not contain, AND/OR), `host`/`port` match both directions, info button, `rid` → rule link, labels. | pflog → filterlog → `filter.log`, websocket-ish streaming | core | nfnetlink_log reader → structured JSON log; SSE stream to GUI. | N |
| FW-LOG-002 | Plain view | Raw filter log. | file | core | Journal query. | N |
| FW-LOG-003 | Overview | Distribution charts over last 5000 lines. | PHP | core | Aggregation endpoint. | N |
| FW-LOG-004 | Logging semantics | First packet of flow only; label mapping by sequence may be stale after reload. | pf | core | Log only on `ct state new` for pass rules; rule UUID carried in log prefix avoids stale mapping. | N |
| FW-DIAG-001 | Aliases / pfTable diagnostics | Alias contents, per-alias statistics, quick add/delete (non-persistent), find references (containment). | pfctl -t | core | nft set dump API. | N |
| FW-DIAG-002 | Sessions (pftop) | Dir, proto, source, gateway/NAT, destination, state, age, expires, pkts, bytes, rule. | pftop | core | conntrack dump with accounting (`nf_conntrack_acct=1`). | N+K |
| FW-DIAG-003 | States | Search, kill matching, kill by rule (from Inspect), reset state table, reset source tracking; columns id, interface, dir, proto, source, NAT, destination, state, rule. TCP states per RFC 793; UDP NO_TRAFFIC/SINGLE/MULTIPLE. | pfctl -s state / -k | core | conntrack netlink dump/delete; state names mapped. | N+K |
| FW-DIAG-004 | Statistics (pfctl -si) | Per-interface counters, memory limits, timeouts, active rules. | pfctl | core | `nf_conntrack` stats, nft counters, `/proc/net/stat/nf_conntrack`. | N |

## 3. NAT (`NAT`)

Sources: nat.rst, how-tos nat_reflection.rst, firewall_settings.rst; core `Filter.xml` (snatrules, npt, onetoone), `DNat.xml`.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| NAT-001 | Destination NAT / Port forward (Firewall › NAT › Destination NAT) | Disabled, sequence, categories, description; interface(s), version inet/inet6/inet46, protocol; invert source, source address/port; invert destination, destination address/port; redirect target IP/port (ranges), pool options round-robin/sticky/random/source-hash/bitmask; No XMLRPC sync; NAT reflection per rule (default/enable/disable → purenat/disable); set tag/match tag; Firewall rule mode Manual / Pass (hidden auto rule, bypasses other rules) / Register rule (linked, read-only); `nordr` (no redirect) rule; transparent-proxy redirect to 127.0.0.1. | pf rdr | core | nft `prerouting dnat to` with `numgen`/`jhash`/`symhash` for pool modes; linked filter rule generated into forward chain. | N |
| NAT-002 | One-to-One (BINAT / NAT) | Type binat (bidirectional, equal size) or nat (unequal allowed); interface; external network; invert source; source; invert destination; destination; log; NAT reflection mode. Used for "NAT before IPsec". | pf binat/nat | core | nft `prerouting dnat`+`postrouting snat` pair with prefix mapping (`ip saddr map`/`dnat to ip daddr & mask \| prefix`). | N |
| NAT-003 | Source NAT / Outbound (modes) | Automatic (default: per WAN-with-gateway interface, LAN nets → interface address), Hybrid (manual first then automatic), Manual, Disabled (e.g. transparent bridge). Migration from legacy "Outbound NAT" page (moved to legacy plugin 26.7.5). | pf nat | core | Compiler stage; automatic rules derived from gateway interfaces. | N |
| NAT-004 | Source NAT rule | Enable, sequence, categories, no XMLRPC sync, description; interface, version, protocol; invert source/address/port; invert destination/address/port; translate source IP (interface address/VIP/alias/network), translate port, pool options + source-hash key, static-port, endpoint-independent (UDP full-cone); Do-not-NAT (`nonat`), log, set/match tag. | pf nat | core | nft `postrouting snat to … persistent/random/fully-random`; static-port → omit port randomisation; endpoint-independent → `nf_nat` `fully-random` + `ct helper` tuning (Linux ≥5.x `snat … persistent`); exceptions via `accept` early in chain. | N+K |
| NAT-005 | NPTv6 | Enable, log, sequence, interface, internal prefix, external prefix (empty = from tracking interface), track interface, categories, description. | pf binat (IPv6 prefix) | core | nft `snat/dnat prefix to` (nft ≥1.0 prefix translation) or netmap. | N |
| NAT-006 | NAT reflection & hairpin | Reflection (rdr on internal interfaces) vs hairpin (rdr + nat); three documented methods; "Register rule" placement (interface tab vs floating); VPN case needs reply-to rule; IPsec VTI NAT needs filtertunnel tunables. | pf | core | Compiler generates per-method rules; documented best practice (method 1) default. | N |
| NAT-007 | Legacy Outbound NAT page | PHP page in `os-firewall-legacy`; migration assistant to Source NAT. | PHP | legacy | Importer only. | X |
| NAT-008 | NAT diagnostics | `pfctl -s nat`, `/tmp/rules.debug`, live view labels NAT/RDR, sessions NAT column. | pfctl | core | nft ruleset dump endpoint + "generated ruleset" viewer. | N |

## 4. Traffic shaper (`SHP`)

Sources: shaping.rst, how-tos shaper*.rst; core `TrafficShaper.xml`.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SHP-001 | Pipes | Number, enabled, bandwidth + metric bit/Kbit/Mbit/Gbit, queue size, mask none/src-ip/dst-ip/src-ip6/dst-ip6 (dynamic per-host pipes), buckets, scheduler fifo/wfq(rr)/qfq/fq_codel/fq_pie (control-plane doc also lists DRR), CoDel enable/target/interval/ECN, PIE, FQ-CoDel quantum/limit/flows, delay (ms), description. | dummynet pipes | core | tc: pipe → HTB/HFSC class with rate; mask → `flow` filters / per-host via `cake` `dual-srchost/dsthost` or `drr`+`flow` classifier; fq_codel/fq_pie/codel/pie qdiscs; delay → `netem`. | N+K |
| SHP-002 | Queues | Number, enabled, pipe, weight 1–100 (WF2Q+ share), mask, buckets, CoDel options, PIE, description. | dummynet queues | core | Child classes with `quantum`/weights under HTB/HFSC or `qfq` classes. | N+K |
| SHP-003 | Rules | Enabled, sequence, interface, interface2 (advanced, two-interface rules), proto ip/ip4/ip6/udp/tcp/tcp_ack/tcp_ack_not/icmp/ipv6-icmp/igmp/esp/ah/gre, iplen, source/not, src port, destination/not, dst port, DSCP list, direction in/out/both, target pipe or queue, description. | ipfw rules | core | nft `mangle` marks + tc `fw` filters; tcp_ack → nft `tcp flags`; iplen → `ip length`. | N+K |
| SHP-004 | Status page | Per pipe/queue/rule traffic since restart, show active flows, show rules counters. | ipfw show / dummynet show | core | tc `-s class/qdisc` stats via rtnetlink. | N |
| SHP-005 | Integration | Firewall rule → pipe/queue (direction and reverse), captive portal bandwidth, CARP; tunable `kern.hz ≥ 1000` advice. | pf tags → ipfw | core | nft mark from FW-008. | N |
| SHP-PAT-001 | Recipes | Dedicated VoIP bandwidth; share evenly (masked queues weight 100); per-user limit (masked pipes); weighted prioritisation (SMTP 9 vs HTTP 1); guest network two-interface rules; bufferbloat (FQ-CoDel tuning: 85% rate, quantum=MTU, limit ~1000, ECN off <4 Mbit); control-plane reserve (WFQ pipe, 1% ≥1 Mbit, ICMPv6/BGP/PIM queues before catch-all). | | core | CAKE is a strong default for bufferbloat recipe; HFSC for dedicated/weighted. | N+K |

## 5. DHCP and relay (`DHCP`)

Sources: dhcp.rst, dhcrelay.rst, dnsmasq.rst, isc.rst, kea.rst; core `Kea/*.xml`, `Dnsmasq/Dnsmasq.xml`, `DHCRelay/DHCRelay.xml`; plugin `net/isc-dhcp`.

OPNsense ships three servers (Dnsmasq default for <1000 clients, Kea for scale/HA/API, ISC as EOL plugin) plus dhcrelay. sensr decision: one native Rust DHCPv4/DHCPv6 server that exposes the union of the Dnsmasq and Kea configuration surfaces (ranges/tags/boot/options from Dnsmasq; subnets/shared-networks/client-classes/HA/DDNS from Kea), plus native DNS registration into the resolver (the main thing Kea lacks).

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| DHCP-001 | DHCP server choice / comparison | Dnsmasq (default v4/v6/RA), Kea, ISC (EOL), DHCRelay; reservations inside pool (dnsmasq) vs outside pool (ISC/Kea); strict interface binding to co-exist with relay. | — | core | Single server; "profiles" instead of daemons. | N |
| DHCP-RELAY-001 | DHCRelay | Destinations (name, server list all-v4 or all-v6); relays: enabled, interface (Ethernet with MAC), destination, Agent information (circuit-id, remote-id), CARP depend-on VHID; log file. | ISC dhcrelay/dhcrelay6 | core | Native Rust DHCPv4/DHCPv6 relay with Option 82 / RFC 6221 relay options. | N |
| DHCP-DM-001 | Dnsmasq DHCP – General/DHCP tab | Enable; interfaces (auto firewall rules); strict interface binding; Interface [no dhcp]; DHCP fqdn; default domain; max leases; authoritative; reply delay (HA); register firewall rules; Router Advertisements global switch; disable HA sync; log DHCP options/tags; quiet log; host ping before offer. | dnsmasq | core | Native server options. | N |
| DHCP-DM-002 | Dnsmasq – Hosts (reservations + host overrides) | Host (wildcard `*`), domain, local (authoritative), IPs (dual-stack, best match by interface subnet), alias records, CNAMEs, client identifier/DUID (`*` ignore), hardware addresses (multiple), lease time (0 infinite), tag [set], ignore, description, comments. One entry = DNS override + static reservation. | dnsmasq `dhcp-host`/`host-record` | core | Unified "host" object feeding DHCP reservations and resolver local-data. | N |
| DHCP-DM-003 | Dnsmasq – DHCP ranges | Interface, tag [set], start/end address, subnet mask (relay case), constructor (IPv6 partial range from interface prefix, `::` for RA only), prefix length, RA mode multi (ra-only, slaac, ra-names, ra-stateless, ra-advrouter, off-link), RA priority high/low, RA MTU/interval/router lifetime, mode `static` (no dynamic), lease time, domain type interface/range, domain, disable HA sync, description. | dnsmasq `dhcp-range` | core | Range object; RA integration with RA-001. | N |
| DHCP-DM-004 | Dnsmasq – DHCP options | Type set/match, option (v4 list), option6 (v6 list), interface tag, tag, tag [set], value (`0.0.0.0`/`[::]` = this host; CSV), force, description. Default sent: 3,6,15,81. Vendor-encapsulated options supported. | dnsmasq `dhcp-option` | core | Option table with tag-based client classes. | N |
| DHCP-DM-005 | Dnsmasq – DHCP boot (PXE) | Interface, tag, filename, servername, server address; client-arch[93] matching recipe (undionly.kpxe / snponly.efi). | dnsmasq `dhcp-boot` | core | Boot options (66/67, option 93 class match). | N |
| DHCP-DM-006 | Dnsmasq – DHCP tags | Named tags; interfaces set tags automatically. | dnsmasq tags | core | Client classes. | N |
| DHCP-DM-007 | Dnsmasq – Leases view | Active leases; ISC/Kea legacy registration tab (register ISC leases, domain override, static mappings, prefer DHCP for PTR). | dnsmasq leases file | core | Lease DB API. | N |
| DHCP-DM-008 | Dnsmasq – HA pattern | Split pools + reply delay on backup; no lease sync; RA priority high/low. | dnsmasq | core | Also offer Kea-style lease sync (DHCP-KEA-009). | N |
| DHCP-DM-009 | Dnsmasq – custom conf.d | `/usr/local/etc/dnsmasq.conf.d/*.conf`. | dnsmasq | core | Raw-option escape hatch limited to native server knobs. | X |
| DHCP-KEA-001 | Kea – Control Agent | Enabled, bind address, port (HA requirement); 26.10 "service broker flag for remote handling of Kea". | kea-ctrl-agent | core | sensr REST API already covers it; HA channel is native. | N |
| DHCP-KEA-002 | Kea – DDNS agent (D2) | Enabled, manual config, server IP, port 53001; RFC2136 updates to authoritative DNS (BIND/PowerDNS/OPNDNS), TSIG. | kea-dhcp-ddns | core | Native RFC2136 client with TSIG (hmac-md5…sha512). | N |
| DHCP-KEA-003 | Kea – General (v4/v6) | Enabled, manual config, interfaces, valid lifetime, firewall rules, socket type udp/raw (v4), socket retries/wait, decline probation, compatibility flags (exclude-first-last-24, ignore-dhcp-server-identifier, ignore-rai-link-selection, lenient-option-parsing), MAC sources (v6: duid, ipv6-link-local, client-link-addr-option, remote-id, docsis-cmts/modem). | kea-dhcp4/6 | core | Native. | N |
| DHCP-KEA-004 | Kea – Lease expiration | Hold reclaimed time, reclaim timer wait, flush reclaimed wait, max reclaim time/leases, unwarned cycles. | kea | core | Lease GC parameters. | N |
| DHCP-KEA-005 | Kea – Subnets v4 | Shared networks via match code/encoding/data (client class on same interface); subnet, interface, pools (range or CIDR; empty = known clients only), valid lifetime, match-client-id, allocator iterative/random/flq, ping check, next-server, option data (autocollect, routers, static routes, classless static routes, DNS, domain, search, NTP, time servers, TFTP server, bootfile, v6-only-preferred (108), v4 DNR), custom options, DDNS block (forward/reverse zone, qualifying suffix, server/port, TSIG name/secret/algo, override no-update/client-update, update on renew, conflict resolution mode), description. | kea-dhcp4 | core | Native, same schema. | N |
| DHCP-KEA-006 | Kea – Subnets v6 | Subnet, interface, dynamic prefix (from IA/PD on WAN), allocator, PD allocator, pools, valid lifetime, option data (DNS, search, v6 DNR), DDNS block, description. | kea-dhcp6 | core | Native; dynamic prefix via prefix-change events. | N |
| DHCP-KEA-007 | Kea – PD pools | Subnet, prefix, prefix length, delegated length; IA_PD route installation to client link-local (via hostwatch/NDP); HA route install on both peers. | kea + prefix watcher | core | Native PD with rtnetlink route install. | N+K |
| DHCP-KEA-008 | Kea – Reservations v4/v6 | Subnet, IP, MAC, client-id, DUID (v6), prefix (v6), hostname, domain search, option data, next-server, custom options, description; "register reservation from lease" action. | kea | core | Native. | N |
| DHCP-KEA-009 | Kea – HA | Enabled, this server name, max unacked clients; peers (name, role primary/standby, URL); HA+MT; requires static prefix; sync config via HA. | kea HA hook | core | Native lease replication (hot-standby) over mTLS; CARP/VRRP-aware. | N |
| DHCP-KEA-010 | Kea – Options (custom) | Description, match code/encoding/data (creates client class), set code/encoding (hex/ipv4/ipv6/uint8/16/32/int32/bool/string/fqdn)/data, force; vendor option 43 hex recipe; user-class 77 recipe. | kea client classes | core | Native. | N |
| DHCP-KEA-011 | Kea – Leases v4/v6 view | Non-static leases; find/register reservation; delete lease; Kea leases dashboard widget. | kea memfile | core | Lease DB API. | N |
| DHCP-KEA-012 | Kea – manual config files | `kea-dhcp4.conf` etc. | kea | core | Not applicable. | X |
| DHCP-ISC-001 | ISC DHCPv4/v6 (`os-isc-dhcp`, legacy) | Per-interface range, DNS, gateway, static mappings by MAC/DUID, PD range, failover peer, leases view with failover states, custom conf.d. | isc-dhcpd | legacy plugin (tier 2) | Out of scope; config importer maps ISC settings to native server. | X (importer N) |
| DHCP-DNSREG-001 | DHCP → DNS registration | Dnsmasq: register leases/static mappings into its DNS, Unbound forwards per domain; Kea: none dynamic (only static via Unbound restart); FreeRADIUS DHCP (plugin). | dnsmasq/unbound | core | Native: lease events → resolver local-data (A/AAAA/PTR) immediately; the key Kea gap is closed. | N |

## 6. DNS services (`DNS`)

Sources: unbound.rst, reporting_unbound_dns.rst, dnsmasq.rst (DNS part), opendns.rst, dynamic_dns.rst, how-tos bind/dnscrypt-proxy/multicast-dns/tayga; core `Unbound/Unbound.xml`, `Dnsmasq.xml`, `services_opendns.php`; plugins dns/*.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| DNS-UB-001 | Unbound – General | Enable, port, interfaces (all recommended), DNSSEC, DNS64 + prefix, AAAA-only, register ISC leases, DHCP domain override, register static mappings, no IPv6 link-local, system A/AAAA records, TXT comments, cache flush on reload, SafeSearch (Google/DDG/Bing/Qwant/Pixabay/YouTube), outgoing interfaces, local zone type (transparent…static), WPAD. | unbound | core | unbound (D) rendered from typed config; later hickory-dns recursive option. | D |
| DNS-UB-002 | Unbound – Host overrides | Host (wildcard), domain, RR A/AAAA/MX/TXT, MX priority/host, TTL, server, TXT data, add PTR, aliases sub-grid, description. | unbound local-data | core | Local-data renderer. | D |
| DNS-UB-003 | Unbound – Domain overrides (superseded) | Replaced by Query Forwarding. | | legacy | Importer maps to forwarding. | X |
| DNS-UB-004 | Unbound – Advanced | Hide identity/version, prefetch, prefetch key, harden DNSSEC stripped, harden below NXDOMAIN, aggressive NSEC, serve expired (+ reply TTL, TTL, reset, client timeout), strict QNAME min, extended stats, log queries/replies/tag/servfail/local actions, verbosity 0–5, validation log level, private domains, rebind protection nets, insecure domains, msg/rrset cache size, outgoing/incoming TCP buffers, queries per thread, outgoing range, jostle/discard timeout, cache max/min/negative TTL, infra host TTL/keep probing/cache hosts, unwanted reply threshold. | unbound.conf | core | Same knobs. | D |
| DNS-UB-005 | Unbound – Access lists | Default action allow/deny/refuse; ACLs with action allow/deny/refuse/allow_snoop/deny_non_local/refuse_non_local, networks; automatic interface ACLs. | unbound access-control | core | Same. | D |
| DNS-UB-006 | Unbound – Blocklists (DNSBL) | Multiple policies: enabled, type group (General, Hagezi Multi, OISD, Hagezi Targeted, Minimal), lists, allowlist regex, blocklist exact, wildcard domains, source nets, destination address (0.0.0.0), NXDOMAIN, cache TTL; dynamic reload without restart; blocklist tester; cron "Update Unbound DNSBLs"; predefined sources (AdAway, AdGuard, OISD ads/big/nsfw, blocklistproject, EasyList, EasyPrivacy, YoYo, Hagezi lists; ThreatFox removed 26.7.8). BE/CE share same format since 26.10. | unbound python module (`dnsbl_module.py`) | core | Native blocklist compiler → unbound RPZ or local-zone data; per-client policy needs a Rust DNS front (hickory) or unbound `views`. | N+D |
| DNS-UB-007 | Unbound – Query forwarding | Use system nameservers; entries enabled, domain (empty = catch-all), server, port; forward-first/TCP upstream. | unbound forward-zone | core | Same. | D |
| DNS-UB-008 | Unbound – DNS over TLS | Entries enabled, domain, server, port 853, verify CN; public resolver table (Cloudflare, Google, Quad9); DoT wins over catch-all forward. | unbound tls-upstream | core | Same; add DoH/DoQ upstream later. | D |
| DNS-UB-009 | Unbound – Statistics / Reporting › Unbound DNS | Enable stats (reporting settings), 7-day rolling data; totals (queries/resolved/blocked/blocklist size), query graph, client graph, top 10 passed/blocked with one-click block/allow, details feed (client, domain, type, action pass/block/drop, source recursion/local/local-data/cache, rcode, resolve time, TTL, blocklist). | unbound + python logging module + SQLite | core | Native query-log collector (unbound dnstap or Rust front) → embedded DB. | N |
| DNS-UB-010 | Unbound – custom includes | `unbound.opnsense.d/*.conf`, `configctl unbound check`. | unbound | core | Validated "extra config" text field. | D |
| DNS-UB-011 | Unbound – WPAD, DNS64, SafeSearch helpers | Auto wpad record/TXT; DNS64 pairing with Tayga; SafeSearch CNAME rewrites. | unbound | core | Same. | D |
| DNS-DM-001 | Dnsmasq – DNS | Listen port (0 disables), DNSSEC proxy, no hosts lookup, expand hosts, log queries, max concurrent, cache size, local TTL, no ident, strict order, require domain, no system DNS, no private reverse, add MAC (standard/base64/text), add subnet, strip subnet. | dnsmasq | core | Native forwarder (N) or dnsmasq (D). Decision: native, because DHCP+DNS registration is the value. | N |
| DNS-DM-002 | Dnsmasq – Domain overrides | Sequence, domain (`*` all), IP (empty = block), port, source IP, firewall alias (ipset → External alias), description. | dnsmasq `server=`, ipset | core | Native forwarder rule + nft set population from answers (DNS-based alias). | N |
| DNS-DM-003 | Dnsmasq as primary with Unbound as recursor pattern | Port 53053 arrangements, per-client stats caveat. | | core | Native front resolver removes need for two daemons. | N |
| DNS-OPENDNS-001 | OpenDNS (Services › OpenDNS) | Enable, username, password, network label; updates WAN IP at OpenDNS and replaces system nameservers. | PHP + OpenDNS API | core (legacy PHP) | Native updater (DynDNS provider "opendns") + nameserver override. | N |
| DNS-DDNS-001 | Dynamic DNS (`os-ddclient`) | General: enable, verbose, allow IPv6, interval, backend ddclient/native(opnsense); accounts: enabled, description, service (hosting1984, changeip, cloudflare, cloudns, digitalocean, dinahosting, dnsmadeeasy, dns-o-matic, dnsexit2, dyndns2, dnspark, dnspodcn, dslreports1, dondominio, duckdns, dynu, easydns, freedns, freemyip, gandi, godaddy, googledomains, he-net, he-net-tunnel, hetzner, …), protocol dyndns1/dyndns2/get/post/put (custom HTTP), resourceId (Azure), username/password/token, zone, hostnames, check-ip method (web_akamai, cloudflare, dns_cloudflare, dynu, freedns, he, icanhazip, ipify v4/v6, loopia, myonlineportal, noip, nsupdate.info, zoneedit, interface), interface to monitor, dynamic IPv6 host, timeout, force SSL. | ddclient or OPNsense Python backend | plugin | Native Rust DDNS client (provider trait per service; HTTP custom protocol; RFC2136 provider merges `os-rfc2136`). | N |
| DNS-RFC2136-001 | RFC 2136 client (`os-rfc2136`) | Legacy PHP page: per-host nsupdate with TSIG key, server, zone, TTL, interface to monitor, IPv4/IPv6. | bind-tools nsupdate | plugin (legacy PHP) | Folded into DNS-DDNS-001 as provider `rfc2136`. | N |
| DNS-BIND-001 | BIND (`os-bind`) | General: enable, disable v6, RPZ, listen v4/v6, query/transfer source, port (53530 default), forwarders, filter AAAA, log size/level, max cache, recursion ACL, allow transfer/query ACLs, DNSSEC validation, hide hostname/version, prefetch, rate limiting, rndc algo/secret; ACLs; Domains (primary/secondary/forward, transfer key algo); Records (A, AAAA, CAA, CNAME, DNAME, DNSKEY, DS, HTTPS, MX, NAPTR, NS, PTR, RP, RRSIG, SRV, SSHFP, SVCB, TLSA, TXT); DNSBL via RPZ (24 list codes, whitelist, SafeSearch Google/DDG/YouTube/Bing). | ISC BIND 9.20 | plugin | Authoritative role: hickory-dns authority (N) or PowerDNS/Knot (D). Recursive role covered by DNS-UB. Decision: native authoritative server (also covers BE OPNDNS). | N |
| DNS-DNSCRYPT-001 | DNSCrypt-Proxy (`os-dnscrypt-proxy`) | General: enable, listen (localhost:5353), privileged ports, max clients; resolver filters IPv4/IPv6/DNSCrypt/DoH/DNSSEC/NoLog/NoFilter; force TCP, proxy (Tor), timeout, keepalive, cert refresh, ephemeral keys, no session tickets, fallback resolver, block IPv6; cache + TTLs; cloaking (overrides), DNSBL, whitelist, forwarding, servers; logs general/queries/NX. | dnscrypt-proxy2 | plugin | Encrypted upstream (DoH/DoT/DoQ/DNSCrypt) as upstream options of the native resolver front; cloaking = host overrides. | N |
| DNS-MDNS-001 | mDNS repeater (`os-mdns-repeater`) | Enabled, CARP-aware, interfaces (2–5), blocklist networks. | mdns-repeater | plugin | Native mDNS reflector (or avahi reflector D). | N |
| DNS-NETFLECTOR-001 | Netflector (`os-netflector`) | Reflect link-local service discovery (mDNS/SSDP/etc.) between interfaces: enabled, log level, CARP depend, counters interval, reflectors (address family default/dual/v4/v6). | netflector | plugin | Merge with DNS-MDNS-001 into one multicast-reflector service. | N |
| DNS-NAT64-001 | Tayga NAT64 (`os-tayga`) | Enable, IPv6 prefix (64:ff9b::/96), IPv4 pool, IPv4/IPv6 addresses, NAT64 interface addresses, disable v6 route, static mappings; creates tun interface needing rules + SNAT; pair with Unbound DNS64 and RA NAT64 prefix. | tayga | plugin | Jool kernel NAT64 (K) driven via netlink, or tayga (D). Decision: Jool. | K+N |
| DNS-NDPPROXY-001 | NDP proxy (`os-ndp-proxy-go`) | Enable, CARP failover, upstream interface (Ethernet; PPPoE experimental), respond to prefixes, downstream interfaces, proxy RAs, install host routes, static prefixes/routers, cache lifetime/max/file, route/alias ops rate limits, pcap timeout, debug; aliases tab (learned addresses → External alias); log. | ndp-proxy-go (userspace) | plugin | Native Rust ND proxy (AF_PACKET) with kernel `proxy_ndp` entries + host routes; replaces removed `os-ndproxy`. | N+K |

## 7. Router advertisements (`RA`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| RA-001 | Router Advertisements (Services › Router Advertisements) | Per interface: enabled, interface (advertises VIP prefixes too), mode router-only/unmanaged/managed/assisted/stateless (M/O/A flags), min/max interval, RDNSS (≤3), DNSSL, routes; advanced: constructor (Base6Interface, WAN prefix), preference low/medium/high, deprecate prefix, remove adv on exit, remove route, default/preferred/valid lifetimes, source address (CARP link-local VIP), NAT64 prefix + lifetime, link MTU, enable DNS (RFC 8106), RDNSS/DNSSL/route lifetimes, hop limit. | radvd | core | Native Rust RA daemon (ICMPv6 raw socket, RFC 4861/8106/8781). | N |
| RA-002 | Dnsmasq RA | Global RA switch + per-range RA modes (see DHCP-DM-003); only one RA daemon at a time. | dnsmasq | core | Same native RA daemon, driven by either config path. | N |
| RA-003 | HA RA | CARP link-local source, DeprecatePrefix/RemoveRoute off with CARP. | radvd | core | VRRP state hooks. | N |

## 8. Captive portal (`CP`)

Sources: captiveportal.rst, how-tos guestnet.rst, vendor oidc.rst; core `CaptivePortal.xml`.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| CP-001 | Zones | Enabled, zone id (alias `__captiveportal_zone_<id>`), interfaces (one or many), client roaming (register all IPs incl. IPv6, needs Hostwatch), disable firewall rules, auth servers (LDAP, RADIUS, local, vouchers, none, multiple, OIDC on BE), always send accounting, enforce local group, idle/hard timeout, concurrent logins, certificate (HTTPS or HTTP only), hostname (DNS record needed), CORS policy same_origin/listed/any + origins, allowed addresses, allowed MACs, extended pre-auth data, template, description. | pf anchors + per-zone lighttpd (ports 8000+id/9000+id) + python API | core | Native Rust portal HTTP server (axum) per zone; nft sets of authenticated clients (ip/mac/zone); RADIUS/LDAP/local/voucher/OIDC via SYS-AUTH providers. | N |
| CP-002 | Templates | Download default zip, edit index.html, upload as named template; `exclude.list` ignored; OIDC sample template. | zip | core | Template store with variable injection; same zip contract. | N |
| CP-003 | Vouchers | Voucher auth server type; generate N vouchers (CSV: username,password,group,validity), delete group, voucher status; countdown runs while logged out. | Voucher.php + SQLite | core | Native voucher store. | N |
| CP-004 | Sessions page | Live top-IP bandwidth, active sessions, time left, drop session, zone selector; `list_clients` CLI; status API for popups. | python + ipfw/pf counters | core | Session API + nft counters. | N |
| CP-005 | Auto firewall rules | RDR 80→9000+id, 443 (to firewall)→8000+id, IPv6 variants, DNS pass, portal port pass, default block for unauthenticated; priority over user rules; need explicit internet pass rule; "No RDR" rule for OIDC IdP. | pf (since 25.1.4; ipfw before) | core | Rule-compiler stage keyed on zone sets. | N |
| CP-006 | Bandwidth per zone/user | Via traffic shaper integration; RADIUS bandwidth attributes. | dummynet | core | tc classes per client (SHP). | N+K |
| CP-007 | RFC 8910/8908 Captive Portal API | DHCPv4 option 114 / RA option 37 URL; JSON status (captive, user-portal-url, seconds-remaining); public cert needed; optional NAT restriction. | python API | core | Native endpoint. | N |
| CP-008 | REST API / accounting | Access, session, voucher, template APIs; RADIUS accounting start/interim/stop; daily session limits via RADIUS. | python | core | Same. | N |
| CP-009 | Log file | Portal auth log. | syslog | core | Structured journal. | N |

## 9. Intrusion detection / prevention (`IDS`)

Sources: ips.rst, etpro_telemetry.rst, how-tos ips-bypass/ips-feodo/ips-sslfingerprint, qfeeds.rst; core `IDS/IDS.xml`; plugins security/intrusion-detection-content-*.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| IDS-001 | General settings | Enabled; mode pcap (IDS) / netmap (IPS) / divert (IPS, listeners = CPUs, needs rules with divert-to); promiscuous; interfaces (physical for netmap; parent for VLANs); home networks; default packet size; pattern matcher ac/ac-ks/hyperscan; detect profile low/medium/high/custom (+ toclient/toserver groups); syslog alerts; EVE syslog; log payload; verbosity; EVE HTTP (extended, dump headers) and TLS (extended, session resumption, custom fields incl. ja3/ja3s/ja4) options; alert log rotate (weekly/daily) and retention; update cron. | Suricata + netmap/divert | core | Suricata (D): IDS via AF_PACKET; IPS via NFQUEUE (replaces divert-to, selectable per rule) or AF_PACKET copy-mode / XDP inline; Hyperscan available on Linux. | D |
| IDS-002 | Rulesets download | Ruleset list with timestamps; "Download & Update"; schedule via cron; sources: ET Open, ET Pro Telemetry (free, token), ET Pro (oinkcode), abuse.ch SSLBL, Feodo Tracker, URLHaus, OPNsense app detection rules; plugins add Snort VRT (`os-intrusion-detection-content-snort-vrt`), PT Open (`-ptopen`), anti-phishing (`-at-antiphishing`), ET Open complement (`-et-open`), ET Pro (`-et-pro`). | rule-updater python + metadata XML | core + plugins | Native rule fetcher with metadata manifest format; same sources (licences permitting). | N |
| IDS-003 | Policies | Enabled, priority, match rulesets, current action disable/alert/drop, metadata filters (affected product, deployment, signature severity…), new action default/alert/drop/disable, description; migrated from pre-21.1 filters. | python rule compiler | core | Native policy engine producing `modify.conf`/`enable.conf` equivalents. | N |
| IDS-004 | Installed rules grid | Filter by metadata/policy, per-rule enable/action override (`__manual__`). | SQLite rule cache | core | Native rule index DB. | N |
| IDS-005 | User-defined rules | Source/destination CIDR, SSL fingerprint (SHA1), action alert/drop/pass, bypass (skip inspection), description; recipes: LAN-to-LAN bypass matrix, fingerprint blocking. | Suricata rule templates | core | Same. | N |
| IDS-006 | Alerts view | Alert grid, details button, log file; EVE JSON to syslog; dashboard not included. | eve.json | core | EVE reader → DB + SSE. | N |
| IDS-007 | Advanced custom YAML | `custom.yaml` Jinja template include. | | core | Validated extra-YAML field. | D |
| IDS-008 | ET Pro Telemetry (`os-etpro-telemetry`) | Token, "ET telemetry" ruleset, daily schedule, dashboard widget ACTIVE/DORMANT/DISABLED, anonymised alert telemetry + sensor keepalive to Proofpoint. | python telemetry script | plugin (tier 2, vendor service) | Possible only with Proofpoint agreement; otherwise X. | X? |
| IDS-009 | Q-Feeds connector (`os-q-feeds-connector`) | API key, feeds grid (IP/domain, licensed), firewall aliases (`__qfeeds_*`), Unbound blocklist registration (allowlist, source nets, address, NXDOMAIN), events tab (alias hits), DNSCrypt integration. | python fetcher | vendor plugin (tier 2) | Generic "threat-feed connector" (N) consuming any IP/domain feed; Q-Feeds API as one provider. | N |
| IDS-010 | Hardware constraints | Offloading must be disabled; netmap emulation tunable; VLAN limits; RSS no benefit. | netmap | core | AF_PACKET/XDP have no such limits; keep offload warning for IPS mode. | — |

## 10. Monit (`MON`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| MON-001 | General | Enable, interval, start delay, mail servers (multiple), port, user/pass, SSL + version + verify, log file, state file, event queue path/slots, HTTPD (enable, user, pass, port, allow list), M/Monit URL/timeout/register. | monit | core | Native Rust monitor engine; mail via lettre; no M/Monit. | N |
| MON-002 | Alerts | Enabled, recipient, not-on invert, events (30 types: action, checksum, bytein/out, connection, content, data, exec, fsflags, gid, icmp, instance, invalid, link, nonexist, packetin/out, permission, pid, ppid, resource, saturation, size, speed, status, timeout, timestamp, uid, uptime), mail format, reminder, description. | monit | core | Same event taxonomy. | N |
| MON-003 | Services | Enabled, name, type process/file/fifo/filesystem/directory/host/system/custom/network, pidfile, match, path, timeout, start timeout, address, interface, start/stop commands, tests, depends, polltime; pre-created services. | monit | core | Same. | N |
| MON-004 | Tests | Name, type (Existence, SystemResource, ProcessResource, ProcessDiskIO, FileChecksum, Timestamp, FileSize, FileContent, FilesystemMountFlags, SpaceUsage, InodeUsage, DiskIO, Permission, UID, GID, PID, PPID, Uptime, ProgramStatus, NetworkInterface, NetworkPing, Connection, Custom), condition, action alert/restart/start/stop/exec/unmonitor, path. | monit | core | Condition mini-language reimplemented. | N |
| MON-005 | Status page, custom includes, syntax check | Status grid; `monit.opnsense.d`; `configctl monit check`. | monit | core | Status API; no raw includes. | N |

## 11. Network time (`NTP`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| NTP-001 | General (Services › Network Time) | Interfaces (listen + outgoing; wildcard default), time servers with prefer/no-use, orphan stratum, NTP graphs (RRD), syslog logging, statistics logging, access restrictions (restrict flags, rejected client handling), leap seconds file; disabled when no servers. | ntpd | core (legacy PHP) | chrony (D): `allow`/`deny`, `server … prefer`, `local stratum`, NTS client/server; graphs from `chronyc tracking/sourcestats`. | D |
| NTP-002 | GPS reference clock | NMEA serial, brand presets or custom, PPS flags. | ntpd refclock 20 | core | chrony `refclock SHM/SOCK` via gpsd (D). | D |
| NTP-003 | PPS | Serial port PPS signal. | ntpd refclock 22 | core | chrony `refclock PPS /dev/pps0`. | D+K |
| NTP-004 | Status | Peer table: status, server, refid/kiss code, stratum, type u/b/p/l/s/A/B/M, when, poll, reach, delay, offset, jitter; log file. | ntpq | core | `chronyc sources -v` parsed. | D |
| NTP-005 | Chrony plugin (`os-chrony`) | Enabled, port, NTS client, NTS no-cert, peers, fallback peers, allowed networks. | chrony | plugin | Folded into NTP-001 (chrony is the default). | D |

## 12. VPN (`VPN`)

Sources: vpnet.rst, how-tos ipsec-*, sslvpn_*, wireguard-*, openconnect, zerotier, netbird, troubleshooting/openvpn; core `IPsec/Swanctl.xml`, `IPsec/IPsec.xml`, `OpenVPN/*.xml`, `Wireguard/*.xml`; plugins security/{openvpn-legacy,strongswan-legacy,openconnect,tailscale,netbird,tinc,stunnel}, net/zerotier.

### 12.1 IPsec (`VPN-IPSEC`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| VPN-IPSEC-001 | Connections | Enabled, proposals (IKE), unique no/never/keep/replace, aggressive, version 0(any)/1/2 (IKEv1 visibly deprecated 26.7.8), MOBIKE, local/remote addresses (IP/FQDN/`%any`), local/remote port 500/4500, UDP encap, reauth/rekey/over time, DPD delay/timeout, pools, send certreq, send cert ifasked/never/always, keyingtries, description; clone action. | strongSwan swanctl | core | strongSwan (D) via VICI; connection schema reproduced 1:1. | D |
| VPN-IPSEC-002 | Local / Remote authentication rounds | Round, auth psk/pubkey/eap-tls/eap-mschapv2/xauth-pam/eap-radius, id, EAP id, certs, CA certs, pubkeys (key pairs), groups (remote), description. | swanctl | core | Same. | D |
| VPN-IPSEC-003 | Children (CHILD_SA) | Enabled, connection, reqid, ESP proposals, sha256_96, start action none/trap\|start/route/start/trap, close action, DPD action clear/trap/start, mode tunnel/transport/pass/drop, install policies toggle, local/remote traffic selectors, rekey time, replay window, description. | swanctl | core | Same; XFRM policies via strongSwan kernel-netlink. | D+K |
| VPN-IPSEC-004 | Pools | Name, addresses, DNS (CP payload); per-user /32 pools pattern. | swanctl pools | core | Same. | D |
| VPN-IPSEC-005 | Pre-shared keys | Local identifier (required), remote identifier, type PSK/EAP, key, description. | swanctl secrets | core | Same (EAP = username/password). | D |
| VPN-IPSEC-006 | Key pairs | Name, type rsa/ecdsa, public/private key, size, fingerprint; generate button. | | core | Rust keygen (rcgen/rsa/p256). | N |
| VPN-IPSEC-007 | Mobile & Advanced settings | Enabled (legacy link), prefer old SA, disable auto VPN rules, passthrough networks, user source (auth server), local group; charon: max IKEv1 exchanges, threads, IKE SA table size/segments, half-open limit, ignore acquire TS, install routes, cisco unity, make-before-break, retransmit tries/timeout/base/jitter/limit, reqid base, retry initiate; syslog per-subsystem levels; attr plugin (subnet, split-include, 28672–28679 Unity attrs, DNS, NBNS); eap-radius servers/accounting/class groups; xauth-pam service/session/trim email; download swanctl.conf. | charon.conf | core | strongswan.conf renderer. | D |
| VPN-IPSEC-008 | Virtual Tunnel Interfaces (VTI) | Enabled, reqid, local/remote, tunnel local/remote (+ second pair), skip firewall rules, description; auto `ipsecN` interface; gateways + static routes; filtertunnel tunables. | if_ipsec(4) | core | Linux XFRM interfaces (`xfrmi`, if_id = reqid) via rtnetlink; routes native. | K+N |
| VPN-IPSEC-009 | Manual SPD entries | Enabled, protocol esp/ah, reqid, child binding, source, destination; NAT-before-IPsec (BINAT). | setkey/updown | core | XFRM policy add via netlink. | K+N |
| VPN-IPSEC-010 | Status Overview / Lease status / SAD / SPD | Session list with connect/disconnect, pool leases, SAD dump, SPD dump (+manual tab). | swanctl --list-*, setkey | core | VICI list-sas/list-pols; `ip xfrm` via netlink. | D+K |
| VPN-IPSEC-011 | Firewall integration | IPsec interface group rules (enc0), no auto WAN rules, auto VPN rules toggle, NAT on VTI. | pf | core | nft chains on `xfrm` interfaces; policy-mode match via `meta ipsec`/`xfrm` expressions. | N |
| VPN-IPSEC-012 | CARP/HA | Disable MOBIKE, VIP as local address, DPD required, new IKE_SA on failover. | | core | VRRP transition hooks (VPN-WG-007 pattern). | N |
| VPN-IPSEC-013 | Tuning | `async_crypto`, netisr threads, `dfbit` modes, multiple IKE SAs. | sysctl | core | Linux: pcrypt/`xfrm` offload, `xfrm_state` DF handling. | K |
| VPN-IPSEC-014 | Custom includes | `strongswan.opnsense.d`, `swanctl/conf.d`. | | core | Validated extra-config fields. | D |
| VPN-IPSEC-015 | Legacy tunnel settings (`os-strongswan-legacy`) | Phase1/Phase2 pages, mobile clients page, tunnel isolation, `ping_hosts.sh`; migration to connections. | PHP | legacy plugin | Importer only. | X (importer N) |
| VPN-IPSEC-016 | Road-warrior recipes | IKEv2 EAP-MSCHAPv2 with pools/per-user; client configs (Windows PowerShell, iOS, Android strongSwan/native, NCP); split vs full tunnel; DNS leak handling. | | core | Documented recipes + generated client profiles (improvement: Apple mobileconfig/Windows PS export). | N |

### 12.2 OpenVPN (`VPN-OVPN`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| VPN-OVPN-001 | Instances (server/client) | vpnid, enabled, role, description, dev tun/tap/ovpn (DCO), verbosity 0–11, proto udp/udp4/udp6/tcp/tcp4/tcp6, port, port-share, local bind, topology net30/p2p/subnet, remote hosts, server v4/v6 networks, nopool, bridge gateway/pool, routes, push routes, push excluded routes, cert/CA/CRL, cert depth, remote-cert-tls, verify client cert none/require, OCSP, auth digest (full list), data-ciphers Recommended/Legacy sets, fallback cipher, TLS key (static key ref), auth mode (auth server), local group, flags (block-ipv6, client-to-client, duplicate-cn, float, passtos, persist-remote-ip, remote-random, route-noexec, route-nopull, explicit-exit-notify, fast-io), push flags (block-ipv6, block-outside-dns, register-dns, explicit-exit-notify), push inactive, username-as-CN, strict user/CN 0/1/2, username/password (client), maxclients, keepalive interval/timeout, reneg-sec, auth-gen-token (+renewal, secret), provision exclusive, redirect gateway options (local, autolocal, def1, bypass-dhcp, bypass-dns, block-local, ipv6, !ipv4), route metric, register DNS, DNS domain/search/servers, NTP servers, tun MTU, fragment, mssfix, CARP depend-on, compress-migrate, ifconfig-pool-persist, http-proxy, verify-x509-name. | OpenVPN 2.6 | core | OpenVPN 2.6 (D) with `ovpn-dco` kernel module; config renderer; management interface. | D+K |
| VPN-OVPN-002 | Static keys | Mode auth/crypt/crypt-v2, key (generate), description. | openvpn --genkey | core | Call openvpn genkey or native. | D |
| VPN-OVPN-003 | Client-specific overrides (CSO) | Enabled, servers (empty=all), common name, block, push reset, tunnel networks v4/v6, local networks, remote networks (iroute), route gateway, redirect gateway opts, register DNS, DNS domain/search/servers, NTP, WINS, description; RADIUS Framed-IP/Route; match by CN or username. | client-config-dir + auth script | core | Native `client-connect` script/management hook producing CCD. | N+D |
| VPN-OVPN-004 | Client export | Per server: hostname, template (plain .ovpn file-only, archive, Viscosity bundle, …), local port / random port, validate server CN, cryptoapi, auth-nocache, static challenge, custom config; per-cert/user downloads. | PHP exporter | core | Native exporter (ovpn, zip, Viscosity, Windows installer out of scope). | N |
| VPN-OVPN-005 | Connection status | Per-instance clients (CN, real/virtual address, bytes, since), kill client; dashboard widgets OpenVPN servers/clients. | management socket | core | Management socket client. | D |
| VPN-OVPN-006 | Firewall / interfaces | Default 1194/UDP; "OpenVPN" interface group; devices assignable; reply-to gotcha (troubleshooting). | pf | core | Group chain; gateway auto-creation flag. | N |
| VPN-OVPN-007 | HA | Bind to CARP VIP; instance CARP depend-on vhid; clients nobind. | | core | VRRP hooks start/stop instance. | N |
| VPN-OVPN-008 | Auth integrations | Local, LDAP, RADIUS, TOTP (token+password concatenation), OTP static-challenge, OpenVPN group alias. | auth framework | core | SYS-AUTH providers via management `auth-user-pass-verify` or plugin. | N |
| VPN-OVPN-009 | Legacy Servers/Clients pages (`os-openvpn-legacy`) | Server modes (Remote Access SSL/TLS, +User Auth, Peer-to-Peer shared key/SSL), legacy fields (DH length, encryption algo, compression, NetBIOS, client management port, renegotiate time…); migration. | PHP | legacy plugin | Importer only; shared-key P2P mode supported in instances via static key. | X (importer N) |
| VPN-OVPN-010 | Troubleshooting | reply-to on assigned OpenVPN interfaces; fix via gateway disable/per-rule/global. | | core | Documented. | — |

### 12.3 WireGuard (`VPN-WG`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| VPN-WG-001 | Instances | Enabled, name, instance number (`wgN`), public/private key (generate), listen port, MTU, DNS servers (overwrites system DNS; leave blank), tunnel addresses (CIDR), disable routes, gateway (for selective routing), CARP depend-on vhid, peers, debug; peer-generator defaults (endpoint, peer DNS, allowed IPs). | wg(4) kernel + wg-quick-like scripts | core (plugin `os-wireguard` historically) | Kernel WireGuard via `wireguard-uapi` netlink; addresses/routes via rtnetlink. | N+K |
| VPN-WG-002 | Peers | Enabled, name, public key, PSK, allowed IPs (tunnel addresses), endpoint address/port (hostname resolved once), keepalive, instances; cron "Renew DNS for WireGuard on stale connections". | wg | core | Native; periodic endpoint re-resolution built in. | N |
| VPN-WG-003 | Peer generator | Pick instance, derive client address from instance nets, new keypair per peer (store private key optional), config text + QR code, reference mode to rebuild config, per-peer PSK/keepalive. | PHP + qrcode | core | Native generator + QR (qrcode crate). | N |
| VPN-WG-004 | Status / diagnostics | Instances & peers, last handshake, transfer, interface up/down; log file. | wg show | core | netlink dump. | N |
| VPN-WG-005 | Interface assignment pattern | Assign `wgN` (none/none), auto `<name> net` alias, auto SNAT, per-interface rules, gateway + dynamic gateway policy, Unbound reload. | | core | Supported via IF-001/IF-008. | N |
| VPN-WG-006 | Selective routing / provider clients | Gateway with far gateway, monitor IP, disable host route; policy rules with inverted RFC1918 alias; floating out rule for router traffic; kill switch via tags; IPv6 /127 gateway; DNS leak options; provider recipes (Mullvad API registration, AzireVPN, ProtonVPN options). | pf route-to | core | FW-009 + SYS-GW; provider recipes documented. | N |
| VPN-WG-007 | HA | CARP depend-on toggles interface up/down keeping addresses/routes. | | core | VRRP hook. | N |
| VPN-WG-008 | MSS clamping recipe | Normalization rule on WireGuard group (1380/1360; PPPoE values). | pf scrub | core | FW-SCRUB-002. | N |

### 12.4 Other VPN plugins

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| VPN-OC-001 | OpenConnect client (`os-openconnect`) | Enabled, server, user, password, server cert hash (sha256/sha1/pin-sha256), group, client certificate, token mode rsa/totp/hotp/oidc + secret, allow insecure, protocol anyconnect/nc/pulse/gp/f5/fortinet/array; creates interface. | openconnect | plugin | openconnect (D) managed by Rust. | D |
| VPN-TS-001 | Tailscale (`os-tailscale`) | Auth: login server (Headscale), pre-auth key; settings: enabled, login timeout, listen port, accept DNS, advertise exit node, use exit node, accept subnet routes, enable SSH, disable SNAT, advertised subnets; status. | tailscaled | plugin | tailscaled (D) via LocalAPI. | D |
| VPN-NB-001 | NetBird (`os-netbird`) | Auth: management URL, setup key; settings: enable, WireGuard port, IP mapping, firewall allow config/block inbound, SSH (enable, root, SFTP, local/remote forwarding, auth), DNS, routing (access LAN, accept client/server routes), Rosenpass (+permissive), log level; CARP interface/VHID start mode; status; `wt0` assignment. | netbird | plugin | netbird (D). | D |
| VPN-ZT-001 | ZeroTier (`os-zerotier`) | Enabled, API token, local.conf JSON, networks (id, description, enabled = join/leave), overview (info/networks/peers), `zt*` assignment with static IP. | zerotier-one | plugin | zerotier-one (D). | D |
| VPN-TINC-001 | Tinc (`os-tinc`) | Networks (mode router/switch, debug level, local address/subnets, keys), hosts (address, port, subnets, pubkey, connect-to); HA sync class. | tinc | plugin | tinc (D); low priority. | D |
| VPN-STUNNEL-001 | Stunnel (`os-stunnel`) | General: enabled, chroot, identd (RFC1413 CN→port); services: listen address/port, target host/port, certificate, CA, CRL, protocol imap/ldap/nntp/pop3/smtp, description. | stunnel | plugin (tier 2) | Native TLS tunnel in Rust (rustls) — simple enough to own; identd optional. | N |
| VPN-SS-001 | Shadowsocks (`os-shadowsocks`) | Server: enabled, address, port, local port, password, cipher class secure/deprecated/insecure, tcp/udp mode, timeout, fragmentation; Local (client): server, local address/port, password, cipher. | shadowsocks-rust | plugin | shadowsocks-rust (D) or crate embed. | D |
| VPN-SSLH-001 | sslh (`os-sslh`) | Enabled, listen addresses, mode fork/select, timeout, targets tls/ssh/openvpn/http/xmpp/tinc/anyprot, on-timeout, verbose, numeric. | sslh | plugin | Native protocol multiplexer (Rust) or sslh (D); Caddy L4 overlaps. | N/D |

## 13. Lobby and GUI framework (`GUI`)

Sources: gui.rst, dashboard.rst, lobby_password.rst, development/frontend; core `Core/Menu/Menu.xml`, widgets dir, themes.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| GUI-001 | Login + lobby | Login page (default root/opnsense), logo → Lobby: Dashboard, License, Password, Logout; SSO button (BE OIDC); status indicator red/yellow/blue/grey (links to crash reporter / system status dismiss). | lighttpd + PHP | core | axum HTTPS server + SPA (TypeScript) talking to REST; status API (`core/system/status`). | N |
| GUI-002 | Menu system | Three levels, Favorites (star), type-ahead search, `Menu.xml` merged from core + plugins, ACL-filtered, menu order/cssClass/url. | MenuSystem PHP | core | Menu registry built from module manifests; same ACL filter. | N |
| GUI-003 | Forms | Full help toggle, advanced mode toggle, per-field help, tabs/subtabs, form XML definitions (id, label, type, help, style, advanced). | Volt + form XML | core | Schema-driven forms generated from Rust model definitions (serde + schemars). | N |
| GUI-004 | Data grids | Column selector, AND-tokenised search, reload, rows per page, "go to page" for logs, row actions enable/disable/edit/clone/delete/add, pagination, full-screen grids (26.10), estimated counts for big datasets; Tabulator replacing bootgrid. | Tabulator/bootgrid | core | One grid component bound to `search*` API contract. | N |
| GUI-005 | Dashboard | Per-user layout (edit/unlock, add widget, restore default, save, resize, configure, remove, link); widgets: Announcements, CARP, Certificates, CPU, Disk, Dnsmasq leases, Firewall (live log), Firewall states, Gateways, Health graph, Interfaces, Interface statistics, IPsec leases, IPsec tunnels, Kea leases, Live log, Mbuf, Memory, Metadata (extensible), Monit, Notes, OpenVPN clients/servers, Picture, Services (flat tiles), Swap, System information, Thermal sensors, Traffic, WireGuard; plugin widgets (telemetry, dmidecode, …); synced via HA "Users and Groups". | JS widgets | core | Widget framework with per-user JSON layout; same widget set. | N |
| GUI-006 | Themes | opnsense, opnsense-auto, opnsense-dark; plugin themes (advanced, cicada, flexcolor, rebellion, tukan, vicuna). | CSS | core + plugins | Light/dark/auto + CSS variables; third-party theme packs optional. | N |
| GUI-007 | Password / self-service (Lobby › Password) | Change own password, language, landing page, OTP seed regeneration (if group allowed). BE User Portal extends this (BE-005). | PHP | core | Self-service endpoints. | N |
| GUI-008 | License page | GPL/BSD licence text. | | core | Static page. | N |
| GUI-009 | Help menu | Documentation, forum, commercial support links. | | core | Links. | N |
| GUI-010 | Power menu | Reboot, Power off (confirm). | | core | systemd `reboot`/`poweroff` via API. | N |
| GUI-011 | Localization | Language per system and per user (translations via Weblate/gettext). | gettext | core | fluent/gettext catalogs. | N |
| GUI-012 | Legacy PHP pages | A few remain (schedules, PPP devices, NTP, authservers, admin/misc/general settings, OpenDNS, wireless status, password manager, crash reporter, backup, auth tester). | PHP | legacy | All reimplemented as MVC-equivalents; no legacy mode. | N |

## 14. System (`SYS`)

Sources: users.rst, backups.rst, firmware.rst, gateways.rst, multiwan.rst, hacarp.rst, routes.rst, settingsmenu.rst, snapshots.rst, certificates.rst, logging_system.rst, diagnostics_system.rst, two_factor.rst, opnsense_tools.rst, how-tos (two_factor, self-signed-chain, user-ldap/local/radius, cloud_backup, carp, multiwan), troubleshooting/*; core `Auth/*.xml`, `Core/*.xml`, `Cron/Cron.xml`, `Syslog/Syslog.xml`, `Trust/*.xml`, `Routing/*.xml`, `Routes/Route.xml`, legacy `system_*.php`, `diag_*.php`, `crash_reporter.php`, `xmlrpc.php`; Auth library.

### 14.1 Access (`SYS-AUTH`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-AUTH-001 | Users | uid, name (33-char shell limit), disabled, scope (system/user), expires, authorized SSH keys, OTP seed (base32, generate 160-bit, QR), shell, password (argon2id since 26.10; bcrypt/SHA-512 before), scrambled password, pwd_changed_at, landing page, comment, email, API keys, privileges, language, group memberships, description, dashboard JSON, menu favorites; certificate lookup by CN; CSV import/export (no passwords); system users cannot be renamed. | config.xml + local `passwd` sync for shell users | core | Users in config store; argon2id; shell users materialised via NixOS `users` activation or `useradd`. | N |
| SYS-AUTH-002 | Groups | gid, name, scope, description, privileges, members, source networks (privileges apply only from these nets); merged privilege `page-system-groupmanager` (26.7). | config | core | Same. | N |
| SYS-AUTH-003 | Privileges (ACL) | ~160 `page-*` privileges mapping to URL patterns (`ui/*`, `api/*`, legacy php) incl. `page-all`, `user-config-readonly`; effective privileges = user ∪ groups; API keys inherit owner's privileges; menu filtered by ACL. | ACL.xml per module | core | Permission registry per module (`AREA.sub` ids) with route patterns; same read-only concept. | N |
| SYS-AUTH-004 | Authentication servers | Local database (password policy: enabled, duration, min length, complexity, SHA-512 compliance), Local + TOTP (token length, time window, grace, token order), LDAP (host, port, transport TCP/STARTTLS/SSL, protocol v3, bind creds, scope, base DN, container picker, extended query, template MicrosoftAD/OpenLDAP/eDirectory, naming attribute, read properties, synchronize groups via memberOf, constraint/limit groups, auto user creation, case-insensitive), LDAP + TOTP, RADIUS (host, secret, auth / auth+acct, ports 1812/1813, timeout, group sync via CLASS, limit groups, auto create), Voucher (validity, group), OpenID Connect (BE). Multiple servers for fallback; per-service selection (GUI, IPsec, OpenVPN, CP, proxy, portal). | Auth library (Local, LocalTOTP, LDAP, LDAPTOTP, Radius, Voucher, API, SSO providers) | core (OIDC = BE) | Rust auth providers: local (argon2), TOTP (RFC 6238), LDAP (`ldap3`), RADIUS (`radius` crate), voucher, OIDC (`openidconnect` crate) — OIDC in core, not paid. | N |
| SYS-AUTH-005 | Authentication tester (System › Access › Tester) | Pick server, username/password → result + returned properties (groups). | PHP | core | Endpoint. | N |
| SYS-AUTH-006 | API keys | Generate key/secret (ini download, shown once), list/revoke; Basic-auth credential for `/api`. | ApiKey model | core | Same contract (compatibility layer for OPNsense API clients where feasible). | N |
| SYS-AUTH-007 | Two-factor | TOTP on GUI/CP/OpenVPN/IPsec/proxy; token+password order configurable; not for console/SSH. | TOTP auth | core | Same; add SSH TOTP via PAM optional. | N |
| SYS-AUTH-008 | Administration › Authentication settings | GUI auth servers (ordered fallback), disable integrated auth (UNIX accounts only), sudo for admins (none/no password/password; group-based), user OTP seed groups. | system_advanced_admin.php | core | Settings schema. | N |
| SYS-AUTH-009 | SSO provider framework | Redirect-capable SSO container (26.10), used by OIDC (BE). | SSOProviders | core | Part of SYS-AUTH-004. | N |

### 14.2 Configuration (`SYS-CFG`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-CFG-001 | Configuration store | Single `config.xml`, written only by frontend models; revision metadata (user, time, description); automatic backups in `/conf/backup` with Backup Count; config syshook on each save. | config.xml | core | Single versioned document (CBOR/JSON + schema) with transactional writes, history ring, change events; XML import of OPNsense `config.xml` (importer). | N |
| SYS-CFG-002 | Backups page | Download (optional encryption password; include RRD data), restore full or single area (exclude console settings default on; interface reassignment prompt on NIC mismatch), backup count. | diag_backup.php | core | Export/import endpoints; encrypted export (age/AES-GCM); area restore kept. | N |
| SYS-CFG-003 | Remote backup providers | Nextcloud (URL, user, app password, dir, strategy, add hostname, keep N days/backups) in core backups page; Google Drive (`os-gdrive-backup`), git (`os-git-backup`: URL ssh/https, branch, key, user/pass, force push, event-driven commits + nightly push), SFTP (`os-sftp-backup`: URL, key, encrypt password, count, hostname prefix), mail (`os-mail-backup`: receiver, SMTP, TLS, GPG public key); cron "Remote backup". | Backup providers + plugins | core + plugins | Pluggable backup sinks in Rust: WebDAV, S3, git (gix), SFTP (russh), SMTP+PGP. | N |
| SYS-CFG-004 | Defaults | Factory reset then shutdown; console option 4. | | core | Reset to seed config. | N |
| SYS-CFG-005 | History | Backup dropdown, diff between versions, revert (no service restart), delete, download; OPNcentral host selector (BE). | diff | core | Config history diff API. | N |
| SYS-CFG-006 | Initial setup wizard (System › Configuration › Wizard) | Hostname, domain, language, DNS servers, DNS override, Unbound enable/DNSSEC/harden, timezone, WAN (disable, ipv4 type dhcp/static/pppoe, spoof MAC, MTU, MSS, address, gateway, DHCP hostname, PPPoE creds/provider, block private/bogons), LAN (address, disable, configure DHCP), deployment type (multiwan, dhcp dns registration, max threads, multipath), root password. | InitialSetup model | core | Same wizard. | N |
| SYS-CFG-007 | Periodic backups (RRD/DHCP leases/NetFlow/CP state) | Removed in 26.7. | — | removed | Not implemented. | X |

### 14.3 Firmware (`SYS-FW`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-FW-001 | Status / updates | Check for updates, update (with reboot flag), major upgrade (console option 12, offline), changelog auto-open, update log, cron "Firmware update check"/"changelog update"/"Automatic firmware update". | pkg + opnsense-update | core | Nix channel/flake-pin updater: fetch closure, switch generation, optional reboot; changelog from release feed. | N |
| SYS-FW-002 | Settings | Mirror (list incl. Deciso commercial), flavour (OpenSSL), release type production/development, type community/business, subscription key, auxiliary; proxy via configd env. | | core (business = BE) | Channel + binary cache selection, signing keys; "subscription" → private cache token. | N |
| SYS-FW-003 | Plugins | Tier 1/2 list, show community plugins (tier 3), `-devel` variants, install/remove/info (maintainer, changelog); plugin ABI series. | pkg | core | Module manifests; install = enable NixOS module + fetch closure. | N |
| SYS-FW-004 | Packages | Installed packages, licenses, reinstall, lock. | pkg | core | Nix store listing; "lock" = pin. | N |
| SYS-FW-005 | Audits | Cleanup, Connectivity, Health (file integrity, missing deps), Security (VuXML CVE scan), Upgrade log. | pkg audit | core | Integrity via Nix store hashes; CVE scan via `vulnix`-like against NVD/OSV. | N |
| SYS-FW-006 | Crash reporter | Collect kernel/PHP crash dumps, submit to OPNsense (opt-in). | crash_reporter.php | core | Collect kernel oops/Rust panics; submit to sensr endpoint (opt-in). | N |
| SYS-FW-007 | CLI tools | `opnsense-update` (-k, -r, -b, …), `opnsense-revert`, `opnsense-patch`, `opnsense-bootstrap`, `opnsense-shell`, `opnsense-code`, `pluginctl`, `configctl`, `pkg`. | shell/python | core | `sensr` CLI: update/rollback/patch(overlay)/shell menu/service control/config query. | N |
| SYS-FW-008 | Release cadence & flavours | YY.1/YY.7 majors, ~fortnightly minors; images dvd/vga/serial/nano; BE track. | | core | Document for sensr release process. | — |

### 14.4 Gateways and multi-WAN (`SYS-GW`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-GW-001 | Gateway configuration | Disabled, name, description, interface, family, gateway IP (or dynamic from DHCP/PPP/RA), default gateway, upstream flag, far gateway, disable monitoring, disable host route, kill states on down (failover) and on priority return (failback), monitor IP, force down, nosync, priority 1–255, weight, latency low/high, loss low/high, probe interval, time period, loss interval, data length; auto-created dynamic gateways (WAN_DHCP, VPN) editable; "(active)" marker; log file. | dpinger | core | Native Rust monitor (ICMP echo per gateway, EWMA latency/loss) + rtnetlink default route management with priorities/metrics. | N |
| SYS-GW-002 | Default gateway switching | Setting in General; priority/upstream ordering; alarm on gateway change; `monitor` syshook. | rc.syshook monitor | core | Monitor events → route table update → hooks. | N |
| SYS-GW-003 | Gateway groups | Name, members with tier 1–5, trigger down/downloss/downlatency/downlosslatency, pool options default/round-robin/sticky, description; used by rules (policy routing), DNS per gateway; migrated to MVC 26.7. | pf route-to pools | core | nft `fwmark` per group + `ip route … nexthop` multipath (weights) or per-tier tables; sticky via `ct mark`. | N+K |
| SYS-GW-004 | Multi-WAN recipes | Failover, load balancing (same tier, disable shared forwarding), combined tiers, per-gateway DNS, local DNS exception rule, bypass rules, weight, state failover/failback. | | core | Documented; FW-SET-004. | N |
| SYS-GW-005 | Troubleshooting | dpinger sendto errors, `arpresolve llinfo` (far gateway), monitor IP static route. | | core | Diagnostics text. | — |

### 14.5 High availability (`SYS-HA`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-HA-001 | HA settings (System › High Availability) | Disable preempt, disconnect PPP on backup, pfsync interface, peer IP, pfsync version 1301/1400/1500 ("sync compatibility"), pfsync defer, synchronize config to IP, verify peer cert, username/password, sync items (classes). | pfsync, XMLRPC | core | conntrackd (D) for state sync; config sync over mTLS gRPC/REST (native) replacing XMLRPC. | N+D |
| SYS-HA-002 | Sync classes | Aliases, Authentication Servers, Captive Portal, Certificates and Authorities, Cron, DHCRelay, Dnsmasq DNS/DHCP, Firewall Categories, Firewall Groups, Firewall Log Templates, Firewall Rules, Firewall Schedules, Host discovery, Intrusion Detection, IPsec, Kea DHCP, Monit, NAT, Netflow/Insight, Network Time, OpenDNS, OpenSSH, OpenVPN, Router Advertisements, Shaper, Static Routes, System logging, Tunables, Unbound DNS, Users and Groups, Virtual IPs, Web GUI, WireGuard; plugins add BIND, coturn, FreeRADIUS, FRR, HAProxy, IGMP proxy, ISC DHCP, Kerberos SSO, nginx, OpenConnect, Postfix, QEMU GA, Tayga, Tinc, UPnP, Zabbix agent, NDP proxy, Authoritative DNS (BE). | `_xmlrpc_sync()` hooks | core + plugins | Every module declares a sync class (section + services to restart); same merge rules (nosync flags per item). | N |
| SYS-HA-003 | HA status page | Backup node services list, restart selected, "update and reconfigure backup" (full sync), pfsync nodes. | XMLRPC | core | Status via peer API. | N |
| SYS-HA-004 | Cron "HA update and reconfigure backup" | Runs only when all CARP interfaces MASTER. | cron | core | Scheduler job gated on VRRP state. | N |
| SYS-HA-005 | CARP how-to behaviours | Identical assignments, CARP protocol rules, dedicated pfsync interface, manual SNAT to VIP, DHCP failover peer, IPv6 CARP (GUA WAN VIP, link-local LAN VIP, RA source), maintenance mode update procedure, split-brain causes, unicast CARP, switching fabric limitations, LAGG workaround for differing NIC names. | carp/pfsync | core | VRRP + conntrackd; interface name abstraction removes NIC-name coupling. | N |
| SYS-HA-006 | XMLRPC library endpoint (`xmlrpc.php`) | Remote config sync target; privilege is effectively admin. | PHP | core | Replaced by authenticated peer API. | N |

### 14.6 Routes (`SYS-RT`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-RT-001 | Static routes | Enabled, network, gateway (from gateway list), description; don't add for VPN-managed routes. | route(8) | core | rtnetlink routes in main table (+ per-gateway tables). | K+N |
| SYS-RT-002 | Routes status | Kernel table: proto, destination, gateway, flags, use, MTU, netif, expire; flag legend. | netstat -r | core | rtnetlink dump (all tables). | N |
| SYS-RT-003 | Routing log | radvd/rtsold/routing messages. | syslog | core | Journal filter. | N |

### 14.7 Settings (`SYS-SET`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-SET-001 | Administration › Web GUI | Protocol HTTP/HTTPS, certificate, ciphers, HSTS, port, disable HTTP redirect, login messages, session timeout, DNS rebind check, alternate hostnames, HTTP compression, access log, server log, listen interfaces (must be static), HTTP_REFERER check, strict security (non-root GUI; console to undo), deployment type. | lighttpd | core | axum server config; non-root by default; CSRF/same-origin. | N |
| SYS-SET-002 | Administration › Secure Shell | Enable, permit root, password auth, port, listen interfaces, KEX/ciphers/MACs/host key/pubkey algos, `sshd_config.d` extras; ML-DSA host keys removed 26.7.8. | OpenSSH | core | OpenSSH (D) via NixOS `services.openssh` rendered from config. | D |
| SYS-SET-003 | Administration › Console | vt vs sc driver, primary/secondary console (video/serial/EFI), serial speed, USB serial, password-protect console menu, quiet login. | loader.conf/ttys | core | systemd getty/serial-getty units + kernel cmdline `console=`; console menu is a Rust TUI. | N+K |
| SYS-SET-004 | General | Hostname, domain (not `.local`), timezone, language, theme, dashboard picture (≤10 MB); networking: prefer IPv4, DNS servers (+ per-gateway binding), allow DNS override by DHCP/PPP, do not use local DNS (dnslocalhost), default gateway switching. | system_general.php | core | Settings schema; resolv.conf management. | N |
| SYS-SET-005 | Miscellaneous | Crypto hardware (aesni/qat…), thermal sensors driver, PowerD (enable, AC/battery/normal modes maximum/minimum/adaptive/hiadaptive), swap file (2 GB), /var and /tmp RAM disks (+ max size), disable beep; periodic backups removed 26.7. | powerd, tmpfs | core | cpufreq governors / `power-profiles`, hwmon sensors, zram/tmpfs, swapfile unit. | K+N |
| SYS-SET-006 | Tunables | loader.conf/sysctl entries with description/default/type; show active values. | sysctl | core | sysctl + kernel cmdline via NixOS `boot.kernel.sysctl`; curated list with defaults (hardening set: random_id, PTI, IBRS, bsd security knobs → Linux equivalents). | K |
| SYS-SET-007 | Cron | Jobs: enabled, minutes/hours/days/months/weekdays, who, command (registered configd actions only), parameters, description, origin (plugin-owned); core commands: Automatic firmware update, Download/reload external proxy ACLs, Firmware changelog update, Firmware update check, HA update and reconfigure backup, Halt, Reboot, Manual gateway switch, Periodic interface reset (param), Remote backup, Restart OpenVPN instance (param), Update and reload firewall aliases, Update and reload IDS rules, Update Unbound DNSBLs, Update GeoIP database, Update bogons, ZFS pool trim/scrub (param), Rotate log files, Renew DNS for WireGuard; plugin commands (ACME renew, OPNProxy apply, etc.). | cron + configctl | core | systemd timers generated from job table; command registry = sensr action catalogue. | N |
| SYS-SET-008 | Logging › Local | Enable local logging, max preserved files, max file size, per-app files `/var/log/<app>/<app>_YYYYMMDD.log`, "Reset log files", rotate cron. | syslog-ng | core | journald + native per-app export; retention policy. | N |
| SYS-SET-009 | Logging › Remote destinations | Enabled, transport udp4/tcp4/udp6/tcp6/tls4/tls6, applications (program filter), levels debug…emerg, facilities, hostname, port 514, certificate (client cert), RFC5424 format, suppress, description. | syslog-ng | core | Native Rust syslog forwarder (RFC 3164/5424, TLS via rustls) reading journald. | N |
| SYS-SET-010 | Snapshots (System › Snapshots) | ZFS boot environments: create, activate, delete, rename; states N/R/NR; loader menu option 8; recommended workflow; ZFS only. | bectl | core | NixOS generations list/select/delete (+ ZFS snapshot of /var when ZFS); boot menu via systemd-boot/GRUB entries. | N+K |
| SYS-SET-011 | Scheduled jobs (one-shot) | BE: time, until, command, params. See BE-006. | | BE | systemd one-shot timers; in core for sensr. | N |

### 14.8 Trust (`SYS-TRUST`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-TRUST-001 | Authorities | Method existing/import, internal, OCSP signing; key type RSA 512–8192 / P-256/384/521; digest sha1…sha512; lifetime; DN (country, state, city, org, OU, email, CN); OCSP URI; issuer (self or parent CA); serial counter; refcount. | OpenSSL (PHP) | core | Rust PKI (`rcgen`, `x509-cert`, `rsa`, `p256/p384`, `ed25519` added). | N |
| SYS-TRUST-002 | Certificates | Method internal/external(CSR)/import/sign CSR/import CSR/reissue/manual; type user/server/combined/CA; key type/digest/lifetime; private key location firewall/local (download only); DN; OCSP URI; SANs DNS/IP/URI/email; RFC3280 purpose; in-use flag; is-user cert; CN↔user lookup. | OpenSSL | core | Same. | N |
| SYS-TRUST-003 | Revocation (CRLs) | Per CA: create/import, add/remove revoked certs with reason (unspecified, key compromise, CA compromise, affiliation changed, superseded, cessation, hold), lifetime, serialNumberHex handling, download. | OpenSSL | core | Same. | N |
| SYS-TRUST-004 | Trust settings | Store intermediates, install CRLs, auto-fetch CRLs (hourly from CDP), enable legacy OpenSSL providers, enable config constraints: CipherString, Ciphersuites, SignatureAlgorithms, groups/curves, MinProtocol TLS1…1.3, MinProtocol DTLS; trust store deployment (`certctl`, `/etc/ssl/certs`). | openssl.cnf, certctl | core | System trust store (p11-kit/`update-ca-certificates` on NixOS) + rustls policy for sensr's own listeners; daemons get rendered TLS policy. | N |
| SYS-TRUST-005 | OCSP | AIA extension from OCSP URI; OCSP signing certs; index export for `openssl ocsp` testing; no responder built in. | | core | Optional native OCSP responder (improvement). | N |
| SYS-TRUST-006 | ACME client (`os-acme-client`) | Settings: enabled, auto renewal, cron, environment prod/staging, HTTP/TLS challenge ports, restart timeout, HAProxy integration refs, log level; accounts (CA buypass/google/letsencrypt/sslcom/zerossl/custom + test variants); certificates (names/SANs, key length 2048/3072/4096/ec256/ec384, alias mode none/automatic/domain/challenge, OCSP must-staple); validations (http01 via OPNsense or HAProxy, dns01 with ~150 acme.sh providers + lexicon providers, tlsalpn01); automations (restart GUI/HAProxy/nginx, reload Caddy, upload SFTP, remote SSH, FRITZ!Box, PAN-OS, Proxmox VE/BS, Ruckus, Vault, Synology, TrueNAS (+ws/websocat), Zyxel, UniFi, JetKVM, generic configd); logs. | acme.sh + dns-lexicon | plugin | Native ACME client in Rust (`instant-acme`) with HTTP-01/TLS-ALPN-01/DNS-01; DNS provider trait shared with DDNS; automations as action hooks. Caddy/OPNWAF-style built-in ACME for GUI cert. | N |

### 14.9 Diagnostics (`SYS-DIAG`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| SYS-DIAG-001 | Activity | Process grid (PID, user, pri, nice, size, res, C, time, WCPU, command), load/process counts. | top | core | procfs reader. | N |
| SYS-DIAG-002 | Services | List configured services with start/stop/restart (incl. hidden services via `pluginctl -s`); dashboard services widget. | configd service registry | core | systemd unit registry per module. | N |
| SYS-DIAG-003 | System statistics (Diagnostics › Statistics) | Memory (vmstat), mbuf, ZFS ARC, disk usage (26.10 bytes). | sysctl | core | /proc/meminfo, statvfs. | N |
| SYS-DIAG-004 | Log viewers | General, Backend (configd), Boot, Web GUI, Audit, Firmware (pkg), Gateways, Routing, PPP, Wireless, per-service logs; grid search with "go to page", severity filter. | syslog-ng per-app logs | core | journald query API with per-unit filters. | N |
| SYS-DIAG-005 | Troubleshooting procedures | Password reset (single-user), reset firmware config (`pluginctl -f`), config restore via console (Ctrl+C shell, copy backup), web GUI reset (console option 2, `configctl webgui restart renew`), boot/serial loader hints, hardening tunables vs performance, netmap pitfalls, RSS tuning. | | core | Equivalent NixOS procedures: recovery generation, `sensr-shell` TUI, boot-time rescue. | N |

## 15. Dynamic routing (`RTG`, plugin `os-frr`)

Sources: dynamic_routing.rst, how-tos dynamic_routing_{bfd,bgp,ospf,rip}; plugin models General/BGP/OSPF/OSPF6/RIP/BFD/STATICd.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| RTG-001 | General | Enable (zebra), daemons bfd/bgp/ospf/ospf6/rip/static, manual config, profile traditional/datacenter, CARP failover (run only on master), syslog + level, SNMP AgentX, auto firewall rules (OSPF 89 mcast, OSPFv3 ff02::5/6, BGP 179, BFD 3784/4784, RIP 520). | FRR 10 | plugin (tier 2) | FRR (D) via vtysh/`frr-reload.py`; later northbound gRPC. | D |
| RTG-002 | BGP | AS, distance, router ID, graceful restart, network import check, enforce first AS, log neighbor changes, networks, bestpath modifiers (as-path confed/multipath-relax, compare-routerid, peer-type multipath-relax, aigp, med missing-as-worst), max paths eBGP/iBGP; neighbors (family, peer IP, remote AS mode internal/external/number, local AS + options, MD5, weight, update-source, link-local interface, next-hop-self/all, multihop, RR client, soft reconfig, BFD (+strict), timers, send default, AS-override, remove private AS variants, allowas-in 1–10/origin, disable connected check, attribute unchanged, capabilities extended-nexthop/dynamic/fqdn/link-local, prefix/route-map in/out, peer group); AS-path lists, prefix lists (v4/v6, seq, ge/le), community lists (standard/expanded), route maps (match lists, set), peer groups (listen ranges), redistribution (ospf/connected/kernel/rip/static + route map). | bgpd | plugin | FRR config renderer. | D |
| RTG-003 | OSPFv2 | Enable, CARP demote, router ID, reference cost, log adjacency, originate default (always, metric); areas (id, type stub/stub no-summary/nssa/nssa no-summary, ranges, prefix-list in/out); networks (legacy); neighbors (NBMA); interfaces (area, auth none/plain/md5 + key id, passive, cost, cost when demoted, depend on CARP, hello/dead/retransmit intervals, transmit delay, priority, BFD, network type broadcast/NBMA/p2mp (+options)/p2p); prefix lists; route maps; redistribution. | ospfd | plugin | FRR. | D |
| RTG-004 | OSPFv3 | Same minus auth/reference cost; areas normal/nssa; interface network type broadcast/p2p. | ospf6d | plugin | FRR. | D |
| RTG-005 | RIP (legacy) | Enable, version 1/2, networks, passive interfaces, redistribute, default metric. | ripd | plugin (legacy) | FRR; low priority. | D |
| RTG-006 | BFD | Enable; neighbors (peer, multihop, local address, interface, detect multiplier, rx/tx intervals). | bfdd | plugin | FRR. | D |
| RTG-007 | STATICd | Routes with network, gateway, interface, BFD dependency. | staticd | plugin | FRR or native (overlaps SYS-RT). | D |
| RTG-008 | Diagnostics | General (routes v4/v6), OSPF/OSPFv3/BGP/BFD summaries, log. | vtysh show | plugin | vtysh JSON output. | D |
| RTG-009 | HA interplay | CARP failover mode, OSPF demotion via log monitor, costs by CARP state, unicast CARP for eBGP; recipes: iBGP/eBGP, OSPF over VTI failover, GRE over policy IPsec. | | plugin | VRRP hooks + FRR. | D |

## 16. Reporting (`REP`)

Sources: systemhealth.rst, netflow.rst, reporting_settings.rst, reporting_traffic.rst, how-tos insight/netflow_exporter, reporting_unbound_dns.rst (see DNS-UB-009); core `Diagnostics/*.xml`.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| REP-001 | System Health (RRD) | Collectors: packets (pps/interface), quality (gateway latency/loss), system (memory, mbufs, states, processes, CPU temp), traffic (per interface incl. IPsec), NTP; GUI: dataset/resolution, inverse, tables (min/max/avg), label filter, zoom, timestamp toggle, CSV export; enable/disable + reset in Reporting settings. | rrdtool | core | Native TSDB (fixed-interval ring files or SQLite); same graphs. | N |
| REP-002 | NetFlow exporter | Interfaces, egress-only, version v5/v9, destinations ip:port, capture local, active/inactive timeouts. | ng_netflow | core | Native exporter from conntrack events (`nf_conntrack` netlink destroy events carry byte/packet counts) → NetFlow v5/v9/IPFIX. | N |
| REP-003 | Insight (NetFlow analyzer) | 5 detail levels (2h/30s … year/24h), stacked/stream/expanded graphs, top 25 IPs/ports per interface, interface totals, details with date range & filters (≤2 months), export collections (FlowSourceAddrTotals, FlowInterfaceTotals, FlowDstPortTotals, FlowSourceAddrDetails) at 300/3600/86400. | flowd + python aggregator (SQLite) | core | Native aggregator over the same flow stream. | N |
| REP-004 | Traffic (Reporting › Traffic) | Live in/out bps per interface, polling resolution, top-consumer host graph, top talkers grid (address, traffic, last seen); dashboard traffic widget. | iftop | core | Per-interface counters + conntrack sampling. | N |
| REP-005 | Reporting settings | Unbound stats enable/reset, RRD disable/reset, NetFlow reset. | | core | Same. | N |
| REP-006 | Unbound DNS reporting | See DNS-UB-009. | | core | | N |
| REP-007 | Firewall log overview / IDS alerts / CP sessions | See FW-LOG-003, IDS-006, CP-004. | | core | | N |

## 17. Plugins by repository category (`PLG`)

All 102 plugins in `opnsense/plugins` at the reference commit, grouped by category directory, with the Makefile `PLUGIN_COMMENT`, tier (Makefile `PLUGIN_TIER`; blank = tier 1/community default; tier 2 = OPNsense-maintained but optional; "tier 3" in docs = shown only with "show community plugins"), FreeBSD dependency, and the sensr disposition. Plugins already inventoried in detail above are cross-referenced rather than repeated.

### 17.1 benchmarks

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-BENCH-001 | os-iperf 2.0 | Connection speed tester: Interfaces › Diagnostics › Iperf server instances (port, interface, timeout) and client (reworked 26.7.7). | iperf3 | plugin | Embed iperf3 (D) or `iperf3`-compatible Rust server; expose in Diagnostics. | D |

### 17.2 databases

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-DB-001 | os-redis 1.1 | Redis DB: enable, bind, port, password, databases, maxmemory; dependency for ntopng, rspamd, OPNProxy. | redis 7.2 | plugin | Redis/Valkey (D) only as a dependency of those modules; no standalone UI priority. | D |

### 17.3 devel

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-DEV-001 | os-debug 1.7 | Debugging tools (phpcs, etc.) for developers. | php tooling | plugin (tier 2) | Dev-only crate features; not a product feature. | X |
| PLG-DEV-002 | os-helloworld 1.4 / os-grid_example 1.1 | Sample framework applications (form page, grid page). | MVC | plugin | sensr module template / cookbook example. | N (dev docs) |

### 17.4 dns

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-DNS-001 | os-bind 1.34 | BIND domain name service → DNS-BIND-001. | bind 9.20 | plugin | Native authoritative server. | N |
| PLG-DNS-002 | os-ddclient 1.33 | Dynamic DNS client → DNS-DDNS-001. | ddclient / python | plugin | Native. | N |
| PLG-DNS-003 | os-dnscrypt-proxy 1.17 | DNSCrypt/DoH proxy → DNS-DNSCRYPT-001. | dnscrypt-proxy2 | plugin | Native upstream encryption. | N |
| PLG-DNS-004 | os-rfc2136 1.10 | RFC 2136 dynamic update client (legacy PHP) → DNS-RFC2136-001. | bind-tools | plugin | Folded into DDNS. | N |

### 17.5 emulators

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-EMU-001 | os-qemu-guest-agent 1.3 | QEMU guest agent: enable, log; HA sync class. | qemu-guest-agent | plugin | `qemu-guest-agent` NixOS service toggle. | D |

### 17.6 ftp

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-FTP-001 | os-tftp 1.0 | TFTP server: enable, listen address/interface, root dir, file upload. | tftp-hpa | plugin | Native TFTP server (Rust `tftpd`) — pairs with PXE DHCP boot options. | N |

### 17.7 mail

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-MAIL-001 | os-postfix 1.24.1 | SMTP mail relay/gateway: general (hostname, domain, origin, interfaces, port, IP version, bind addresses, mynetworks, banner, size limit, masquerade, TLS server/client compatibility modern/intermediate/old, wrapper mode, cert/CA, smtp client security none/may/encrypt/dane, relayhost + SASL auth, recipient check, HELO/sender restrictions (10 reject_* toggles), permit_* toggles, delay warning); domains; recipients (OK/REJECT); recipient/sender BCC; senders; sender canonical; header checks (while delivering/receiving); address rewriting; antispam (rspamd milter, default action accept/tempfail); HA sync. | postfix | plugin | postfix (D). Mail gateway is niche for a firewall; keep as optional module. | D |
| PLG-MAIL-002 | os-rspamd 1.13 | Spam filter: general (Redis, Bayes autolearn, reject/header/greylist/subject scores, rewrite subject, history rows, nameserver), milter headers, greylisting, DKIM verification options, MX check, phishing (OpenPhish/PhishTank), rate limits (per recipient/IP/from/bounce/user), spamtrap, SPF cache, AV force-reject. | rspamd | plugin | rspamd (D) optional. | D |

### 17.8 misc (themes)

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-THEME-001 | os-theme-advanced 1.1, os-theme-cicada 1.42, os-theme-flexcolor 1.1, os-theme-rebellion 1.9.8, os-theme-tukan 1.32, os-theme-vicuna 1.52 | GUI themes (AdvancedTomato-based; dark onyx; 3 colour schemes; dark; blue/white; blue sapphire). | CSS | plugin | Theme packs = CSS variable sets; ship light/dark/auto; allow community packs. | N |

### 17.9 net

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-NET-001 | os-chrony 1.5 | Chrony time sync → NTP-005. | chrony | plugin | Default NTP backend. | D |
| PLG-NET-002 | os-cloudflared 1.1 | Cloudflare Tunnel: enabled, token, protocol auto/quic/http2, post-quantum, disable QUIC PMTU, edge IP version, log level; QUIC buffer tunables; multi-WAN rule recipe; healthcheck. | cloudflared | plugin | cloudflared (D). | D |
| PLG-NET-003 | os-firewall-legacy 1.1 | Legacy static PHP firewall rules + outbound NAT pages → FW-013, NAT-007. | PHP | plugin (new 26.7) | Importer only. | X |
| PLG-NET-004 | os-freeradius 1.10.3 | RADIUS AAA server: general (enable, VLAN assignment + fallback VLAN/tunnel password, LDAP, EXOS/WISPr/ChilliSpot/MikroTik dictionaries, SQLite, session limit, log destination/auth logging, DHCP server + listen IP, MySQL backend, fallback proxy); users (password cleartext/NT, service type, IP/mask, VLAN, AV pairs, expiry); clients (NAS secret/IP); DHCP + leases; EAP (default type md5/pwd/mschapv2/peap/tls/ttls, TTLS inner, EC curve, client cert, CA/cert/CRL, TLS names, TLS min/max); LDAP (+ group mapping); proxy (home servers auth/acct/coa, UDP/TCP, status checks; pools fail-over/load-balance/client-balance/…; realms); AV pairs; HA sync. | freeradius3 | plugin | FreeRADIUS (D). Also evaluate native RADIUS server (`radius` crate) for the common 802.1X/WPA-Enterprise case. | D |
| PLG-NET-005 | os-frr 2.1 | FRRouting → §15. | frr10 | plugin (tier 2) | FRR (D). | D |
| PLG-NET-006 | os-ftp-proxy 1.0 | Control ftp-proxy processes: instances (listen address/port, source address, reverse mode, log, rewrite source port, max sessions, timeout, debug) + NAT rules. | ftp-proxy(8) (pf) | plugin | nft `ct helper ftp` (kernel `nf_conntrack_ftp`) covers active FTP NAT; no proxy daemon needed. | K |
| PLG-NET-007 | os-google-cloud-sdk 1.0 | Google Cloud SDK (gcloud CLI) for GCE images. | google-cloud-sdk | plugin | Cloud-init/metadata handled by NixOS image profile. | X |
| PLG-NET-008 | os-haproxy 5.1 | TCP/HTTP load balancer: service settings (graceful stop, hard stop after, seamless reload, OCSP store), peers/session sync, global params (resolvers prefer v4/v6, SSL verify, bind options, min/max TLS), defaults (redispatch, init_addr), logging (facility/level), statistics (built-in stats page), cache; frontends (mode http/ssl/tcp, bind, SSL options, client auth none/optional/required, stick tables pattern/data types (25 types), advertised protocols h3/h2/http11/http10, connection behaviour), backends (mode, algorithm source/roundrobin/static-rr/leastconn/uri/random, proxy protocol v1/v2, resolver opts, health check proxy proto, forwarded header params, persistence sticktable/cookie, http-reuse), servers (active/backup/disabled, mux fcgi/h2/h1, static/template/unix), health checks (tcp/http/agent/ldap/mysql/pgsql/redis/smtp/esmtp/ssl; HTTP method/version/expression), actions (rules), ACLs (~40 expressions incl. hdr/path/http_auth/nbsrv/ssl/sc_*), users/groups, Lua scripts, FastCGI apps, error files, map files, resolvers, mailers; statistics (overview/status/counters/stick tables), maintenance (server state), config export, log; ACME integration; HA sync. | haproxy 3.2 | plugin | HAProxy (D) with full schema; runtime API socket for stats/maintenance. | D |
| PLG-NET-009 | os-igmp-proxy 1.5 | IGMP proxy (legacy PHP): enable, upstream/downstream interfaces, networks, threshold; needed for IPTV recipes; HA sync. | igmpproxy | plugin | igmpproxy (D) or smcroute; MVC-ify. | D |
| PLG-NET-010 | os-isc-dhcp 1.0 | ISC DHCPv4/v6 server [legacy] → DHCP-ISC-001. | isc-dhcp44 | plugin (tier 2, legacy) | Out of scope; importer. | X |
| PLG-NET-011 | os-mdns-repeater 1.2 | mDNS repeater → DNS-MDNS-001. | mdns-repeater | plugin | Native reflector. | N |
| PLG-NET-012 | os-ndp-proxy-go 1.5 | NDP proxy → DNS-NDPPROXY-001. | ndp-proxy-go | plugin | Native. | N+K |
| PLG-NET-013 | os-netflector 1.0 | Link-local service discovery reflection → DNS-NETFLECTOR-001. | netflector | plugin | Merged reflector. | N |
| PLG-NET-014 | os-ntopng 1.3 | Traffic analysis & flow collection: enable, interfaces, HTTP port 3000, DNS mode; requires Redis; plain HTTP UI. | ntopng | plugin | ntopng (D) optional; REP-003/REP-004 cover basics natively. | D |
| PLG-NET-015 | os-radsecproxy 1.1 | RADIUS proxy with UDP/TCP/TLS/DTLS: general (log level, log full username, MAC logging modes, loop prevention, listen/source per transport), clients (type, cert name check), servers (status-server, type), TLS configs (CRL check), realms (accounting response), rewrite rules (whitelist mode). | radsecproxy | plugin | radsecproxy (D). | D |
| PLG-NET-016 | os-realtek-re 1.0 | Realtek re(4) vendor driver kmod. | realtek-re-kmod | plugin | Linux `r8169`/`r8125` in-tree; N/A. | X |
| PLG-NET-017 | os-relayd 2.9 | Relayd load balancer: general (interval, log updates/all, prefork, timeout), hosts (address, TTL, priority, retry), tables, table checks (icmp/tcp/tls/send/script/http + path/host/code/digest/expect/ssl), virtual servers (relay/redirect, listen address/proto/port range/interface, transport forward/route + routing interface, table, port, interval, timeout, mode hash/least-states/loadbalance/random/roundrobin/source-hash, backup table, session timeout, sticky), protocols (tcp/dns/http options); status page with host enable/disable. | relayd | plugin (tier 2) | Redirect mode → nft DNAT with `numgen`/`jhash` to a dynamic set maintained by native health checker; relay mode → HAProxy TCP. | N+K |
| PLG-NET-018 | os-shadowsocks 1.3 | → VPN-SS-001. | shadowsocks-rust | plugin | See cross-referenced row. | D |
| PLG-NET-019 | os-siproxd 1.3 | SIP proxy: inbound/outbound interface, outbound host, allow reg/SIP nets, deny nets, SIP port, RTP port range/timeout/DSCP, SIP DSCP, dejitter, proxy auth, TCP timeouts/keepalive, UA string, rport mode, plugins (default target, fix bogus via, fix DTAG, Fritz!Box anon call, STUN); users; domains. | siproxd | plugin | nft SIP conntrack helper (`nf_conntrack_sip`) covers most NAT cases; siproxd (D) optional. | K/D |
| PLG-NET-020 | os-sslh 1.0 | → VPN-SSLH-001. | sslh | plugin | See cross-referenced row. | N/D |
| PLG-NET-021 | os-tayga 1.5 | NAT64 → DNS-NAT64-001. | tayga | plugin | Jool. | K+N |
| PLG-NET-022 | os-turnserver 1.4 | coturn STUN/TURN: enabled, listen IP/port, relay port range, external IPs, TLS (cert, port), auth secret (static), realm, fingerprints, user/total quota, stale nonce, channel/permission lifetimes; HA sync. | coturn | plugin | coturn (D). | D |
| PLG-NET-023 | os-udpbroadcastrelay 1.0 | UDP broadcast relay instances: interfaces, multicast address(es), source address, port, instance ID, revert TTL, description. | udpbroadcastrelay | plugin | Native UDP broadcast/multicast relay (merge into reflector service). | N |
| PLG-NET-024 | os-upnp 1.10 | UPnP IGD & PCP/NAT-PMP (legacy PHP): enable, interfaces, external interface, UPnP/NAT-PMP toggles, default deny, allowed users/ports ACL, log, presentation URL/model, STUN; status (active maps); HA sync. | miniupnpd | plugin | miniupnpd (D) with nft backend, or native PCP/UPnP IGD in Rust (manageable scope). | D→N |
| PLG-NET-025 | os-vnstat 1.4 | Network traffic monitor: enable, interfaces, month rotate day; hourly/daily/monthly tables. | vnstat | plugin | Covered by native REP-001/REP-004 counters with long-term rollups. | N |
| PLG-NET-026 | os-wol 2.5 | Wake on LAN: entries (interface, MAC, description), wake single/all, ARP-table picker. | wol | plugin | Native magic packet sender. | N |
| PLG-NET-027 | os-zerotier 1.3.2 | → VPN-ZT-001. | zerotier | plugin | See cross-referenced row. | D |

### 17.10 net-mgmt

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-MGMT-001 | os-collectd 1.4 | Metrics collection: enable, hostname, interval, network plugin (server/port), graphite/influx outputs, plugins list. | collectd5 | plugin | Native metrics exporter (OpenMetrics) replaces collectd/munin/nrpe/zabbix-agent/node_exporter family; plus collectd network protocol sender if demanded. | N |
| PLG-MGMT-002 | os-lldpd 1.2 | LLDP daemon: enable, interfaces, CDP/EDP/FDP/SONMP compatibility, description/name/location overrides, neighbors view. | lldpd | plugin | lldpd (D) with JSON neighbor output; neighbours shown in Interfaces. | D |
| PLG-MGMT-003 | os-net-snmp 1.7 | SNMP agent: enabled, community, syslocation/contact, L3 visibility, version OID, AgentX, Observium MIB, listen; SNMPv3 users. | net-snmp | plugin | net-snmp (D) or native SNMP agent (`snmp` crate) exposing IF-MIB/HOST-RESOURCES; AgentX for FRR. | D |
| PLG-MGMT-004 | os-netdata 1.2 | Real-time performance monitoring (web UI, streaming). | netdata | plugin | netdata (D) optional. | D |
| PLG-MGMT-005 | os-nrpe 1.2 | Nagios NRPE: general (listen, allowed hosts, args), commands. | nrpe | plugin | Low priority; metrics endpoint instead. | X/D |
| PLG-MGMT-006 | os-telegraf 1.12.15 | Telegraf agent: general (interval, round, batch/buffer, jitter, flush, hostname), inputs (cpu, disk, diskio, internet_speed, mem, processes, swap, system, network, pf, ping/ping6, haproxy, zfs, ntpq, IDS alerts, unbound, apcupsd), outputs (InfluxDB v1/v2, Graphite, Graylog, Elasticsearch, Prometheus, Datadog, MQTT, OpenTelemetry), keys. | telegraf | plugin | telegraf (D) optional; native OpenMetrics/OTLP exporter covers most. | D |
| PLG-MGMT-007 | os-zabbix-agent 1.19 | Zabbix agent: main (server, hostname, listen), features (remote commands, user params), tuning; HA sync. | zabbix agent | plugin | zabbix-agent2 (D). | D |
| PLG-MGMT-008 | os-zabbix-proxy 1.17 | Zabbix proxy: settings (server, hostname, DB, timeouts), log. | zabbix proxy | plugin | zabbix-proxy (D) optional. | D |

### 17.11 security

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-SEC-001 | os-acme-client 4.18 | → SYS-TRUST-006. | acme.sh | plugin | Native ACME. | N |
| PLG-SEC-002 | os-clamav 1.8.1 | ClamAV: clamd/freshclam enable, TCP, limits (threads, queue, idle, dir recursion), symlinks/cache, scan options (PE/ELF/broken/OLE2/macros/PDF/SWF/XML/HWP3/mail/HTML/archives/encrypted), size/recursion/file limits, logging, mirror, timeout, extra signature sources (MalwareExpert, URLhaus, JURLBL, Bofhland), custom URL lists. | clamav | plugin | ClamAV (D). | D |
| PLG-SEC-003 | os-crowdsec 1.0.12 | CrowdSec security engine: agent/LAPI/firewall bouncer toggles, LAPI listen, manual LAPI config, rules enable/log/tag, enroll key; views machines, bouncers, alerts, decisions, collections, scenarios, parsers, postoverflows, appsec rules/configs; Caddy integration. | crowdsec + firewall bouncer | plugin | crowdsec (D) with nft bouncer feeding a sensr alias set. | D |
| PLG-SEC-004 | os-etpro-telemetry 1.8 | → IDS-008. | python | plugin (tier 2, vendor) | See cross-referenced row. | X? |
| PLG-SEC-005 | os-intrusion-detection-content-{at-antiphishing, et-open, et-pro, ptopen, snort-vrt} | IDS ruleset metadata packs → IDS-002. | metadata XML | plugin | Native ruleset manifests. | N |
| PLG-SEC-006 | os-maltrail 1.10 | Malicious traffic detection: general (heuristics, host header check, update period, admin password, monitor interface, whitelist), sensor (capture all, buffer, remote server/port, syslog), server (listen, log listen, blocklist alias). | maltrail | plugin | maltrail (D) optional; overlaps IDS + threat feeds. | D |
| PLG-SEC-007 | os-netbird 1.3 | → VPN-NB-001. | netbird | plugin | See cross-referenced row. | D |
| PLG-SEC-008 | os-openconnect 1.4.6 | → VPN-OC-001. | openconnect | plugin | See cross-referenced row. | D |
| PLG-SEC-009 | os-openvpn-legacy 1.0 | → VPN-OVPN-009. | PHP | legacy plugin | See cross-referenced row. | X |
| PLG-SEC-010 | os-q-feeds-connector 1.7.d | → IDS-009. | python | vendor plugin (tier 2) | See cross-referenced row. | N (generic connector) |
| PLG-SEC-011 | os-strongswan-legacy 1.0 | → VPN-IPSEC-015. | PHP | legacy plugin | See cross-referenced row. | X |
| PLG-SEC-012 | os-stunnel 1.0.6 | → VPN-STUNNEL-001. | stunnel | plugin (tier 2) | See cross-referenced row. | N |
| PLG-SEC-013 | os-tailscale 1.4 | → VPN-TS-001. | tailscale | plugin | See cross-referenced row. | D |
| PLG-SEC-014 | os-tinc 1.8 | → VPN-TINC-001. | tinc | plugin | See cross-referenced row. | D |
| PLG-SEC-015 | os-tor 1.10 | Tor: general (enable, SOCKS listen interfaces/port, control port + password, log file/syslog levels, scheduler, fascist firewall + ports, transparent proxy port/DNS port/IP pool, map hosts, client auths, max memory queues), SOCKS ACL (v4/v6 accept/reject), exit policy ACL (type/network/ports/action), hidden services (basic/stealth, clients) + routing (port→target), relay (host, v6, outbound bind, port, dir port, nickname, contact, family, bandwidth rate/burst, relay/bridge, reject private, publish, exit, exit v6, reject local if); info and diagnostics pages. | tor | plugin | tor (D). | D |
| PLG-SEC-016 | os-wazuh-agent 1.3 | Wazuh agent: manager hostname, enable, auth password, debug; log ingestion from syslog apps + IDS eve; custom ossec.conf snippets; active response `opnsense-fw` (block IP via alias); logs ossec/active-responses. | wazuh-agent | plugin (tier 3 support) | wazuh-agent (D) with active-response hook into alias set API. | D |

### 17.12 sysutils

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-SYS-001 | os-apcupsd 1.2 | APC UPS daemon: UPS name, cable (19 types), type apcsmart/usb/net/snmp/netsnmp/dumb/pcnet/modbus, device, polltime, netserver + address/port, on-battery delay, battery level, minutes, timeout, annoy, kill delay, class, mode, nologon; status; log. | apcupsd | plugin | NUT covers APC via `usbhid-ups`/`apcsmart`; apcupsd (D) optional. | D |
| PLG-SYS-002 | os-beats 1.0 | Filebeat → Elasticsearch: modules (suricata), inputs (audit, configd, boot, system, lighttpd), output ES + SSL verification mode. | beats8 | plugin | Native log shipper targets (Elastic/OpenSearch bulk API) in SYS-SET-009. | N |
| PLG-SYS-003 | os-cpu-microcode 1.1 (amd/intel) | Early-load CPU microcode; x86info check; flaky with 26.7 loader. | cpu-microcode | plugin | NixOS `hardware.cpu.{intel,amd}.updateMicrocode` default on. | K |
| PLG-SYS-004 | os-dec-hw 1.1 | Deciso hardware info (dashboard/API info). | | plugin (tier 2, vendor) | Generic hardware info widget (dmidecode/sysfs). | N |
| PLG-SYS-005 | os-dmidecode 1.2 | Hardware information dashboard widget. | dmidecode | plugin | sysfs DMI reader widget. | N |
| PLG-SYS-006 | os-gdrive-backup 1.0 | Config backup to Google Drive (service account P12, folder id, count). | google-api-php-client | plugin | Backup sink via Drive API (reqwest). | N |
| PLG-SYS-007 | os-git-backup 1.1 | → SYS-CFG-003. | git | plugin (tier 2) | gix. | N |
| PLG-SYS-008 | os-hw-probe 1.0 | Collect hardware diagnostics (upload to linux-hardware.org style probe). | hw-probe | plugin | `hw-probe` exists for Linux; optional. | D |
| PLG-SYS-009 | os-lcdproc-sdeclcd 1.1 | LCDproc for SDEC LCD front panels. | lcdproc | plugin | lcdproc (D) optional; niche hardware. | X/D |
| PLG-SYS-010 | os-mail-backup 1.1 | → SYS-CFG-003 (SMTP + GPG). | phpmailer, gnupg | plugin | lettre + sequoia-openpgp. | N |
| PLG-SYS-011 | os-munin-node 1.1 | Munin node: hostname, port, allowed networks. | munin-node | plugin | Low priority; metrics endpoint. | X/D |
| PLG-SYS-012 | os-nextcloud-backup 1.2 | → SYS-CFG-003. | WebDAV | plugin | WebDAV sink. | N |
| PLG-SYS-013 | os-node_exporter 1.2 | Prometheus exporter: listen address/port, collectors cpu/exec/filesystem/loadavg/meminfo/netdev/time/devstat/interrupts/ntp/zfs. | node_exporter | plugin | Native OpenMetrics endpoint (sensr metrics) + optional node_exporter (D). | N |
| PLG-SYS-014 | os-nut 1.9 | Network UPS Tools: mode standalone/netclient, name, listen, admin/monitor passwords, drivers usbhid/apcsmart/apcupsd/bcmxcp-usb/blazer usb+ser/qx/riello/snmp (+args), netclient (address/port/user/pass); diagnostics (device vars); shutdown on low battery. | nut | plugin | NUT (D) via NixOS `power.ups`. | D |
| PLG-SYS-015 | os-puppet-agent 2.0 | Puppet/OpenVox agent: FQDN, environment, run interval/timeout, cache on failure; logs. | openvox-agent | plugin | Config-management is the NixOS flake itself; optional. | X |
| PLG-SYS-016 | os-sftp-backup 1.2 | → SYS-CFG-003. | sftp | plugin (tier 2) | russh. | N |
| PLG-SYS-017 | os-smart 2.4 | SMART tools: device list, info/attributes/self-test/log views, run tests. | smartmontools | plugin | smartctl JSON (D) in Diagnostics. | D |
| PLG-SYS-018 | os-virtualbox 1.0 / os-vmware 1.5 (tier 2) / os-xen 1.2 | Guest additions / open-vm-tools / xe-guest-utilities. | guest tools | plugin | NixOS `virtualisation.{virtualbox.guest,vmware.guest,xe-guest-utilities}` toggles. | D |

### 17.13 vendor

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-VENDOR-001 | os-sunnyvalley 1.5 | Vendor repository enabler for Zenarmor (installs `os-sensei`). → VND-001. | pkg repo | vendor (tier 2) | Third-party repo mechanism: sensr "external module channel" (binary cache + manifest). | N |

### 17.14 www

| ID | Plugin | Comment / scope | Backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLG-WWW-001 | os-c-icap 1.9 | c-icap server: general (timeout, keepalive, servers/threads, listen, admin, servername, access log, local squid), antivirus (ClamAV, scan file types TEXT/DATA/EXECUTABLE/ARCHIVE/GIF/JPEG/MSOFFICE, send percent data, 204 responses, pass on error, max object size). | c-icap + modules | plugin | c-icap (D) only with Squid module. | D |
| PLG-WWW-002 | os-cache 1.0 | Webserver cache (Squid helper package). | | plugin | Part of Squid module. | D |
| PLG-WWW-003 | os-caddy 2.2.3 | Reverse proxy with automatic HTTPS, DynDNS, L4: general (enable, L4, strict SNI, HTTP/HTTPS ports, ACME email, auto HTTPS modes, DNS provider cloudflare + API key, propagation settings, ECH domain, access lists, client IP headers, proxy protocol allow, superuser toggle, grace period, HTTP versions h1/h2/h3, timeouts, log credentials/plain access log/keep, log level, DynDNS (simple HTTP, interface, interval, IP versions, TTL, update only), auth provider authelia/authentik + target, copy headers); domains (TLS disable, client auth mode), subdomains, handlers (handle/handle_path, reverse_proxy/redir, upstream TLS modes, HTTP version, lb policy first/round_robin/least_conn/ip_hash/client_ip_hash/uri_hash), access lists (client_ip/remote_ip), basic auth, headers up/down, layer4 routes (listener_wrappers/global, tcp/udp, matchers incl. OpenVPN modes, SNI, remote IP, TLS terminate, proxy protocol); diagnostics (Caddyfile, validate, JSON); custom imports; HA/ACME patterns. | caddy-custom (caddy-l4, dynamicdns, dns/cloudflare) | plugin | Caddy (D) — strong default reverse proxy for sensr; native ACME for the GUI itself. | D |
| PLG-WWW-004 | os-nginx 1.36 | Nginx HTTP server/reverse proxy: general (ban TTL, limit GUI networks, worker processes/connections, sendfile, keepalive, reset timedout, default type, hash sizes, ban response 403/444, log perm ban, bots UA list, headers_more); users/credentials/userlists; upstreams (ip_hash, keepalive, host port, X-Forwarded-Host verbatim, proxy protocol, store, TLS client cert/name override/protocols/session reuse/trusted cert/verify/depth) + servers (priority, max conns/fails, fail timeout, down/backup); locations (match type =/~/~*/^~, WAF enable/learning/error page/XSS/SQLi scores, root, PHP, router script, auth, headers); HTTP servers (TLS, client auth, security headers, TLS fingerprints); stream servers (TCP/UDP, SNI maps, TLS terminate); WAF (NAXSI main/basic rules, policies, match zones); security headers; IP ACLs; bans view; TLS fingerprint analysis; VTS traffic statistics; logs (HTTP/stream access/error); HA sync. | nginx (+naxsi, headers_more, vts) | plugin | nginx (D) optional alongside Caddy; WAF via Coraza/ModSecurity-compatible module (see BE-003). | D |
| PLG-WWW-005 | os-OPNProxy 1.0.5 | Squid access-control policies: users/groups/networks audience, categorized lists + custom domain/path lists, allow/deny, closest-match priority, SNI-only mode, policy tester, daily apply cron; needs Redis. | squid external ACL + redis | plugin (Deciso) | Native policy engine for the proxy module (if Squid kept). | N |
| PLG-WWW-006 | os-squid 1.5 | Caching web proxy: general (error pages, ICP port, logging target file/json/syslog, alternate DNS, X-Forwarded-For handling, URI whitespace, pinger, Via header, suppress version, connect timeout, visible email/hostname, memory cache mode), local cache (dir, mem, max object sizes, size, swap timeout, swap rate, slot size, cache Linux packages/Windows updates), traffic management (max download/upload size, overall/per-host throttling), parent proxy, forward (interfaces, port, SSL bump port/enable/URL-only/cert/no-bump sites, workers, crtd storage/children, SNMP, FTP proxy interfaces/port/transparent, add ACL for interface subnets, transparent mode), ACL (allowed subnets, unrestricted, banned hosts, whitelist/blacklist, browser, MIME types, Google apps domains, YouTube strict/moderate, safe/SSL ports, remote ACLs with categories + cron download), authentication (method, enforce group, realm, TTL, children), ICAP (request/response URLs, send client IP/username, encoding, header, preview, options TTL, exclude), PAC (proxies PROXY/DIRECT/HTTP/HTTPS/SOCKS4/5, matches url/hostname/dns_domain/destination_in_net/my_ip_in_net/plain_hostname/is_resolvable/dns_domain_levels/weekday/date/time ranges, rules if/unless and/or) + WPAD via DNS/DHCP; error page templates; logs cache/access/store. No longer default-installed since 24.1. | squid + squid-langpack | plugin | Squid (D) optional module; transparent HTTPS bump de-emphasised; PAC/WPAD generator native. | D |
| PLG-WWW-007 | os-web-proxy-sso 2.2 | Kerberos SSO for Squid (AD join via msktutil, keytab, realm, KDC). | msktutil, cyrus-sasl-gssapi | plugin | Only with Squid module; low priority. | D |

## 18. Business Edition (`BE`)

Sources: be.rst, vendor/deciso/*.rst, business changelog 26.4/26.10, security.rst (LINCE).

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| BE-001 | Business Edition track | Conservative release intake based on a community release (26.10 ← 26.7.7), commercial mirror + subscription key, LINCE compliance/certification (tested twice a year), free GeoIP DB, official OVA, e-book, 1 year free with Deciso hardware. | Deciso mirror | BE | sensr has one open track; "stable" vs "edge" channels; GeoIP auto-download free (IPinfo lite). | — |
| BE-002 | OPNcentral (`os-OPNcentral` 1.13) | Managed hosts (URL, API key/secret, cert validation), host groups → user groups (multi-tenancy), host grid (download configs, clone), central WebGUI certificate push, generic host settings (merge interfaces, backups enable, retention count/interval), nightly centralized backups + manual run, one-click auto-login to remote GUI, firmware status/upgrade (with reboot) across fleet, service matrix with bulk restart, resource status (host info, CPU/mem/swap, interfaces, CARP, root FS, gateways; firewall state/alias/source-tracking tables, traffic per protocol), provisioning by HA sync classes with drift detection (md5 per class), special merge rules (users keep API keys, aliases in use kept, firewall rules per interface override/exclusion, multi-interface floating rules dropped, NAT alike, categories in use kept, WebGUI cert kept), cron tasks; node side `opncentral/sync` API (listClasses, readConfig, reconfigure, restartService, metrics, listServices). | PHP + REST API to nodes | BE | sensr fleet manager (separate service, same Rust models): node registry, mTLS peer API (reuses SYS-HA-002 sync classes), fleet dashboards, bulk upgrades (Nix closures), central backups. Core feature, not paid. | N |
| BE-003 | OPNWAF (`os-OPNWAF` 2.6) | Apache httpd reverse proxy + ModSecurity/OWASP CRS: general (ACME tls-alpn-01/http-01, HA peer challenge forwarding), server settings (HTTP version h2/h2c, redirect HTTP→HTTPS, MPM event/prefork, strict SNI, server name, error document), server limits, web protection (paranoia level, allowed verbs, body limits/actions, regex limits), virtual servers (log level, name, port, error doc, ACME/cert, SSL proxy check, client auth CA/CRL/depth, OIDC provider/redirect/timeouts/claims-as, header security/TLS profile, disable rule IDs, protection on/off/detection-only), locations (proxy pass + LB, proxy pass match, redirect/redirect match, Exchange template with path restriction; access control nets/hostnames, OIDC auth + claims, TLS header passthrough, request headers, preserve host, timeouts), request header objects, OIDC claims objects, error document templates/overlay, server status (general/workers/requests/ACME). | apache24 + mod_security + mod_md | BE | WAF via Caddy + Coraza (OWASP CRS, Apache-2.0) module or standalone Coraza-proxy; virtual server/location schema reproduced; OIDC forward-auth native. Core feature. | D+N |
| BE-004 | OPNDNS (`os-OPNDNS` 1.0) | Authoritative DNS: zones (static / allowupdate with "allow updates from"), records as RRsets (A, AAAA, NS, MX, PTR, TXT, SRV…), SOA settings (primary NS, mailbox, refresh/retry/expire/min TTL; auto serial), roles primary/secondary with single peer (AXFR/NOTIFY), listen port (53053 alongside Unbound), logging (level, queries, details), RFC2136 from Kea DDNS (no TSIG), HA sync class, Unbound forward integration. | PowerDNS Authoritative | BE | Native authoritative server (hickory-dns authority) with RFC2136+TSIG, AXFR/IXFR/NOTIFY; same zone/record model; core feature. Merges DNS-BIND-001. | N |
| BE-005 | OpenID Connect | Providers: app code, service (WebGUI/Admin, Captive Portal, OPNWAF), extensive log, provider URL (discovery), client ID/secret, auth method POST/BASIC/default, extra scopes, user identification field, create user + update groups, group attribute, default/limit groups; login button on GUI; CP endpoints + custom template; OPNWAF callback. | PHP OIDC RP | BE | `openidconnect` crate in SYS-AUTH-004; core. | N |
| BE-006 | User Portal | Replaces Lobby › Password: password, language, OTP token creation (by group), OpenVPN profile downloads with automatic per-user certificates (group, server instance, cert lifetime, key type, digest, export template, hostname, static challenge, custom config); admin settings (allowed groups, welcome HTML); LDAP auto-created users; offboarding via CRL. | PHP | BE | Self-service portal in core (GUI-007 extension). | N |
| BE-007 | Scheduled jobs | One-shot: time, until (countdown), command (configd action), parameters, description. | configd | BE | systemd one-shot timers; core (SYS-SET-011). | N |
| BE-008 | Free GeoIP database | Empty URL → auto download from OPNsense mirrors. | | BE | Bundled IPinfo lite fetcher with sensr-hosted mirror. | N |
| BE-009 | BE-only hardware docs | Deciso DEC series defaults/config.xml downloads, BIOS updates, SFP compatibility, serial console, RMA/support. | | BE (hardware) | Hardware compatibility notes for sensr-supported appliances; N/A otherwise. | — |

## 19. Third-party vendor integrations (`VND`)

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| VND-001 | Zenarmor / Sensei (`os-sunnyvalley` → `os-sensei`) | NGFW: application control, cloud app control, network analytics, web filtering & security, cloud threat intel, user-based filtering/reporting, AD integration, REST API, Zenconsole cloud management, app/web-category shaping, policy-based filtering/QoS, encrypted threat prevention, TLS inspection (announced); deployment modes (routed with emulated netmap default, bridge, passive), CPU pinning, security zone tags, reporting DB (local/remote Elasticsearch, MongoDB, SQLite), sizing table, subscriptions (Free/SOHO/Business trial). | Zenarmor packet engine (netmap) | vendor (Sunny Valley) | Cannot be reproduced; sensr equivalent = Suricata app-layer rules + DNS/SNI categorisation + flow analytics (native). Provide an external-module channel so vendors can ship Linux builds. | X (channel N) |
| VND-002 | Q-Feeds threat intelligence | → IDS-009. | API | vendor | Generic feed connector. | N |
| VND-003 | Proofpoint ET Pro / ET Pro Telemetry | → IDS-002, IDS-008. | rulesets | vendor | Oinkcode-based ET Pro fetch is feasible; telemetry needs agreement. | N/X |
| VND-004 | ICAP AV engines (e.g. Symantec Protection Engine) | External ICAP server URLs in proxy. | squid ICAP | vendor | Squid module ICAP settings. | D |
| VND-005 | Cloud marketplaces (AWS AMI, Azure VM, OVA) | Deciso-published images; ec2-user password via user-data; SSH on by default; Azure custom admin user. | | commercial images | sensr NixOS image profiles for AWS/Azure/GCE/OVA with cloud-init-equivalent (SSH keys, password via metadata). | N |
| VND-006 | M/Monit, Wazuh manager, Cloudflare Zero Trust, NetBird/Tailscale/ZeroTier control planes | External services consumed by plugins. | | vendor | Agents only, as in OPNsense. | D |

## 20. Platform, installation and operations (`PLAT`)

Sources: install.rst, hardware.rst, virtuals.rst, updates.rst, software_included.rst, opnsense_tools.rst, how-tos (serial_access, installaws/ova/azure, changelog), hardware/*, troubleshooting/*.

| ID | Feature | Scope / settings | OPNsense backs it with | Tier | sensr approach | Class |
|---|---|---|---|---|---|---|
| PLAT-001 | Image types | dvd (ISO, UEFI), vga (USB), serial (USB, 115200), nano (embedded, RAM disks, 4 GB media); signed sha256 + .sig verification; amd64 only; release images twice a year. | FreeBSD release build (`tools` repo) | core | NixOS image builds: ISO (UEFI+BIOS), raw USB (vga/serial variants via kernel console param), embedded raw (A/B partitions, tmpfs logs), cloud images; signed manifests. aarch64 as stretch goal. | N |
| PLAT-002 | Installer | Live environment (GUI 192.168.1.1, root/opnsense), `installer` user, keymap, UFS/ZFS (+ stripe/mirror), disk, swap, root password, clone running system; importer (boot existing config from disk or FAT USB `/conf/config.xml`); nano procedure; bootstrap from stock FreeBSD (`opnsense-bootstrap`). | bsdinstall-based | core | Rust TUI installer on live image: disk layout (ext4/ZFS/btrfs), config import from USB (sensr or OPNsense `config.xml`), serial-aware; "convert existing NixOS" via flake. | N |
| PLAT-003 | Console menu | 0 logout, 1 assign interfaces, 2 set interface IP (incl. GUI reset/HTTP/self-signed), 3 reset root password, 4 factory defaults, 5 reboot, 6 halt, 7 ping, 8 shell, 9 pfTop, 10 filter logs, 11 restart web GUI, 12 upgrade from console, 13 restore configuration; password-protectable. | opnsense-shell | core | `sensr-shell` TUI with same options (9 → conntrack top, 10 → live log). | N |
| PLAT-004 | Hardware sizing | Minimum/reasonable/recommended specs, throughput tiers, Intel NIC advice, ~1 KB/state, Squid/CP/IPS impact. | | core | Document for sensr. | — |
| PLAT-005 | Virtualisation | ESXi (VMXNET3 + os-vmware), Xen (os-xen), Hyper-V gen1/2 (Secure Boot off), KVM (os-qemu-guest-agent, i440FX/Q35), bhyve, VirtualBox (os-virtualbox); disable offloading; known issues (VMXNET3 + shaper → E1000). | guest tools | core + plugins | NixOS guest profiles (virtio, vmware, hyperv, xen); Secure Boot supported via lanzaboote (improvement). | N+D |
| PLAT-006 | Updates & release cadence | YY.1/YY.7 majors + fortnightly minors; production vs development release type; console/GUI major upgrade (offline); mirrors; `opnsense-update -k/-r`, `opnsense-revert`, `opnsense-patch` (git commit hot-patching, plugins repo, forks). | pkg sets | core | Nix generations: atomic update + rollback; "patch" = overlay from a git commit rebuilt in CI; dev channel. | N |
| PLAT-007 | Included software / package policy | Kernel+base via opnsense-update, plugins repo, raw `pkg` use unsupported, ports building via `opnsense-code`. | pkg/ports | core | Nix: declared extra packages allowed in a user overlay; everything else pinned by the sensr flake. | N |
| PLAT-008 | Serial console access | 115200 8N1, device names per host OS, enabling via Administration › Console; EFI vs legacy UART BIOS option (Deciso). | | core | Same (serial-getty). | K |
| PLAT-009 | Cloud images | AWS (user-data password, security groups, ec2-user), Azure (custom admin user, private 443), OVA (2 NICs). | | commercial | VND-005. | N |
| PLAT-010 | Hardening defaults | random IP IDs, PTI, IBRS on, bsd security knobs (hardlink checks, proc debug, see other uids/gids, msgbuf), strict security mode (non-root GUI), argon2id passwords, non-root services, priv-sep scripts (26.7.x). | sysctl/rc | core | NixOS hardened profile subset; systemd sandboxing (DynamicUser, capabilities) for every daemon; Rust memory safety. | N+K |
| PLAT-011 | Performance tuning | RSS (`net.inet.rss.*`, netisr threads), `kern.ipc.maxsockbuf`, `kern.hz`, netmap caveats, offload interplay with IPS. | sysctl | core | RPS/XPS, `net.core.*`, IRQ affinity presets; XDP for IPS fast path. | K |
| PLAT-012 | Troubleshooting guides | Password reset, firmware config reset, console config restore, GUI reset, boot/loader hints, hardening vs performance, netmap errors, gateways/dpinger errors. | | core | Equivalent runbooks (SYS-DIAG-005). | — |
| PLAT-013 | Security process | Audits vs VuXML, dependency minimisation, GitHub advisories + CVEs, disclosure policy, release lifecycle dev→community→BE, LINCE certification. | | core/BE | sensr SECURITY.md, OSV-based audit (SYS-FW-005), signed releases; certification out of scope initially. | — |

## 21. Architecture concepts to reproduce (`ARCH`)

Sources: development/architecture, backend (configd, templates, legacy hooks, syshooks, carp), api, frontend (routing, controllers, models, field types, menu), components (acl, menu). These are not user features but the contracts every module above relies on.

| ID | Concept | OPNsense implementation | sensr approach | Class |
|---|---|---|---|---|
| ARCH-001 | Single configuration document | `config.xml`; only frontend models write; backend reads; revision metadata; backup ring; `config` syshook on save. | Typed config tree (Rust structs with serde + JSON schema), transactional store with history, change-event bus; OPNsense XML importer. | N |
| ARCH-002 | Models with XML schema + field types | ~35 field types (Array, AuthGroup, AuthenticationServer, AutoNumber, Base64, Boolean, Certificate, CSVList, ConfigdActions, Country, Description, Email, Hostname, Integer, Interface, IPPort, JsonKeyValueStore, LegacyLink, MacAddress, ModelRelation, NetworkAlias, Network, Numeric, Option, Port, Protocol, StrictText, Text, UniqueId, UpdateOnlyText, Url, VirtualIP, …), constraints, migrations. | Derive-macro based model definitions generating validation, API, forms and docs; migration framework versioned per module. | N |
| ARCH-003 | Backend service broker | configd (Python, unix socket): actions in `actions.d/*.conf` (command, parameters, type script/script_output/stream_output/inline, allowed_groups, message, cache_ttl, description → usable by cron); `configctl`; environment overrides. | Rust service broker (tokio, unix socket + in-process): typed action registry; same "description makes it schedulable" rule feeds Cron/Scheduled jobs. | N |
| ARCH-004 | Templates | Jinja2 templates per vendor/app with `+TARGETS` (source:target:cleanup), dynamic targets from config tags, overwrite by vendor; `template reload/cleanup`. | Typed renderers (minijinja or askama) per external daemon; atomic write + validate (`-t` checks) + reload. | N |
| ARCH-005 | Plugin hooks | `_services()` (service registry, pluginctl -s), `_configure()` events (early, bootup, newwanip, updateip, vpn, monitor, …), `_firewall($fw)` rule registration, `_interfaces()` virtual interfaces, `_devices()` device types, `_syslog()` targets, `_xmlrpc_sync()` HA classes, dashboard widgets, Menu.xml, ACL.xml, API controllers. | Module trait: `services()`, `on_event()`, `firewall_rules()`, `interfaces()`, `device_types()`, `log_sources()`, `sync_class()`, `widgets()`, `menu()`, `permissions()`, `routes()`; registered at compile time (features) or via external module manifest. | N |
| ARCH-006 | Syshooks | `rc.syshook.d/{backup,carp,config,early,import,monitor,start,stop,update,upgrade}/NN-name`. | Event bus topics with ordered subscribers; user hook directory for scripts (same stage names). | N |
| ARCH-007 | REST API | `/api/<module>/<controller>/<command>/[params]`, GET read / POST mutate, Basic auth with key/secret, ACL via `page-*` privileges, grid contract `search*` → `{total,rowCount,current,rows}`, command naming get/set/add_x/set_x/del_x/toggle_x/search_x, `service/reconfigure\|start\|stop\|restart\|status`, CSV import/export helpers; per-module API reference docs. | axum REST with identical conventions where feasible (compat for existing automation/Ansible/Terraform providers), plus OpenAPI generated from models. | N |
| ARCH-008 | ACL / privileges | ACL.xml per module mapping privilege → URL patterns; merged into effective privileges; menu filtered in views; `user-config-readonly`; `page-all`. | Permission registry, route guards, read-only mode. | N |
| ARCH-009 | Menu system | Menu.xml tree per module (order, VisibleName, cssClass, url, visibility hidden), favorites. | Menu manifest per module. | N |
| ARCH-010 | Frontend | PHP MVC (Phalcon heritage), Volt views, form XML, Tabulator grids, dashboard widget JS, i18n via gettext. | TypeScript SPA fed by model schemas; i18n via fluent. | N |
| ARCH-011 | Legacy layer | `legacy_*` PHP includes, static pages with weaker safeguards, migrations to MVC ongoing (26.x). | None; importer handles legacy config sections. | X |
| ARCH-012 | Service lifecycle | rc.d scripts + `pluginctl -s`, hidden services, boot/running/shutdown stages, priv-sep reload scripts. | systemd units generated per module; sensr supervisor for status; sandboxing. | N |
| ARCH-013 | Logging pipeline | syslog-ng per-app files, log viewer API with "go to page", log templates (`Lvtemplate`), remote destinations. | journald + structured fields + export; per-module log source registry. | N |
| ARCH-014 | Build & release tooling | `tools` repo: image builds (dvd/vga/serial/nano), ports, kernel, signing; plugin tiers; changelog repo. | Nix flake: images, module set, CI signing, changelog generation. | N |

## 22. Counts

464 feature IDs. Row counts per area (one row may cover several closely related settings; plugin rows that bundle variants, e.g. six themes or five IDS content packs, count once).

| Area | IDs | Of which native Rust (N, N+K, K+N, N+D) | External daemon (D, D+K, D+N, D→N) | Kernel only (K) | Out of scope (X*) |
|---|---|---|---|---|---|
| Interfaces (`IF*`) | 52 | 38 | 4 | 9 | 1 |
| Firewall (`FW*`) | 56 | 54 | 0 | 1 | 1 |
| NAT | 8 | 7 | 0 | 0 | 1 |
| Traffic shaper (`SHP*`) | 6 | 6 | 0 | 0 | 0 |
| DHCP (`DHCP*`) | 25 | 22 | 0 | 0 | 3 |
| DNS (`DNS*`) | 23 | 12 | 10 | 0 | 1 |
| Router advertisements (`RA`) | 3 | 3 | 0 | 0 | 0 |
| Captive portal (`CP`) | 9 | 9 | 0 | 0 | 0 |
| IDS/IPS (`IDS`) | 10 | 6 | 2 | 0 | 1 (+1 informational) |
| Monit (`MON`) | 5 | 5 | 0 | 0 | 0 |
| NTP (`NTP`) | 5 | 0 | 5 | 0 | 0 |
| VPN (`VPN-*`) | 42 | 19 | 21 | 0 | 2 |
| Lobby/GUI (`GUI`) | 12 | 12 | 0 | 0 | 0 |
| System (`SYS-*`) | 60 | 54 | 1 | 1 | 1 (+3 informational) |
| Dynamic routing (`RTG`) | 9 | 0 | 9 | 0 | 0 |
| Reporting (`REP`) | 7 | 7 | 0 | 0 | 0 |
| Plugins (`PLG-*`, 102 plugins in 90 rows) | 90 | 30 | 44 | 2 | 14 |
| Business Edition (`BE`) | 9 | 6 | 1 | 0 | 0 (+2 informational) |
| Vendor (`VND`) | 6 | 2 | 2 | 0 | 2 |
| Platform (`PLAT`) | 13 | 7 | 0 | 2 | 0 (+4 informational) |
| Architecture (`ARCH`) | 14 | 13 | 0 | 0 | 1 |
| **Total** | **464** | **~312** | **~99** | **~15** | **~29** |

Headline: roughly two thirds of the surface is native Rust (the whole firewall/NAT/shaper/interfaces/DHCP/RA/CP/system/GUI layer), about a fifth is Rust-managed daemons (unbound, strongSwan, OpenVPN, Suricata, FRR, chrony, HAProxy/Caddy/nginx, Squid family, mesh VPN agents, monitoring agents), and the rest is kernel-only configuration or out of scope.

Source coverage: 78 manual pages, 102 how-to pages, 10 vendor pages, 8 hardware pages, 10 troubleshooting pages, 4 development chapters (+ API reference index), 19 core `Menu.xml`, 19 `ACL.xml` (~160 privileges), 62 core model XMLs, 24 legacy PHP pages, 102 plugin Makefiles with their menus/models, community changelog 26.1.10–26.7.9 and business 26.4/26.10.

## 23. Out of scope, deprecated, or deliberately different

| ID | Item | Reason |
|---|---|---|
| OOS-001 | ISC DHCPv4/v6 server (`os-isc-dhcp`, DHCP-ISC-001) | EOL upstream, no security updates; OPNsense itself moved it to a legacy plugin and recommends Kea/Dnsmasq. sensr ships one native DHCP server; the config importer translates ISC settings. |
| OOS-002 | Legacy firewall rules and outbound NAT pages (`os-firewall-legacy`, FW-013, NAT-007) | Static PHP pages moved out of core in 26.7/26.7.5 with a migration assistant; no API. Importer only. |
| OOS-003 | Legacy OpenVPN servers/clients (`os-openvpn-legacy`, VPN-OVPN-009) | Replaced by Instances since 23.7; shared-key P2P is covered by static keys in instances. Importer only. |
| OOS-004 | Legacy IPsec tunnel settings / mobile clients (`os-strongswan-legacy`, VPN-IPSEC-015), pre-23.1 `ipsec.conf`/`ipsec.secrets` include dirs | Replaced by swanctl Connections; IKEv1 is visibly deprecated in 26.7.8. Importer maps Phase1/2 to connections/children. |
| OOS-005 | Legacy `interfaces.php` page (IF-009) and legacy DHCP "advanced/file override" modes | Slated for plugin in 27.1; MVC dialog is the contract. Raw send/request options are kept natively. |
| OOS-006 | Unbound Domain Overrides (DNS-UB-003) | Superseded by Query Forwarding; importer maps them. |
| OOS-007 | Unbound "custom options" text (removed 21.7) | Replaced by include dir in OPNsense; sensr exposes a validated extra-config field only. |
| OOS-008 | Periodic backups of RRD/DHCP/NetFlow/CP state (SYS-CFG-007) | Removed in 26.7 by OPNsense. |
| OOS-009 | `os-ndproxy` | Removed in 26.7 in favour of `os-ndp-proxy-go`; sensr implements the latter natively. |
| OOS-010 | Automatic NAT reflection options (FW-SET-001) | Kept for compatibility but documented by OPNsense as historical/discouraged; sensr implements them but defaults to the manual method. |
| OOS-011 | Track Interface (legacy) IPv6 mode | Replaced by Identity Association; sensr offers only the latter (same fields) plus explicit DHCPv6/RA service config. |
| OOS-012 | RIP (RTG-005) and OSPF "Networks" configuration | Marked legacy by OPNsense; available through FRR but not promoted. |
| OOS-013 | PPTP client / L2TP without IPsec (IF-DEV-011) | Insecure protocols; low priority, daemon-backed if demanded. |
| OOS-014 | Transparent HTTPS interception (Squid SSL bump, PLG-WWW-006) | Legal/terms risk and certificate-pinning breakage acknowledged by OPNsense docs; Squid module optional and HTTPS bump off by default. |
| OOS-015 | ET Pro Telemetry (IDS-008) and Zenarmor (VND-001) | Vendor agreements / proprietary engines; sensr provides a feed connector and an external module channel instead. |
| OOS-016 | Realtek `re` vendor kmod, CPU microcode plugins, guest-tool plugins | Linux in-tree drivers and NixOS options cover these; no plugin needed. |
| OOS-017 | `os-debug`, `os-google-cloud-sdk`, `os-puppet-agent`, `os-lcdproc-sdeclcd`, `os-munin-node`, `os-nrpe` | Developer tooling, cloud SDK, config management and legacy monitoring agents; NixOS/declarative config and the native metrics endpoint supersede them. Can be added as external modules. |
| OOS-018 | `os-ftp-proxy`, `os-siproxd` (as proxies) | Linux conntrack helpers (`nf_conntrack_ftp`, `nf_conntrack_sip`) handle NAT traversal in-kernel; proxies only as optional daemons. |
| OOS-019 | XMLRPC config sync endpoint (SYS-HA-006) | Replaced by mTLS peer API; XMLRPC privilege is effectively full admin in OPNsense's own security notes. |
| OOS-020 | ZFS boot environments as such (SYS-SET-010) | Replaced by NixOS generations; ZFS snapshots of state remain optional. |
| OOS-021 | pf-specific knobs with no Linux analogue: random IP ID scrub (Linux randomises), netmap emulation tunables, `kern.hz`, mbuf statistics, netisr tabs | Replaced by Linux equivalents (softnet, slab, RPS/XPS) in the corresponding diagnostics. |
| OOS-022 | Business-Edition licensing, LINCE certification, Deciso hardware BIOS/RMA pages | sensr has no paid tier; BE features (OPNcentral, OPNWAF, OPNDNS, OIDC, portal, scheduled jobs) are planned as core. Certification is a later programme decision. |
| OOS-023 | Themes as plugins (PLG-THEME-001) | Light/dark/auto built in; community CSS packs allowed but not inventoried as features. |
| OOS-024 | Blowfish/bcrypt password hashing option, "SHA-512 compliance" toggle | sensr uses argon2id only (OPNsense moved to argon2id in 26.10 as well). |

## 24. Open decisions flagged by this inventory

| ID | Decision | Options |
|---|---|---|
| DEC-001 | Dnsmasq role | (a) native Rust forwarder+DHCP (chosen in this doc) vs (b) ship dnsmasq as daemon. Native wins because DHCP→DNS registration, per-client stats and HA lease sync need one process. |
| DEC-002 | Recursive resolver | unbound (D) first; hickory-dns recursor later. Blocklists/per-client policies may require a Rust DNS front even with unbound. |
| DEC-003 | CARP replacement | Native VRRPv3 vs keepalived. Native chosen for maintenance-mode, demotion, unicast and hook semantics; keepalived as interim. |
| DEC-004 | State sync | conntrackd now; native conntrack netlink replication later. |
| DEC-005 | Shaper mapping | HTB/HFSC + fq_codel/CAKE; exact dummynet weight semantics (WF2Q+) approximated by HFSC link-share or `drr`. |
| DEC-006 | IPS inline mode | NFQUEUE (per-rule divert equivalent) vs AF_PACKET/XDP inline. Support both; NFQUEUE is the divert-to analogue. |
| DEC-007 | Reverse proxy default | Caddy (+Coraza WAF) as default; HAProxy and nginx as optional modules. |
| DEC-008 | Authoritative DNS | One native server covering os-bind + BE OPNDNS use cases vs PowerDNS/Knot daemon. |
| DEC-009 | DDNS/ACME DNS providers | One shared provider trait (Cloudflare, Route53, Hetzner, deSEC, RFC2136, …) used by both. |
| DEC-010 | OPNsense API compatibility | Keep `/api/<module>/<controller>/<command>` naming where models match, to reuse existing Ansible/Terraform ecosystems. |

## 25. Documentation inconsistencies noticed while extracting (for the behaviour notes, not bugs in sensr)

- dhcp.rst/radvd.rst say Dnsmasq is the default RA daemon; dnsmasq.rst says radvd is. The 26.x wizard enables Dnsmasq for DHCPv4/v6/RA and Unbound for DNS.
- nat.rst swaps the Protocol and Description cells in the Interface tab tables; calls both "Pass" and "Manual" the recommended firewall-rule mode.
- security-zones.rst VLAN numbering differs between its table and its group tabs.
- ipsec-s2s-conn.rst says "Pre-Shared Key" where the table shows Public Key; ipsec-s2s-conn-binat.rst mixes 10.0.99.0/24 and 10.99.0.0/24.
- wireguard-s2s.rst still says to install `os-wireguard`; WireGuard has been core since 24.1.
- sftp-backup.rst mentions https username/password transport (copied from git-backup).
- interfaces.rst lists Sierra MC7304 while cellular.rst uses MC7430; menu paths for Point-to-Point devices differ between pages.
- Dynamic DNS page lacks the provider/check-ip lists; they were taken from the `os-ddclient` model (DNS-DDNS-001).
