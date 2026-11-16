# Slice models (`sensr_schema::models`)

The typed configuration the routing slice needs. The importer maps
OPNsense `config.xml` into these types; the renderers read from them.
`tests/fixtures/factory.json` is a complete example document.

Stability: changes are additive (`#[serde(default)]` on new fields). Anything
else bumps `SCHEMA_VERSION` and ships a migration.

## Sections

| Path | Type | OPNsense source |
|---|---|---|
| `system` | `system::System` (hostname, domain, dns_servers, timezone, time_servers, users, groups, ssh) | `system`, `Auth/User.xml`, `Auth/Group.xml` |
| `interfaces.<id>` | `interfaces::Interface` (role, device, match_mac, spoof_mac, mtu, ipv4 (DHCP client options), ipv6 (DHCPv6-PD client, DUID, tracking), block_private, block_bogons, qdisc) | `interfaces/<id>`, `Interfaces/Settings.xml` (DHCPv6 DUID, no-release) |
| `firewall.aliases` | `ArrayField<firewall::Alias>` | `Firewall/Alias.xml` |
| `firewall.rules` | `ArrayField<firewall::FilterRule>` (evaluated by tier, then `sequence`: see below) | `Firewall/Filter.xml` rules, legacy `filter/rule` |
| `firewall.groups` | `ArrayField<firewall::InterfaceGroup>` (members, automatic WireGuard membership, tier sequence; omitted while empty) | `Firewall/Group.xml` (`ifgroups`), plugin groups in `interfaces` |
| `firewall.settings` | `firewall::FirewallSettings` | `Firewall/Filter.xml` settings |
| `nat.outbound` | `nat::OutboundNat` (mode + manual rules) | `nat/outbound`, `Filter.xml` snatrules |
| `nat.port_forwards` | `ArrayField<nat::PortForward>` | `Firewall/DNat.xml` (`nat/rule`) |
| `nat.one_to_one` | `ArrayField<nat::OneToOneRule>` (interface, `type` binat/nat, external address or network, source and destination with `not`, log, reflection override; omitted while empty) | `Filter.xml` onetoone, legacy `nat/onetoone` |
| `nat.reflection` | `nat::Reflection` (`port_forwards`, `source_nat`, `one_to_one`; the last omitted while off) | `Filter.xml` settings `reflection_dnat` / `reflection_snat` / `reflection_binat`, legacy `system` switches |
| `dhcpv4` | `dhcp::Dhcpv4` (subnets, pools, options, reservations) | `Kea/KeaDhcpv4.xml` (and legacy ISC/dnsmasq via the importer) |
| `dns` | `dns::DnsResolver` (settings, forwarding, host_overrides, access lists, tuning, blocklists) | `Unbound/Unbound.xml` |
| `dns.blocklists` | `ArrayField<dnsbl::Blocklist>` (curated lists by name, URLs, extra names, allow entries, source networks, answer mode, refresh) | `unboundplus/dnsbl/blocklist` |
| `wireguard` | `wireguard::WireGuard` (servers, peers) | `Wireguard/{General,Server,Client}.xml` |
| `devices` | `devices::Devices` (bridges with STP, LAGGs/bonds, loopbacks; omitted while empty) | `Interfaces/{Bridge,Lagg,Loopback}.xml` |
| `virtual_ips` | `devices::VirtualIps` (IP alias, proxy ARP, CARP/VRRP; omitted while empty) | `Interfaces/Vip.xml` |
| `dhcpv6` | `dhcpv6::Dhcpv6` (static or dynamic-prefix subnets, pools, DUID/MAC reservations, PD pools; omitted while unconfigured) | `Kea/KeaDhcpv6.xml` |
| `router_advertisements` | `dhcpv6::RouterAdvertisements` (per-interface RA mode, RDNSS/DNSSL, intervals, NAT64 prefix) | `Radvd/Radvd.xml` |
| `ntp` | `ntp::Ntp` (serve, listen interfaces, per-server prefer/noselect/iburst/pool/NTS flags, orphan stratum; servers themselves are `system.time_servers`) | `ntpd` section |
| `routes` | `routes::Routes` (static routes to gateways by name; omitted while empty) | `Routes/Route.xml` (`staticroutes`) |

## WAN and LAN addressing (networkd)

The interfaces applier renders one systemd-networkd `.network` per
interface. What the addressing fields become:

- `spoof_mac` → `[Link] MACAddress=`. networkd sets it when it configures
  the link (taking the link down first when the driver needs that), before
  the DHCP clients start, so DHCPv4 `chaddr`, the client identifier
  (`client_id: mac`, type 1 + MAC, dhclient's default), the EUI-64
  link-local address and the default DHCPv6 DUID-LL all carry the spoofed
  MAC. That is what a residential gateway in IP passthrough mode keys the
  public address on. Removing `spoof_mac` takes effect at the next reboot:
  networkd does not restore the permanent address.
- `ipv4: dhcp`: `ClientIdentifier=` (`mac` default, `duid`), `Hostname=`,
  `DenyList=` (`reject_from`), `UseMTU=` (`use_mtu`, off as in OPNsense),
  `VendorClassIdentifier=`, `UserClass=`, `SendOption=<code>:<type>:<value>`
  (hex values are sent as an escaped string), `RequestOptions=` (added to
  networkd's own request list; dhclient's `request` replaces its list).
  `vlan_priority` on a VLAN interface sets `SocketPriority=8` and maps skb
  priority 8 to that PCP in the VLAN's `EgressQOSMaps=` (networkd applies
  the socket priority to the raw socket of the initial exchange; renewals go
  out with the VLAN's default PCP). The schema rejects options the client
  builds itself (12, 50, 51, 53-55, 57, 60, 61, 77).
- `ipv6: dhcp6`: `UseDelegatedPrefix=` (yes when a delegation size is set),
  `PrefixDelegationHint=::/<len>` only with `send_prefix_hint`, as dhcp6c
  sends the hint; `UseAddress=no` for `prefix_only`; `RapidCommit=`;
  `SendRelease=` (`send_release`, OPNsense `dhcp6_norelease`);
  `DUIDType=`/`DUIDRawData=` from `duid` (type from its first two bytes),
  else `DUIDType=link-layer` so the ISP sees the same client after a
  reinstall (networkd's default derives the DUID from `/etc/machine-id`).
  `prefix_id` gives the WAN its own /64 (`[DHCPPrefixDelegation]
  UplinkInterface=:self`, not announced). `WithoutRA=solicit`: the client
  starts without waiting for an RA (OPNsense's `dhcp6_ratimeout` path).
- `ipv6: track`: `DHCPPrefixDelegation=yes`, `[DHCPPrefixDelegation]
  UplinkInterface=<uplink device> SubnetId=0x<prefix_id> Announce=yes`.
  Several interfaces may track one uplink; prefix IDs must differ.
- Router advertisements: a tracking interface without a
  `router_advertisements` entry gets OPNsense's automatic RA:
  `IPv6SendRA=yes`, `EmitDNS=yes DNS=_link_local` (the router's own
  link-local address) when Unbound serves the interface, else the system's
  IPv6 DNS servers (at most three), `EmitDomains=yes Domains=<system
  domain>`. M and O are set only when sensr's DHCPv6 server serves the
  interface (OPNsense sets both because it always starts one). Unbound
  binds the wildcard address when any interface advertises its link-local
  address, so the RDNSS answers. An entry overrides this: `enabled: false`
  stops RAs (and the prefix announcement), `mode` sets M/O and the prefix
  flags (`router_only` announces no prefix), `dns`/`rdnss`/`dnssl`,
  `default_lifetime` (default 3 × `max_interval`) → `RouterLifetimeSec=`,
  `preference`, `hop_limit`, `routes` → `[IPv6RoutePrefix]`,
  `nat64_prefix` → `[IPv6PREF64Prefix]`. A static IPv6 interface with an
  entry advertises its prefix (`[IPv6Prefix]`, `OnLink=`/
  `AddressAutoconfiguration=` from the mode).
  Not expressible in networkd: `min_interval`/`max_interval` (sd-radv uses
  fixed 200-600 s, OPNsense's defaults), `mtu`, `prefix_from`, and clearing
  the A flag of a delegated prefix (`managed` on a tracking interface still
  lets hosts autoconfigure).

The importer maps `spoofmac`, `dhcphostname`, `dhcprejectfrom`,
`dhcphonourmtu`, `dhcpvlanprio` (VLAN interfaces only), the "advanced"
`adv_dhcp_send_options`/`adv_dhcp_request_options` (and the basic
`dhcp_send_options`/`dhcp_request_options`), `dhcp6-ia-pd-len` (stored as
the bits below /64: 0 → /64, 4 → /60, 8 → /56, 16 → /48, `none`),
`dhcp6-ia-pd-send-hint`, `dhcp6prefixonly`, `dhcp6_rapid_commit`,
`dhcp6-prefix-id`, `track6-prefix-id` (decimal, entered as hex) and the
global `OPNsense/Interfaces/settings` `dhcp6_duid` (or legacy
`system/ipv6duid`) and `dhcp6_norelease`, copied into every DHCPv6
interface. It reports as degraded: the basic mode's host name sent as
client identifier, arbitrary client identifiers, `{mac_addr_*}`
substitutions without a spoofed MAC, protocol timings, required options,
option modifiers, configuration file overrides, alias addresses, DHCPv4
VLAN priority on a non-VLAN interface, `dhcp6vlanprio` and dhcp6c advanced
mode. `track6_ifid`, `dhcp6_ifid` and the multi-PD `*_assoc_pd` fields are
not modelled yet and surface as unmapped when set.

## Text grammars

| Type | Forms |
|---|---|
| `NetOrAlias` | `any`, `self`, `net:<if>`, `addr:<if>`, `alias:<name>`, `10.0.0.0/8`, `10.0.0.1` |
| `PortSpec` | `80`, `https`, `8000-8080` (also `8000:8080` on input), `alias:<name>` |
| `AliasEntry` | `[!]` + address, `a-b` range, CIDR, host name, or `alias:<name>` |
| `Protocol` | `any`, `tcp/udp`, IANA names or numbers, case-insensitive; displays lower-case |
| `Pool4` | `start-end` or CIDR; displays `start-end` |
| `AllowEntry` | `example.com` (exactly), `*.example.com` (and below), `/regex/` |
| `CacheSize` | bytes or `4m`, `512k`, `1g` |

## Rule evaluation order

`Firewall::priority` reproduces `FilterRuleField::getPriority()`: rules on no
single interface, on several interfaces, with an inverted interface match or
marked `floating` are evaluated first (200000), then rules on one interface
group (300000 plus the group's `sequence`), then rules on one interface
(400000). `sequence` orders rules only within a tier, so a `lan,opt1` block
with sequence 9 still runs before a `lan` allow with sequence 1.

## Differences from OPNsense

| OPNsense | sensr | Why |
|---|---|---|
| `lan` in a rule may be an interface net or an alias; `lanip` is the address | `net:lan`, `addr:lan`, `alias:x` | unambiguous without the rest of the config |
| Ports keep service names (`https`) | stored as numbers | renderers never resolve names; table frozen in `fields::well_known` |
| Interface role inferred from `wan`/`lan` ids and gateways | explicit `role` | NAT, anti-lockout and default rules key off it |
| Interface bound to a FreeBSD device | Linux `device` plus optional `match_mac` pin (systemd.link) | stable NIC identity |
| no egress AQM by default | `qdisc` defaults to fq_codel; CAKE with optional shaping | latency results in docs/research/07 |
| Reservation `hw_address` and `client_id` both optional, "not both" checked | `client` is one of `hw_address` / `client_id` | invalid state unrepresentable |
| `ipaddr`/`subnet`/`ipaddrv6`/`track6-*` flat fields | `ipv4` / `ipv6` tagged enums (`none`, `dhcp`, `static`, `dhcp6`, `slaac`, `track`) | only meaningful combinations exist |
| `no_antilockout` | `anti_lockout` | positive booleans |
| Host override `rr` + `server`/`mx`/`mxprio`/`txtdata` | `record` tagged by `rr` with only that type's data | invalid state unrepresentable |
| 1:1 `natreflection` (`''`, `enable`, `disable`) | `reflection`: absent (follow `nat.reflection.one_to_one`), `enable`, `disable` | same as port forwards |
| 1:1 BINAT accepts any source pfctl later rejects (alias, interface, inverted, unequal masks) | validation: a BINAT source is a literal address or network, not inverted, and the external network has its size (or is a host, which takes the source's prefix) | pfctl refuses the whole ruleset otherwise |
| Port forward `associated-rule-id` (`''`, `pass`, uuid) | `filter`: `pass`, `none`, `{"rule": uuid}` | typed relation |
| User names may be e-mail addresses | Linux-compatible names only | accounts are real Linux users |
| LAGG protocols `fec` and `loadbalance` | one `loadbalance` (Linux `balance-xor`) | same behaviour on Linux bonds |
| Loopbacks `lo<n>` are FreeBSD clones | `lo<n>` Linux dummy devices | Linux has one `lo` |
| CARP | VRRP (Holo/keepalived), same fields | PLAN §2.1 |
| "not any" (`source_not` on `any`) is accepted and silently means "any" | rejected by validation; the importer imports it as `any` and warns | the inversion never did anything, and it surprised people |
| Legacy rules on a plugin group (`wireguard`) sit in the interface tier | every rule on a group is in the group tier | one rule, one tier |
| DHCPv6 DUID and "do not release" are global (`Interfaces/settings`) | per DHCPv6 interface (`duid`, `send_release`); the importer copies the global values | networkd configures them per link |
| DHCPv4 client identifier is the host name when one is set (basic mode) | `client_id`: `mac` or `duid` | networkd cannot send an arbitrary identifier; `mac` is dhclient's default |
| Kea6 `subnet` empty when `dynamic_prefix` | `addressing` is `static {subnet, pools}` or `dynamic_prefix` | invalid combinations unrepresentable |
| DNSBL `type` short codes (`hgz003`) | `lists`: `hagezi-pro`, ... | readable; codes kept for import/export |
| DNSBL allowlists are regular expressions | `allow`: names, `*.name` subtrees, or `/regex/` | a plain name means that name; regexes cannot open a hole under a blocked subtree (compiled, not evaluated per query) |
| DNSBL `nxdomain` + `address` | `answer`: `{"mode":"address","address":...}` or `{"mode":"nxdomain"}` | one meaning per state |
| `noregrecords`, `addptr` | `register_firewall_records`, `ptr` | positive booleans |
