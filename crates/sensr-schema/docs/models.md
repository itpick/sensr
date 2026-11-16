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
| `interfaces.<id>` | `interfaces::Interface` (role, device, match_mac, spoof_mac, mtu, ipv4, ipv6, block_private, block_bogons, qdisc) | `interfaces/<id>` |
| `firewall.aliases` | `ArrayField<firewall::Alias>` | `Firewall/Alias.xml` |
| `firewall.rules` | `ArrayField<firewall::FilterRule>` | `Firewall/Filter.xml` rules, legacy `filter/rule` |
| `firewall.settings` | `firewall::FirewallSettings` | `Firewall/Filter.xml` settings |
| `nat.outbound` | `nat::OutboundNat` (mode + manual rules) | `nat/outbound`, `Filter.xml` snatrules |
| `nat.port_forwards` | `ArrayField<nat::PortForward>` | `Firewall/DNat.xml` (`nat/rule`) |
| `dhcpv4` | `dhcp::Dhcpv4` (subnets, pools, options, reservations) | `Kea/KeaDhcpv4.xml` (and legacy ISC/dnsmasq via the importer) |
| `dns` | `dns::DnsResolver` (settings, forwarding, host_overrides) | `Unbound/Unbound.xml` |
| `wireguard` | `wireguard::WireGuard` (servers, peers) | `Wireguard/{General,Server,Client}.xml` |
| `devices` | `devices::Devices` (bridges with STP, LAGGs/bonds, loopbacks; omitted while empty) | `Interfaces/{Bridge,Lagg,Loopback}.xml` |
| `virtual_ips` | `devices::VirtualIps` (IP alias, proxy ARP, CARP/VRRP; omitted while empty) | `Interfaces/Vip.xml` |
| `routes` | `routes::Routes` (static routes to gateways by name; omitted while empty) | `Routes/Route.xml` (`staticroutes`) |

## Text grammars

| Type | Forms |
|---|---|
| `NetOrAlias` | `any`, `self`, `net:<if>`, `addr:<if>`, `alias:<name>`, `10.0.0.0/8`, `10.0.0.1` |
| `PortSpec` | `80`, `https`, `8000-8080` (also `8000:8080` on input), `alias:<name>` |
| `AliasEntry` | `[!]` + address, `a-b` range, CIDR, host name, or `alias:<name>` |
| `Protocol` | `any`, `tcp/udp`, IANA names or numbers, case-insensitive; displays lower-case |
| `Pool4` | `start-end` or CIDR; displays `start-end` |

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
| Port forward `associated-rule-id` (`''`, `pass`, uuid) | `filter`: `pass`, `none`, `{"rule": uuid}` | typed relation |
| User names may be e-mail addresses | Linux-compatible names only | accounts are real Linux users |
| LAGG protocols `fec` and `loadbalance` | one `loadbalance` (Linux `balance-xor`) | same behaviour on Linux bonds |
| Loopbacks `lo<n>` are FreeBSD clones | `lo<n>` Linux dummy devices | Linux has one `lo` |
| CARP | VRRP (Holo/keepalived), same fields | PLAN §2.1 |
