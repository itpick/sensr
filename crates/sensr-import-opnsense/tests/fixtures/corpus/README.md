# Synthetic OPNsense config.xml corpus

Everything in this directory is **synthetic and hand-written**. Per the owner's
decision (docs/PLAN.md section 7, item 1), no real router configuration is
ever used, copied, or "anonymised" into this corpus. Every hostname, address,
MAC, key, hash and UUID here was invented.

**Never replace any value in these files with real data.** That includes
values copied from your own router "just to test something". If a test needs a
new shape, invent the data and follow the conventions below.

## Files

| File | What it models |
|------|----------------|
| `home-router.xml` | A typical home/SMB router. WAN `igc0` uses DHCPv4 plus DHCPv6 with prefix delegation (`dhcp6-ia-pd-len` 8, which the `interfaces.php` select maps to /56). LAN `igc1` is 192.168.1.1/24 with identity association (`idassoc6`) to WAN. IoT is VLAN 20 (`vlan01`, opt1, 192.168.20.1/24) and Guest is VLAN 30 (`vlan02`, opt2, 192.168.30.1/24). There is a WireGuard instance `wg0` (opt3, 10.10.10.1/24) with two peers, phone and laptop. Unbound has DNSBL blocklists, host overrides, a domain forward and a DoT upstream. Kea DHCPv4 has subnets for LAN, IoT and Guest with pools (Guest has two pool ranges, newline-separated) and 3 reservations. Aliases cover host, network (multi-line content), port (multi-line content), urltable (with refresh) and geoip. MVC filter rules cover LAN allow, IoT to LAN block placed before IoT internet allow, WireGuard on WAN and policy-free LAN rules. Guest isolation uses legacy `<filter><rule>` entries in the shape the `firewall-legacy` plugin's `firewall_rules_edit.php` writes. There is a port forward of 443 to the NAS with NAT reflection and an auto-registered filter rule (`pass` = `rule`). Outbound NAT is hybrid with one manual MVC source NAT rule. The file also has NTP, remote syslog (192.168.1.20 udp/514), root plus an API user with two API keys (newline-separated), the admins group, a CA plus a web GUI certificate referenced by `system/webgui/ssl-certref`, and sysctl tunables. |
| `multiwan.xml` | A smaller dual-WAN variant. `igc0` is a DHCP WAN and `igc2` is a static WAN (opt1, 198.51.100.2/30, gateway 198.51.100.1). Both gateways have monitor IPs. Two gateway groups use failover tiers, and the policy filter rules use them. It also has a legacy-named VLAN device (`igc1_vlan50`), legacy `track6` on LAN, a multi-line network alias and automatic outbound NAT. |

## Conventions (mandatory for any new fixture)

- **Public IPv4:** only the RFC 5737 documentation ranges 192.0.2.0/24,
  198.51.100.0/24 and 203.0.113.0/24. Private (RFC 1918) and other special
  ranges are fine for inside networks.
- **Public IPv6:** only the RFC 3849 range 2001:db8::/32.
- **MAC addresses:** `02:00:5e:xx:xx:xx` (locally administered).
- **Domains:** `home.example`, `example.com`, `example.net` and subdomains.
  NTP servers, blocklist URLs and GeoIP URLs also point at these.
- **Passwords:** bcrypt-shaped dummies such as
  `$2y$11$synthetic.synthetic.synthetic.synthetic.synthetic.syn`. API secrets
  use a fake `$6$synthetic$...` string.
- **WireGuard keys, API keys and certificate/key PEMs:** base64 of obviously
  fake ASCII text such as `SYNTHETIC-WG-...-NOT-A-REAL-KEY` or
  `-----BEGIN CERTIFICATE----- SYNTHETIC TEST CERTIFICATE - NOT A REAL KEY ...`.
  Never generate real key material.
- **UUIDs:** well-formed, invented UUIDv4 values, unique within each file.

## Structure source

Everything below was checked against OPNsense core at tag `26.7.9`
(`git -C reference/opnsense/core show 26.7.9:<path>`) and plugins at tag
`26.7.9`. The reference checkout HEAD is 27.1 development, where
`Firewall/Filter` is already 1.1.7 with a new `settings` subtree; the corpus
deliberately models 26.7, so it uses Filter 1.0.6. Paths below are relative to
`src/` in core unless noted.

### How MVC models are written

- `BaseModel::toXML()` (`opnsense/mvc/app/models/OPNsense/Base/BaseModel.php`)
  builds the mount path and, when the model has a version, adds three root
  attributes in this order: `version`, `persisted_at` (`sprintf("%0.2f",
  microtime(true))`) and `description` (the model's `<description>`, with
  whitespace collapsed). This applies to every mount that is not a legacy
  mapper, including single-slash mounts such as `/vlans`.
- Legacy mappers are mounts that end in `+` and do not start with `//`
  (`BaseModel::isLegacyMapper()`). They get no root attributes. Their array
  items are merged node by node into the existing legacy location
  (`internalSerializeToConfig()`): an item replaces the old item at the same
  index, and new items are appended to the parent (for example `/system` for
  `/system/user+`). New parents are created at the end of `<opnsense>`.
- `BaseField::addToXMLNode()` writes fields in **model-definition order**. It
  writes every non-volatile field, empty ones included (as `<x/>`), and copies
  node attributes. ArrayField items therefore carry `uuid`. That includes
  legacy-mapper items: `BaseModel::parseXml()` generates a uuid for an item
  that has none, and it is persisted on the next save. A container whose only
  children are volatile is still written as an empty element (Filter's
  `<general/>`, which holds only the volatile `snat_mode`). Volatile fields
  (`volatile="true"`) and the virtual placeholder item of an empty ArrayField
  are never written.
- Fields not defined in the model are dropped on save. Repeated legacy tags are
  folded into one value, for example `MemberField` joins several `<member>`
  with commas.

### Models (mount, version at 26.7.9)

All checked under `opnsense/mvc/app/models/OPNsense/`. Every model item in the
corpus was compared field by field (names and order) against these files, with
volatile fields excluded.

- `Firewall/Alias.xml`: `//OPNsense/Firewall/Alias`, 1.0.1
- `Firewall/Filter.xml`: `//OPNsense/Firewall/Filter`, 1.0.6. Children are
  `general` (written empty), `rules`, `snatrules`, `npt` and `onetoone`.
- `Firewall/DNat.xml`: `/nat/rule+`, a legacy mapper (the file says 1.0.0,
  but no version is written)
- `Routing/Gateways.xml`: `//OPNsense/Gateways`, 1.0.0
- `Routing/GatewayGroups.xml`: `/gateways/gateway_group+`, a legacy mapper
- `Wireguard/General.xml`: `//OPNsense/wireguard/general`, 0.0.1. WireGuard is
  part of core in 26.7 (`etc/inc/plugins.inc.d/wireguard.inc`).
- `Wireguard/Server.xml`: `//OPNsense/wireguard/server`, 1.0.1
- `Wireguard/Client.xml`: `//OPNsense/wireguard/client`, 1.0.0
- `Kea/KeaDhcpv4.xml`: `//OPNsense/Kea/dhcp4`, 1.0.7
- `Unbound/Unbound.xml`: `//OPNsense/unboundplus`, 1.0.15. DNSBL uses
  `dnsbl/blocklist` items. `hosts/host/aliases` is volatile and is not written.
  The top-level `<aliases/>` is the host-alias container.
- `Syslog/Syslog.xml`: `//OPNsense/Syslog`, 1.0.3
- `Interfaces/Vlan.xml`: `/vlans`, 1.0.0 (versioned, because there is no `+`)
- `Auth/User.xml` and `Auth/Group.xml`: `/system/user+` and `/system/group+`,
  legacy mappers
- `Trust/Ca.xml` and `Trust/Cert.xml`: `/ca+` and `/cert+`, legacy mappers
- `Trust/General.xml`: `//OPNsense/trust/general`, 1.0.2
- `Core/Tunables.xml`: `//sysctl`, 1.0.2
- `Core/Firmware.xml`: `//system/firmware`, 1.0.1

### Value formats

- **Newline (`\n`) separated:** alias `content` (`Firewall/FieldTypes/AliasContentField.php`,
  `$separatorchar = "\n"`; the legacy-alias migration `Firewall/Migrations/M1_0_0.php`
  also converts to `\n`), Kea `pools` (`Kea/FieldTypes/KeaPoolsField.php`), and
  user `apikeys` (`Auth/FieldTypes/ApiKeyField.php`). Each API key line is exactly
  `key|crypted-secret`, where the key is base64 of 60 random bytes and the secret
  is `crypt(secret, '$6$')`. A line with any other number of `|` parts is ignored
  by `get()` and `all()`.
- **Comma separated:** everything built on `BaseSetField` (`CSVListField`, and
  `NetworkField` / `HostnameField` with `AsList`, default `internalFieldSeparator`
  `,`), every `Multiple` `OptionField`, `InterfaceField` and `ModelRelationField`
  (`BaseListField`), and `MemberField` / `PrivField`. In the corpus this covers
  WireGuard `tunneladdress` and `peers`, Kea `interfaces` and `option_data`
  lists, Unbound `type`, `lists`, `allowlists`, `source_nets` and
  `privateaddress`, Syslog `level`, alias `proto`, and group `member`.
- **Gateway groups** (`Routing/FieldTypes/GatewayGroupItemField.php`): tier 1
  gateway names go in `item`, and tiers 2 to 5 go in `item2` to `item5`,
  comma-separated. The legacy `<item>GW|tier|...</item>` lists are converted on
  load.
- **Dynamic gateways** are stored with an empty `<gateway/>`
  (`Routing/Migrations/M1_0_0.php` rewrites `dynamic` to an empty string, and
  `Gateways.php` treats empty and `dynamic` alike).
- **`audit`** (`Base/FieldTypes/JsonAuditField.php`) is base64 of
  `json_encode()` output with the keys `created`, `updated` and `userdata.note`,
  and with `/` escaped as `\/`. `ApiMutableModelControllerBase::setAuditMetadata()`
  fills the description as `$_SERVER['SCRIPT_NAME'] . ' made changes'`. Because
  `etc/inc/plugins.inc.d/webgui.inc` rewrites `/api/...` to `/api/api.php`, the
  corpus uses `/api/api.php made changes`. That value is inferred from the
  rewrite, not observed on a live box. The importer must treat it as opaque.
- **`revision`** (`opnsense/mvc/app/library/OPNsense/Core/Config.php`,
  `getRevisionContext()`) has the children `username`, `description` (built
  from `REQUEST_URI`) and `time`, in that order.

### Legacy sections

- **`<filter><rule>`.** At 26.7 the legacy rule pages are no longer in core
  (commit "firewall: legacy rules pages move to plugin #9947"). They live in
  plugins `net/firewall-legacy/src/www/firewall_rules_edit.php`, and
  `etc/inc/filter.inc` still reads and sorts the rules. A saved rule is a PHP
  array that `Config::fromArray()` serializes in insertion order. False
  booleans are skipped and `true` becomes `1`. The order is: the non-empty
  copy fields (`type, interface, ipprotocol, tag, tagged, max, max-src-nodes,
  max-src-conn, max-src-states, statetimeout, statetype, os, descr, gateway,
  sched, associated-rule-id, direction, state-policy, max-src-conn-rate,
  max-src-conn-rates, category, shaper1, shaper2`), then `interfacenot`, the
  adaptive, overload, floating and tcpflags fields, `allowopts`,
  `disablereplyto`/`reply-to`, `nopfsync`, `nosync`, `disabled`, `log`, the
  prio and tos fields, `quick` (always written), `protocol` (omitted for
  `any`), `icmptype`, `source`, `destination`, `updated` and `created`.
  `source` and `destination` come from `pconfig_to_address()` (`www/guiconfig.inc`)
  and hold `<any>1</any>`, `<network>` (special nets such as `opt2` or
  `opt2ip`) or `<address>` (an alias or IP), then `<not>`, then `<port>`.
  `updated` and `created` come from `make_config_revision_entry()`
  (`etc/inc/config.inc`), with the children `username`, `time` and
  `description`. Every save gives the rule a `uuid` attribute.
- **`<nat>`.** Port forwards are the DNat legacy mapper (`<nat><rule uuid>`).
  `nat/outbound/mode` (`automatic|hybrid|advanced|disabled`) is written by
  `Filter::serializeToConfig()` from the volatile `general/snat_mode`. Manual
  outbound rules are MVC `Filter/snatrules`. The legacy outbound page also
  moved to the `firewall-legacy` plugin.
- **`<interfaces>`** follow `www/interfaces.php` at 26.7.9. A save rebuilds
  the interface array in this order: `if, descr, enable, lock, spoofmac,
  blockpriv, blockbogons, gateway_interface, promisc, mtu, mss, media,
  mediaopt`, then the IPv4 block, then the IPv6 block. False booleans and empty
  `mtu`/`mss`/`media` are omitted. The IPv4 blocks are: static (`ipaddr,
  subnet[, gateway]`), or DHCP (`ipaddr=dhcp, dhcphostname, alias-address,
  alias-subnet` (posted default 32), `dhcprejectfrom`, the six `adv_dhcp_pt_*`
  timing fields, `adv_dhcp_pt_values` (posted default `SavedCfg`), the
  send/request/required/option-modifier fields, and
  `adv_dhcp_config_advanced, adv_dhcp_config_file_override,
  adv_dhcp_config_file_override_path`; all of these are written even when
  empty). The `dhcp6` block is `ipaddrv6, dhcp6-ia-pd-len`, the optional
  flags, then every posted `adv_dhcp6_*` text field, written empty. The
  `idassoc6` and `track6` blocks are `ipaddrv6, track6-interface,
  track6-prefix-id`. `track6` is labelled "Track Interface (legacy)", and
  `dhcpd6track6allowoverride` is only written when it is true. `lo0` and
  `wireguard` are dynamic entries from `etc/inc/plugins.inc`
  (`plugins_interfaces()`, with `internal_dynamic` first) and from
  `plugins.inc.d/loopback.inc` and `plugins.inc.d/wireguard.inc`.
- **VLAN device names** (`opnsense/mvc/app/controllers/OPNsense/Interfaces/Api/VlanSettingsController.php`):
  new devices are named `vlan0<N>` (`vlan01`, `vlan02`, ...), and the legacy
  `<parent>_vlan<tag>` name is kept as long as it does not change.
- **`<system>`.** `www/system_general.php` always writes `dnsallowoverride`
  (`1`/`0`), and `dns1gw` through `dns8gw` (`none` or a gateway name), on every
  save. `www/system_advanced_admin.php` always writes `ssh/noauto` plus empty
  `ssh/{interfaces,kex,ciphers,macs,keys,keysig,rekeylimit}`. NAT reflection
  keys come from `www/system_advanced_firewall.php`. `timeservers` is
  space-separated, as are `ntpd/prefer` and `ntpd/iburst`. `ntpd/interface` is
  comma-separated (`www/services_ntpd.php`).
- The baseline layout follows `etc/config.xml.sample`.

## Canonical format (byte-exact round-trip test)

The import tests parse each file and re-serialize it with the canonical writer.
They then assert the output is **byte-identical** to the input, so these files
must already be canonical. The writer mirrors `Config::__toString()`
(`opnsense/mvc/app/library/OPNsense/Core/Config.php`). That function creates a
fresh `DOMDocument('1.0')` with a new `<opnsense>` root, imports only the
element children (so root attributes are dropped), sets `formatOutput = true`
and `preserveWhiteSpace = false`, and does a `loadXML(saveXML())` round trip
before `saveXML()`. Both files are byte-identical to `xmllint --noblanks
--format` output, which is the same libxml2 formatter.

- The first line is exactly `<?xml version="1.0"?>`, because no encoding is
  given. The root is `<opnsense>` with no attributes, and the file ends with
  `</opnsense>` and a single LF.
- Indentation is 2 spaces per level, with one element per line. Line endings are
  LF only: no tabs, no trailing whitespace, no comments and no CDATA.
- Text goes inline (`<descr>LAN</descr>`). Empty elements are always written as
  `<x/>`, never `<x></x>` and never `<x />`.
- Attributes are double-quoted and kept in their written order. In attributes,
  escape `&`, `<`, `>` and `"`. In text, escape only `&`, `<` and `>`. Do not
  escape quotes in text.
- ASCII only. With no declared encoding, libxml2 would write non-ASCII as
  character references. No whitespace-only text, and no leading or trailing
  whitespace in text.
- Multi-value fields that OPNsense stores newline-separated are written exactly
  as OPNsense writes them: a single text node with embedded LF characters and
  no indentation inside it. For example:

  ```
            <content>10.0.0.0/8
  172.16.0.0/12
  192.168.0.0/16</content>
  ```

  Both fixtures contain such values (alias `content`, plus Kea `pools` and
  `apikeys` in `home-router.xml`), so the importer must preserve embedded LF.
  CR never appears; libxml2 would write it as `&#13;`.

## Verified against 26.7.9

Claims from the earlier, unverified version of this README and the fixtures:

| Claim / guess | Outcome |
|---|---|
| Model mounts and versions listed above | **Confirmed.** All 17 match the 26.7.9 model XMLs. |
| MVC roots carry `version`, `persisted_at`, `description` | **Confirmed** (`BaseModel::toXML()`, in that order). The model descriptions in the fixtures match too. |
| Legacy mappers: no version, items carry `uuid` | **Confirmed** (`isLegacyMapper()`, `ArrayField`, `parseXml()`). |
| Field order of every MVC item follows the model | **Confirmed** for all items, with one exception. **Corrected:** Filter lacked its first child `<general/>`, which is now added in both files. |
| Volatile fields omitted | **Confirmed.** |
| Legacy `<filter><rule>` format | **Mostly confirmed.** The sub-structure, the `updated`/`created` child order and the `uuid` were right. **Corrected:** `protocol` is written after `quick`, not after `descr`. The rules are not "migrated": at 26.7 they come from the `firewall-legacy` plugin. |
| Multi-value fields kept single-valued, "no embedded LF" | **Replaced.** OPNsense writes alias `content`, Kea `pools` and `apikeys` with LF, and the fixtures now contain such values. Everything else is comma-separated and was already correct. |
| `apikeys` format `key\|secret\|time\|descr` | **Corrected** to `key\|crypted-secret` lines (`ApiKeyField`). There are now two keys. |
| Gateways `<gateway>dynamic</gateway>` | **Corrected** to an empty `<gateway/>` (Gateways migration M1_0_0). |
| Interfaces in config.xml.sample order with `mtu/media/mediaopt` empties and `<blockpriv>0</blockpriv>` | **Corrected** to the `interfaces.php` save order. Added the DHCPv4 and DHCPv6 advanced fields that are always written. Dropped the empty `mtu`/`media`/`mediaopt`, the false `blockpriv` and the false `dhcpd6track6allowoverride`. |
| `system` section | **Corrected:** added `dnsallowoverride` (0) and `dns1gw`..`dns8gw`, which `system_general.php` always writes. Moved `language`/`prefer_ipv4` before `dnsserver` (insertion order). |
| `audit` description `/api/firewall/.../... made changes` | **Corrected** to `/api/api.php made changes`. This is inferred from `SCRIPT_NAME` plus the webgui rewrite; see above. |
| DNat, gateway group, user, group, CA, cert, VLAN, tunables, Kea, Unbound, WireGuard, Syslog and Trust structure and values | **Confirmed.** This covers option values, booleans and defaults. |
| VLAN device naming `vlan0N` and legacy `igc1_vlan50` | **Confirmed** (`VlanSettingsController::generateVlanIfName()`). |
| `lo0`/`wireguard` dynamic interface entries | **Confirmed** (`plugins_interfaces()`, `loopback.inc`, `wireguard.inc`). |
| Canonical byte format | **Confirmed** (`Config::__toString()`). Both files equal `xmllint --noblanks --format` output and pass `every_fixture_roundtrips`. |
