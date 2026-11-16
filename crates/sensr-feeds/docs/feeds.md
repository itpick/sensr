# Alias feeds (`sensr-feeds`)

Everything an alias needs from outside the configuration. OPNsense
counterpart: `scripts/filter/update_tables.py` and `scripts/filter/lib/alias/*`
(behaviour read, code not copied).

## Schedule (upstream TTLs)

| Alias type | Source | Checked | Notes |
|---|---|---|---|
| URL table | its URL | every `refresh` (`updatefreq`); never again when 0 | conditional GET (`ETag`, `If-Modified-Since`): an unchanged list costs a 304 |
| URL | each URL | once (new URL = new fetch) | as upstream's `ttl -1` |
| GeoIP | `firewall.feeds.geoip_url`, default DB-IP Lite country CSV | daily; immediately when a new country is used | only countries in use are stored, `geoip/<CC>-IPv4|IPv6` |
| BGP ASN | `firewall.feeds.asn_url`, default iptoasn.com `ip2asn-combined.tsv.gz` | daily; immediately when a new AS is used | only AS numbers in use are stored, `asn/AS<n>` |
| Host names | system resolver (the box's Unbound) | every `firewall.feeds.resolve_interval` (300 s) | a failed lookup keeps the last answer |
| MAC | neighbour table (`ip -j neigh`) | every 30 s | |

The agent ticks every 10 s; each source keeps its own schedule.

## Last good, never empty

A fetch that fails (network, HTTP status, an HTML error page instead of a
database, a body that does not decompress) never replaces stored contents:
the alias keeps what it had, `status` shows the error, and the source is
retried after 5 min, doubling to at most 1 h. Bodies and databases are
written atomically under `/var/lib/sensr/state/aliases` and survive reboots:
the boot apply renders the stored contents before any network is up.

Changed aliases reach the kernel as one `flush set` + `add element`
transaction (no ruleset reload, conntrack untouched); nested aliases that
include a changed one are updated in the same transaction.

## Data sources and licences

| Source | Licence | Attribution |
|---|---|---|
| DB-IP Lite country (`https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz`, monthly; the previous month is used until the current one is published) | CC BY 4.0 | "IP Geolocation by DB-IP" with a link to <https://db-ip.com>; the UI shows it on GeoIP aliases using the default source |
| iptoasn.com `ip2asn-combined.tsv.gz` | PDDL 1.0 (public domain) | none required |
| MaxMind GeoLite2 country CSV zip, IPinfo country CSV | their own terms (account/licence key) | when configured as `geoip_url` |
| ipdeny.com zones, Spamhaus DROP/EDROP, Emerging Threats, abuse.ch Feodo/SSLBL, … | the list owner's terms | used as URL-table aliases |

MaxMind is not the default because it needs an account key.

## Differences from OPNsense

| OPNsense | sensr | Why |
|---|---|---|
| GeoIP needs a MaxMind/IPinfo URL with a key | DB-IP Lite by default, no account | works out of the box |
| ASN data from rulesets.opnsense.org | iptoasn.com (public domain) by default | no vendor dependency |
| every country file of the database is written | only countries in use | small SD-card footprint |
| a failed URL-table download is retried on the next cron run | back-off 5 min → 1 h, error in the alias status | visible, no hammering |
| every fetch is a full download | conditional requests | 304s for unchanged lists |
