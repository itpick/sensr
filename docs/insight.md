# Traffic insight (Reporting › Insight)

sensr replaces OPNsense's NetFlow + flowd + Insight stack, and the ntopng
container the owner ran on VyOS, with in-kernel counting plus a small reader.

## How it counts

When `insight.enabled` is on, the agent loads table `inet sensr_flow`
(`crates/sensr-flow/src/nft.rs`). Its forward-hook chain runs at priority 20,
after the filter and the IDS queue, so dropped packets are not counted. The
table holds dynamic sets with a counter per element:

| set | key | updated for |
|---|---|---|
| `hu4` `hd4` `hu6` `hd6` | local host | traffic in from a local interface (up) / out to one (down) |
| `au4` … `ad6` | local host . protocol . service port | TCP and UDP; the port is the connection's original destination, so replies count toward the service |
| `ru4` … `rd6` | remote address | the other end |

"Local" means `insight.interfaces`. If that list is empty, every interface
that is not a WAN is local. Idle elements expire after an hour.

`sensr-insight` runs `nft -j list table inet sensr_flow` every
`sample_seconds` (10 by default) and reads `/sys/class/net/*/statistics`. It
turns counter values into deltas: a counter that went down (the table was
reloaded, or an element came back after expiring) counts from zero. It adds
the deltas to buckets in `/var/lib/sensr-insight/flows.db`:

- 10 s, interfaces only, kept for 1 hour;
- 1 minute, `retention.minute_hours` (48);
- 1 hour, `retention.hour_days` (62);
- 1 day, `retention.day_days` (730).

Buckets accumulate, so a stop loses at most one sample.

## Cost

`nix build .#checks.x86_64-linux.insight` measures the cost with iperf3 at
line rate through the VM router, sampling every 2 s:

- **`sensr-insight` used about 0.001 cores.** The test fails above 0.1.
- The kernel side is one set lookup per packet per set kind. In the VM the
  router's busy time and throughput stayed within run-to-run noise with the
  table loaded and with it removed.

For comparison, ntopng cost 0.4 to 0.7 of a core under load on the owner's
Pi 5, and 8 to 37 % of a core when idle.

## API

Read-only, guarded by the `page-diagnostics-networkinsight` privilege:

- `GET /api/v1/insight/top?kind=host|app|remote|iface&from=&to=&limit=&host=`
- `GET /api/v1/insight/series?kind=&key=&from=&to=&res=`
  - Without `key`, it returns the sum over the kind: `kind=iface` is the dashboard traffic graph.
  - `res=10` gives the live interface samples.

Times are Unix seconds. The default range is the last hour.

The IDS alerts that the same daemon tails from eve.json are guarded by
`page-services-ids`:

- `GET /api/v1/ids/alerts?sid=&text=&host=&since=&until=&limit=&offset=`
- `GET /api/v1/ids/signatures`
- `GET /api/v1/ids/stats`

`since` and `until` are in Unix milliseconds.

## Service overrides

`insight.dns.service_overrides` renames or recategorises domains in the
built-in service catalogue used by per-host DNS activity. Each entry has a
lowercase `suffix` of at least two labels (`example.com`; a bare `com` is
rejected), a `service` name (1-48 characters) and a `category`. An override
beats a built-in entry with the same suffix. Matching is by longest suffix, so
a longer built-in suffix still wins over a shorter override: overriding
`google.com` leaves `classroom.google.com` as Google Classroom unless you
override that name too. Suffixes must be unique.

## Not yet

- Host names from DHCP leases. The UI shows addresses.
- NetFlow/IPFIX export to remote collectors. An OPNsense import reports such
  targets as not imported.
