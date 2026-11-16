# sensr-monitor: gateway monitoring

`sensr-monitor` replaces OPNsense's per-gateway `dpinger` processes and the
`gateway_watcher.php` loop that turns their numbers into a status. Behaviour
was derived from the pinned OPNsense core tree (see `reference/COVERAGE.toml`):

- `src/etc/inc/plugins.inc.d/dpinger.inc`: how dpinger is started.
- `mvc/app/models/OPNsense/Routing/FieldTypes/GatewayField.php`
  (`getDpingerDefaults`) and `Routing/Gateways.xml`: defaults and limits.
- `mvc/app/models/OPNsense/Routing/Gateways.php`: validation, gateway ordering,
  `getDefaultGW`.
- `mvc/app/library/OPNsense/System/StaticRoute.php`: `getMonitorStatus`
  (status mapping) and `staticRoutes` (default gateway switching).
- `mvc/app/models/OPNsense/Routing/GatewayGroups.php`: `gatewayIsUp`,
  `gatewayStateChange`, `getActiveGroups`.
- `src/opnsense/scripts/routes/gateway_watcher.php` and
  `src/etc/rc.syshook.d/monitor/20-recover`: transitions and alarms.

## Defaults

OPNsense applies these whenever a gateway leaves the field empty. dpinger is
started as `dpinger -f -S -r 0 -i NAME -B SRC -p PID -u SOCK -s Is -l Ls -t Ts
-d D MONITOR`, so it uses its own default alert interval (1 s).

| Setting | OPNsense field | Default | Limits upstream |
|---|---|---|---|
| `latency_low` | `latencylow` | 200 ms | >= 1, < `latencyhigh` |
| `latency_high` | `latencyhigh` | 500 ms | >= 1, > `latencylow` |
| `loss_low` | `losslow` | 10 % | 1..=99, < `losshigh` |
| `loss_high` | `losshigh` | 20 % | 1..=100, > `losslow` |
| `interval` | `interval` (dpinger `-s`) | 1 s | >= 1 s |
| `loss_interval` | `loss_interval` (`-l`) | 4 s | >= 1 s |
| `time_period` | `time_period` (`-t`) | 60 s | >= 2 x (interval + loss_interval) |
| `data_length` | `data_length` (`-d`) | 1 byte | >= 0 |
| `alert_interval` | none (dpinger `-A`) | 1 s | not configurable |

Other gateway defaults that matter to selection: `priority` 255 (254 for
auto-created dynamic gateways on non-tunnel interfaces), `weight` 1 (1..=10),
monitoring disabled (`monitor_disable` defaults to 1), group trigger `down`.

## Statistics

Per target a ring of probes (sequence number, send instant, round-trip time
if answered) covers the last `time_period`:

- One echo request every `interval`. A request that could not be sent counts
  like an unanswered one.
- An answered probe counts as received if its round-trip time is at most
  `loss_interval`, otherwise as lost.
- An unanswered probe counts as lost once it is older than `loss_interval`;
  before that it is pending and not counted at all.
- Latency average and (population) standard deviation over the received
  probes; loss = lost / (received + lost) x 100.
- No counted probe means no sample, dpinger's `0 0 0`.

Every instant is passed in, so tests replay timelines without a clock.

## Status mapping

`getMonitorStatus` reads dpinger's figures and compares them to the
thresholds with strict "greater than":

| Condition | sensr `Status` | OPNsense string |
|---|---|---|
| force down configured | `ForceDown` | `force_down` |
| monitoring disabled | `Online` (`monitored: false`) | `none` |
| monitored, no sample yet | `Pending` | `down` (with `~` figures) |
| latency > latency_high **or** loss > loss_high | `Down` | `down` |
| latency > latency_low **and** loss > loss_low | `DelayLoss` | `delay+loss` |
| latency > latency_low | `Delay` | `delay` |
| loss > loss_low | `Loss` | `loss` |
| otherwise | `Online` | `none` |

`Status::opnsense_str()` gives the upstream string; `Status::is_down()` is
upstream's "contains `down`" test (`down`, `force_down`, and so `Pending`).

**Hysteresis.** Neither dpinger nor OPNsense has threshold hysteresis: the
status follows the windowed average directly. Smoothing comes only from the
window, so a gateway that was down for a while needs enough good probes to
push the averages back under the thresholds. The watcher additionally
waits 10 s after start, treats the first report of each gateway as `down`,
and sleeps 10 s after raising an alarm; those belong to the alarm action and
are left to the agent (see differences).

## Gateway groups

`Trigger::is_up(status)` (upstream `gatewayIsUp`):

| Status | `down` | `downloss` | `downlatency` | `downlosslatency` |
|---|---|---|---|---|
| `Online` | up | up | up | up |
| `Delay` | up | up | **down** | **down** |
| `Loss` | up | **down** | up | **down** |
| `DelayLoss` | up | **down** | **down** | **down** |
| `Down`, `ForceDown`, `Pending` | **down** | **down** | **down** | **down** |

`select_group` (upstream `getActiveGroups`): walk the tiers from the lowest
number; the first tier with at least one up member is used, and all its up
members share traffic by weight (`share = weight / sum`). If no member of any
tier is up, the whole lowest tier is returned with `all_down = true`.

`Trigger::crossed(from, to)` is `gatewayStateChange`: a transition raises a
group alarm when it changes the member's usability under that trigger.

## Default gateway

Upstream sorts all gateways by a key of (marked `defaultgw` first, then
ascending `priority`, then configuration order) and `getDefaultGW` returns
the first gateway of the family that is not disabled, defunct, loopback or
forced down, and not in the skip list. The skip list is the set of gateways
whose status contains `down`, but only when "default gateway switching"
(`gw_switch_default`) is on and the system is not booting.

`select_default_gateway(candidates, family, switching)` does the same:

- every gateway of the family is a candidate; `default_route` only ranks
  first, it is not a filter;
- disabled, forced-down and address-less gateways are never chosen;
- with `switching`, gateways that are `Down`, `ForceDown` or `Pending` are
  skipped and the next one wins;
- without `switching`, the monitor is ignored: the first candidate stays
  default even while it is down (`Delay`, `Loss` never cause a switch in any
  mode).

## Probing

`IcmpProber` opens one socket per gateway and target: a raw ICMP / ICMPv6
socket first (`CAP_NET_RAW`), an unprivileged ping socket
(`SOCK_DGRAM`, Linux `net.ipv4.ping_group_range`, always allowed on macOS)
when raw is refused. The socket is bound to the interface
(`SO_BINDTODEVICE`, Linux only) and optionally to a source address, and is
connected to the target so the kernel delivers only that peer's packets.
Each prober has its own echo identifier (process id + counter); requests carry
`data_length` payload bytes. Replies are parsed without panicking: IPv4 raw
sockets (and macOS ping sockets) include the IP header, detected by the
version nibble; ICMPv6 sockets never do. IPv4 checksums are verified; ICMPv6
checksums are the kernel's job. Linux ping sockets rewrite the identifier and
demultiplex by themselves, so the identifier check is skipped there.

`Monitor` runs one tokio task per probed gateway (send on `interval`,
receive continuously, evaluate on `alert_interval`), publishes a `Snapshot`
through a `watch` channel and `StatusChanged { gateway, from, to }` events
through a `broadcast` channel. A gateway without a known address is
`Pending` until `set_target` supplies one; unmonitored gateways are `Online`
without probing; a socket that cannot be opened is retried every 5 s with the
error in the gateway state.

## Differences from OPNsense

| Area | OPNsense | sensr | Why |
|---|---|---|---|
| No data yet | reported as `down` with `~` figures | distinct `Pending` (still `is_down()`, still not usable in groups) | the UI can tell "waiting for DHCP / first reply" from an outage |
| Monitoring disabled | status `none` | `Online` with `monitored: false` | same meaning, explicit flag |
| Process model | one dpinger process per gateway plus a PHP watcher polling Unix sockets every second | one tokio task per gateway in the agent, push-based snapshot and events | no IPC or polling; status changes are immediate |
| Late replies | dpinger decides internally | a reply later than `loss_interval` is counted as lost | documented, deterministic rule |
| Sub-second timing | whole seconds only | any non-zero `Duration` | tests and fast links; validation keeps upstream's ordering rules |
| Address-less default candidate | `getDefaultGW` may return a dynamic gateway without an address, and then no default route is installed | such gateways are skipped and the next candidate wins | avoids losing the default route while a lease is pending |
| All tiers down | first configured tier (tier 1) is used; if tier 1 is empty the group is empty | the lowest tier that has members, flagged `all_down` | tier 1 may be unused |
| Watcher start-up delay (10 s), first-report-is-down, 10 s alarm hold-off | in `gateway_watcher.php` | not in this crate; the agent decides when to act on `StatusChanged` | these throttle the alarm action (route sync, state kill), which lives in the agent |
| Monitor host routes, link-local `%scope` strings | `dpinger_host_routes`, string suffixes | not here; IPv6 scope comes from `ProbeSpec::scope_id` or the bound device's ifindex | route management is the agent's job |
| Gateway switching while booting | ignored during boot | caller passes `switching = false` while booting | the crate has no notion of boot |
