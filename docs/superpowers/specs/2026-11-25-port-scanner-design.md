# Port scanner service — design

Status: draft for owner approval, 2026-11-25.

## Why

The owner wants to see which ports are open on every device on the home
networks, at a glance in the hosts table, and to scan any address or range on
demand, "similar to nmap and better if possible". Today sensr only knows what
devices say about themselves (DHCP, mDNS, the neighbour table). Traffic
between two LAN devices never passes the router, so open ports cannot be
learned passively: the router has to ask.

This deliberately reverses one non-goal of the smart host labels design
(2026-11-23: "No active scanning: no nmap, port probes"). That design's
anti-goal, "anything that could disturb a device", still holds and shapes the
pacing and the exclude list below.

## Goals

- A new Rust service, **`sensr-scan`**, running on the router as its own
  systemd unit, used by the rest of the app.
- **Triggers:**
  - one automatic scan of each device the first time it joins the network
    (a new inventory row). Devices already in the inventory when the service
    is first enabled count as new: they are queued once, one at a time;
  - **Scan now** on any host (hosts table, host page, Services page);
  - a scan of **any address or range** typed on the Services page.
  - No periodic or daily scans.
- **What a scan does:**
  1. For a range: find which addresses are alive. Skipped for one host.
  2. **TCP:** all 65,535 ports, by full connect, gently rate-limited.
  3. **UDP:**
     - ~40 well-known services, each probed with a real request in its own
       protocol (DNS, NTP, SNMP, SSDP/UPnP, mDNS, NetBIOS-NS, DHCP, TFTP,
       syslog, IKE, Chromecast/AirPlay discovery, …). An answer = open;
     - the top ~1,000 UDP ports with empty probes. No answer and no ICMP
       "port unreachable" = **open|filtered**, shown greyed, never as open.
  4. **Service identification** on every open port: read what the service
     says back. At least the SSH version, HTTP `Server` header and page
     `<title>`, TLS certificate subject/SAN/issuer/expiry, plus greeting
     banners (FTP, SMTP, IMAP, POP3, MQTT, Redis, RTSP, …), SNMP
     `sysDescr`, SSDP `SERVER` and device model.
  5. **Compare** with the previous scan of the same target: ports opened,
     ports closed, a changed banner/certificate.
- **Hosts table** (dashboard Hosts card): a muted line under the host name
  with the open ports and their service names, `+port new` for changes, the
  scan date and a **Scan now** button; "scanning…" while a scan runs.
- **Host page** (`/ui/hosts/<key>`): a **Ports** section with the full
  latest result (port, protocol, service, what it said) and the change
  history.
- **Services › Port Scanner** page (`/ui/portscan`):
  - **New scan** form: an address, a CIDR, or a range `a.b.c.d-e`;
  - the running scan with progress, a queue, and Cancel;
  - **Device scans**: every inventory device, its open ports, changes, last
    scan, Scan now;
  - **Range scans**: past range scans and their results;
  - settings (below).
- Results that beat plain nmap: titles, certificates and device names up
  front; changes since the last scan; ports tied to the inventory device
  (by MAC), so they follow a device across IP changes; device type from the
  existing smart labels.

## Non-goals

- OS detection. The smart labels (DHCP/mDNS/OUI) already say what a device
  is, and nmap's OS database is NPSL-licensed.
- A full UDP scan of all 65,535 ports (a closed UDP port answers at most
  about once a second, so it would take most of a day per device).
- Periodic scans, alerts or notifications on changes (the data model keeps
  history, so a later piece can add them).
- Vulnerability checks or anything nmap's NSE scripts do beyond reading what
  a service says back.
- Scanning from or onto the WAN side by default (see Constraints).

## Anti-goals

- **Disturbing devices.** Cheap IoT devices and printers can misbehave under
  a fast scan. Scans are paced, one target at a time, with an exclude list.
- **The router as an internet scanner.** Public addresses are refused unless
  the owner ticks an explicit "I own or am allowed to scan this" for that
  scan.
- **SD-card wear.** Results are written once per finished target, not per
  port.
- **Running as root,** or giving the API/UI new privileges.
- **Copying nmap's data files** (`nmap-services`, `nmap-service-probes`,
  `nmap-os-db` are NPSL). Probes and match rules are our own; service names
  come from the IANA registry already on the system (`/etc/services`, from
  `iana-etc`).

## Approaches considered

1. **Own TCP/UDP scanner in Rust, plain sockets** (chosen). Full TCP
   connects and connected UDP sockets (which report ICMP port unreachable as
   `ECONNREFUSED`) need no privileges. No new runtime dependency, no licence
   question, testable in the NixOS VM tests. Devices see completed
   connections, which some log.
2. **Run nmap.** Mature, with version detection. A sizeable new dependency in
   the Pi image and the NPSL restricts redistributing it inside a product,
   which conflicts with sensr's MIT/Apache licence. Rejected.
3. **Half-open (raw SYN) scanner.** Gentlest on applications and fastest, but
   needs raw sockets/CAP_NET_RAW, reply matching and more code, for little
   gain on a home network. Kept as a later upgrade behind the same API if a
   device turns out to dislike full connects.

The owner chose a new, separate Rust service under Services ("similar to
nmap and better if possible"), both for ranges and for managing the device
scans, with TCP and UDP.

## Design

### Crate and process

- New crate **`crates/sensr-scan`**: a library (scanner, probes, store) and a
  binary `sensr-scan`. Async on tokio, like the other daemons.
- systemd unit `sensr-scan.service` in `nix/modules/sensr.nix`, modelled on
  `sensr-insight`:
  - `User = sensr-scan`, `Group = sensr`, `commonHardening`,
    `ProtectSystem = strict`, no capabilities, `RestrictAddressFamilies =
    AF_UNIX AF_INET AF_INET6 AF_NETLINK`;
  - `StateDirectory = sensr-scan` (0750, group `sensr`): `scans.db`;
  - `RuntimeDirectory = sensr-scan`: the control socket `scan.sock` (0660,
    group `sensr`);
  - reads its config from `/run/sensr/portscan/portscan.json` (rendered by
    an applier, like `insight.json`); `ConditionPathExists` on it;
  - `Nice = 10`, `MemoryMax = 128M`.

### Config (`sensr-schema`, model `portscan`)

- `portscan.enabled` (default true).
- `portscan.auto_scan_new` (default true): scan a device the first time it
  joins.
- `portscan.exclude`: MACs and addresses for fragile devices (builder's
  call on ranges):
  - never scanned automatically;
  - **skipped in range scans.** Discovery maps each live address to a MAC
    through the neighbour table before probing. The job lists the addresses
    it skipped, and the New scan form has an "include excluded devices" tick
    to scan them anyway;
  - Scan now on one asks for confirmation.
- `portscan.pace`: `gentle` (default) | `normal` | `fast`, setting
  concurrency and the connection rate (gentle: ≤ 200 TCP connects/s and ≤ 64
  in flight per target; one target at a time).
- `portscan.history` (default 10): scans kept per target.
- `portscan.max_range` (default 4096 addresses per range scan).
- An applier in `sensr-apply` renders `portscan.json`, including the internal
  interfaces' subnets and WireGuard networks (the "local" target set).

### Control socket protocol

JSON lines over `scan.sock`, used by the agent (new devices) and the API
(user actions):

- `start {target, kind: device|range, mac?, label?, public_ok: bool}` →
  `{job_id}`; refused with a reason for a public target without
  `public_ok`, a range above `max_range`, or an excluded device without
  `confirm: true`.
- `cancel {job_id}`, `status` → `{running, queue[]}` with progress
  (addresses alive, target n of m, ports done).
- Queue: one job runs; manual jobs go ahead of automatic ones; a target
  already queued is not queued twice.

### New devices

- The rule is standing, not a one-time event (builder's call): **every
  inventory MAC row with no complete scan and no owner-cancelled automatic
  scan is queued for one automatic scan.** It covers both new devices and
  the devices present on first enable.
- `HostCollector` (sensr-agent) already knows when it creates an inventory
  row. When `portscan.auto_scan_new` is on, it sends `start {kind: device,
  auto: true, mac, target: ipv4}` once the row has an IPv4 address.
- At startup (and when the agent reconnects to `scan.sock`), the agent sends
  the rule's whole list once. So the queue can live in memory: a scan lost to
  a restart, or a device that appeared while `sensr-scan` was down, is
  picked up again. `sensr-scan` ignores a `start` for a target it already
  has queued or a complete scan for.
- An automatic scan the owner cancels is recorded (`status = cancelled`), and
  that device is not queued automatically again. Scan now still works.
- A device keeps its results keyed by MAC. A new random MAC is a new device,
  and gets its one scan.

### Scanning

- **Discovery** (ranges): neighbour table and ARP for local subnets; ICMP
  echo via an unprivileged ping socket (systemd's `ping_group_range`
  default) and a TCP connect to a few common ports elsewhere. An address
  is alive if anything answers.
- **TCP**: connect scan of 1-65535, the ~1,000 most common ports first so
  the UI shows useful results early. Connection refused = closed; timeout
  (adaptive from measured RTT, min 300 ms, one retry) = filtered; connected
  = open, then identified.
- **UDP**: the protocol probe table first, then empty datagrams to the top
  ~1,000 ports. A reply = open; `ECONNREFUSED` = closed; silence =
  open|filtered. Paced to respect ICMP rate limits.
- **Identification** (per open port, 5 s budget): read a greeting first; if
  none, send the probes matching the port's likely service, then a generic
  HTTP probe, then a TLS ClientHello (rustls, verification off, cert
  recorded). Captured text is capped (e.g. 256 bytes per field) and
  sanitised for display.
- Port lists (top TCP/UDP) and the probe/match table are our own, built
  from the IANA registry and public protocol specs.

### Storage (`scans.db`, SQLite)

- `jobs(id, kind: device|range, target, requested_by: auto|owner, started,
  finished, status, public_ok)`: one row per scan request. A range is one
  job.
- `scans(id, job_id, address, mac, started, finished, status:
  complete|partial|cancelled|failed)`: one row per scanned address. A device
  job has exactly one.
- `ports(scan_id, proto, port, state, service, product, version, title,
  tls_subject, tls_issuer, tls_not_after, banner)`.
- **Range results count for devices (builder's call).** When a live address
  in a range maps to an inventory MAC (neighbour table at scan time), its
  `scans.mac` is set. A complete one becomes that device's latest scan, so it
  updates the hosts line, the history and the change markers. One truth per
  device, whichever way it was scanned.
- **Writes:** one transaction per address when its scan ends, whether
  complete, cancelled or failed. Ports found so far are kept.
- **Partial results (builder's call):**
  - A cancelled or interrupted scan stores what it found, marked `partial`.
  - The UI shows it as "partial scan" and lists the open ports seen.
  - It is never the baseline for the change summary, so unreached ports do
    not show as "closed".
  - It does not count as the device's one automatic scan, unless it was an
    owner cancel (see New devices).
- **Changes** are computed against the previous `complete` scan of the same
  MAC, or of the same address for non-inventory targets.
- **Pruning:**
  - `portscan.history` complete scans per MAC or address;
  - range jobs older than 90 days, with any of their scans that are no
    longer within a device's kept history.

### API and UI

- API (`sensr-api`, group `sensr`): reads `scans.db` read-only like the
  Insight routes; forwards actions to `scan.sock`.
  - `GET /api/v1/portscan/status`, `GET /api/v1/portscan/scans`,
    `GET /api/v1/portscan/scans/<id>`, `GET /api/v1/portscan/hosts/<mac>`;
  - `POST /api/v1/portscan/start`, `POST /api/v1/portscan/cancel`.
- The hosts view gains `ports: {open: [{proto, port, service, label}],
  changes: […], scanned_at, scanning: bool}` for each MAC row.
- **Hosts card**: under the host name, a muted line:
  `22 ssh · 80 http "Synology" · 443 https · 53/udp dns · +3389 new` ·
  `scanned Nov 25` · `Scan now`. Long lists show the first 8 and "+N more"
  (link to the host page). Tooltip per port: what it said.
- **Host page**: a Ports section (table + history).
- **Services › Port Scanner** (`menu.rs` SERVICES, `/ui/portscan`): the page
  from Goals, with settings on the same page.
- CLI: `sensr scan <target>` and `sensr scan status`, through the API.

### Testing

- Unit tests: target parsing and the public/local check, queue order, the
  UDP probe encoders/decoders, banner and HTTP/TLS parsers, change summary,
  pruning.
- Integration test against local listeners in the test process (TCP open
  and closed, a TLS server, a UDP echo, a silent UDP port).
- NixOS VM test `nix/tests/portscan.nix`: a target VM with sshd, an HTTP
  server, a TLS server, Unbound (53/udp) and an SNMP agent; asserts a
  device scan finds and identifies each, a new device is scanned
  automatically, a public target is refused without `public_ok`, and the
  hosts view carries the ports.
- Mock backend + component tests for the hosts line and the Services page;
  Playwright e2e for Scan now and New scan.

## Constraints

- Latest dependency versions, tests for every behaviour, Leptos SSR UI with
  server functions, as the other features.
- `sensr-scan` never scans a public address without `public_ok`. "Local"
  is: the internal interfaces' subnets, WireGuard networks, and RFC 1918 /
  ULA / link-local addresses.
- No AI attribution in commits or PRs.

## Left to the builder

- The exact top-port lists and the UDP probe set beyond the examples.
- Exact timeouts, retry counts and the `normal`/`fast` pace numbers.
- Table and page layout details, icons, and the wording of messages.
- Whether `sensr scan` waits for results or returns a job id.
