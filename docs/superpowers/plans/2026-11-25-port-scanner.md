# Port Scanner Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `sensr-scan` service that scans devices (once on first join, and on demand) and any range for open TCP/UDP ports. It identifies what is listening and shows the results in the hosts table, on the host page and on Services › Port Scanner.

**Architecture:**
- A new crate `crates/sensr-scan`, split by features:
  - the default build is the shared contract (config, control protocol, targets), used by sensr-apply, sensr-agent, sensr-api and sensr-ui;
  - `store` adds the SQLite results database (read by API/UI);
  - `daemon` adds the scanner and the `sensr-scan` binary.
- The daemon runs unprivileged:
  - it takes jobs over a JSON-lines unix socket (`/run/sensr-scan/scan.sock`);
  - it writes `scans.db` once per finished address.
- The agent queues the automatic device scans. The API and UI read the database and send user actions to the socket. This mirrors `sensr-insight` / `sensr-flow`.

**Tech Stack:**
- Rust 2024 and tokio, with `rusqlite` (bundled).
- `rustls`/`tokio-rustls` with verification off, and `x509-parser` for certificates.
- Leptos SSR UI, NixOS module, NixOS VM tests, Playwright.

**Spec:** `docs/superpowers/specs/2026-11-25-port-scanner-design.md`

## Global Constraints

- Latest stable dependency versions in `[workspace.dependencies]`. A new dep goes there first (`x509-parser`, dev-dep `rcgen`).
- Tests for every behaviour. Every new API route must be covered by a privilege (`every_route_has_privilege_t0368`).
- No AI attribution in commits or PRs (no `Co-Authored-By`, no "Generated with").
- Never copy nmap data files (`nmap-services`, `nmap-service-probes`, `nmap-os-db`, NPSL). Probes, port lists and match rules are our own. Service names come from IANA `/etc/services`.
- `sensr-scan` runs as `User = sensr-scan`, `Group = sensr`, with no capabilities, and never as root.
- Public targets are refused unless `public_ok`. "Local" means:
  - internal interfaces' subnets;
  - WireGuard networks;
  - RFC 1918, `100.64.0.0/10`, ULA `fc00::/7`, link-local.
- Defaults:
  - `enabled = true`, `auto_scan_new = true`;
  - `pace = gentle` (≤ 200 TCP connects/s, ≤ 64 in flight per target, one target at a time);
  - `history = 10`, `max_range = 4096`;
  - range jobs are pruned after 90 days.
- Identification budget is 5 s per open port. Each captured text field is capped at 256 bytes and sanitised.
- Writes are one SQLite transaction per finished address (SD-card wear).

## Review Focus

1. **A device that is off or unreachable when its scan runs:** the result is `failed` ("no response"), never a `complete` scan with zero open ports. It stays eligible for its automatic scan. Test in Task 9.
2. **A device whose IP changed between queueing and scanning:** a device job scans the MAC's current address (neighbour table at start) and records it. Test in Task 9.
3. **Hostile banners/titles** (HTML, `<script>`, ANSI escapes, NUL, invalid UTF-8, 1 MB bodies): stored sanitised and capped, and rendered escaped. Tests in Task 6 and Task 12.
4. **A target that accepts every port** (tarpit, or a firewall that SYN-ACKs everything):
   - at most 1,000 open ports are stored;
   - the scan is flagged `all_open`;
   - identification runs only on the first 50.
   Test in Task 4.
5. **Range edge addresses:** the network and broadcast addresses of an IPv4 range larger than /31, and the router's own addresses, are never probed. Test in Task 1.

---

### Task 1: Crate, contract types and targets

**Files:**
- Create: `crates/sensr-scan/Cargo.toml`, `crates/sensr-scan/src/lib.rs`, `src/config.rs`, `src/proto.rs`, `src/target.rs`
- Modify: `Cargo.toml` (`[workspace.dependencies] sensr-scan = { path = "crates/sensr-scan", default-features = false }`)

**Interfaces:**
- Produces (`sensr_scan::config`):
  - constants `CONFIG_PATH = "/run/sensr/portscan/portscan.json"`, `DB_DIR = "/var/lib/sensr-scan"`, `DB = "scans.db"`, `SOCKET = "/run/sensr-scan/scan.sock"`;
  - `struct Config { enabled: bool, auto_scan_new: bool, pace: Pace, history: u16, max_range: u32, exclude: Vec<Exclude>, local: Vec<ipnet::IpNet>, router: Vec<IpAddr> }`;
  - `enum Pace { Gentle, Normal, Fast }` with `fn limits(self) -> PaceLimits { connects_per_sec: u32, in_flight: u16 }` (Gentle = 200/64);
  - `enum Exclude { Mac(String), Addr(IpAddr) }`.
- Produces (`sensr_scan::proto`), serde JSON-lines `#[serde(tag = "op", rename_all = "snake_case")]`:
  - `enum Request { Start(StartReq), Cancel { job_id: u64 }, Status, Known { macs: Vec<KnownDevice> } }`;
  - `struct StartReq { target: String, kind: JobKind, auto: bool, mac: Option<String>, public_ok: bool, confirm: bool, include_excluded: bool }`;
  - `enum JobKind { Device, Range }`;
  - `struct KnownDevice { mac: String, ipv4: Ipv4Addr }`;
  - `enum Reply { Started { job_id: u64 }, Refused { reason: Refusal }, Ok, Status(StatusView) }`;
  - `enum Refusal { Public, TooLarge { addresses: u64, max: u32 }, Excluded, Invalid(String), Disabled }`;
  - `struct StatusView { running: Option<JobProgress>, queue: Vec<QueuedJob> }`;
  - `struct JobProgress { job_id, kind, target, alive: Option<u32>, address_n: u32, address_total: u32, tcp_done: u32, udp_done: u32 }`.
- Produces (`sensr_scan::target`):
  - `enum Target { One(IpAddr), Net(ipnet::IpNet), Span(IpAddr, IpAddr) }`;
  - `fn parse(s: &str) -> Result<Target, String>`;
  - `fn addresses(t: &Target, router: &[IpAddr]) -> impl Iterator<Item = IpAddr>`;
  - `fn count(t: &Target) -> u64`;
  - `fn is_local(ip: IpAddr, local: &[IpNet]) -> bool`;
  - `fn check(t: &Target, cfg: &Config, public_ok: bool) -> Result<(), Refusal>`.

- [ ] **Step 1: Write failing tests** in `src/target.rs`:
  - `parse("192.168.1.5")` → `One`;
  - `parse("192.168.1.0/24")` → `Net`;
  - `parse("192.168.1.10-20")` → `Span(.10, .20)`;
  - `parse("10.0.0.1-10.0.1.5")` → `Span`;
  - `parse("fd00::1")` → `One`;
  - `parse("::/0")` → `Err` (IPv6 nets limited to /120 or smaller);
  - `parse("hostname")` → `Err`.
  - `addresses(&parse("192.168.1.0/30")?, &[])` yields exactly `[.1, .2]`. Network and broadcast are skipped (Review Focus 5).
  - `addresses(&parse("192.168.68.0/29")?, &["192.168.68.1".parse()?])` excludes `.1`.
  - `count(&parse("10.0.0.0/20")?) == 4096`.
  - `check` with a `/19` and `max_range = 4096` → `Refusal::TooLarge { addresses: 8192, max: 4096 }`.
  - `check` on `8.8.8.8` with `public_ok = false` → `Refusal::Public`; with `true` → `Ok`.
  - `check` on `192.168.1.5` and on `100.64.1.1` → `Ok`.
  - `proto` round-trip: `Request::Start` serialises to one line with `"op":"start"`.
- [ ] **Step 2: Run** `cargo test -p sensr-scan` → FAIL (crate missing).
- [ ] **Step 3: Implement.**
  - Features in `Cargo.toml`: `default = []`, `store = ["dep:rusqlite"]`, `daemon = ["store", "dep:tokio", "dep:tokio-rustls", "dep:rustls", "dep:x509-parser", "dep:socket2", "dep:clap", "dep:tracing-subscriber", "dep:anyhow"]`.
  - Use `[lints] workspace = true` and serde `deny_unknown_fields` on config structs (as `sensr_flow::config`).
- [ ] **Step 4: Run** `cargo test -p sensr-scan` → PASS; `cargo clippy -p sensr-scan --all-targets` clean.
- [ ] **Step 5: Commit** `feat(scan): sensr-scan crate with config, protocol and targets`.

### Task 2: Config model and applier

**Files:**
- Create: `crates/sensr-schema/src/models/portscan.rs`, `crates/sensr-apply/src/appliers/portscan.rs`
- Modify:
  - `crates/sensr-schema/src/models/mod.rs` (module);
  - `models/document.rs` (field `#[serde(default, skip_serializing_if = "Portscan::is_default")] pub portscan: Portscan` after `hosts`);
  - `crates/sensr-apply/src/appliers/mod.rs`;
  - `crates/sensr-apply/src/engine.rs` (`plan_portscan`, called next to `plan_insight`).

**Interfaces:**
- Consumes: `sensr_scan::config::{Config, Pace, Exclude, CONFIG_PATH}` (Task 1).
- Produces:
  - schema `struct Portscan { enabled: bool (yes), auto_scan_new: bool (yes), pace: ScanPace, history: u16 (10, 1..=100), max_range: u32 (4096, 1..=65536), exclude: ArrayField<ScanExclude> }`;
  - `ScanExclude { enabled, target: String /* MAC or IP */, description }`;
  - `sensr_apply::appliers::portscan::{DIR = "run/sensr/portscan", CONFIG = "portscan.json", UNIT = "sensr-scan.service", fn config(doc: &Document) -> Option<Config>}`.
  - `config` fills `local` from enabled non-WAN interface subnets and WireGuard instance addresses, and `router` from the interfaces' own addresses.

- [ ] **Step 1: Failing tests.**
  - `portscan.rs` (schema): the defaults deserialize from `{}`; `history = 0` and an exclude target `"nonsense"` fail validation with field paths `portscan.history` / `portscan.exclude.0.target`.
  - Applier: with the test document fixture used by `insight.rs`'s tests, `config(&doc)` has `local` containing the LAN subnet and not the WAN one, `router` containing the LAN address, and `exclude` mapping a MAC entry to `Exclude::Mac` (lowercased).
  - `config` returns `None` when `portscan.enabled = false`.
- [ ] **Step 2: Run** `cargo test -p sensr-schema portscan` and `cargo test -p sensr-apply portscan` → FAIL.
- [ ] **Step 3: Implement** following `models/insight.rs` and `appliers/insight.rs` / `plan_insight`. The plan writes `portscan.json` (0644) and restarts `sensr-scan.service` on change. Update any document snapshot tests (`cargo insta review`) that list every top-level key.
- [ ] **Step 4: Run** both test commands → PASS; `cargo test -p sensr-schema -p sensr-apply` all green.
- [ ] **Step 5: Commit** `feat(scan): portscan config model and applier`.

### Task 3: Port lists and service names

**Files:**
- Create: `crates/sensr-scan/src/ports.rs`, `crates/sensr-scan/data/top-tcp.txt`, `crates/sensr-scan/data/top-udp.txt`

**Interfaces:**
- Produces:
  - `fn tcp_order() -> Vec<u16>`: all 1..=65535, the ~1,000 entries of `top-tcp.txt` first, in file order, then the rest ascending, no duplicates;
  - `fn top_udp() -> &'static [u16]`: ~1,000 entries from `top-udp.txt`;
  - `struct Services` with `fn load(path: &Path) -> Services` (parses `/etc/services`; a missing file gives an empty table) and `fn name(&self, proto: Proto, port: u16) -> Option<&str>`;
  - `enum Proto { Tcp, Udp }` (serde lowercase).
- The data files are our own lists, compiled from the IANA registry and common home/IoT services. One port per line, `#` comments allowed. Embed them with `include_str!`.

- [ ] **Step 1: Failing tests.**
  - `tcp_order().len() == 65535`, with no duplicates (`HashSet` len), and `tcp_order()[..5]` all in `top-tcp.txt`.
  - `top_udp()` contains 53, 123, 161, 1900, 5353.
  - `Services::load` on a fixture `"ssh 22/tcp\ndomain 53/udp # comment\n"` gives `name(Tcp, 22) == Some("ssh")`, `name(Udp, 53) == Some("domain")` and `name(Tcp, 53) == None`.
- [ ] **Step 2: Run** `cargo test -p sensr-scan ports` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(scan): port order and IANA service names`.

### Task 4: Paced TCP connect scan

**Files:**
- Create: `crates/sensr-scan/src/tcp.rs`, `crates/sensr-scan/src/pace.rs`
- Test: `crates/sensr-scan/tests/tcp.rs`

**Interfaces:**
- Consumes: `PaceLimits` (Task 1), `tcp_order` (Task 3).
- Produces:
  - `struct Pacer` with `fn new(l: PaceLimits) -> Pacer` and `async fn permit(&self) -> PacerPermit` (token bucket for connects/s plus a semaphore for in-flight).
  - `enum PortState { Open, Closed, Filtered, OpenFiltered }` (serde snake_case).
  - `struct TcpResult { open: Vec<u16>, filtered: u32, all_open: bool, done: u32 }`.
  - `async fn scan_tcp(ip: IpAddr, ports: &[u16], pacer: &Pacer, cancel: &CancellationToken, progress: &AtomicU32) -> TcpResult`.
  - The timeout is adaptive: 3 × the median connect RTT of the first refused/accepted replies, min 300 ms, max 2 s, with one retry for timeouts. Refused = closed, timeout twice = filtered.
  - `all_open`: once more than 1,000 ports are open, stop recording and set it (Review Focus 4).
  - Use `tokio_util::sync::CancellationToken` (add `tokio-util` to workspace deps if absent).

- [ ] **Step 1: Failing tests** (`tests/tcp.rs`, all on `127.0.0.1`):
  - `finds_open_listeners`: bind 3 `TcpListener`s on ephemeral ports, plus 3 closed ports (bind and drop). `scan_tcp` over those 6 gives `open` = the 3 listening ports, sorted.
  - `pacer_limits_rate`: `Pacer::new(PaceLimits { connects_per_sec: 50, in_flight: 4 })`; 100 permits take ≥ 1.8 s and in-flight never exceeds 4.
  - `cancel_stops_early`: cancel after 100 ms; the result `done` < number of ports.
  - `all_open_capped`: a fake connector (make `scan_tcp` generic over `trait Connector { async fn connect(&self, addr: SocketAddr, t: Duration) -> io::Result<()> }`, default `TokioConnector`) that always succeeds, over 2,000 ports, gives `open.len() == 1000` and `all_open`.
- [ ] **Step 2: Run** `cargo test -p sensr-scan --features daemon --test tcp` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(scan): paced TCP connect scan`.

### Task 5: UDP probes and empty-probe sweep

**Files:**
- Create: `crates/sensr-scan/src/udp.rs`, `crates/sensr-scan/src/udp_probes.rs`
- Test: `crates/sensr-scan/tests/udp.rs`

**Interfaces:**
- Produces:
  - `struct UdpProbe { port: u16, service: &'static str, payload: fn() -> Vec<u8>, parse: fn(&[u8]) -> Option<Ident> }`;
  - `static PROBES: &[UdpProbe]`: ~40 entries, at least DNS (53, `version.bind` CH TXT), NTP (123, mode 3 client), SNMP (161, v2c `public` GET sysDescr.0), SSDP (1900, M-SEARCH `ssdp:all`), mDNS (5353, `_services._dns-sd._udp.local` PTR, unicast), NetBIOS-NS (137, NBSTAT `*`), DHCP (67, INFORM), TFTP (69, RRQ for a missing file, expecting ERROR), syslog (514), IKE (500, SA_INIT), Chromecast (`_googlecast` via mDNS), plus WS-Discovery (3702), CoAP (5683), MQTT-SN, Memcached (11211, stats), RIP, LLMNR (5355), Ubiquiti discovery (10001), SIP (5060 OPTIONS), STUN (3478);
  - `struct UdpResult { ports: Vec<(u16, PortState, Option<Ident>)>, done: u32 }`;
  - `async fn scan_udp(ip: IpAddr, pacer: &Pacer, cancel: &CancellationToken, progress: &AtomicU32) -> UdpResult`.
  - `scan_udp` sends the probes first, then empty datagrams to the remaining `top_udp()` ports, through a connected `UdpSocket` per port:
    - a reply → `Open`;
    - `ECONNREFUSED` on recv → `Closed`;
    - silence for 1 s plus one retry → `OpenFiltered`.
  - The UDP pace is capped at 20 ports/s per target, regardless of `Pace`, to stay under ICMP rate limits.
  - `Ident` is from Task 6. Define it in `src/ident.rs` here with just the fields: `struct Ident { product: Option<String>, version: Option<String>, title: Option<String>, tls: Option<TlsInfo>, banner: Option<String> }`, `struct TlsInfo { subject: String, sans: Vec<String>, issuer: String, not_after: i64 }`.

- [ ] **Step 1: Failing tests.**
  - Unit tests per parser on captured real replies (hex fixtures in `tests/fixtures/udp/`, recorded from our own devices or written from the RFC):
    - DNS `version.bind` → `version = "unbound 1.22"`;
    - SNMP sysDescr → `product = "Linux nas 6.1"`;
    - SSDP → `product` from `SERVER:` and `title` from `X-` friendly name where present;
    - NTP → `product = "ntp"` with stratum in `banner`.
  - Integration (`tests/udp.rs`):
    - a local `UdpSocket` echo server on an ephemeral port → `Open`;
    - a closed port (bind and drop) → `Closed`;
    - a socket that reads and never replies → `OpenFiltered`.
- [ ] **Step 2: Run** `cargo test -p sensr-scan --features daemon udp` → FAIL.
- [ ] **Step 3: Implement.** `scan_udp` takes an optional port list override for tests: `scan_udp_ports(ip, ports, ...)`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(scan): UDP service probes and sweep`.

### Task 6: Service identification on open TCP ports

**Files:**
- Modify: `crates/sensr-scan/src/ident.rs`
- Test: `crates/sensr-scan/tests/ident.rs`
- Modify: `Cargo.toml` workspace deps (`x509-parser`; dev `rcgen`)

**Interfaces:**
- Consumes: `Ident`, `TlsInfo` (Task 5).
- Produces:
  - `async fn identify(ip: IpAddr, port: u16, hint: Option<&str>) -> Option<Ident>`, with a 5 s budget. The order is:
    1. read a greeting (1.5 s);
    2. if there is none, the probes for `hint` / port (HTTP `GET / HTTP/1.0` with `Host:`, Redis `PING`, RTSP `OPTIONS`, MQTT CONNECT);
    3. a generic HTTP probe;
    4. a TLS ClientHello (rustls with a no-verify `ServerCertVerifier`), recording `TlsInfo`, then HTTP over TLS for the title.
  - `fn sanitize(s: &[u8]) -> String`: lossy UTF-8, drops control characters except space, collapses whitespace, caps at 256 bytes on a char boundary.
  - `fn parse_greeting(b: &[u8]) -> Ident` recognises:
    - `SSH-2.0-OpenSSH_9.6` → product "OpenSSH", version "9.6";
    - FTP/SMTP/POP3/IMAP 220/+OK/* OK lines → banner.
  - `fn parse_http(b: &[u8]) -> Ident`: `Server:` → product, `<title>` → title (first 64 KiB only).

- [ ] **Step 1: Failing tests.**
  - `parse_greeting(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")` → product `OpenSSH`, version `9.6p1`.
  - `parse_http` on a response with `Server: nginx/1.27` and `<title>Synology DiskStation</title>` → both captured.
  - **Review Focus 3:** `sanitize(b"<script>\x1b[31mx\x00\xff")` contains no `\x1b`, NUL or U+FFFD runs longer than one, and is ≤ 256 bytes; `parse_http` on a 1 MB body without `<title>` returns quickly with `title = None`.
  - Integration:
    - a local TLS server (rcgen self-signed for `nas.local`, tokio-rustls acceptor) serving `<title>Hi</title>` → `tls.subject` contains `nas.local`, `sans == ["nas.local"]`, `title == "Hi"`;
    - a silent TCP listener → `identify` returns within 5.5 s.
- [ ] **Step 2: Run** `cargo test -p sensr-scan --features daemon ident` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(scan): identify services from greetings, HTTP and TLS`.

### Task 7: Results database

**Files:**
- Create: `crates/sensr-scan/src/store.rs`

**Interfaces:**
- Consumes: `PortState`, `Proto`, `Ident`, `JobKind` (Tasks 1, 3–5).
- Produces (feature `store`):
  - `struct Store` with `fn open(path: &Path) -> rusqlite::Result<Store>` (creates the schema, WAL) and `fn open_ro(path: &Path) -> rusqlite::Result<Store>`.
  - Tables:
    - `jobs(id INTEGER PK, kind TEXT, target TEXT, requested_by TEXT, started INT, finished INT, status TEXT, public_ok INT, skipped TEXT /* JSON list */)`;
    - `scans(id INTEGER PK, job_id INT, address TEXT, mac TEXT, started INT, finished INT, status TEXT, all_open INT)`;
    - `ports(scan_id INT, proto TEXT, port INT, state TEXT, service TEXT, product TEXT, version TEXT, title TEXT, tls_subject TEXT, tls_issuer TEXT, tls_not_after INT, banner TEXT)`;
    - indexes on `scans(mac)`, `scans(address)`.
  - `enum ScanStatus { Complete, Partial, Cancelled, Failed }`.
  - `struct PortRow { proto, port, state, service, ident: Ident }`.
  - `fn begin_job(&self, kind, target, auto: bool, public_ok) -> i64` and `fn end_job(&self, id, status: &str, skipped: &[IpAddr])`.
  - `fn write_scan(&self, job_id, address: IpAddr, mac: Option<&str>, started, finished, status: ScanStatus, all_open: bool, ports: &[PortRow]) -> i64`: one transaction.
  - `fn latest_for_mac(&self, mac) -> Option<ScanView>`: the latest scan of any status, with its ports.
  - `fn has_complete(&self, mac) -> bool`.
  - `fn auto_cancelled(&self, mac) -> bool`: an auto job for this MAC ended `cancelled` by the owner.
  - `fn history(&self, mac_or_addr: &str, limit) -> Vec<ScanView>`.
  - `fn jobs(&self, kind: JobKind, limit) -> Vec<JobView>` and `fn job(&self, id) -> Option<(JobView, Vec<ScanView>)>`.
  - `fn changes(&self, scan_id) -> Changes { opened: Vec<(Proto,u16)>, closed: Vec<(Proto,u16)>, changed: Vec<(Proto,u16)> }`: against the previous **Complete** scan of the same MAC, else the same address. The current scan must be Complete, else empty.
  - `fn prune(&self, history: u16, now: i64)`.
  - `ScanView { id, job_id, address, mac, started, finished, status, all_open, ports: Vec<PortRow> }`; `JobView { id, kind, target, requested_by, started, finished, status, skipped, hosts_alive: u32 }`.

- [ ] **Step 1: Failing tests** (in-memory/tempfile DB):
  - Write two complete scans for MAC `aa:..:01`, the first with tcp 22, 80 and the second with 22, 3389. `changes(second) == { opened: [(Tcp,3389)], closed: [(Tcp,80)], changed: [] }`.
  - A `Partial` scan after them: `changes(partial)` is empty, and a later complete scan with 22, 3389 compares against the second scan, not the partial one.
  - A banner change on 22 → `changed: [(Tcp,22)]`.
  - `prune(history=2)` with 4 complete scans of one MAC keeps the newest 2. A range job finished 91 days ago is deleted, along with its scans unless they are among a MAC's kept 2.
  - `auto_cancelled` is true only for `requested_by = auto` and job status `cancelled`.
  - `latest_for_mac` returns a `Failed` scan if it is newest, with the status visible.
- [ ] **Step 2: Run** `cargo test -p sensr-scan --features store store` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(scan): results database with changes and pruning`.

### Task 8: Discovery and MAC lookup

**Files:**
- Create: `crates/sensr-scan/src/discover.rs`

**Interfaces:**
- Produces:
  - `fn neighbours(proc_arp: &str) -> HashMap<IpAddr, String>`: parses `/proc/net/arp` (readable unprivileged); skips incomplete `00:00:00:00:00:00` entries and lowercases.
  - `async fn alive(ip: IpAddr, neigh: &HashMap<IpAddr,String>) -> bool`: true if a neighbour entry exists, or an ICMP echo answers via an unprivileged ping socket (`socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))`), or a TCP connect to any of 22, 80, 443, 445, 8080 succeeds or is refused (500 ms each).
  - `fn mac_for(ip, neigh) -> Option<String>` and `fn ip_for(mac, neigh) -> Option<Ipv4Addr>`.

- [ ] **Step 1: Failing tests.**
  - `neighbours` on a `/proc/net/arp` fixture with one complete and one incomplete row → one entry, lowercase MAC.
  - `alive(127.0.0.1)` → true (TCP refused counts).
  - `alive` on a TEST-NET-1 address (`192.0.2.1`) → false within 3 s.
  - `ip_for` finds the IP for a MAC regardless of case.
- [ ] **Step 2: Run** `cargo test -p sensr-scan --features daemon discover` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(scan): discovery and neighbour lookups`.

### Task 9: Job queue, runner, socket server and daemon

**Files:**
- Create: `crates/sensr-scan/src/queue.rs`, `src/runner.rs`, `src/server.rs`, `src/client.rs`, `src/bin/sensr-scan.rs`
- Test: `crates/sensr-scan/tests/daemon.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `struct Queue` with:
    - `fn push(&mut self, job: Job) -> Result<u64, Refusal>`: manual jobs go ahead of auto jobs; a target already queued or running gets that job's id back;
    - `fn next(&mut self) -> Option<Job>`;
    - `fn cancel(&mut self, id) -> bool`;
    - `fn view(&self) -> Vec<QueuedJob>`.
  - `async fn run_job(job: Job, cfg: &Config, store: &Store, services: &Services, progress: &Progress, cancel: CancellationToken)`:
    - A **device job** resolves the MAC's current IPv4 from `/proc/net/arp`, falling back to the given IP (Review Focus 2).
    - It records `Failed` with no ports when the address is not alive (Review Focus 1).
    - Otherwise it runs TCP, identifies the open TCP ports (the first 50 when `all_open`), then runs UDP, and writes `Complete`.
    - On cancel it writes `Partial` (status `cancelled` on the job) with the ports found so far.
    - A **range job** runs discovery over `target::addresses`:
      - excluded MACs/addresses are skipped unless `include_excluded`, and recorded in `jobs.skipped`;
      - each alive address is scanned as above, with `mac` from the neighbour table.
  - `server::serve(path: &Path, state: Arc<Daemon>)`: JSON-lines over `UnixListener`, socket mode 0660.
    - `Start` runs `target::check`, the exclude/`confirm` rule (an excluded device needs `confirm`) and `Disabled` when `!cfg.enabled`. An `auto` start is ignored (`Reply::Ok`) when `store.has_complete(mac) || store.auto_cancelled(mac)` or when `!cfg.auto_scan_new`.
    - `Known { macs }` queues an auto device job for each MAC that passes that same test.
  - `client::send(path: &Path, req: &Request) -> io::Result<Reply>`: blocking std `UnixStream`, 2 s timeout (used by the agent and API).
  - The binary is `sensr-scan --config <json> --db <path> --socket <path> [--services /etc/services]`. It prunes at startup and every 24 h.

- [ ] **Step 1: Failing tests** (`tests/daemon.rs`, a daemon on a tempdir socket against `127.0.0.1`):
  - `start_device_scan_completes`: a local listener; `Start { kind: Device, target: "127.0.0.1", mac: Some("aa:bb:cc:00:00:01"), .. }` → `Started`. Poll `Status` until idle. `latest_for_mac` is `Complete` with the listener's port open.
  - `unreachable_device_fails` (RF 1): target `192.0.2.1` → `Failed`, zero ports, and `has_complete` stays false.
  - `auto_dedupes`: two auto `Start`s for the same MAC give the same `job_id`; after it completes a third auto `Start` replies `Ok` with no job.
  - `manual_before_auto`: queue 2 auto jobs then 1 manual → `Status.queue` order has the manual first.
  - `cancel_keeps_partial`: cancel a running scan → the scan row is `Partial` with ports found, and the job is `cancelled`. The auto job for that MAC is then not re-queued by `Known`.
  - `public_refused`: `8.8.8.8` without `public_ok` → `Refused { Public }`.
  - `excluded_needs_confirm`: config excluding `127.0.0.1` → `Refused { Excluded }`; with `confirm: true` → `Started`.
  - `device_follows_mac` (RF 2): the runner given a neighbour fixture mapping the MAC to 127.0.0.1 while the job carries 127.0.0.2 scans 127.0.0.1 and records that address. Make the neighbour source injectable: `run_job` takes `&dyn Fn() -> HashMap<IpAddr,String>`.
- [ ] **Step 2: Run** `cargo test -p sensr-scan --features daemon --test daemon` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; `cargo test -p sensr-scan --all-features` all green.
- [ ] **Step 5: Commit** `feat(scan): job queue, runner and sensr-scan daemon`.

### Task 10: NixOS service and agent auto-scans

**Files:**
- Modify:
  - `nix/modules/sensr.nix` (user `sensr-scan`, `systemd.services.sensr-scan`);
  - `nix/overlays` (the package builds the `sensr-scan` bin with `--features daemon`, the same way `sensr-insight` is built);
  - `crates/sensr-agent/Cargo.toml` (`sensr-scan` default features);
  - `crates/sensr-agent/src/hosts.rs`;
  - `crates/sensr-agent/src/slice_applier.rs`.

**Interfaces:**
- Consumes: `client::send`, `Request::{Start, Known}`, `config::SOCKET` (Tasks 1, 9).
- Produces:
  - In `HostCollector`: a `fn scan_candidates(&self) -> Vec<KnownDevice>` (MAC rows with an IPv4).
  - A scan notifier thread `sensr-scan-notify`. It sends `Known { macs: scan_candidates() }` at start and whenever `client::send` succeeds after a failure (reconnect, retried every 30 s). It sends `Start { kind: Device, auto: true, mac, target: ipv4 }` when `observe` creates a row that has an IPv4, or a row gains its first IPv4.
  - Unit hardening is as the spec:
    - `ExecStart = sensr-scan --config /run/sensr/portscan/portscan.json --db /var/lib/sensr-scan/scans.db --socket /run/sensr-scan/scan.sock --services /etc/services`;
    - `StateDirectory`/`RuntimeDirectory` `sensr-scan` (0750);
    - `RestrictAddressFamilies = [AF_UNIX AF_INET AF_INET6 AF_NETLINK]`;
    - no capabilities; `Nice = 10`; `MemoryMax = 128M`; `ConditionPathExists` on the config;
    - `partOf`/`after` as `sensr-insight`;
    - `SupplementaryGroups` none.
    - `sensr-api` already runs in group `sensr`. Verify the socket is reachable from `sensr-api` (0660 group `sensr`).

- [ ] **Step 1: Failing test** in `crates/sensr-agent/src/hosts.rs` tests: `new_row_with_ipv4_notifies_once`. Use a fake notifier `trait ScanNotify { fn new_device(&self, mac: &str, ipv4: Ipv4Addr); }` injected into `HostCollector`. Observing a snapshot with a new lease calls it once; observing the same snapshot again does not; a row first seen without an IPv4 notifies when it gains one.
- [ ] **Step 2: Run** `cargo test -p sensr-agent new_row_with_ipv4_notifies_once` → FAIL.
- [ ] **Step 3: Implement** the hook and the socket-backed `ScanNotify`, which is fire-and-forget on its own thread, so the agent never blocks on the scanner. Implement the NixOS unit.
- [ ] **Step 4: Run** `cargo test -p sensr-agent` → PASS; `nix build .#checks.x86_64-linux.sensr` on CI (local: `nix eval .#nixosConfigurations.qcow.config.systemd.services.sensr-scan.serviceConfig.User` → `"sensr-scan"`, run on a machine with Nix).
- [ ] **Step 5: Commit** `feat(scan): sensr-scan unit and automatic first-join scans`.

### Task 11: API routes, privilege and CLI

**Files:**
- Create: `crates/sensr-api/src/portscan.rs`
- Modify: `crates/sensr-api/src/lib.rs` (`ROUTES`), `crates/sensr-auth/src/acl.rs`, `crates/sensr-api/tests/api.rs`, `crates/sensr-cli/src/lib.rs`

**Interfaces:**
- Consumes: `Store::open_ro`, `client::send` (Tasks 7, 9).
- Produces:
  - Routes:
    - `GET /api/v1/portscan/status` → `StatusView`;
    - `GET /api/v1/portscan/jobs?kind=device|range&limit=` → `[JobView]`;
    - `GET /api/v1/portscan/jobs/{id}` → `{job, scans}`;
    - `GET /api/v1/portscan/hosts/{mac}` → `{latest, changes, history}`;
    - `POST /api/v1/portscan/start` (body `StartReq`, but `auto` is forced false) → the `Reply`, with 409 for `Refused`;
    - `POST /api/v1/portscan/cancel` → `Ok`.
  - The DB dir comes from `SENSR_SCAN_DIR` or `config::DB_DIR` (as `insight::dir`).
  - Privilege `page-services-portscan`, "Services: Port Scanner", patterns `["ui/portscan", "ui/portscan/*", "api/v1/portscan/*"]`.
  - CLI: `sensr scan <target> [--public-ok] [--confirm]` prints the job id; `sensr scan status`; `sensr scan show <mac|job-id>`.

- [ ] **Step 1: Failing tests** in `crates/sensr-api/tests/api.rs` (tempdir DB seeded with `Store::write_scan`; a fake socket server answering `Started { job_id: 7 }`):
  - `GET hosts/{mac}` returns `latest.ports[0].port == 22`;
  - `POST start` → `{"job_id":7}`;
  - a `Refused` reply → 409 with the reason;
  - a user without `page-services-portscan` → 403.
  - `every_route_has_privilege_t0368` passes.
  - CLI arg parsing test for `scan 192.168.1.0/24 --public-ok`.
- [ ] **Step 2: Run** `cargo test -p sensr-api portscan` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p sensr-api -p sensr-auth -p sensr-cli` → PASS.
- [ ] **Step 5: Commit** `feat(scan): port scanner API, privilege and CLI`.

### Task 12: UI: hosts line, host page and Services › Port Scanner

**Files:**
- Create: `crates/sensr-ui/src/portscan.rs` (DB reads and views), `crates/sensr-ui/e2e/tests/portscan.spec.ts`
- Modify:
  - `crates/sensr-ui/src/api.rs` (`Backend`: `fn scan_dir(&self) -> PathBuf`, `fn portscan(&self, req: sensr_scan::proto::Request) -> BoxFuture<'_, ApiResult<sensr_scan::proto::Reply>>`);
  - `crates/sensr-ui/src/mock.rs` (seeded scans, canned replies);
  - `actions.rs` (`hosts()` merges `ports` per row when `may_access("/api/v1/portscan/jobs")`; server fns `portscan_start`, `portscan_cancel`, `portscan_status`, `portscan_page`);
  - `runtime.rs` (`HostRow.ports: Option<HostPorts>`);
  - `islands.rs` (the line under the name);
  - `pages.rs` (host page Ports section, `/ui/portscan` page);
  - `menu.rs` (SERVICES: `n("Portscan").label("Port Scanner").url("/ui/portscan")`).

**Interfaces:**
- Consumes: `Store::{open_ro, latest_for_mac, changes, history, jobs, job}`, `Request`, `Reply`.
- Produces:
  - `struct HostPorts { open: Vec<PortChip>, more: u32, changes: Vec<String>, scanned_at: Option<i64>, status: String, scanning: bool }`;
  - `struct PortChip { proto, port, service: Option<String>, label: Option<String> /* title or product */, tip: String, open_filtered: bool }`.
- Hosts line format, exactly:
  - `22 ssh · 80 http "Synology" · 53/udp domain · +3389 new · scanned Nov 25 · [Scan now]`;
  - the first 8 chips, then `+N more` linking to `/ui/hosts/<key>#ports`;
  - "scanning…" while running; "partial scan" or "no response" per status;
  - open|filtered UDP chips are greyed with the tooltip "no reply: open or filtered".

- [ ] **Step 1: Failing tests** (component tests with the mock backend, as the existing host-labels tests):
  - `hosts_line_shows_ports`: a seeded host with tcp 22 (ssh), 80 (title "Synology") and udp 53 renders the exact line text above (without the button).
  - `hosts_line_marks_new_port`: changes opened 3389 → `+3389 new`.
  - `hosts_line_escapes_titles` (RF 3): a title `<img src=x onerror=alert(1)>` renders escaped (`&lt;img`).
  - `host_page_ports_section`: `/ui/hosts/<key>` has `id="ports"` with a row per port (port, protocol, service, what it said) and a history list of the seeded scans, newest first, each with its status and changes.
  - `portscan_page_lists_jobs`: the page has the New scan form (`name="target"`), the running job progress text `12 of 254 alive`, and the device and range tables.
  - `portscan_menu_entry`: `/ui/portscan` is under Services.
  - Playwright `portscan.spec.ts`: Scan now on a host shows "scanning…"; submitting `8.8.8.8` without the tick shows the public-address refusal; with `192.168.1.0/24` it shows the queued job.
- [ ] **Step 2: Run** `cargo test -p sensr-ui portscan` → FAIL; `npx playwright test portscan` (in `crates/sensr-ui/e2e`) → FAIL.
- [ ] **Step 3: Implement** following the host-labels line (islands.rs) and the IDS alerts page (pages.rs). The Services page embeds the `portscan` settings with the model-driven settings form used by other service pages.
- [ ] **Step 4: Run** both → PASS; the whole `cargo test -p sensr-ui` stays green.
- [ ] **Step 5: Commit** `feat(scan): ports in the hosts table, host page and Services › Port Scanner`.

### Task 13: NixOS VM test

**Files:**
- Create: `nix/tests/portscan.nix`
- Modify: `flake.nix` (`checks.portscan`, x86_64 only, next to `insight`)

**Interfaces:**
- Consumes: the module (Task 10), API (Task 11).

- [ ] **Step 1: Write the test.**
  - Nodes: `router` (sensr, LAN 192.168.10.1/24) and `target` on the LAN with:
    - sshd;
    - nginx on 80 with `<title>Target</title>`;
    - nginx on 443 with a self-signed cert for `target.lan`;
    - unbound on 53/udp;
    - net-snmp `public` with sysDescr `"vmtarget"`.
  - Assertions:
    - (a) `target` gets a DHCP lease, and an automatic device scan for its MAC completes without any request (poll `GET /api/v1/portscan/hosts/<mac>`, timeout 600 s);
    - (b) the result has tcp 22 with product "OpenSSH", 80 with title "Target", 443 with tls subject containing `target.lan`, udp 53 open and udp 161 with product "vmtarget";
    - (c) `POST start {"target":"1.1.1.1"}` → 409 `public`;
    - (d) `POST start {"target":"192.168.10.0/24"}` completes, with `hosts_alive >= 1` and the target's scan mapped to its MAC;
    - (e) the `sensr-scan` process runs as user `sensr-scan`, and `systemctl show -P CapabilityBoundingSet sensr-scan` is empty;
    - (f) no failed units.
- [ ] **Step 2: Run** `nix build .#checks.x86_64-linux.portscan -L` (CI or a Nix machine) → FAIL before the earlier tasks' wiring is complete, PASS after.
- [ ] **Step 3: Fix** whatever the VM test exposes.
- [ ] **Step 4: Run** again → PASS.
- [ ] **Step 5: Commit** `test(scan): VM test for automatic, device and range scans`.
