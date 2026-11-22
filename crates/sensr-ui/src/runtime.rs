//! Run-time state the agent reports next to the configuration: gateway monitoring, alias
//! feeds, IPv6 prefix delegation and the host inventory (`Op::Runtime`, `GET /api/v1/status/{section}`).
//!
//! The agent sends plain JSON; these types mirror its shapes leniently (every field
//! defaulted) so an older or newer agent degrades to "unknown" instead of breaking a page.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Which run-time view to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeSection {
    /// Gateway monitor: status, latency, loss, active group members.
    Gateways,
    /// Alias feeds: entries, last update, errors.
    Aliases,
    /// IPv6 prefix delegation: delegated prefix, lifetimes, per-LAN prefixes.
    Ipv6,
    /// Host inventory: every client seen on an internal network.
    Hosts,
}

/// Monitor verdict for one gateway (the agent's snake_case status).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayState {
    /// Monitored, no answer or timeout yet.
    #[default]
    Pending,
    /// Within thresholds, or not monitored.
    Online,
    /// Latency above the low threshold.
    Delay,
    /// Loss above the low threshold.
    Loss,
    /// Latency and loss above the low thresholds.
    DelayLoss,
    /// Above the high threshold.
    Down,
    /// Marked down by the administrator.
    ForceDown,
    /// A status this UI does not know yet.
    #[serde(other)]
    Unknown,
}

/// How a status is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Green.
    Ok,
    /// Amber.
    Warn,
    /// Red.
    Bad,
    /// Neutral.
    Info,
}

impl Tone {
    /// The `pill` modifier class.
    pub fn pill(self) -> &'static str {
        match self {
            Self::Ok => "pill pill-on",
            Self::Warn => "pill pill-warn",
            Self::Bad => "pill pill-off",
            Self::Info => "pill pill-info",
        }
    }
}

impl GatewayState {
    /// The words OPNsense's gateway pages use.
    pub fn label(self) -> &'static str {
        match self {
            Self::Online => "Online",
            Self::Delay => "Latency",
            Self::Loss => "Packetloss",
            Self::DelayLoss => "Latency, Packetloss",
            Self::Down => "Offline",
            Self::ForceDown => "Offline (forced)",
            Self::Pending => "Pending",
            Self::Unknown => "Unknown",
        }
    }

    /// Green when online, red when down, amber in between, neutral without data.
    pub fn tone(self) -> Tone {
        match self {
            Self::Online => Tone::Ok,
            Self::Delay | Self::Loss | Self::DelayLoss => Tone::Warn,
            Self::Down | Self::ForceDown => Tone::Bad,
            Self::Pending | Self::Unknown => Tone::Info,
        }
    }
}

/// One gateway as the monitor sees it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayRow {
    /// Name (`WAN_DHCP` for an automatic one).
    pub name: String,
    /// Logical interface.
    pub interface: String,
    /// `inet` or `inet6`.
    pub family: String,
    /// Next hop in use; `None` while a dynamic one is not learned yet.
    pub next_hop: Option<String>,
    /// Probe target when it differs from the next hop.
    pub monitor_address: Option<String>,
    /// Monitor verdict.
    pub status: GatewayState,
    /// Average round trip, ms.
    pub latency_ms: Option<f64>,
    /// Round-trip deviation, ms.
    pub stddev_ms: Option<f64>,
    /// Loss, percent.
    pub loss_pct: Option<f64>,
    /// Probe error (socket could not be used).
    pub error: Option<String>,
    /// Carries the default route of its family.
    pub active_default: bool,
    /// Created automatically for a DHCP/RA interface.
    pub dynamic: bool,
    /// Lower wins.
    pub priority: u8,
}

/// `12.3 ms`, or `~` without a measurement (OPNsense's placeholder).
pub fn ms(v: Option<f64>) -> String {
    v.map_or_else(|| "~".to_owned(), |v| format!("{v:.1} ms"))
}

/// `0.0 %`, or `~`.
pub fn pct(v: Option<f64>) -> String {
    v.map_or_else(|| "~".to_owned(), |v| format!("{v:.1} %"))
}

impl GatewayRow {
    /// `IPv4` / `IPv6`.
    pub fn family_label(&self) -> &'static str {
        if self.family == "inet6" {
            "IPv6"
        } else {
            "IPv4"
        }
    }
}

/// System › Gateways › Status and the dashboard widget.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewaysView {
    /// Gateways, in configuration order.
    pub gateways: Vec<GatewayRow>,
    /// Active members per gateway group.
    pub groups: BTreeMap<String, Vec<String>>,
    /// Default gateway switching on.
    pub switch_default: bool,
}

/// Run-time state of one feed-backed alias (URL table, GeoIP, ASN, …).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AliasFeed {
    /// Alias name.
    pub name: String,
    /// Alias type.
    pub kind: String,
    /// Entries currently loaded.
    pub entries: u64,
    /// Last successful fetch, seconds since the epoch.
    pub updated_at: Option<u64>,
    /// Last error; the previous contents stay loaded.
    pub error: Option<String>,
    /// Next scheduled check, seconds since the epoch.
    pub next_check: Option<u64>,
    /// Data attribution the licence requires (DB-IP, CC BY 4.0).
    pub attribution: Option<String>,
}

/// A delegated prefix with its absolute deadlines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Delegation {
    /// The delegated prefix, e.g. `2001:db8:42::/56`.
    pub prefix: String,
    /// Stops being preferred (seconds since the epoch; `u64::MAX` for infinite).
    pub preferred_until: u64,
    /// Stops being valid.
    pub valid_until: u64,
}

/// A formerly delegated prefix still advertised as deprecated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaleDelegation {
    /// The prefix.
    pub prefix: String,
    /// When sensr stops advertising it.
    pub deprecate_until: u64,
}

/// Persisted PD state of one uplink.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PdState {
    /// The prefix in use.
    pub current: Option<Delegation>,
    /// Prefixes being phased out.
    pub stale: Vec<StaleDelegation>,
}

/// One /64 a LAN advertises.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Advertised {
    /// The on-link prefix.
    pub prefix: String,
    /// PIO preferred lifetime, seconds.
    pub preferred_lifetime_secs: u32,
    /// PIO valid lifetime, seconds.
    pub valid_lifetime_secs: u32,
    /// Subnet of a stale prefix.
    pub deprecated: bool,
}

/// Prefix delegation on one uplink.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PdUplink {
    /// Uplink interface id.
    pub interface: String,
    /// Current and stale prefixes.
    pub state: PdState,
    /// What each LAN advertises, by interface id.
    pub advertised: BTreeMap<String, Vec<Advertised>>,
}

/// The IPv6 panel's data plus the server clock the deadlines are relative to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6Status {
    /// Uplinks with prefix delegation.
    pub uplinks: Vec<PdUplink>,
    /// Server time, seconds since the epoch.
    pub now: u64,
}

/// The running system, as the update service reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCurrent {
    /// `nixos-version` of the running generation.
    #[serde(default)]
    pub version: String,
    /// Release tag (`v0.1.1`) when the running store path matched a manifest.
    #[serde(default)]
    pub tag: Option<String>,
    /// Image variant (`pi4`, `pi5`, `qcow`, `iso`).
    #[serde(default)]
    pub image: String,
}

impl UpdateCurrent {
    /// What to call the running system: its release tag when known.
    pub fn label(&self) -> &str {
        match self.tag.as_deref() {
            Some(tag) if !tag.is_empty() => tag,
            _ => &self.version,
        }
    }
}

/// A newer system the manifest offers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCandidate {
    /// Release tag (`v0.1.1`), when the manifest carries one.
    #[serde(default)]
    pub tag: String,
    /// Version string of the offered generation.
    #[serde(default)]
    pub version: String,
    /// sha256 of the closure archive.
    #[serde(default)]
    pub sha256: String,
    /// Download URL.
    #[serde(default)]
    pub url: String,
    /// Release notes, if the manifest carries any.
    #[serde(default)]
    pub notes: String,
}

/// State of the in-app updater, as `sensr-update` leaves it in
/// `/run/sensr/updates/status.json` (nix/modules/updates.nix).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStatus {
    /// `idle`, `checking`, `update-available`, `downloading`, `installing`,
    /// `up-to-date`, `done` or `error`.
    #[serde(default)]
    pub phase: String,
    /// One line for the page.
    #[serde(default)]
    pub message: String,
    /// Whether the timer installs by itself.
    #[serde(default)]
    pub auto: bool,
    /// The running system.
    #[serde(default)]
    pub current: UpdateCurrent,
    /// The offered system, when one was found.
    #[serde(default)]
    pub available: Option<UpdateCandidate>,
    /// Manifest the service was built with.
    #[serde(default)]
    pub manifest_url: String,
    /// Last check, RFC 3339.
    #[serde(default)]
    pub last_check: Option<String>,
    /// Last successful install, RFC 3339.
    #[serde(default)]
    pub last_install: Option<String>,
    /// When the status was written, RFC 3339.
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl UpdateCandidate {
    /// What to call this release on the page: the tag, else the version.
    pub fn label(&self) -> &str {
        if self.tag.is_empty() {
            &self.version
        } else {
            &self.tag
        }
    }
}

impl UpdateStatus {
    /// True while the service is doing something the page should poll for.
    pub fn busy(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "checking" | "downloading" | "installing"
        )
    }

    /// Whether a newer system is ready to install.
    pub fn has_update(&self) -> bool {
        self.available.is_some()
    }
}

/// The DHCP lease behind a host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostLease {
    /// Kea's lease state (`active`, `expired`, ...).
    pub state: String,
    /// Lease expiry, seconds since the epoch.
    pub expires: Option<u64>,
}

/// One client in the host inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostRow {
    /// Inventory key: the lowercase MAC, else `id:<client id>`.
    pub key: String,
    /// MAC address, when known.
    pub mac: Option<String>,
    /// The reservation's host name, else the lease's.
    pub name: Option<String>,
    /// Host name from a static reservation.
    pub reserved_name: Option<String>,
    /// Host name the client sent with its lease.
    pub lease_hostname: Option<String>,
    /// Interface id (`lan`, `opt1`); empty when unknown (`null` reads as empty).
    #[serde(deserialize_with = "null_default")]
    pub interface: String,
    /// Interface display name (`LAN`); empty when unknown.
    #[serde(deserialize_with = "null_default")]
    pub interface_name: String,
    /// IPv4 address.
    pub ipv4: Option<String>,
    /// IPv6 addresses.
    pub ipv6: Vec<String>,
    /// Where the host is known from: `reserved`, `lease`, `neighbour`.
    pub sources: Vec<String>,
    /// The lease, when there is one.
    pub lease: Option<HostLease>,
    /// First sighting, seconds since the epoch.
    pub first_seen: u64,
    /// Last sighting; `None` when never seen on the network.
    pub last_seen: Option<u64>,
    /// Currently on the network.
    pub online: bool,
    /// A reservation for it is staged but not applied yet (set by the UI from the
    /// staged document, never sent by the agent).
    pub staged: bool,
}

/// `null` as the type's default, for fields an agent may send as `null`.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Option::unwrap_or_default)
}

/// The rows that parse; one odd row is dropped instead of failing the whole list.
fn lenient_rows<'de, D>(d: D) -> Result<Vec<HostRow>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rows: Option<Vec<Value>> = Option::deserialize(d)?;
    Ok(rows
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| serde_json::from_value(r).ok())
        .collect())
}

impl HostRow {
    fn has(&self, source: &str) -> bool {
        self.sources.iter().any(|s| s == source)
    }

    /// A static reservation covers the host.
    pub fn reserved(&self) -> bool {
        self.has("reserved")
    }

    /// Leased without a reservation: a reservation can be made from it.
    pub fn leased_only(&self) -> bool {
        self.has("lease") && !self.reserved()
    }

    /// What the table calls it: the name, else the MAC, else the key.
    pub fn label(&self) -> String {
        self.name
            .clone()
            .filter(|n| !n.is_empty())
            .or_else(|| self.mac.clone())
            .unwrap_or_else(|| self.key.clone())
    }

    /// `static`, `dynamic` or `seen`.
    pub fn source(&self) -> &'static str {
        if self.reserved() {
            "static"
        } else if self.has("lease") {
            "dynamic"
        } else {
            "seen"
        }
    }

    /// `now` while online, `never` if never seen, else how long ago (`5m`, `3h`, `2d`).
    pub fn seen(&self, now: u64) -> String {
        if self.online {
            return "now".to_owned();
        }
        let Some(t) = self.last_seen else {
            return "never".to_owned();
        };
        let ago = now.saturating_sub(t);
        match ago {
            0..60 => format!("{ago}s"),
            60..3_600 => format!("{}m", ago / 60),
            3_600..86_400 => format!("{}h", ago / 3_600),
            _ => format!("{}d", ago / 86_400),
        }
    }

    /// Case-insensitive substring match on name, MAC and addresses; `q` is lowercase.
    pub fn matches(&self, q: &str) -> bool {
        q.is_empty()
            || self
                .name
                .iter()
                .chain(&self.mac)
                .chain(&self.ipv4)
                .chain(&self.ipv6)
                .any(|f| f.to_lowercase().contains(q))
    }
}

/// The host inventory with the agent's clock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostList {
    /// Agent time, seconds since the epoch.
    pub now: u64,
    /// Hosts, online first, then most recently seen.
    #[serde(deserialize_with = "lenient_rows")]
    pub hosts: Vec<HostRow>,
}

impl HostList {
    /// Marks the unreserved hosts a reservation in `doc` (the staged document) covers,
    /// by MAC or address, so the card stops offering Make static before Apply.
    pub fn mark_staged(&mut self, doc: &Value) {
        let reservations: Vec<&Value> = doc
            .pointer("/dhcpv4/reservations")
            .and_then(Value::as_object)
            .map(|m| m.values().collect())
            .unwrap_or_default();
        let get = |r: &Value, p: &str| {
            r.pointer(p)
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
        };
        for h in &mut self.hosts {
            // a reserved row's reservation is already applied
            h.staged = !h.reserved()
                && reservations.iter().any(|r| {
                    (h.mac.is_some() && get(r, "/client/hw_address").as_deref() == h.mac.as_deref())
                        || (h.ipv4.is_some() && get(r, "/ip_address") == h.ipv4)
                });
        }
    }
}

/// Parses an agent reply; `null` (subsystem not running) and unknown shapes give the default.
pub fn parse<T: serde::de::DeserializeOwned + Default>(v: Value) -> T {
    if v.is_null() {
        return T::default();
    }
    serde_json::from_value(v).unwrap_or_default()
}

/// A duration as `3d 4h`, `2h 5m`, `45s`.
pub fn span(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {}s", secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// Time left until an absolute deadline; deadlines past ~100 years count as infinite.
pub fn until(now: u64, deadline: u64) -> String {
    if deadline >= now.saturating_add(100 * 365 * 86_400) {
        "infinite".to_owned()
    } else if deadline <= now {
        "expired".to_owned()
    } else {
        span(deadline - now)
    }
}

/// A PIO lifetime (`0xffffffff` is infinite).
pub fn lifetime(secs: u32) -> String {
    if secs == u32::MAX {
        "infinite".to_owned()
    } else {
        span(u64::from(secs))
    }
}

/// UTC timestamp `YYYY-MM-DD HH:MM:SS UTC` (no tz database needed).
pub fn fmt_time(t: u64) -> String {
    // civil-from-days (Howard Hinnant's algorithm)
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_the_agent_gateway_view() {
        // Shape of sensr-agent's GatewaysView (EffectiveGateway flattened into each row).
        let v: GatewaysView = parse(json!({
            "gateways": [{
                "name": "WAN_DHCP", "interface": "wan", "device": "eth0", "family": "inet",
                "address": null, "monitor_address": null, "monitor": true, "default_route": true,
                "priority": 255, "weight": 1, "force_down": false, "dynamic": true,
                "next_hop": "203.0.113.1", "status": "delay_loss", "status_text": "delay+loss",
                "latency_ms": 12.5, "stddev_ms": 1.25, "loss_pct": 4.0, "error": null,
                "active_default": true
            }, {"name": "X", "status": "something_new"}],
            "groups": {"failover": ["WAN_DHCP"]},
            "switch_default": true
        }));
        let g = &v.gateways[0];
        assert_eq!(g.status, GatewayState::DelayLoss);
        assert_eq!(g.status.label(), "Latency, Packetloss");
        assert_eq!(g.status.tone(), Tone::Warn);
        assert!(g.active_default && g.dynamic);
        assert_eq!(g.next_hop.as_deref(), Some("203.0.113.1"));
        assert_eq!(v.gateways[1].status, GatewayState::Unknown);
        assert_eq!(v.groups["failover"], ["WAN_DHCP"]);
        assert_eq!(ms(g.latency_ms), "12.5 ms");
        assert_eq!(ms(None), "~");
    }

    #[test]
    fn parses_the_updater_status() {
        let s: UpdateStatus = parse(json!({
            "phase": "update-available",
            "message": "Version x is available",
            "auto": true,
            "current": {"version": "sd-card-26.11.1", "image": "pi4"},
            "available": {
                "tag": "v0.1.1", "version": "sd-card-26.11.2", "sha256": "abc", "url": "https://example/u",
                "store_path": "/nix/store/x-nixos-system", "notes": "notes"
            },
            "manifest_url": "https://example/m.json",
            "last_check": "2026-11-19T00:00:00Z",
            "last_install": null,
            "updated_at": "2026-11-19T00:00:00Z"
        }));
        assert!(!s.busy() && s.has_update() && s.auto);
        assert_eq!(s.available.as_ref().unwrap().version, "sd-card-26.11.2");
        assert_eq!(s.available.as_ref().unwrap().label(), "v0.1.1");
        assert_eq!(s.current.image, "pi4");
        // Without a remembered tag the label falls back to the version.
        assert_eq!(s.current.label(), "sd-card-26.11.1");
        let tagged: UpdateStatus = parse(json!({
            "current": {"version": "sd-card-26.11.1", "tag": "v0.1.1", "image": "pi4"}
        }));
        assert_eq!(tagged.current.label(), "v0.1.1");
        // An older service, or a disabled module, gives the defaults.
        let e: UpdateStatus = parse(Value::Null);
        assert!(!e.busy() && !e.has_update());
    }

    #[test]
    fn null_and_garbage_parse_to_empty() {
        let v: GatewaysView = parse(Value::Null);
        assert!(v.gateways.is_empty());
        let a: Vec<AliasFeed> = parse(json!({"not": "a list"}));
        assert!(a.is_empty());
    }

    #[test]
    fn parses_the_agent_host_list() {
        let l: HostList = parse(json!({"now": 1000, "hosts": [
            {"key": "84:47:09:38:a5:fc", "mac": "84:47:09:38:a5:fc", "name": "old-router",
             "reserved_name": null, "lease_hostname": "old-router", "client_id": "01:ab",
             "interface": "opt1", "interface_name": "LAN2", "ipv4": "192.168.72.2",
             "ipv6": ["2600::1"], "sources": ["lease", "neighbour"],
             "lease": {"state": "active", "expires": 2000},
             "first_seen": 900, "last_seen": 990, "online": true},
            {"key": "id:01ff", "sources": ["reserved"], "first_seen": 0}
        ]}));
        assert_eq!(l.now, 1000);
        let h = &l.hosts[0];
        assert_eq!(h.interface_name, "LAN2");
        assert_eq!(h.lease.as_ref().unwrap().expires, Some(2000));
        assert_eq!((h.source(), h.seen(l.now).as_str()), ("dynamic", "now"));
        assert!(h.leased_only() && h.matches("2600") && h.matches("old-r") && !h.matches("zz"));
        let r = &l.hosts[1];
        assert_eq!(
            (r.label(), r.source(), r.seen(1000)),
            ("id:01ff".into(), "static", "never".into())
        );
        let ago = |s: u64| {
            HostRow {
                last_seen: Some(10_000_000 - s),
                ..Default::default()
            }
            .seen(10_000_000)
        };
        assert_eq!(
            [ago(30), ago(300), ago(7_200), ago(172_800)],
            ["30s", "5m", "2h", "2d"]
        );
    }

    #[test]
    fn one_odd_host_row_does_not_empty_the_list() {
        // `null` interfaces are what the agent sent before they were always strings.
        let l: HostList = parse(json!({"now": 1000, "hosts": [
            {"key": "aa:bb:cc:dd:ee:09", "interface": null, "interface_name": null,
             "sources": ["reserved"], "first_seen": 900},
            {"key": "garbage", "first_seen": "yesterday"},
            {"key": "aa:bb:cc:dd:ee:01", "interface": "lan", "interface_name": "LAN",
             "sources": ["neighbour"], "first_seen": 900, "online": true}
        ]}));
        let keys: Vec<&str> = l.hosts.iter().map(|h| h.key.as_str()).collect();
        assert_eq!(keys, ["aa:bb:cc:dd:ee:09", "aa:bb:cc:dd:ee:01"]);
        assert_eq!(
            (
                l.hosts[0].interface.as_str(),
                l.hosts[0].interface_name.as_str()
            ),
            ("", "")
        );
        assert_eq!(l.now, 1000);
        let none: HostList = parse(json!({"now": 5, "hosts": null}));
        assert_eq!((none.now, none.hosts.len()), (5, 0));
    }

    /// The agent's own `view()` output (its `view_matches_the_ui_contract` test keeps
    /// the file current): every row survives, one on a no-longer-internal interface too.
    #[test]
    fn parses_the_agent_view_golden() {
        let v: Value = serde_json::from_str(include_str!(
            "../../sensr-agent/tests/golden/hosts-view.json"
        ))
        .unwrap();
        let l: HostList = parse(v);
        assert_eq!(l.now, 1010);
        let row = |name: &str| l.hosts.iter().find(|h| h.name.as_deref() == Some(name));
        assert_eq!(l.hosts.len(), 3);
        assert_eq!(l.hosts[0].interface_name, "LAN");
        assert!(l.hosts[0].online);
        let camera = row("camera").expect("camera");
        assert_eq!(
            (camera.interface.as_str(), camera.interface_name.as_str()),
            ("opt9", "OPT9")
        );
        assert_eq!(camera.source(), "static");
        let orphan = row("orphan").expect("orphan");
        assert_eq!(orphan.interface, "");
        assert_eq!(orphan.seen(l.now), "never");
    }

    #[test]
    fn parses_the_agent_pd_view() {
        let v: Vec<PdUplink> = parse(json!([{
            "interface": "wan",
            "state": {
                "current": {"prefix": "2001:db8:42::/56", "preferred_until": 1_000_600u64,
                            "valid_until": u64::MAX, "iaid": 1, "obtained_at": 1, "renewed_at": 2},
                "confirmed": true,
                "stale": [{"prefix": "2001:db8:41::/56", "stale_since": 5, "deprecate_until": 1_007_200u64}],
                "last_now": 1_000_000u64,
                "stale_signal": "none"
            },
            "advertised": {"lan": [
                {"prefix": "2001:db8:42::/64", "preferred_lifetime_secs": 600, "valid_lifetime_secs": 4_294_967_295u32, "deprecated": false},
                {"prefix": "2001:db8:41::/64", "preferred_lifetime_secs": 0, "valid_lifetime_secs": 7200, "deprecated": true}
            ]}
        }]));
        let cur = v[0].state.current.as_ref().unwrap();
        assert_eq!(until(1_000_000, cur.preferred_until), "10m 0s");
        assert_eq!(until(1_000_000, cur.valid_until), "infinite");
        assert_eq!(v[0].state.stale[0].prefix, "2001:db8:41::/56");
        assert!(v[0].advertised["lan"][1].deprecated);
        assert_eq!(lifetime(u32::MAX), "infinite");
        assert_eq!(lifetime(7200), "2h 0m");
    }

    #[test]
    fn formats_utc() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_time(1_794_787_200), "2026-11-16 00:00:00 UTC");
    }
}
