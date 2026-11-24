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
    /// Its host mode: `isolated` or `quarantine`; `None` (omitted) is Normal.
    pub mode: Option<String>,
    /// The mode staged for it (`normal`, `isolated`, `quarantine`) when that differs from
    /// `mode` and waits for Apply (set by the UI from the staged document, never sent by
    /// the agent).
    pub staged_mode: Option<String>,
    /// What the router thinks the host is; `None` for `id:` rows (and an odd label).
    #[serde(rename = "label", deserialize_with = "lenient")]
    pub host_label: Option<HostLabelView>,
    /// The owner's kind and maker for it in the staged document (set by the UI, never
    /// sent by the agent), to fill the label editor.
    pub owner_kind: Option<String>,
    /// See [`HostRow::owner_kind`].
    pub owner_maker: Option<String>,
    /// The staged owner label differs from the one in force (set by the UI).
    pub staged_label: bool,
    /// Screen-time minutes since local midnight (from the insight database, set by the UI
    /// when the caller may read it); `None` when there is no such data.
    pub today_minutes: Option<u32>,
    /// Ports found open by the last port scan; `None` when never scanned.
    pub open_ports: Option<u32>,
    /// Lookups over the last 24 hours by category key ([`CATEGORIES`] order), for the
    /// Hosts card's colour preview; empty when there is no DNS data.
    #[serde(deserialize_with = "null_default")]
    pub dns_mix: Vec<(String, u32)>,
}

/// `(key, display name)` of every DNS activity category, in display order (sensr-schema's
/// `Category::ALL` and `display()`, which the wasm bundle does not link; a test in
/// sensr-api keeps them equal).
pub const CATEGORIES: [(&str, &str); 11] = [
    ("video", "Video"),
    ("social", "Social"),
    ("games", "Games"),
    ("messaging", "Messaging"),
    ("music", "Music"),
    ("education", "Education"),
    ("shopping", "Shopping"),
    ("system", "Apple/Google/Microsoft system"),
    ("ads_tracking", "Ads & tracking"),
    ("smart_home", "Smart home"),
    ("other", "Other"),
];

/// The display name of category `key` (an unknown key reads as Other).
pub fn category_name(key: &str) -> &'static str {
    CATEGORIES
        .iter()
        .find(|c| c.0 == key)
        .map_or("Other", |c| c.1)
}

/// The theme token of category `key`: `cat-video`, `cat-ads-tracking` (see
/// [`crate::theme`]); the faint row shade is the same name with `tint-`.
pub fn category_token(key: &str) -> String {
    let key = if CATEGORIES.iter().any(|c| c.0 == key) {
        key
    } else {
        "other"
    };
    format!("cat-{}", key.replace('_', "-"))
}

/// The host page of inventory key `key` (a MAC stays readable: `/ui/hosts/aa:bb:…`).
pub fn host_href(key: &str) -> String {
    let mut out = String::from("/ui/hosts/");
    for b in key.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b':' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Minutes as `1 h 12 m`, `2 h 05 m`, `48 m`.
pub fn fmt_minutes(m: u32) -> String {
    if m < 60 {
        format!("{m} m")
    } else {
        format!("{} h {:02} m", m / 60, m % 60)
    }
}

/// `n` tenths of a percent as `72.5%`.
fn pct10(n: u64) -> String {
    format!("{}.{}%", n / 10, n % 10)
}

/// The Hosts card's colour preview of a DNS mix (lookups per category key): an inline
/// `--mix` custom property holding a left-to-right stacked gradient, each category's
/// faint tint as wide as its share, blending into the next over a few percent. `None`
/// with no lookups.
pub fn mix_style(mix: &[(String, u32)]) -> Option<String> {
    let total: u64 = mix.iter().map(|m| u64::from(m.1)).sum();
    if total == 0 {
        return None;
    }
    let mut stops = Vec::new();
    let mut at = 0u64;
    let mut sum = 0u64;
    let parts: Vec<_> = mix.iter().filter(|m| m.1 > 0).collect();
    for (i, (key, n)) in parts.iter().enumerate() {
        sum += u64::from(*n);
        // in tenths of a percent; the last segment ends at exactly 100%
        let end = sum * 1000 / total;
        // blend half-width: 2.5%, or a third of a narrow segment
        let w = ((end - at) / 3).min(25);
        let (from, to) = (
            if i == 0 { 0 } else { at + w },
            if i + 1 == parts.len() { 1000 } else { end - w },
        );
        let tint = category_token(key).replacen("cat-", "tint-", 1);
        stops.push(format!(
            "var(--{tint}) {},var(--{tint}) {}",
            pct10(from),
            pct10(to)
        ));
        at = end;
    }
    Some(format!("--mix:linear-gradient(90deg,{})", stops.join(",")))
}

/// The row's `title` for its colour preview: `DNS lookups (24 h): Video 62%, Games 20%`.
/// The percentages add up to exactly 100 (largest remainder); a share that rounds to 0
/// reads `<1%`.
pub fn mix_title(mix: &[(String, u32)]) -> Option<String> {
    let parts: Vec<_> = mix.iter().filter(|m| m.1 > 0).collect();
    let total: u64 = parts.iter().map(|m| u64::from(m.1)).sum();
    if total == 0 {
        return None;
    }
    // floor of each share, then the leftover points to the largest remainders
    let mut pct: Vec<u64> = parts.iter().map(|m| u64::from(m.1) * 100 / total).collect();
    let mut order: Vec<usize> = (0..parts.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse((u64::from(parts[i].1) * 100) % total));
    let left = 100 - pct.iter().sum::<u64>();
    for &i in order.iter().take(usize::try_from(left).unwrap_or(0)) {
        pct[i] += 1;
    }
    let text: Vec<String> = parts
        .iter()
        .zip(pct)
        .map(|((k, _), p)| {
            let p = if p == 0 {
                "<1".to_owned()
            } else {
                p.to_string()
            };
            format!("{} {p}%", category_name(k))
        })
        .collect();
    Some(format!("DNS lookups (24 h): {}", text.join(", ")))
}

/// `(kind, display name, icon)` for every host kind, in the order the editor lists them
/// (sensr-schema's `HostKind::ALL`, which the wasm bundle does not link).
pub const HOST_KINDS: [(&str, &str, &str); 14] = [
    ("phone", "Phone", "📱"),
    ("tablet", "Tablet", "📱"),
    ("computer", "Computer", "💻"),
    ("tv", "TV/streaming", "📺"),
    ("speaker", "Speaker", "🔊"),
    ("camera", "Camera", "📷"),
    ("printer", "Printer", "🖨"),
    ("console", "Game console", "🎮"),
    ("network", "Network gear", "🌐"),
    ("smart_home", "Smart home", "🏠"),
    ("server", "Server", "🗄"),
    ("wearable", "Wearable", "⌚"),
    ("virtual", "Virtual machine", "🧩"),
    UNKNOWN_KIND,
];

/// The kind a name that is not in [`HOST_KINDS`] reads as.
pub const UNKNOWN_KIND: (&str, &str, &str) = ("unknown", "Unknown", "•");

/// The agent's guess (or the owner's word) about what a host is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostLabelView {
    /// Who made it (`Raspberry Pi`, `Private MAC`).
    pub maker: Option<String>,
    /// A [`HOST_KINDS`] name.
    pub kind: String,
    /// `high`, `medium` or `low`.
    pub confidence: String,
    /// Why, one line each.
    pub reasons: Vec<String>,
    /// `auto` or `owner`.
    pub by: String,
}

impl HostLabelView {
    /// The kind's `(display name, icon)`; a name not in [`HOST_KINDS`] reads as Unknown.
    pub fn kind_display(&self) -> (&'static str, &'static str) {
        let k = HOST_KINDS
            .iter()
            .find(|k| k.0 == self.kind)
            .unwrap_or(&UNKNOWN_KIND);
        (k.1, k.2)
    }

    /// A guess rather than something known: low confidence and not the owner's.
    pub fn guess(&self) -> bool {
        self.confidence == "low" && self.by != "owner"
    }

    /// The line under the MAC: `Wyze · Camera`, `Raspberry Pi · Server?` for a weak
    /// guess, just the maker for an unknown kind (empty with no maker either).
    pub fn text(&self) -> String {
        let maker = self.maker.as_deref().unwrap_or_default();
        let (display, _) = self.kind_display();
        let kind = if display == UNKNOWN_KIND.1 {
            ""
        } else if maker == "Private MAC" && self.kind == "phone" && self.guess() {
            "Phone/laptop"
        } else {
            display
        };
        let sep = if maker.is_empty() || kind.is_empty() {
            ""
        } else {
            " · "
        };
        let q = if self.guess() && !kind.is_empty() {
            "?"
        } else {
            ""
        };
        format!("{maker}{sep}{kind}{q}")
    }
}

/// The ARP interceptor that enforces host modes between hosts of one network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Intercept {
    /// Redirecting now: it runs and a locked host has an address.
    pub active: bool,
    /// Interface ids with a locked host, while active.
    pub interfaces: Vec<String>,
    /// Why it could not start.
    pub error: Option<String>,
}

/// `null` as the type's default, for fields an agent may send as `null`.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Option::unwrap_or_default)
}

/// The value if it parses, else `None`: an odd block does not empty the whole list.
fn lenient<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let v: Option<Value> = Option::deserialize(d)?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok()))
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

    /// `isolated` or `quarantine`; `None` for Normal (and for a mode this UI does not know).
    pub fn locked_mode(&self) -> Option<&'static str> {
        match self.mode.as_deref() {
            Some("isolated") => Some("isolated"),
            Some("quarantine") => Some("quarantine"),
            _ => None,
        }
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
    /// The ARP interceptor's state; `None` when the agent runs none.
    #[serde(deserialize_with = "lenient")]
    pub intercept: Option<Intercept>,
}

impl HostList {
    /// Marks the unreserved hosts a reservation in `doc` (the staged document) covers,
    /// by MAC or address, so the card stops offering Make static before Apply, and the
    /// hosts whose staged mode differs from the one in force.
    pub fn mark_staged(&mut self, doc: &Value) {
        let modes: std::collections::BTreeMap<String, &str> = doc
            .pointer("/firewall/host_modes")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.values())
            .filter(|h| h.get("enabled").and_then(Value::as_bool).unwrap_or(true))
            .filter_map(|h| {
                Some((
                    h.get("mac")?.as_str()?.to_ascii_lowercase(),
                    h.get("mode")?.as_str()?,
                ))
            })
            .collect();
        // MAC -> (kind, maker) of each enabled owner label
        let labels: std::collections::BTreeMap<String, (Option<&str>, Option<&str>)> = doc
            .pointer("/hosts/labels")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.values())
            .filter(|l| l.get("enabled").and_then(Value::as_bool).unwrap_or(true))
            .filter_map(|l| {
                let s = |k: &str| l.get(k).and_then(Value::as_str);
                Some((s("mac")?.to_ascii_lowercase(), (s("kind"), s("maker"))))
            })
            .collect();
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
            // the staged keys are lowercased; so is the row's MAC
            let mac = h.mac.as_deref().map(str::to_ascii_lowercase);
            h.staged_mode = mac.as_deref().and_then(|mac| {
                let staged = modes.get(mac).copied().unwrap_or("normal");
                (staged != h.locked_mode().unwrap_or("normal")).then(|| staged.to_owned())
            });
            let (kind, maker) = mac
                .as_deref()
                .and_then(|m| labels.get(m).copied())
                .unwrap_or_default();
            h.owner_kind = kind.map(str::to_owned);
            h.owner_maker = maker.map(str::to_owned);
            // The agent's label says only that some field is the owner's, so this is a
            // close guess: an owner label that disagrees with the shown one, or none
            // while the shown one is the owner's.
            h.staged_label = h.host_label.as_ref().is_some_and(|l| {
                let owner = l.by == "owner";
                if kind.is_none() && maker.is_none() {
                    owner
                } else {
                    !owner
                        || kind.is_some_and(|k| k != l.kind)
                        || maker.is_some_and(|m| Some(m) != l.maker.as_deref())
                }
            });
            // a reserved row's reservation is already applied
            h.staged = !h.reserved()
                && reservations.iter().any(|r| {
                    (mac.is_some() && get(r, "/client/hw_address") == mac)
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
    fn host_activity_fields_are_lenient() {
        let l: HostList = parse(json!({"now": 1, "hosts": [
            {"key": "a", "today_minutes": 95, "dns_mix": [["video", 7], ["other", 2]]},
            {"key": "b", "dns_mix": null},
            {"key": "c"}
        ]}));
        assert_eq!(l.hosts[0].today_minutes, Some(95));
        assert_eq!(
            l.hosts[0].dns_mix,
            [("video".to_owned(), 7), ("other".to_owned(), 2)]
        );
        assert!(l.hosts[1].dns_mix.is_empty() && l.hosts[1].today_minutes.is_none());
        assert!(l.hosts[2].dns_mix.is_empty());
        assert_eq!(category_name("smart_home"), "Smart home");
        assert_eq!(category_name("nope"), "Other");
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
    fn parses_host_modes_and_the_intercept_block() {
        let l: HostList = parse(json!({"now": 1, "hosts": [
            {"key": "aa:bb:cc:dd:ee:01", "mac": "aa:bb:cc:dd:ee:01", "mode": "isolated"},
            {"key": "aa:bb:cc:dd:ee:02", "mac": "aa:bb:cc:dd:ee:02", "mode": "quarantine"},
            {"key": "aa:bb:cc:dd:ee:03", "mac": "aa:bb:cc:dd:ee:03"},
            {"key": "aa:bb:cc:dd:ee:04", "mac": "aa:bb:cc:dd:ee:04", "mode": "later"}
        ], "intercept": {"active": true, "interfaces": ["lan"], "error": null}}));
        let modes: Vec<_> = l.hosts.iter().map(HostRow::locked_mode).collect();
        assert_eq!(modes, [Some("isolated"), Some("quarantine"), None, None]);
        assert_eq!(
            l.intercept,
            Some(Intercept {
                active: true,
                interfaces: vec!["lan".into()],
                error: None
            })
        );
        // an odd intercept block keeps the hosts
        let odd: HostList = parse(json!({"now": 1, "hosts": [{"key": "k"}], "intercept": 5}));
        assert_eq!((odd.hosts.len(), odd.intercept), (1, None));
    }

    /// The agent's MAC may be uppercase; the staged document's is matched
    /// case-insensitively.
    #[test]
    fn mark_staged_matches_an_uppercase_mac() {
        let mut l: HostList = parse(json!({"now": 1, "hosts": [
            {"key": "k1", "mac": "AA:BB:CC:DD:EE:01", "mode": "isolated"},
            {"key": "k2", "mac": "AA:BB:CC:DD:EE:02"}
        ]}));
        l.mark_staged(&json!({
            "firewall": {"host_modes": {
                "a": {"mac": "aa:bb:cc:dd:ee:01", "mode": "isolated"},
                "b": {"mac": "aa:bb:cc:dd:ee:02", "mode": "quarantine"}
            }},
            "dhcpv4": {"reservations": {
                "r": {"client": {"hw_address": "aa:bb:cc:dd:ee:02"}, "ip_address": "192.168.1.9"}
            }}
        }));
        assert_eq!(
            l.hosts[0].staged_mode, None,
            "already isolated: nothing staged"
        );
        assert_eq!(l.hosts[1].staged_mode.as_deref(), Some("quarantine"));
        assert!(l.hosts[1].staged, "its reservation is staged");
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

    fn lbl(maker: Option<&str>, kind: &str, confidence: &str, by: &str) -> HostLabelView {
        HostLabelView {
            maker: maker.map(str::to_owned),
            kind: kind.into(),
            confidence: confidence.into(),
            reasons: vec![],
            by: by.into(),
        }
    }

    #[test]
    fn minutes_tokens_and_mix_title() {
        assert_eq!(fmt_minutes(0), "0 m");
        assert_eq!(fmt_minutes(48), "48 m");
        assert_eq!(fmt_minutes(72), "1 h 12 m");
        assert_eq!(fmt_minutes(125), "2 h 05 m");
        assert_eq!(category_token("ads_tracking"), "cat-ads-tracking");
        assert_eq!(category_token("bogus"), "cat-other");
        let mix = vec![("video".to_owned(), 3), ("system".to_owned(), 1)];
        assert_eq!(
            mix_title(&mix).unwrap(),
            "DNS lookups (24 h): Video 75%, Apple/Google/Microsoft system 25%"
        );
        assert_eq!(mix_title(&[]), None);
        // thirds: 34 + 33 + 33, not 33 + 33 + 33
        let thirds: Vec<(String, u32)> = ["video", "games", "music"]
            .iter()
            .map(|k| ((*k).to_owned(), 1))
            .collect();
        assert_eq!(
            mix_title(&thirds).unwrap(),
            "DNS lookups (24 h): Video 34%, Games 33%, Music 33%"
        );
        // 1/7 each: 15 + 15 + 14 * 5 = 100
        let sevenths: Vec<(String, u32)> = CATEGORIES[..7]
            .iter()
            .map(|(k, _)| ((*k).to_owned(), 1))
            .collect();
        let t = mix_title(&sevenths).unwrap();
        let sum: u32 = t
            .split(['%', ' '])
            .filter_map(|w| w.parse::<u32>().ok())
            .filter(|n| *n != 24)
            .sum();
        assert_eq!(sum, 100, "{t}");
        let single = mix_style(&[("music".to_owned(), 5)]).unwrap();
        assert_eq!(
            single,
            "--mix:linear-gradient(90deg,var(--tint-music) 0.0%,var(--tint-music) 100.0%)"
        );
    }

    #[test]
    fn host_label_text() {
        let t = |m, k, c, b| lbl(m, k, c, b).text();
        assert_eq!(t(Some("Wyze"), "camera", "medium", "auto"), "Wyze · Camera");
        assert_eq!(
            t(Some("Raspberry Pi"), "server", "low", "auto"),
            "Raspberry Pi · Server?"
        );
        assert_eq!(t(None, "tv", "high", "auto"), "TV/streaming");
        assert_eq!(t(None, "tv", "low", "auto"), "TV/streaming?");
        assert_eq!(t(Some("Espressif"), "unknown", "low", "auto"), "Espressif");
        assert_eq!(t(None, "unknown", "low", "auto"), "");
        assert_eq!(
            t(Some("Private MAC"), "phone", "low", "auto"),
            "Private MAC · Phone/laptop?"
        );
        assert_eq!(
            t(Some("Private MAC"), "phone", "high", "owner"),
            "Private MAC · Phone"
        );
        assert_eq!(
            t(Some("Brother"), "printer", "high", "owner"),
            "Brother · Printer"
        );
        // a kind this UI does not know reads as unknown: just the maker
        assert_eq!(t(None, "toaster", "high", "auto"), "");
        assert_eq!(t(Some("Acme"), "toaster", "low", "auto"), "Acme");
        assert_eq!(
            lbl(None, "toaster", "low", "auto").kind_display(),
            ("Unknown", "•")
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn host_kinds_follow_the_schema() {
        use sensr_schema::models::hosts::HostKind;
        assert_eq!(HOST_KINDS.len(), HostKind::ALL.len());
        for (k, (name, display, _)) in HostKind::ALL.iter().zip(HOST_KINDS) {
            assert_eq!(serde_json::to_value(k).unwrap(), json!(name));
            assert_eq!(k.display(), display);
        }
    }

    #[test]
    fn mark_staged_reads_owner_labels() {
        let mut l: HostList = parse(json!({"now": 1, "hosts": [
            {"key": "k1", "mac": "aa:bb:cc:dd:ee:01",
             "label": {"maker": "Brother", "kind": "printer", "confidence": "high", "reasons": ["Set by you"], "by": "owner"}},
            {"key": "k2", "mac": "aa:bb:cc:dd:ee:02",
             "label": {"maker": "Wyze", "kind": "camera", "confidence": "medium", "reasons": [], "by": "auto"}},
            {"key": "k3", "mac": "aa:bb:cc:dd:ee:03",
             "label": {"maker": "Acme", "kind": "tv", "confidence": "high", "reasons": [], "by": "owner"}},
            {"key": "k4", "mac": "aa:bb:cc:dd:ee:04", "label": "odd"}
        ]}));
        assert_eq!(l.hosts.len(), 4, "an odd label keeps its row");
        assert_eq!(l.hosts[3].host_label, None);
        l.mark_staged(&json!({"hosts": {"labels": {
            "a": {"mac": "AA:BB:CC:DD:EE:01", "kind": "printer", "maker": "Brother"},
            "b": {"mac": "aa:bb:cc:dd:ee:02", "kind": "speaker"}
        }}}));
        let h = &l.hosts;
        assert_eq!(h[0].owner_kind.as_deref(), Some("printer"));
        assert_eq!(h[0].owner_maker.as_deref(), Some("Brother"));
        assert!(!h[0].staged_label, "applied as is");
        assert!(h[1].staged_label, "an override not in force yet");
        assert!(h[2].staged_label, "an owner label being removed");
        assert_eq!(h[2].owner_kind, None);
        assert!(!h[3].staged_label);
    }
}
