//! Intrusion detection and prevention (OPNsense `OPNsense/IDS`, Services ›
//! Intrusion Detection; served by Suricata on sensr).
//!
//! Where sensr differs from upstream, on purpose:
//!
//! - **HOME_NET follows the box.** With [`Ids::home_net_auto`] (the default)
//!   the applier adds every address and subnet of every interface, including
//!   the WAN's current public address(es) from its lease. On the WAN, after
//!   NAT, every outbound flow is public-to-public, so an RFC 1918-only
//!   HOME_NET makes nearly every `$HOME_NET -> $EXTERNAL_NET` rule dead
//!   (measured on the owner's router on both OPNsense and VyOS, 2026-11-16).
//! - **IPS is NFQUEUE, fail-open, midstream-tolerant.** Netmap and divert
//!   become [`IdsMode::Prevent`]: forwarded packets are queued to Suricata
//!   with `queue bypass`, so a stopped or overloaded engine lets traffic
//!   through, and connections already open when IPS starts are picked up
//!   midstream instead of dropped.
//! - **Suppressions are first-class**, with a default list for the chatty
//!   informational signatures a household triggers constantly (STUN,
//!   stream-engine noise).

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, HttpUrl, InterfaceId, string_serde};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldError, FieldPath, Validations, ValidatorKind};

/// What Suricata does with matching traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdsMode {
    /// Passive capture (af-packet); alerts only (OPNsense `pcap`).
    #[default]
    Detect,
    /// Inline via nftables NFQUEUE: `drop` rules block (OPNsense `netmap`,
    /// `divert`).
    Prevent,
}

/// A rules file name as the ruleset ships it (`emerging-scan.rules`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleFile(String);

impl RuleFile {
    /// The file name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RuleFile {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stem = s.strip_suffix(".rules").unwrap_or_default();
        if (1..=128).contains(&stem.len())
            && !stem.starts_with('.')
            && stem
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
        {
            Ok(Self(s.to_owned()))
        } else {
            Err(FieldError::syntax(
                "A ruleset is a file name ending in .rules (letters, digits, '.', '-', '_').",
            ))
        }
    }
}

impl fmt::Display for RuleFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(RuleFile);

/// Which rules files are loaded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleProfile {
    /// A curated ET Open subset for a home or small-office router: exploits,
    /// malware, command-and-control, compromised hosts, attack responses,
    /// scans, coin miners, DNS and phishing: 29,624 of ET Open's 53,492
    /// enabled rules (2026-11-16), without the chatty INFO, DYN_DNS and
    /// server-side WEB_SPECIFIC_APPS sets.
    #[default]
    Home,
    /// Every file the sources ship.
    All,
    /// Exactly [`Ids::rule_files`] (what an OPNsense import produces).
    Custom,
}

/// The files of [`RuleProfile::Home`].
pub const HOME_RULE_FILES: &[&str] = &[
    "botcc.portgrouped.rules",
    "botcc.rules",
    "ciarmy.rules",
    "compromised.rules",
    "drop.rules",
    "dshield.rules",
    "emerging-attack_response.rules",
    "emerging-coinminer.rules",
    "emerging-current_events.rules",
    "emerging-dns.rules",
    "emerging-exploit.rules",
    "emerging-exploit_kit.rules",
    "emerging-malware.rules",
    "emerging-mobile_malware.rules",
    "emerging-phishing.rules",
    "emerging-scan.rules",
    "emerging-worm.rules",
    "threatview_CS_c2.rules",
];

/// Where rules come from (fetched by `suricata-update`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleSource {
    /// Proofpoint Emerging Threats Open (no account needed).
    EtOpen,
    /// A ruleset archive or `.rules` file at a URL.
    Url {
        /// The URL.
        url: HttpUrl,
    },
}

/// A rule's action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Log an alert.
    Alert,
    /// Alert and, in prevent mode, drop the packet.
    Drop,
}

/// A policy's resulting action (OPNsense `new_action`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Keep the rule's own action.
    Default,
    /// Alert.
    #[default]
    Alert,
    /// Drop.
    Drop,
    /// Disable the rule.
    Disable,
}

/// A rule metadata condition (`metadata: signature_severity Major`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetadataMatch {
    /// The metadata key (`affected_product`, `signature_severity`).
    pub key: String,
    /// The value.
    pub value: String,
}

/// A policy: change the action of every rule matching its conditions
/// (OPNsense `policies/policy`). Policies apply in priority order; a later
/// match does not override an earlier one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdsPolicy {
    /// Use the policy.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Lower first.
    #[serde(default)]
    pub priority: i32,
    /// Rules files it applies to; empty means all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rulesets: Vec<RuleFile>,
    /// Metadata conditions, all of which must hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Vec<MetadataMatch>,
    /// The new action.
    #[serde(default)]
    pub action: PolicyAction,
    /// Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// A per-signature override (OPNsense `rules/rule`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleOverride {
    /// Signature id.
    pub sid: u32,
    /// Load the rule.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Its action.
    pub action: RuleAction,
}

/// A user-defined rule's action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserRuleAction {
    /// Alert.
    #[default]
    Alert,
    /// Drop (prevent mode).
    Drop,
    /// Pass: stop inspecting the matching flow.
    Pass,
}

/// A user-defined rule (OPNsense `userDefinedRules/rule`): match on
/// addresses or a TLS certificate fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserRule {
    /// Use the rule.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Source network; `None` is any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub source: Option<IpNet>,
    /// Destination network; `None` is any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub destination: Option<IpNet>,
    /// TLS certificate SHA-1 fingerprint (`aa:bb:…`, 59 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Action.
    #[serde(default)]
    pub action: UserRuleAction,
    /// With `pass`: bypass the flow entirely (no further inspection, in the
    /// kernel when the capture method can).
    #[serde(default)]
    pub bypass: bool,
    /// Description (also the rule's `msg`).
    pub description: Description,
}

/// Which address of an alert a suppression matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrackBy {
    /// The source address.
    Src,
    /// The destination address.
    Dst,
    /// Either address.
    Either,
}

/// Limit a suppression to some addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuppressTrack {
    /// Which side.
    pub by: TrackBy,
    /// The addresses.
    #[schemars(with = "String")]
    pub net: IpNet,
}

/// Silence a signature's alerts (Suricata `threshold.config` `suppress`).
/// The rule still runs, and still drops in prevent mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    /// Use it.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Generator id (1 for normal rules).
    #[serde(default = "one")]
    pub gid: u32,
    /// Signature id.
    pub sid: u32,
    /// Only for these addresses; `None` suppresses everywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track: Option<SuppressTrack>,
    /// Why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

fn one() -> u32 {
    1
}

/// Signatures suppressed by default (when [`Ids::default_suppressions`] is
/// on): (sid, why). Taken from the alerts the owner's household raised in
/// minutes on 2026-11-16: STUN from video calls (≈ 150 alerts a minute),
/// stream-engine and app-layer events that say nothing about an attack, and
/// ordinary client software.
pub const DEFAULT_SUPPRESSIONS: &[(u32, &str)] = &[
    (2016149, "ET INFO STUN Binding Request (video calls)"),
    (2016150, "ET INFO STUN Binding Response (video calls)"),
    (2033077, "ET INFO STUN Binding Request on a low port"),
    (2033078, "ET INFO STUN Binding Request on a high port"),
    (2100230, "GPL CHAT Jabber/Google Talk outgoing traffic"),
    (2060251, "ET INFO Go-http-client User-Agent outbound"),
    (2210044, "SURICATA STREAM packet with invalid timestamp"),
    (
        2210050,
        "SURICATA STREAM reassembly overlap with different data",
    ),
    (2210054, "SURICATA STREAM excessive retransmissions"),
    (
        2260000,
        "SURICATA Applayer mismatch protocol both directions",
    ),
    (2260001, "SURICATA Applayer wrong direction first data"),
    (2260003, "SURICATA Applayer protocol detection skipped"),
];

/// Prevent-mode (NFQUEUE) settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpsSettings {
    /// Let packets through when Suricata is not reading the queue (stopped,
    /// restarting, overloaded): nftables `queue bypass` plus Suricata's
    /// `fail-open`. Turning this off makes the IDS a hard dependency of
    /// forwarding.
    #[serde(default = "yes")]
    pub fail_open: bool,
    /// First NFQUEUE number (one queue per worker from here).
    #[serde(default)]
    pub queue: u16,
    /// Pick up TCP connections that were already open when Suricata started
    /// (`stream.midstream`), instead of dropping their packets as
    /// `stream_midstream`.
    #[serde(default = "yes")]
    pub midstream: bool,
}

impl Default for IpsSettings {
    fn default() -> Self {
        Self {
            fail_open: true,
            queue: 0,
            midstream: true,
        }
    }
}

/// Suricata detection-engine profile (`detect.profile`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectProfile {
    /// Less memory, slower.
    Low,
    /// Suricata's default.
    #[default]
    Medium,
    /// More memory, faster.
    High,
}

/// Multi-pattern matcher (`mpm-algo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PatternMatcher {
    /// Aho-Corasick.
    Ac,
    /// Aho-Corasick, Ken Steele variant.
    AcKs,
    /// Hyperscan / Vectorscan.
    Hs,
}

/// Capture and engine tuning. `None` means the applier picks a value for
/// the hardware it runs on (see docs/ids.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdsTuning {
    /// Capture/detect worker threads per interface (1-64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<u8>,
    /// af-packet ring size in packets per worker (1024-1048576).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_size: Option<u32>,
    /// Detection profile.
    #[serde(default)]
    pub detect_profile: DetectProfile,
    /// Pattern matcher; `None` lets Suricata choose (Hyperscan when built in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_matcher: Option<PatternMatcher>,
    /// Default packet size (OPNsense `defaultPacketSize`, 82-65535).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_packet_size: Option<u16>,
    /// Keep workers off CPU 0, where the NIC interrupts land on a Pi 5.
    #[serde(default = "yes")]
    pub pin_workers: bool,
}

impl Default for IdsTuning {
    fn default() -> Self {
        Self {
            workers: None,
            ring_size: None,
            detect_profile: DetectProfile::default(),
            pattern_matcher: None,
            default_packet_size: None,
            pin_workers: true,
        }
    }
}

/// Scheduled rule downloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleUpdates {
    /// Download daily.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Hour (0-23, local time).
    #[serde(default = "update_hour")]
    pub hour: u8,
    /// Minute (0-59).
    #[serde(default)]
    pub minute: u8,
}

fn update_hour() -> u8 {
    4
}

impl Default for RuleUpdates {
    fn default() -> Self {
        Self {
            enabled: true,
            hour: update_hour(),
            minute: 0,
        }
    }
}

/// Alert logging and retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdsLogging {
    /// Days of alerts kept in the alert database (1-3650).
    #[serde(default = "retention_days")]
    pub retention_days: u16,
    /// At most this many alerts are kept (1000-10000000).
    #[serde(default = "max_alerts")]
    pub max_alerts: u32,
    /// Log the packet payload with each alert (OPNsense `LogPayload`).
    #[serde(default)]
    pub payload: bool,
    /// Also log HTTP transactions to eve.json.
    #[serde(default)]
    pub http: bool,
    /// Also log TLS handshakes to eve.json.
    #[serde(default)]
    pub tls: bool,
    /// Send alerts to the system log (OPNsense `syslog`).
    #[serde(default)]
    pub syslog: bool,
}

fn retention_days() -> u16 {
    30
}
fn max_alerts() -> u32 {
    500_000
}

impl Default for IdsLogging {
    fn default() -> Self {
        Self {
            retention_days: retention_days(),
            max_alerts: max_alerts(),
            payload: false,
            http: false,
            tls: false,
            syslog: false,
        }
    }
}

fn default_interfaces() -> Vec<InterfaceId> {
    vec!["wan".parse().expect("valid literal")]
}

/// OPNsense's default HOME_NET (RFC 1918).
pub fn rfc1918() -> Vec<IpNet> {
    ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
        .iter()
        .map(|n| n.parse().expect("valid literal"))
        .collect()
}

fn default_sources() -> Vec<RuleSource> {
    vec![RuleSource::EtOpen]
}

/// Intrusion detection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ids {
    /// Run Suricata.
    #[serde(default)]
    pub enabled: bool,
    /// Detect or prevent.
    #[serde(default)]
    pub mode: IdsMode,
    /// Interfaces to inspect. In prevent mode, forwarded traffic entering or
    /// leaving these is queued.
    #[serde(default = "default_interfaces")]
    pub interfaces: Vec<InterfaceId>,
    /// Capture in promiscuous mode (detect mode).
    #[serde(default)]
    pub promiscuous: bool,
    /// Networks that are "ours" (`$HOME_NET`), besides the automatic ones.
    #[serde(default = "rfc1918")]
    #[schemars(with = "Vec<String>")]
    pub home_net: Vec<IpNet>,
    /// Add every interface's addresses and subnets to HOME_NET, following
    /// lease changes (the WAN's public address included).
    #[serde(default = "yes")]
    pub home_net_auto: bool,
    /// Rule sources.
    #[serde(default = "default_sources")]
    pub sources: Vec<RuleSource>,
    /// Which rules files load.
    #[serde(default)]
    pub profile: RuleProfile,
    /// The files for [`RuleProfile::Custom`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_files: Vec<RuleFile>,
    /// Action policies.
    #[serde(default)]
    pub policies: ArrayField<IdsPolicy>,
    /// Per-signature overrides (win over policies).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_overrides: Vec<RuleOverride>,
    /// User-defined rules.
    #[serde(default)]
    pub user_rules: ArrayField<UserRule>,
    /// Include [`DEFAULT_SUPPRESSIONS`].
    #[serde(default = "yes")]
    pub default_suppressions: bool,
    /// Suppressions.
    #[serde(default)]
    pub suppressions: ArrayField<Suppression>,
    /// Prevent-mode settings.
    #[serde(default)]
    pub ips: IpsSettings,
    /// Engine tuning.
    #[serde(default)]
    pub tuning: IdsTuning,
    /// Rule downloads.
    #[serde(default)]
    pub updates: RuleUpdates,
    /// Logging.
    #[serde(default)]
    pub logging: IdsLogging,
}

impl Default for Ids {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: IdsMode::default(),
            interfaces: default_interfaces(),
            promiscuous: false,
            home_net: rfc1918(),
            home_net_auto: true,
            sources: default_sources(),
            profile: RuleProfile::default(),
            rule_files: Vec::new(),
            policies: ArrayField::default(),
            rule_overrides: Vec::new(),
            user_rules: ArrayField::default(),
            default_suppressions: true,
            suppressions: ArrayField::default(),
            ips: IpsSettings::default(),
            tuning: IdsTuning::default(),
            updates: RuleUpdates::default(),
            logging: IdsLogging::default(),
        }
    }
}

impl Ids {
    /// True when nothing differs from the defaults (the section is then
    /// omitted).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The rules files that load (`None`: every file).
    pub fn loaded_files(&self) -> Option<Vec<RuleFile>> {
        match self.profile {
            RuleProfile::All => None,
            RuleProfile::Home => Some(
                HOME_RULE_FILES
                    .iter()
                    .map(|f| RuleFile(f.to_string()))
                    .collect(),
            ),
            RuleProfile::Custom => Some(self.rule_files.clone()),
        }
    }

    /// Every active suppression: the defaults (unless turned off) followed by
    /// the user's, without repeats.
    pub fn active_suppressions(&self) -> Vec<Suppression> {
        let mut out: Vec<Suppression> = Vec::new();
        if self.default_suppressions {
            out.extend(DEFAULT_SUPPRESSIONS.iter().map(|(sid, why)| Suppression {
                enabled: true,
                gid: 1,
                sid: *sid,
                track: None,
                description: why.parse().ok(),
            }));
        }
        for s in self.suppressions.values().filter(|s| s.enabled) {
            if !out
                .iter()
                .any(|o| (o.gid, o.sid, &o.track) == (s.gid, s.sid, &s.track))
            {
                out.push(s.clone());
            }
        }
        out
    }
}

fn is_fingerprint(s: &str) -> bool {
    s.len() == 59
        && s.split(':').count() == 20
        && s.split(':')
            .all(|b| b.len() == 2 && b.bytes().all(|c| c.is_ascii_hexdigit()))
}

impl Validate for Ids {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::interfaces(ctx, &self.interfaces, &at.join("interfaces"), out);
        if self.enabled && self.interfaces.is_empty() {
            out.add(
                &at.join("interfaces"),
                ValidatorKind::PresenceOf,
                "Select at least one interface to inspect.",
            );
        }
        if self.enabled && self.sources.is_empty() {
            out.add(
                &at.join("sources"),
                ValidatorKind::PresenceOf,
                "Select at least one rule source.",
            );
        }
        if self.profile == RuleProfile::Custom && self.enabled && self.rule_files.is_empty() {
            out.add(
                &at.join("rule_files"),
                ValidatorKind::PresenceOf,
                "A custom profile needs at least one rules file.",
            );
        }
        let mut sids = HashSet::new();
        for (i, r) in self.rule_overrides.iter().enumerate() {
            let p = at.join("rule_overrides").join(i).join("sid");
            if r.sid == 0 {
                out.add(&p, ValidatorKind::MinMax, "Sid should be a number.");
            }
            if !sids.insert(r.sid) {
                out.add(&p, ValidatorKind::Constraint, "Duplicate entry exists.");
            }
        }
        for (id, m) in self.policies.iter() {
            // suricata-update matchers are OR'ed, so "these rulesets AND this
            // metadata" cannot be expressed: refuse it rather than widen it
            if !m.rulesets.is_empty() && !m.metadata.is_empty() {
                out.add(
                    &at.join("policies").join(id),
                    ValidatorKind::Callback,
                    "A policy matches either rulesets or rule metadata, not both.",
                );
            }
            for (i, kv) in m.metadata.iter().enumerate() {
                let ok = |s: &str| {
                    !s.is_empty()
                        && s.len() <= 128
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_-. ".contains(&c))
                };
                if !ok(&kv.key) || kv.key.contains(' ') || !ok(&kv.value) {
                    out.add(
                        &at.join("policies").join(id).join("metadata").join(i),
                        ValidatorKind::Regex,
                        "Metadata keys are one word; values are letters, digits, '_', '-', '.' or spaces.",
                    );
                }
            }
        }
        for (id, r) in self.user_rules.iter() {
            let p = at.join("user_rules").join(id);
            if let Some(f) = &r.fingerprint
                && !is_fingerprint(f)
            {
                out.add(
                    &p.join("fingerprint"),
                    ValidatorKind::Regex,
                    "A SSL fingerprint should be a 59 character long hex value.",
                );
            }
            if r.bypass && r.action != UserRuleAction::Pass {
                out.add(
                    &p.join("bypass"),
                    ValidatorKind::Callback,
                    "Bypass only applies to pass rules.",
                );
            }
            if r.source.is_none() && r.destination.is_none() && r.fingerprint.is_none() {
                out.add(
                    &p,
                    ValidatorKind::Callback,
                    "Set a source, a destination or a fingerprint.",
                );
            }
        }
        check::unique(
            self.suppressions.iter().map(|(id, s)| {
                (
                    at.join("suppressions").join(id),
                    Some((s.gid, s.sid, s.track.clone())),
                )
            }),
            "sid",
            "This signature is already suppressed for these addresses.",
            out,
        );
        for (id, s) in self.suppressions.iter() {
            if s.sid == 0 || s.gid == 0 {
                out.add(
                    &at.join("suppressions").join(id).join("sid"),
                    ValidatorKind::MinMax,
                    "Sid should be a number.",
                );
            }
        }
        let t = &self.tuning;
        if let Some(w) = t.workers {
            check::range(w, 1..=64, &at.join("tuning").join("workers"), out);
        }
        if let Some(r) = t.ring_size {
            check::range(
                r,
                1024..=1_048_576,
                &at.join("tuning").join("ring_size"),
                out,
            );
        }
        if let Some(s) = t.default_packet_size {
            check::range(
                s,
                82..=65535,
                &at.join("tuning").join("default_packet_size"),
                out,
            );
        }
        check::range(
            self.updates.hour,
            0..=23,
            &at.join("updates").join("hour"),
            out,
        );
        check::range(
            self.updates.minute,
            0..=59,
            &at.join("updates").join("minute"),
            out,
        );
        check::range(
            self.logging.retention_days,
            1..=3650,
            &at.join("logging").join("retention_days"),
            out,
        );
        check::range(
            self.logging.max_alerts,
            1000..=10_000_000,
            &at.join("logging").join("max_alerts"),
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;

    fn doc_with(ids: Ids) -> Document {
        let mut d = Document::factory();
        d.ids = ids;
        d
    }

    #[test]
    fn defaults_round_trip_and_are_empty() {
        let ids = Ids::default();
        assert!(ids.is_empty());
        let back: Ids = serde_json::from_str("{}").unwrap();
        assert_eq!(back, ids);
        assert_eq!(ids.home_net, rfc1918());
        assert!(ids.home_net_auto && ids.ips.fail_open && ids.ips.midstream);
        assert!(ids.tuning.pin_workers);
        assert_eq!(
            serde_json::from_str::<IdsTuning>("{}").unwrap(),
            IdsTuning::default()
        );
    }

    #[test]
    fn rule_file_names() {
        assert!("emerging-scan.rules".parse::<RuleFile>().is_ok());
        assert!("botcc.portgrouped.rules".parse::<RuleFile>().is_ok());
        for bad in [
            "",
            ".rules",
            "x.txt",
            "../etc.rules",
            "a b.rules",
            ".hidden.rules",
        ] {
            assert!(bad.parse::<RuleFile>().is_err(), "{bad}");
        }
    }

    #[test]
    fn default_suppressions_cover_stun_and_merge_with_user_ones() {
        let mut ids = Ids::default();
        let sids: Vec<u32> = ids.active_suppressions().iter().map(|s| s.sid).collect();
        for stun in [2016149, 2016150, 2033077, 2033078] {
            assert!(sids.contains(&stun));
        }
        // a user repeat of a default is not listed twice
        ids.suppressions.push(Suppression {
            enabled: true,
            gid: 1,
            sid: 2016149,
            track: None,
            description: None,
        });
        ids.suppressions.push(Suppression {
            enabled: true,
            gid: 1,
            sid: 2024897,
            track: Some(SuppressTrack {
                by: TrackBy::Src,
                net: "192.168.1.20/32".parse().unwrap(),
            }),
            description: None,
        });
        let all = ids.active_suppressions();
        assert_eq!(all.len(), DEFAULT_SUPPRESSIONS.len() + 1);
        ids.default_suppressions = false;
        assert_eq!(ids.active_suppressions().len(), 2);
    }

    #[test]
    fn profiles_select_files() {
        let mut ids = Ids::default();
        assert!(ids.loaded_files().unwrap().len() > 10);
        ids.profile = RuleProfile::All;
        assert!(ids.loaded_files().is_none());
        ids.profile = RuleProfile::Custom;
        ids.rule_files = vec!["botcc.rules".parse().unwrap()];
        assert_eq!(ids.loaded_files().unwrap().len(), 1);
    }

    #[test]
    fn validation() {
        let mut ids = Ids {
            enabled: true,
            interfaces: vec!["nope".parse().unwrap()],
            profile: RuleProfile::Custom,
            ..Ids::default()
        };
        ids.rule_overrides = vec![
            RuleOverride {
                sid: 1,
                enabled: true,
                action: RuleAction::Drop,
            },
            RuleOverride {
                sid: 1,
                enabled: false,
                action: RuleAction::Alert,
            },
        ];
        ids.user_rules.push(UserRule {
            enabled: true,
            source: None,
            destination: None,
            fingerprint: Some("zz".into()),
            action: UserRuleAction::Alert,
            bypass: true,
            description: "x".parse().unwrap(),
        });
        for _ in 0..2 {
            ids.suppressions.push(Suppression {
                enabled: true,
                gid: 1,
                sid: 5,
                track: None,
                description: None,
            });
        }
        ids.policies.push(IdsPolicy {
            enabled: true,
            priority: 0,
            rulesets: vec!["botcc.rules".parse().unwrap()],
            metadata: vec![MetadataMatch {
                key: "signature_severity".into(),
                value: "Major".into(),
            }],
            action: PolicyAction::Drop,
            description: None,
        });
        ids.tuning.workers = Some(0);
        ids.updates.hour = 24;
        let v = doc_with(ids).validate();
        let text = format!("{v:?}");
        for needle in [
            "Interface nope does not exist",
            "custom profile",
            "Duplicate entry",
            "59 character",
            "Bypass only",
            "already suppressed",
            "between 1 and 64",
            "between 0 and 23",
            "not both",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert!(doc_with(Ids::default()).validate().is_empty());
        let on = Ids {
            enabled: true,
            ..Ids::default()
        };
        assert!(doc_with(on).validate().is_empty());
    }

    #[test]
    fn fingerprints() {
        let fp = (0..20).map(|_| "ab").collect::<Vec<_>>().join(":");
        assert!(is_fingerprint(&fp));
        assert!(!is_fingerprint(&fp.replace("ab", "zz")));
    }
}
