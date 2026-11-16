//! DNS blocklists (OPNsense `unboundplus/dnsbl`, Services › Unbound DNS ›
//! Blocklist).
//!
//! A [`Blocklist`] is a policy: the lists it draws names from, its own extra
//! names, the names it never blocks, which clients it applies to and how
//! blocked names are answered. sensr fetches and compiles the lists itself
//! (the `sensr-dns` crate) into Unbound local zones; nothing here is
//! evaluated per query.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, DomainName, HttpUrl};
use crate::refs::RefContext;
use crate::validation::{FieldError, FieldPath, Validations, ValidatorKind};

/// One curated list sensr knows by name (OPNsense's predefined `type`
/// options). Each has an OPNsense short code so imports round-trip.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum KnownList {
    /// AdGuard DNS filter (firebog mirror).
    Adguard,
    /// EasyList (firebog mirror).
    Easylist,
    /// EasyPrivacy (firebog mirror).
    Easyprivacy,
    /// Steven Black's unified hosts.
    StevenBlack,
    /// Peter Lowe's (yoyo.org) ad servers.
    Yoyo,
    /// HaGeZi Multi LIGHT.
    HageziLight,
    /// HaGeZi Multi NORMAL.
    HageziNormal,
    /// HaGeZi Multi PRO.
    HageziPro,
    /// HaGeZi Multi PRO mini.
    HageziProMini,
    /// HaGeZi Multi PRO++.
    HageziProPlus,
    /// HaGeZi Multi PRO++ mini.
    HageziProPlusMini,
    /// HaGeZi Multi ULTIMATE.
    HageziUltimate,
    /// HaGeZi Multi ULTIMATE mini.
    HageziUltimateMini,
    /// HaGeZi fake: scams and fakes.
    HageziFake,
    /// HaGeZi pop-up ads.
    HageziPopupAds,
    /// HaGeZi Threat Intelligence Feeds.
    HageziTif,
    /// HaGeZi Threat Intelligence Feeds, medium.
    HageziTifMedium,
    /// HaGeZi Threat Intelligence Feeds, mini.
    HageziTifMini,
    /// HaGeZi DoH/VPN/TOR/proxy bypass.
    HageziBypass,
    /// HaGeZi safe-search-not-supported.
    HageziNoSafesearch,
    /// HaGeZi dynamic DNS.
    HageziDyndns,
    /// HaGeZi badware hosters.
    HageziHoster,
    /// HaGeZi anti-piracy.
    HageziAntiPiracy,
    /// HaGeZi gambling.
    HageziGambling,
    /// HaGeZi gambling, medium.
    HageziGamblingMedium,
    /// HaGeZi gambling, mini.
    HageziGamblingMini,
    /// HaGeZi social networks.
    HageziSocial,
    /// OISD small (ads).
    OisdSmall,
    /// OISD big (ads and more).
    OisdBig,
    /// OISD NSFW.
    OisdNsfw,
}

const HAGEZI: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";

/// (list, OPNsense short code, label, URL or HaGeZi file name).
const KNOWN: &[(KnownList, &str, &str, &str)] = &[
    (
        KnownList::Adguard,
        "ag",
        "AdGuard List",
        "https://v.firebog.net/hosts/AdguardDNS.txt",
    ),
    (
        KnownList::Easylist,
        "el",
        "EasyList",
        "https://v.firebog.net/hosts/Easylist.txt",
    ),
    (
        KnownList::Easyprivacy,
        "ep",
        "EasyPrivacy",
        "https://v.firebog.net/hosts/Easyprivacy.txt",
    ),
    (
        KnownList::StevenBlack,
        "sb",
        "Steven Black List",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        KnownList::Yoyo,
        "yy",
        "YoYo List",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&mimetype=plaintext",
    ),
    (
        KnownList::HageziLight,
        "hgz001",
        "HaGeZi LIGHT - Relaxed Blocking",
        "light.txt",
    ),
    (
        KnownList::HageziNormal,
        "hgz002",
        "HaGeZi NORMAL - Relaxed/Balanced Blocking",
        "multi.txt",
    ),
    (
        KnownList::HageziPro,
        "hgz003",
        "HaGeZi PRO - Balanced Blocking",
        "pro.txt",
    ),
    (
        KnownList::HageziProMini,
        "hgz004",
        "HaGeZi Multi PRO - Mini",
        "pro.mini.txt",
    ),
    (
        KnownList::HageziProPlus,
        "hgz005",
        "HaGeZi PRO++ - Balanced/Aggressive Blocking",
        "pro.plus.txt",
    ),
    (
        KnownList::HageziProPlusMini,
        "hgz006",
        "HaGeZi Multi PRO++ - Mini",
        "pro.plus.mini.txt",
    ),
    (
        KnownList::HageziUltimate,
        "hgz007",
        "HaGeZi ULTIMATE - Aggressive Blocking",
        "ultimate.txt",
    ),
    (
        KnownList::HageziUltimateMini,
        "hgz008",
        "HaGeZi Multi ULTIMATE - Mini",
        "ultimate.mini.txt",
    ),
    (
        KnownList::HageziFake,
        "hgz009",
        "HaGeZi Fake - scams / fakes",
        "fake.txt",
    ),
    (
        KnownList::HageziPopupAds,
        "hgz010",
        "HaGeZi Pop-Up Ads",
        "popupads.txt",
    ),
    (
        KnownList::HageziTif,
        "hgz011",
        "HaGeZi Threat Intelligence Feeds",
        "tif.txt",
    ),
    (
        KnownList::HageziTifMedium,
        "hgz012",
        "HaGeZi Threat Intelligence Feeds - Medium",
        "tif.medium.txt",
    ),
    (
        KnownList::HageziTifMini,
        "hgz013",
        "HaGeZi Threat Intelligence Feeds - Mini",
        "tif.mini.txt",
    ),
    (
        KnownList::HageziBypass,
        "hgz014",
        "HaGeZi DoH/VPN/TOR/Proxy Bypass",
        "doh-vpn-proxy-bypass.txt",
    ),
    (
        KnownList::HageziNoSafesearch,
        "hgz015",
        "HaGeZi Safesearch not supported",
        "nosafesearch.txt",
    ),
    (
        KnownList::HageziDyndns,
        "hgz016",
        "HaGeZi Dynamic DNS blocking",
        "dyndns.txt",
    ),
    (
        KnownList::HageziHoster,
        "hgz017",
        "HaGeZi Badware Hoster blocking",
        "hoster.txt",
    ),
    (
        KnownList::HageziAntiPiracy,
        "hgz018",
        "HaGeZi Anti Piracy",
        "anti.piracy.txt",
    ),
    (
        KnownList::HageziGambling,
        "hgz019",
        "HaGeZi Gambling",
        "gambling.txt",
    ),
    (
        KnownList::HageziGamblingMedium,
        "hgz020",
        "HaGeZi Gambling - Medium",
        "gambling.medium.txt",
    ),
    (
        KnownList::HageziGamblingMini,
        "hgz021",
        "HaGeZi Gambling - Mini",
        "gambling.mini.txt",
    ),
    (
        KnownList::HageziSocial,
        "hgz022",
        "HaGeZi Social Networks",
        "social.txt",
    ),
    (
        KnownList::OisdSmall,
        "oisd0",
        "OISD Ads Blocklist",
        "https://small.oisd.nl/domainswild",
    ),
    (
        KnownList::OisdBig,
        "oisd1",
        "OISD Big Blocklist (incl. Ads)",
        "https://big.oisd.nl/domainswild",
    ),
    (
        KnownList::OisdNsfw,
        "oisd2",
        "OISD NSFW Blocklist",
        "https://nsfw.oisd.nl/domainswild",
    ),
];

impl KnownList {
    /// Every known list, in display order.
    pub fn all() -> impl Iterator<Item = KnownList> {
        KNOWN.iter().map(|k| k.0)
    }

    fn row(self) -> &'static (KnownList, &'static str, &'static str, &'static str) {
        KNOWN.iter().find(|k| k.0 == self).unwrap_or(&KNOWN[0])
    }

    /// The OPNsense short code (`hgz003`).
    pub fn opnsense_code(self) -> &'static str {
        self.row().1
    }

    /// The list for an OPNsense short code.
    pub fn from_opnsense_code(code: &str) -> Option<KnownList> {
        KNOWN.iter().find(|k| k.1 == code).map(|k| k.0)
    }

    /// Human-readable name.
    pub fn label(self) -> &'static str {
        self.row().2
    }

    /// Where the list is downloaded from. HaGeZi lists come from the
    /// project's own repository in its wildcard format (one `*.domain` per
    /// line, which also blocks the domain itself).
    pub fn url(self) -> String {
        let u = self.row().3;
        if u.starts_with("http") {
            u.to_owned()
        } else {
            format!("{HAGEZI}{u}")
        }
    }
}

/// A name the policy never blocks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllowEntry {
    /// Exactly this name (`updates.example.com`).
    Domain(DomainName),
    /// The name and everything below it (`*.example.com`).
    Subtree(DomainName),
    /// Names matching a regular expression, anchored at the start and
    /// case-insensitive as in OPNsense (`/^cdn[0-9]+\./`). Applied when the
    /// lists are compiled: it removes listed names, but cannot carve a hole
    /// into a name blocked with its subdomains (use a domain entry for that).
    Pattern(String),
}

impl FromStr for AllowEntry {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(p) = s.strip_prefix('/').and_then(|p| p.strip_suffix('/')) {
            if p.is_empty() {
                return Err(FieldError::syntax("The pattern is empty."));
            }
            fancy_regex::Regex::new(p)
                .map_err(|e| FieldError::syntax(format!("Invalid regular expression: {e}")))?;
            return Ok(Self::Pattern(p.to_owned()));
        }
        let (sub, name) = match s.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let d: DomainName = name.trim_end_matches('.').to_ascii_lowercase().parse()?;
        Ok(if sub {
            Self::Subtree(d)
        } else {
            Self::Domain(d)
        })
    }
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(d) => write!(f, "{d}"),
            Self::Subtree(d) => write!(f, "*.{d}"),
            Self::Pattern(p) => write!(f, "/{p}/"),
        }
    }
}
crate::fields::string_serde!(AllowEntry);

/// How a blocked name is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum BlockAnswer {
    /// A records answer this address (OPNsense default `0.0.0.0`); with
    /// `0.0.0.0`, AAAA records answer `::`.
    Address {
        /// The address.
        #[serde(default = "unspecified")]
        address: Ipv4Addr,
    },
    /// NXDOMAIN (OPNsense `nxdomain`).
    Nxdomain,
}

fn unspecified() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

impl Default for BlockAnswer {
    fn default() -> Self {
        Self::Address {
            address: Ipv4Addr::UNSPECIFIED,
        }
    }
}

/// One blocklist policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Blocklist {
    /// Apply this policy.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// What the policy is for (required, as in OPNsense).
    pub description: Description,
    /// Curated lists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<KnownList>,
    /// Further list URLs (hosts files, domain lists, `*.domain` wildcard
    /// lists and AdBlock-style `||domain^` lines are understood).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<HttpUrl>,
    /// Names blocked exactly (OPNsense `blocklists`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block: Vec<DomainName>,
    /// Names blocked with all their subdomains (OPNsense `wildcards`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_subtrees: Vec<DomainName>,
    /// Names never blocked (OPNsense `allowlists`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<AllowEntry>,
    /// Clients the policy applies to; empty means every client. The most
    /// specific policy for a client is consulted first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(with = "Vec<String>")]
    pub source_nets: Vec<IpNet>,
    /// Answer for blocked names.
    #[serde(default)]
    pub answer: BlockAnswer,
    /// Seconds a downloaded list is reused before it is fetched again
    /// (OPNsense `cache_ttl`).
    #[serde(default = "default_refresh")]
    pub refresh_seconds: u32,
}

/// OPNsense's `cache_ttl` default (20 hours).
pub const DEFAULT_REFRESH_SECONDS: u32 = 72_000;

fn default_refresh() -> u32 {
    DEFAULT_REFRESH_SECONDS
}

impl Blocklist {
    /// An enabled policy with only a description.
    pub fn new(description: Description) -> Self {
        Self {
            enabled: true,
            description,
            lists: Vec::new(),
            urls: Vec::new(),
            block: Vec::new(),
            block_subtrees: Vec::new(),
            allow: Vec::new(),
            source_nets: Vec::new(),
            answer: BlockAnswer::default(),
            refresh_seconds: DEFAULT_REFRESH_SECONDS,
        }
    }

    /// Every URL the policy downloads (curated lists first).
    pub fn sources(&self) -> Vec<String> {
        self.lists
            .iter()
            .map(|l| l.url())
            .chain(self.urls.iter().map(|u| u.as_str().to_owned()))
            .collect()
    }
}

/// Validates the policies of `dns.blocklists`.
pub(crate) fn validate(
    lists: &ArrayField<Blocklist>,
    _ctx: &dyn RefContext,
    at: &FieldPath,
    out: &mut Validations,
) {
    for (id, b) in lists {
        let p = at.join(id);
        if b.enabled
            && b.lists.is_empty()
            && b.urls.is_empty()
            && b.block.is_empty()
            && b.block_subtrees.is_empty()
        {
            out.add(
                &p.join("lists"),
                ValidatorKind::Callback,
                "Select a list, add a URL or name a domain to block.",
            );
        }
        // OPNsense: equally sized networks of one family, so that policy
        // priority (the most specific network first) is well defined.
        let nets = &b.source_nets;
        if nets
            .windows(2)
            .any(|w| w[0].prefix_len() != w[1].prefix_len())
        {
            out.add(
                &p.join("source_nets"),
                ValidatorKind::Callback,
                "All offered networks should be equally sized to avoid overlaps.",
            );
        }
        if nets
            .windows(2)
            .any(|w| matches!(w[0], IpNet::V4(_)) != matches!(w[1], IpNet::V4(_)))
        {
            out.add(
                &p.join("source_nets"),
                ValidatorKind::Callback,
                "All offered networks should use the same IP protocol.",
            );
        }
        if nets.iter().any(|n| n.trunc() != *n) {
            out.add(
                &p.join("source_nets"),
                ValidatorKind::Callback,
                "Please specify a valid network segment or address (IPv4/IPv6). If a mask is provided, please omit the host bits.",
            );
        }
        check::range(
            b.refresh_seconds,
            60..=31_536_000,
            &p.join("refresh_seconds"),
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_lists_round_trip_codes() {
        for l in KnownList::all() {
            assert_eq!(KnownList::from_opnsense_code(l.opnsense_code()), Some(l));
            assert!(l.url().starts_with("https://"), "{l:?}");
        }
        assert_eq!(
            KnownList::HageziPro.url(),
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt"
        );
        assert_eq!(KnownList::all().count(), KNOWN.len());
        assert_eq!(
            serde_json::to_string(&KnownList::HageziTif).unwrap(),
            "\"hagezi-tif\""
        );
    }

    #[test]
    fn allow_entries_parse() {
        let e: AllowEntry = "Updates.Example.com.".parse().unwrap();
        assert_eq!(
            e,
            AllowEntry::Domain("updates.example.com".parse().unwrap())
        );
        let e: AllowEntry = "*.example.com".parse().unwrap();
        assert_eq!(e.to_string(), "*.example.com");
        let e: AllowEntry = "/^always_allow\\..*/".parse().unwrap();
        assert_eq!(e, AllowEntry::Pattern("^always_allow\\..*".into()));
        assert!("/(/".parse::<AllowEntry>().is_err());
        assert!("not a domain".parse::<AllowEntry>().is_err());
    }

    #[test]
    fn answer_defaults_to_unspecified_address() {
        let b: BlockAnswer = serde_json::from_str(r#"{"mode":"address"}"#).unwrap();
        assert_eq!(b, BlockAnswer::default());
        let b: BlockAnswer = serde_json::from_str(r#"{"mode":"nxdomain"}"#).unwrap();
        assert_eq!(b, BlockAnswer::Nxdomain);
    }
}
