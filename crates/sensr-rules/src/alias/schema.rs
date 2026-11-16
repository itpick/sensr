//! Typed `sensr-schema` aliases → [`AliasDef`].

use ipnet::IpNet;
use sensr_schema::fields::PortSpec;
use sensr_schema::models::firewall::{self as fw, AliasContent, AliasValue};

use super::{AliasDef, AliasKind, Auth, Families, HostEntry, PortEntry, ipset::TableEntry};

fn families(f: &fw::Families) -> Families {
    Families {
        v4: f.ipv4,
        v6: f.ipv6,
    }
}

fn host_entries(entries: &[fw::AliasEntry]) -> Vec<HostEntry> {
    entries
        .iter()
        .map(|e| match &e.value {
            AliasValue::Addr(a) => HostEntry::Net(TableEntry {
                net: IpNet::from(*a),
                negate: e.exclude,
            }),
            AliasValue::Net(n) => HostEntry::Net(TableEntry {
                net: n.trunc(),
                negate: e.exclude,
            }),
            AliasValue::Range(r) => HostEntry::Range {
                lo: r.start(),
                hi: r.end(),
                exclude: e.exclude,
            },
            AliasValue::Name(n) => HostEntry::Name(n.as_str().to_owned()),
            AliasValue::Alias(a) => HostEntry::Alias {
                name: a.as_str().to_owned(),
                exclude: e.exclude,
            },
        })
        .collect()
}

impl From<&fw::Alias> for AliasDef {
    fn from(a: &fw::Alias) -> Self {
        let kind = match &a.content {
            AliasContent::Host { entries } => AliasKind::Host(host_entries(entries)),
            AliasContent::Network { entries } => AliasKind::Network(host_entries(entries)),
            AliasContent::Port { entries } => AliasKind::Port(
                entries
                    .iter()
                    .map(|p| match p {
                        PortSpec::Range(r) => PortEntry::Range(r.start().get(), r.end().get()),
                        PortSpec::Alias(n) => PortEntry::Alias(n.as_str().to_owned()),
                    })
                    .collect(),
            ),
            AliasContent::Url { urls } => AliasKind::Url {
                urls: urls.iter().map(|u| u.as_str().to_owned()).collect(),
                auth: Auth::None,
                families: Families::default(),
            },
            AliasContent::UrlTable {
                url,
                refresh,
                families: f,
            } => AliasKind::UrlTable {
                url: url.as_str().to_owned(),
                auth: Auth::None,
                refresh_secs: u64::from(refresh.days) * 86_400 + u64::from(refresh.hours) * 3_600,
                families: families(f),
            },
            AliasContent::GeoIp {
                countries,
                families: f,
            } => AliasKind::GeoIp {
                countries: countries.iter().map(|c| c.as_str().to_owned()).collect(),
                families: families(f),
            },
            AliasContent::NetworkGroup { members } => {
                AliasKind::NetworkGroup(members.iter().map(|m| m.as_str().to_owned()).collect())
            }
            AliasContent::Mac { addresses } => {
                AliasKind::Mac(addresses.iter().map(ToString::to_string).collect())
            }
            AliasContent::External => AliasKind::External,
        };
        AliasDef {
            name: a.name.as_str().to_owned(),
            enabled: a.enabled,
            kind,
        }
    }
}
