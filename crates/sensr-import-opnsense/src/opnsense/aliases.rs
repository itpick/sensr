//! `OPNsense/Firewall/Alias`: named address, port and feed sets.

use std::collections::HashSet;

use sensr_schema::Document;
use sensr_schema::fields::{AliasName, CountryCode, HttpUrl, MacAddr, PortSpec};
use sensr_schema::models::firewall::{
    Alias, AliasContent, AliasEntry, AliasValue, Families, Refresh,
};

use super::common::{description, item_uuid, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

pub struct AliasMapper;

impl Mapper<Document> for AliasMapper {
    fn name(&self) -> &'static str {
        "firewall-alias"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["OPNsense/Firewall/Alias"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let Some(aliases) = ctx.child(s, "aliases") else {
            return;
        };
        // Aliases nest by bare name in any order, so learn every name first.
        let names: HashSet<String> = aliases
            .children_named("alias")
            .filter_map(|a| a.child("name").map(Element::text))
            .collect();
        for a in ctx.children(aliases, "alias") {
            match map_alias(a, ctx, &names) {
                Some((id, alias)) => {
                    out.firewall.aliases.insert(id, alias);
                }
                None => ctx.release(a),
            }
        }
    }

    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[(
            "OPNsense/Firewall/Alias/geoip",
            "GeoIP database source is not modelled yet",
        )]
    }
}

fn map_alias<'doc>(
    a: &'doc Element,
    ctx: &mut MapContext<'doc>,
    names: &HashSet<String>,
) -> Option<(sensr_schema::Uuid, Alias)> {
    let type_el = a.child("type")?;
    let kind = type_el.text();
    let content_el = a.child("content");
    let raw = content_el.map(Element::text).unwrap_or_default();
    let items = list(&raw, &['\n']);
    let at = content_el.unwrap_or(a);
    let families = || families(a);

    let content = match kind.trim() {
        "host" | "network" => {
            let mut entries = Vec::new();
            for item in &items {
                entries.extend(address_entry(ctx, at, item, names));
            }
            if kind.trim() == "host" {
                AliasContent::Host { entries }
            } else {
                AliasContent::Network { entries }
            }
        }
        "port" => {
            let mut entries = Vec::new();
            for item in &items {
                let spec = if names.contains(item.as_str()) {
                    item.parse::<AliasName>().map(PortSpec::Alias).ok()
                } else {
                    parse_or_warn::<PortSpec>(ctx, at, item, "port")
                };
                entries.extend(spec);
            }
            AliasContent::Port { entries }
        }
        "url" => AliasContent::Url {
            urls: items
                .iter()
                .filter_map(|u| parse_or_warn::<HttpUrl>(ctx, at, u, "URL"))
                .collect(),
        },
        "urltable" => {
            let Some(first) = items.first() else {
                ctx.warn(
                    a,
                    Severity::Invalid,
                    "URL table alias without a URL not imported",
                );
                return None;
            };
            if items.len() > 1 {
                ctx.warn(
                    at,
                    Severity::Degraded,
                    "only the first URL of a URL table alias is imported",
                );
            }
            let url = parse_or_warn::<HttpUrl>(ctx, at, first, "URL")?;
            let refresh = match a.child("updatefreq") {
                Some(f) => {
                    ctx.consume(f);
                    refresh(ctx, f)
                }
                None => Refresh::default(),
            };
            AliasContent::UrlTable {
                url,
                refresh,
                families: families(),
            }
        }
        "geoip" => AliasContent::GeoIp {
            countries: items
                .iter()
                .filter_map(|c| parse_or_warn::<CountryCode>(ctx, at, c, "country code"))
                .collect(),
            families: families(),
        },
        "networkgroup" => AliasContent::NetworkGroup {
            members: items
                .iter()
                .filter_map(|m| parse_or_warn::<AliasName>(ctx, at, m, "alias name"))
                .collect(),
        },
        "mac" => AliasContent::Mac {
            addresses: items
                .iter()
                .filter_map(|m| parse_or_warn::<MacAddr>(ctx, at, m, "MAC address"))
                .collect(),
        },
        "external" => AliasContent::External,
        // asn, dynipv6host, authgroup, urljson, internal: not modelled; the whole
        // alias stays unconsumed and is reported.
        _ => return None,
    };

    ctx.consume(type_el);
    if let Some(c) = content_el {
        ctx.consume_subtree(c);
    }
    if !matches!(
        content,
        AliasContent::GeoIp { .. } | AliasContent::UrlTable { .. }
    ) {
        // Only feed aliases use the address-family selector.
        ctx.defaults(a, &[("proto", "")]);
    } else if let Some(p) = a.child("proto") {
        ctx.consume(p);
    }
    let id = item_uuid(ctx, a);
    let name_el = ctx.child(a, "name")?;
    let name = parse_or_warn::<AliasName>(ctx, name_el, &name_el.text(), "alias name")?;
    let enabled = ctx.flag(a, "enabled");
    let counters = ctx.flag(a, "counters");
    let descr = ctx.text(a, "description");
    // Fetch credentials and the other per-type knobs are empty unless used.
    ctx.defaults(
        a,
        &[
            ("path_expression", ""),
            ("interface", ""),
            ("updatefreq", ""),
            ("password", ""),
            ("username", ""),
            ("authtype", ""),
            ("expire", ""),
            ("categories", ""),
        ],
    );
    Some((
        id,
        Alias {
            enabled,
            name,
            content,
            description: description(ctx, a, descr),
            counters,
        },
    ))
}

/// A host/network entry; bare names of other aliases become nested references.
fn address_entry(
    ctx: &mut MapContext<'_>,
    at: &Element,
    item: &str,
    names: &HashSet<String>,
) -> Option<AliasEntry> {
    let (exclude, bare) = match item.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, item),
    };
    if names.contains(bare)
        && let Ok(name) = bare.parse::<AliasName>()
    {
        return Some(AliasEntry {
            exclude,
            value: AliasValue::Alias(name),
        });
    }
    parse_or_warn(ctx, at, item, "alias entry")
}

/// `IPv4`, `IPv6` or both (empty means both).
fn families(a: &Element) -> Families {
    let proto = a.child("proto").map(Element::text).unwrap_or_default();
    let items = list(&proto, &[',']);
    if items.is_empty() {
        return Families::default();
    }
    Families {
        ipv4: items.iter().any(|p| p == "IPv4"),
        ipv6: items.iter().any(|p| p == "IPv6"),
    }
}

/// OPNsense `updatefreq` is days with a fraction (`1`, `0.5`); empty means fetch on
/// every reload.
fn refresh(ctx: &mut MapContext<'_>, f: &Element) -> Refresh {
    let t = f.text();
    let t = t.trim();
    if t.is_empty() {
        return Refresh::default();
    }
    match t.parse::<f64>() {
        Ok(days) if days.is_finite() && (0.0..65536.0).contains(&days) => {
            let whole = days.trunc();
            let hours = ((days - whole) * 24.0).round();
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Refresh {
                days: whole as u16,
                hours: hours.min(23.0) as u8,
            }
        }
        _ => {
            ctx.warn(
                f,
                Severity::Invalid,
                format!("refresh interval {t:?} not imported"),
            );
            Refresh::default()
        }
    }
}
