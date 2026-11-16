//! Value translations shared by the OPNsense mappers.

use std::str::FromStr;

use sensr_schema::Document as SensrDocument;
use sensr_schema::Uuid;
use sensr_schema::fields::{AliasName, Description, InterfaceId, IpFamily, NetOrAlias, PortSpec};
use sensr_schema::ipnet::IpNet;

use crate::mapper::MapContext;
use crate::report::Severity;
use crate::tree::Element;

/// The item's OPNsense `uuid` attribute, kept so references and API clients that
/// remember UUIDs keep working. Items without one (legacy sections) get a UUID
/// derived from their XPath, so importing the same file twice gives the same
/// document.
pub fn item_uuid(ctx: &mut MapContext<'_>, item: &Element) -> Uuid {
    match item.attribute("uuid").map(Uuid::from_str) {
        Some(Ok(u)) => u,
        Some(Err(_)) => {
            ctx.warn(
                item,
                Severity::Info,
                "malformed uuid replaced by one derived from the item's position",
            );
            stable_uuid(&ctx.xpath(item))
        }
        None => stable_uuid(&ctx.xpath(item)),
    }
}

/// A version-8 (custom) UUID from two FNV-1a passes over `key`: deterministic, not
/// secret, and distinct for distinct XPaths in practice.
pub fn stable_uuid(key: &str) -> Uuid {
    fn fnv(seed: u64, bytes: &[u8]) -> u64 {
        bytes.iter().fold(seed, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }
    let hi = fnv(0xcbf2_9ce4_8422_2325, key.as_bytes());
    let lo = fnv(0x6c62_272e_07bb_0142, key.as_bytes());
    let mut v = (u128::from(hi) << 64) | u128::from(lo);
    v = (v & !(0xf_u128 << 76)) | (0x8_u128 << 76); // version 8
    v = (v & !(0x3_u128 << 62)) | (0x2_u128 << 62); // RFC 4122 variant
    Uuid::from_u128(v)
}

/// Split an OPNsense list value (comma- or newline-separated), dropping empty items.
pub fn list(text: &str, separators: &[char]) -> Vec<String> {
    text.split(|c| separators.contains(&c))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// OPNsense `ipprotocol`: `inet`, `inet6` or `inet46`; empty means "any", which pf
/// renders without an address family, i.e. both.
pub fn family(text: &str) -> Result<IpFamily, String> {
    match text.trim() {
        "inet" => Ok(IpFamily::Inet),
        "inet6" => Ok(IpFamily::Inet6),
        "inet46" | "" => Ok(IpFamily::Inet46),
        other => Err(format!("unknown address family {other:?}")),
    }
}

/// A description, or `None` when empty. Over-long or multi-line text is cut to what
/// sensr accepts, with a note.
pub fn description(
    ctx: &mut MapContext<'_>,
    at: &Element,
    text: Option<String>,
) -> Option<Description> {
    let text = text?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(d) = text.parse() {
        return Some(d);
    }
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(255)
        .collect();
    match cleaned.trim().parse() {
        Ok(d) => {
            ctx.warn(
                at,
                Severity::Info,
                "description shortened to one line of at most 255 characters",
            );
            Some(d)
        }
        Err(e) => {
            ctx.warn(
                at,
                Severity::Invalid,
                format!("description not imported: {e}"),
            );
            None
        }
    }
}

/// Interface ids known to the document being built.
pub fn interface_id(doc: &SensrDocument, name: &str) -> Option<InterfaceId> {
    let id: InterfaceId = name.parse().ok()?;
    doc.interfaces.get(&id).map(|_| id)
}

/// Translate an OPNsense address operand: `any`, `(self)`, an interface (`lan` = its
/// network, `lanip` = its address), an alias name, or a literal address/network.
/// Interface names win over aliases, as in OPNsense's rule renderer.
pub fn operand(doc: &SensrDocument, text: &str) -> Result<NetOrAlias, String> {
    let t = text.trim();
    match t {
        "" | "any" => return Ok(NetOrAlias::Any),
        "(self)" | "self" => return Ok(NetOrAlias::This),
        _ => {}
    }
    if let Some(id) = interface_id(doc, t) {
        return Ok(NetOrAlias::InterfaceNet(id));
    }
    if let Some(id) = t.strip_suffix("ip").and_then(|i| interface_id(doc, i)) {
        return Ok(NetOrAlias::InterfaceAddr(id));
    }
    if let Ok(name) = t.parse::<AliasName>()
        && doc.firewall.alias(&name).is_some()
    {
        return Ok(NetOrAlias::Alias(name));
    }
    if let Ok(net) = t.parse::<IpNet>() {
        return Ok(NetOrAlias::Net(net));
    }
    if let Ok(ip) = t.parse::<std::net::IpAddr>() {
        return Ok(NetOrAlias::Net(IpNet::from(ip)));
    }
    Err(format!("{t:?} is not an interface, alias or address"))
}

/// Translate an OPNsense port operand: empty for any, a port alias, or a port, name
/// or range (`80`, `https`, `1000-2000`, `1000:2000`).
pub fn port_operand(doc: &SensrDocument, text: &str) -> Result<Option<PortSpec>, String> {
    let t = text.trim();
    if t.is_empty() || t == "any" {
        return Ok(None);
    }
    if let Ok(name) = t.parse::<AliasName>()
        && doc.firewall.alias(&name).is_some()
    {
        return Ok(Some(PortSpec::Alias(name)));
    }
    t.parse::<PortSpec>()
        .map(Some)
        .map_err(|e| format!("{t:?} is not a port, range or port alias: {e}"))
}

/// Parse a leaf's text with `f`, reporting failure as an invalid value at that leaf.
pub fn translate<T>(
    ctx: &mut MapContext<'_>,
    at: &Element,
    text: &str,
    f: impl FnOnce(&str) -> Result<T, String>,
) -> Option<T> {
    match f(text) {
        Ok(v) => Some(v),
        Err(e) => {
            ctx.warn(at, Severity::Invalid, e);
            None
        }
    }
}

/// Parse with `FromStr`, reporting failure as an invalid value at `at`.
pub fn parse_or_warn<T: FromStr>(
    ctx: &mut MapContext<'_>,
    at: &Element,
    text: &str,
    what: &str,
) -> Option<T>
where
    T::Err: std::fmt::Display,
{
    match text.trim().parse() {
        Ok(v) => Some(v),
        Err(e) => {
            ctx.warn(
                at,
                Severity::Invalid,
                format!("{what} {text:?} not imported: {e}"),
            );
            None
        }
    }
}
