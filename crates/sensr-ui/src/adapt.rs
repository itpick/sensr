//! Maps between the sensr-schema document (what sensr-api stores and validates) and the flat
//! view rows and forms the UI edits.
//!
//! The UI keeps OPNsense's flat field layout (one "Source" text box, one "Port" box); the
//! schema is nested and typed (`source: {net, not, port}`, tagged enums, UUID-keyed maps).
//! Each adapter:
//! - turns a schema item into a view row (`to_view`),
//! - writes a view row back over the stored item (`from_view`), keeping every schema field the
//!   view does not show,
//! - maps schema validation paths back to view fields (`view_path`).
//!
//! The adapters run on the server only. Typed checking against the schema happens when the
//! backend validates the staged document (see [`crate::mock`] and sensr-api).

use crate::api::FieldError;
use crate::form::get_path;
use crate::models::{FormId, GridId};
use serde_json::{Map, Value, json};

/// The value sensr-schema serialises instead of a secret (the mock uses it; the agent uses
/// its own `***…` marker). Either reads back as "unchanged" when written.
pub const REDACTED: &str = "*redacted*";

fn s(v: &Value, path: &str) -> String {
    match get_path(v, path) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Schema fields left at their default are omitted from the document; show the default.
fn or_default(v: String, default: &str) -> String {
    if v.is_empty() { default.to_owned() } else { v }
}

fn b(v: &Value, path: &str, default: bool) -> bool {
    get_path(v, path)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

fn arr(v: &Value, path: &str) -> Vec<Value> {
    get_path(v, path)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn strings(v: &Value, path: &str) -> Value {
    Value::Array(
        arr(v, path)
            .into_iter()
            .map(|x| match x {
                Value::String(_) => x,
                other => Value::String(other.to_string()),
            })
            .collect(),
    )
}

fn obj(v: &mut Value) -> &mut Map<String, Value> {
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    match v {
        Value::Object(m) => m,
        _ => unreachable!("just made it an object"),
    }
}

/// Sets `key` to the view's string, or removes it when empty (schema `Option` fields).
fn put_opt(o: &mut Map<String, Value>, key: &str, view: &Value, field: &str) {
    match get_path(view, field) {
        Some(Value::String(x)) if !x.trim().is_empty() => {
            o.insert(key.into(), Value::String(x.trim().into()));
        }
        Some(Value::Number(n)) => {
            o.insert(key.into(), Value::Number(n.clone()));
        }
        _ => {
            o.remove(key);
        }
    }
}

fn put(o: &mut Map<String, Value>, key: &str, view: &Value, field: &str) {
    if let Some(v) = get_path(view, field) {
        o.insert(key.into(), v.clone());
    }
}

/// Ports are strings in the schema (`"443"`, or a service name); numbers in the view.
fn put_port(o: &mut Map<String, Value>, key: &str, view: &Value, field: &str) {
    match get_path(view, field) {
        Some(Value::Number(n)) => drop(o.insert(key.into(), Value::String(n.to_string()))),
        Some(Value::String(x)) if !x.is_empty() => {
            drop(o.insert(key.into(), Value::String(x.clone())))
        }
        _ => drop(o.remove(key)),
    }
}

/// A schema port string as a view number (service names stay strings).
fn port_num(v: &Value, path: &str) -> Value {
    match get_path(v, path) {
        Some(Value::String(x)) => x
            .parse::<u16>()
            .map_or_else(|_| Value::String(x.clone()), Value::from),
        Some(n @ Value::Number(_)) => n.clone(),
        _ => Value::Null,
    }
}

fn put_list(o: &mut Map<String, Value>, key: &str, view: &Value, field: &str) {
    o.insert(key.into(), strings(view, field));
}

/// Endpoint `{net, not, port}` ⇄ (`"!net"`, `"port"`).
fn endpoint_to_view(ep: &Value) -> (String, String) {
    let net = match get_path(ep, "net") {
        Some(Value::String(n)) => n.clone(),
        _ => "any".to_owned(),
    };
    let net = if b(ep, "not", false) {
        format!("!{net}")
    } else {
        net
    };
    (net, s(ep, "port"))
}

fn endpoint_from_view(base: Option<&Value>, net: &str, port: &str) -> Value {
    let mut ep = base.cloned().unwrap_or_else(|| json!({}));
    let o = obj(&mut ep);
    let net = net.trim();
    let (not, net) = match net.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, net),
    };
    o.insert(
        "net".into(),
        Value::String(if net.is_empty() {
            "any".into()
        } else {
            net.into()
        }),
    );
    o.insert("not".into(), Value::Bool(not));
    let port = port.trim();
    if port.is_empty() || port == "any" {
        o.remove("port");
    } else {
        o.insert("port".into(), Value::String(port.into()));
    }
    ep
}

/// Floating rules apply to no interface or several; a tab shows rules on exactly one.
fn rule_scope(item: &Value, key: &str) -> String {
    match get_path(item, key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([Value::String(one)]) => one.clone(),
        _ => "floating".to_owned(),
    }
}

fn rule_interfaces_from_view(base: Option<&Value>, chosen: &str) -> Value {
    if chosen == "floating" {
        // Keep a multi-interface selection made elsewhere; one interface is not floating.
        let kept = base.map(|b| arr(b, "interfaces")).unwrap_or_default();
        Value::Array(if kept.len() == 1 { vec![] } else { kept })
    } else {
        json!([chosen])
    }
}

/// How a grid's rows are stored in the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Store {
    /// A JSON object keyed by UUID (or interface id), in list order.
    Map(String),
    /// A JSON array; the row key is the index.
    Array(String),
}

/// Where `grid` rows live for `scope`, given the whole document.
pub fn store(grid: GridId, scope: &str, doc: &Value) -> Store {
    match grid {
        GridId::Assignments => Store::Map("interfaces".into()),
        GridId::Aliases => Store::Map("firewall.aliases".into()),
        GridId::FilterRules => Store::Map("firewall.rules".into()),
        GridId::SourceNat => Store::Map("nat.outbound.rules".into()),
        GridId::PortForwards => Store::Map("nat.port_forwards".into()),
        GridId::DhcpRanges => Store::Array(format!(
            "dhcpv4.subnets.{}.pools",
            subnet_for(doc, scope).unwrap_or_default()
        )),
        GridId::StaticMaps => Store::Map("dhcpv4.reservations".into()),
        GridId::HostOverrides => Store::Map("dns.host_overrides".into()),
        GridId::WgInstances => Store::Map("wireguard.servers".into()),
        GridId::WgPeers => Store::Map("wireguard.peers".into()),
    }
}

/// The UUID of the DHCPv4 subnet bound to interface `iface`.
pub fn subnet_for(doc: &Value, iface: &str) -> Option<String> {
    get_path(doc, "dhcpv4.subnets")?
        .as_object()?
        .iter()
        .find(|(_, s)| get_path(s, "interface").and_then(Value::as_str) == Some(iface))
        .map(|(k, _)| k.clone())
}

/// Does a stored item belong to the grid's scope?
pub fn in_scope(grid: GridId, scope: &str, doc: &Value, item: &Value) -> bool {
    match grid {
        GridId::FilterRules => rule_scope(item, "interfaces") == scope,
        GridId::StaticMaps => subnet_for(doc, scope)
            .is_some_and(|sub| get_path(item, "subnet").and_then(Value::as_str) == Some(&sub)),
        _ => true,
    }
}

/// Whether rows of this grid carry a `sequence` that defines their order.
pub fn sequenced(grid: GridId) -> bool {
    matches!(
        grid,
        GridId::FilterRules | GridId::SourceNat | GridId::PortForwards
    )
}

/// Schema item → view row (without its key).
pub fn to_view(grid: GridId, doc: &Value, item: &Value) -> Value {
    match grid {
        GridId::Assignments => interface_to_view(item),
        GridId::Aliases => {
            let ty = s(item, "content.type");
            let content = match ty.as_str() {
                "host" | "network" | "port" => strings(item, "content.entries"),
                "url" => strings(item, "content.urls"),
                "url_table" => Value::Array(vec![Value::String(s(item, "content.url"))]),
                "geo_ip" => strings(item, "content.countries"),
                "network_group" => strings(item, "content.members"),
                "mac" => strings(item, "content.addresses"),
                _ => json!([]),
            };
            json!({
                "enabled": b(item, "enabled", true),
                "name": s(item, "name"),
                "type": ty,
                "content": content,
                "description": s(item, "description"),
            })
        }
        GridId::FilterRules => {
            let (src, sport) = endpoint_to_view(get_path(item, "source").unwrap_or(&Value::Null));
            let (dst, dport) =
                endpoint_to_view(get_path(item, "destination").unwrap_or(&Value::Null));
            json!({
                "enabled": b(item, "enabled", true),
                "sequence": get_path(item, "sequence").cloned().unwrap_or(json!(1)),
                "action": or_default(s(item, "action"), "pass"),
                "quick": b(item, "quick", true),
                "interface": rule_scope(item, "interfaces"),
                "direction": or_default(s(item, "direction"), "in"),
                "ipprotocol": or_default(s(item, "ip_protocol"), "inet"),
                "protocol": or_default(s(item, "protocol"), "any"),
                "source": src, "source_port": sport,
                "destination": dst, "destination_port": dport,
                "log": b(item, "log", false),
                "description": s(item, "description"),
            })
        }
        GridId::SourceNat => {
            let (src, _) = endpoint_to_view(get_path(item, "source").unwrap_or(&Value::Null));
            let (dst, _) = endpoint_to_view(get_path(item, "destination").unwrap_or(&Value::Null));
            json!({
                "enabled": b(item, "enabled", true),
                "sequence": get_path(item, "sequence").cloned().unwrap_or(json!(1)),
                "nonat": b(item, "no_nat", false),
                "interface": s(item, "interface"),
                "protocol": or_default(s(item, "protocol"), "any"),
                "source": src,
                "destination": dst,
                "target": s(item, "target"),
                "description": s(item, "description"),
            })
        }
        GridId::PortForwards => {
            let (dst, dport) =
                endpoint_to_view(get_path(item, "destination").unwrap_or(&Value::Null));
            json!({
                "enabled": b(item, "enabled", true),
                "sequence": get_path(item, "sequence").cloned().unwrap_or(json!(1)),
                "interface": arr(item, "interfaces").first().and_then(Value::as_str).unwrap_or_default(),
                "protocol": s(item, "protocol"),
                "destination": dst,
                "destination_port": dport,
                "target": s(item, "target"),
                "target_port": s(item, "target_port"),
                "description": s(item, "description"),
            })
        }
        GridId::DhcpRanges => {
            // Pools are `start-end` strings (or a CIDR block inside the subnet).
            let text = item.as_str().unwrap_or_default();
            let (from, to) = text.split_once('-').unwrap_or((text, ""));
            json!({"from": from.trim(), "to": to.trim()})
        }
        GridId::StaticMaps => json!({
            "mac": s(item, "client.hw_address"),
            "ipaddr": s(item, "ip_address"),
            "hostname": s(item, "hostname"),
            "description": s(item, "description"),
        }),
        GridId::HostOverrides => {
            let rr = s(item, "record.rr");
            let (server, mx, prio) = match rr.as_str() {
                "A" | "AAAA" => (s(item, "record.address"), String::new(), Value::Null),
                "MX" => (
                    String::new(),
                    s(item, "record.host"),
                    get_path(item, "record.priority")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                "TXT" => (s(item, "record.data"), String::new(), Value::Null),
                _ => (String::new(), String::new(), Value::Null),
            };
            json!({
                "enabled": b(item, "enabled", true),
                "hostname": s(item, "hostname"),
                "domain": s(item, "domain"),
                "rr": rr,
                "server": server,
                "mx": mx,
                "mxprio": prio,
                "description": s(item, "description"),
            })
        }
        GridId::WgInstances => {
            let peers = get_path(doc, "wireguard.peers")
                .cloned()
                .unwrap_or(Value::Null);
            let names: Vec<Value> = arr(item, "peers")
                .iter()
                .filter_map(Value::as_str)
                .map(|uuid| {
                    Value::String(
                        get_path(&peers, uuid).map_or_else(|| uuid.to_owned(), |p| s(p, "name")),
                    )
                })
                .collect();
            json!({
                "enabled": b(item, "enabled", true),
                "name": s(item, "name"),
                "instance": get_path(item, "instance").cloned().unwrap_or(Value::Null),
                "pubkey": s(item, "public_key"),
                "privkey": "",
                "port": port_num(item, "listen_port"),
                "mtu": get_path(item, "mtu").cloned().unwrap_or(Value::Null),
                "tunneladdress": strings(item, "tunnel_addresses"),
                "dns": strings(item, "dns"),
                "disableroutes": b(item, "disable_routes", false),
                "peers": names,
            })
        }
        GridId::WgPeers => json!({
            "enabled": b(item, "enabled", true),
            "name": s(item, "name"),
            "pubkey": s(item, "public_key"),
            "psk": "",
            "tunneladdress": strings(item, "allowed_ips"),
            "serveraddress": s(item, "endpoint"),
            "serverport": port_num(item, "endpoint_port"),
            "keepalive": get_path(item, "keepalive").cloned().unwrap_or(Value::Null),
            "servers": [],
        }),
    }
}

fn interface_to_view(item: &Value) -> Value {
    let v4 = s(item, "ipv4.mode");
    let v6 = s(item, "ipv6.mode");
    json!({
        "device": s(item, "device"),
        "description": s(item, "description"),
        "enabled": b(item, "enabled", true),
        "block_private": b(item, "block_private", false),
        "block_bogons": b(item, "block_bogons", false),
        "ipv4_type": if v4.is_empty() { "none".to_owned() } else { v4 },
        "ipv4_address": s(item, "ipv4.address"),
        "ipv4_gateway": s(item, "ipv4.gateway"),
        "ipv6_type": match v6.as_str() { "" => "none".to_owned(), "track" => "track6".to_owned(), _ => v6 },
        "ipv6_address": s(item, "ipv6.address"),
        "mtu": get_path(item, "mtu").cloned().unwrap_or(Value::Null),
    })
}

fn interface_from_view(base: Option<&Value>, view: &Value) -> Value {
    let mut item = base.cloned().unwrap_or_else(|| json!({"role": "other"}));
    let o = obj(&mut item);
    put(o, "enabled", view, "enabled");
    put_opt(o, "description", view, "description");
    put(o, "device", view, "device");
    put(o, "block_private", view, "block_private");
    put(o, "block_bogons", view, "block_bogons");
    put_opt(o, "mtu", view, "mtu");
    let v4_mode = s(view, "ipv4_type");
    let keep4 = base
        .and_then(|b| get_path(b, "ipv4"))
        .filter(|v| s(v, "mode") == v4_mode)
        .cloned();
    let ipv4 = match v4_mode.as_str() {
        "static" => {
            let mut v = json!({"mode": "static", "address": s(view, "ipv4_address")});
            if !s(view, "ipv4_gateway").is_empty() {
                v["gateway"] = Value::String(s(view, "ipv4_gateway"));
            }
            v
        }
        "dhcp" => keep4.unwrap_or_else(|| json!({"mode": "dhcp"})),
        _ => json!({"mode": "none"}),
    };
    o.insert("ipv4".into(), ipv4);
    let v6_mode = match s(view, "ipv6_type").as_str() {
        "track6" => "track".to_owned(),
        other => other.to_owned(),
    };
    let keep6 = base
        .and_then(|b| get_path(b, "ipv6"))
        .filter(|v| s(v, "mode") == v6_mode)
        .cloned();
    let ipv6 = match v6_mode.as_str() {
        "static" => json!({"mode": "static", "address": s(view, "ipv6_address")}),
        "dhcp6" | "slaac" | "track" => keep6.unwrap_or_else(|| match v6_mode.as_str() {
            "track" => json!({"mode": "track", "interface": "wan"}),
            m => json!({"mode": m}),
        }),
        _ => json!({"mode": "none"}),
    };
    o.insert("ipv6".into(), ipv6);
    item
}

/// View row → schema item, written over `base` (the stored item, if editing).
///
/// `doc` gives cross-references (peer names → UUIDs); `scope` fills scoped fields.
pub fn from_view(
    grid: GridId,
    doc: &Value,
    scope: &str,
    base: Option<&Value>,
    view: &Value,
) -> Value {
    let mut item = base.cloned().unwrap_or_else(|| json!({}));
    match grid {
        GridId::Assignments => return interface_from_view(base, view),
        GridId::Aliases => {
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            put(o, "name", view, "name");
            put_opt(o, "description", view, "description");
            let ty = s(view, "type");
            let lines = strings(view, "content");
            let mut content = base
                .and_then(|b| get_path(b, "content"))
                .filter(|c| s(c, "type") == ty)
                .cloned()
                .unwrap_or_else(|| json!({}));
            let c = obj(&mut content);
            let keep: &[&str] = match ty.as_str() {
                "host" | "network" | "port" => &["entries"],
                "url" => &["urls"],
                "url_table" => &["url", "refresh", "families"],
                "geo_ip" => &["countries", "families"],
                "network_group" => &["members"],
                "mac" => &["addresses"],
                _ => &[],
            };
            c.retain(|k, _| keep.contains(&k.as_str()));
            c.insert("type".into(), Value::String(ty.clone()));
            match ty.as_str() {
                "host" | "network" | "port" => drop(c.insert("entries".into(), lines)),
                "url" => drop(c.insert("urls".into(), lines)),
                "url_table" => {
                    let first = lines
                        .as_array()
                        .and_then(|l| l.first())
                        .cloned()
                        .unwrap_or(json!(""));
                    c.insert("url".into(), first);
                }
                "geo_ip" => drop(c.insert("countries".into(), lines)),
                "network_group" => drop(c.insert("members".into(), lines)),
                "mac" => drop(c.insert("addresses".into(), lines)),
                _ => {}
            }
            o.insert("content".into(), content);
        }
        GridId::FilterRules => {
            let (bs, bd) = (
                base.and_then(|b| get_path(b, "source")),
                base.and_then(|b| get_path(b, "destination")),
            );
            let chosen = s(view, "interface");
            let ifs =
                rule_interfaces_from_view(base, if chosen.is_empty() { scope } else { &chosen });
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            put(o, "action", view, "action");
            put(o, "quick", view, "quick");
            o.insert("interfaces".into(), ifs);
            put(o, "direction", view, "direction");
            put(o, "ip_protocol", view, "ipprotocol");
            put(o, "protocol", view, "protocol");
            o.insert(
                "source".into(),
                endpoint_from_view(bs, &s(view, "source"), &s(view, "source_port")),
            );
            o.insert(
                "destination".into(),
                endpoint_from_view(bd, &s(view, "destination"), &s(view, "destination_port")),
            );
            put(o, "log", view, "log");
            put_opt(o, "description", view, "description");
        }
        GridId::SourceNat => {
            let (bs, bd) = (
                base.and_then(|b| get_path(b, "source")),
                base.and_then(|b| get_path(b, "destination")),
            );
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            put(o, "no_nat", view, "nonat");
            put(o, "interface", view, "interface");
            put(o, "protocol", view, "protocol");
            o.insert(
                "source".into(),
                endpoint_from_view(bs, &s(view, "source"), ""),
            );
            o.insert(
                "destination".into(),
                endpoint_from_view(bd, &s(view, "destination"), ""),
            );
            put_opt(o, "target", view, "target");
            put_opt(o, "description", view, "description");
        }
        GridId::PortForwards => {
            let bd = base.and_then(|b| get_path(b, "destination"));
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            o.insert("interfaces".into(), json!([s(view, "interface")]));
            put(o, "protocol", view, "protocol");
            o.insert(
                "destination".into(),
                endpoint_from_view(bd, &s(view, "destination"), &s(view, "destination_port")),
            );
            put(o, "target", view, "target");
            put_opt(o, "target_port", view, "target_port");
            put_opt(o, "description", view, "description");
        }
        GridId::DhcpRanges => {
            item = Value::String(format!("{}-{}", s(view, "from"), s(view, "to")));
        }
        GridId::StaticMaps => {
            let o = obj(&mut item);
            if !o.contains_key("subnet") {
                o.insert(
                    "subnet".into(),
                    Value::String(subnet_for(doc, scope).unwrap_or_default()),
                );
            }
            o.insert("client".into(), json!({"hw_address": s(view, "mac")}));
            put_opt(o, "ip_address", view, "ipaddr");
            put_opt(o, "hostname", view, "hostname");
            put_opt(o, "description", view, "description");
        }
        GridId::HostOverrides => {
            let rr = s(view, "rr");
            let record = match rr.as_str() {
                "A" | "AAAA" => json!({"rr": rr, "address": s(view, "server")}),
                "MX" => {
                    json!({"rr": "MX", "priority": get_path(view, "mxprio").cloned().unwrap_or(json!(10)), "host": s(view, "mx")})
                }
                _ => json!({"rr": "TXT", "data": s(view, "server")}),
            };
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            put(o, "hostname", view, "hostname");
            put(o, "domain", view, "domain");
            o.insert("record".into(), record);
            put_opt(o, "description", view, "description");
        }
        GridId::WgInstances => {
            let peers = get_path(doc, "wireguard.peers")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let uuids: Vec<Value> = strings(view, "peers")
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|name| {
                    peers
                        .iter()
                        .find(|(_, p)| s(p, "name") == name)
                        .map_or_else(
                            || Value::String(name.to_owned()),
                            |(k, _)| Value::String(k.clone()),
                        )
                })
                .collect();
            let next_instance = get_path(doc, "wireguard.servers")
                .and_then(Value::as_object)
                .map_or(0, |m| {
                    m.values()
                        .filter_map(|v| v.get("instance").and_then(Value::as_u64))
                        .max()
                        .map_or(0, |n| n + 1)
                });
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            put(o, "name", view, "name");
            match get_path(view, "instance") {
                Some(Value::Number(n)) => {
                    drop(o.insert("instance".into(), Value::Number(n.clone())))
                }
                _ if !o.contains_key("instance") => {
                    drop(o.insert("instance".into(), json!(next_instance)))
                }
                _ => {}
            }
            put_opt(o, "public_key", view, "pubkey");
            // An empty secret keeps whatever the stored item holds (the backend's
            // redaction marker reads back as "unchanged").
            let key = s(view, "privkey");
            if !key.is_empty() {
                o.insert("private_key".into(), Value::String(key));
            }
            put_port(o, "listen_port", view, "port");
            put_opt(o, "mtu", view, "mtu");
            put_list(o, "tunnel_addresses", view, "tunneladdress");
            put_list(o, "dns", view, "dns");
            put(o, "disable_routes", view, "disableroutes");
            o.insert("peers".into(), Value::Array(uuids));
        }
        GridId::WgPeers => {
            let o = obj(&mut item);
            put(o, "enabled", view, "enabled");
            put(o, "name", view, "name");
            put(o, "public_key", view, "pubkey");
            let psk = s(view, "psk");
            if !psk.is_empty() {
                o.insert("preshared_key".into(), Value::String(psk));
            }
            put_list(o, "allowed_ips", view, "tunneladdress");
            put_opt(o, "endpoint", view, "serveraddress");
            put_port(o, "endpoint_port", view, "serverport");
            put_opt(o, "keepalive", view, "keepalive");
        }
    }
    item
}

/// Fills computed, read-only view columns that need the whole document.
pub fn decorate(grid: GridId, doc: &Value, key: &str, row: &mut Value) {
    if grid == GridId::WgPeers {
        let names: Vec<Value> = get_path(doc, "wireguard.servers")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, srv)| arr(srv, "peers").iter().any(|p| p.as_str() == Some(key)))
            .map(|(_, srv)| Value::String(s(srv, "name")))
            .collect();
        row["servers"] = Value::Array(names);
    }
}

/// Schema field (relative to the item) → view field.
pub fn view_path(grid: GridId, schema: &str) -> Option<&'static str> {
    let first = schema.split('.').next().unwrap_or(schema);
    let map: &[(&str, &'static str)] = match grid {
        GridId::Assignments => &[
            ("device", "device"),
            ("description", "description"),
            ("mtu", "mtu"),
            ("ipv4.address", "ipv4_address"),
            ("ipv4.gateway", "ipv4_gateway"),
            ("ipv4", "ipv4_type"),
            ("ipv6.address", "ipv6_address"),
            ("ipv6", "ipv6_type"),
        ],
        GridId::Aliases => &[
            ("name", "name"),
            ("content", "content"),
            ("description", "description"),
        ],
        GridId::FilterRules => &[
            ("source.port", "source_port"),
            ("source", "source"),
            ("destination.port", "destination_port"),
            ("destination", "destination"),
            ("interfaces", "interface"),
            ("ip_protocol", "ipprotocol"),
            ("protocol", "protocol"),
            ("description", "description"),
        ],
        GridId::SourceNat => &[
            ("source", "source"),
            ("destination", "destination"),
            ("target", "target"),
            ("interface", "interface"),
            ("protocol", "protocol"),
        ],
        GridId::PortForwards => &[
            ("destination.port", "destination_port"),
            ("destination", "destination"),
            ("target_port", "target_port"),
            ("target", "target"),
            ("interfaces", "interface"),
            ("protocol", "protocol"),
        ],
        GridId::DhcpRanges => &[],
        GridId::StaticMaps => &[
            ("client", "mac"),
            ("ip_address", "ipaddr"),
            ("hostname", "hostname"),
        ],
        GridId::HostOverrides => &[
            ("record.host", "mx"),
            ("record.priority", "mxprio"),
            ("record", "server"),
            ("hostname", "hostname"),
            ("domain", "domain"),
        ],
        GridId::WgInstances => &[
            ("public_key", "pubkey"),
            ("private_key", "privkey"),
            ("listen_port", "port"),
            ("tunnel_addresses", "tunneladdress"),
            ("name", "name"),
            ("dns", "dns"),
            ("peers", "peers"),
            ("mtu", "mtu"),
        ],
        GridId::WgPeers => &[
            ("public_key", "pubkey"),
            ("preshared_key", "psk"),
            ("allowed_ips", "tunneladdress"),
            ("endpoint_port", "serverport"),
            ("endpoint", "serveraddress"),
            ("name", "name"),
        ],
    };
    map.iter()
        .find(|(k, _)| {
            schema == *k
                || schema.starts_with(&format!("{k}."))
                || schema.starts_with(&format!("{k}["))
        })
        .or_else(|| map.iter().find(|(k, _)| *k == first))
        .map(|(_, v)| *v)
}

/// Settings form: schema section(s) → view.
pub fn form_to_view(form: FormId, doc: &Value, scope: &str) -> Option<Value> {
    Some(match form {
        FormId::SystemGeneral => {
            let sys = get_path(doc, "system")?;
            json!({
                "hostname": s(sys, "hostname"),
                "domain": s(sys, "domain"),
                "timezone": s(sys, "timezone"),
                "dns_servers": strings(sys, "dns_servers"),
                "dns_allow_override": b(sys, "dns_allow_override", true),
                "ipv6_allow": b(sys, "ipv6_allow", true),
            })
        }
        FormId::Interface => {
            let item = get_path(doc, "interfaces")?.get(scope)?;
            let mut v = interface_to_view(item);
            v["id"] = Value::String(scope.to_owned());
            v
        }
        FormId::SourceNatMode => json!({"mode": s(doc, "nat.outbound.mode")}),
        FormId::DhcpSettings => {
            let dhcp = get_path(doc, "dhcpv4").cloned().unwrap_or(Value::Null);
            let sub = subnet_for(doc, scope)
                .and_then(|k| get_path(&dhcp, &format!("subnets.{k}")).cloned());
            let served = b(&dhcp, "enabled", false)
                && arr(&dhcp, "interfaces")
                    .iter()
                    .any(|i| i.as_str() == Some(scope));
            let sub = sub.unwrap_or(Value::Null);
            json!({
                "enabled": served,
                "subnet": s(&sub, "subnet"),
                "dns_servers": strings(&sub, "options.dns_servers"),
                "gateway": arr(&sub, "options.routers").first().and_then(Value::as_str).unwrap_or_default(),
                "domain": s(&sub, "options.domain_name"),
                "lease": get_path(&sub, "valid_lifetime").or_else(|| get_path(&dhcp, "valid_lifetime")).cloned().unwrap_or(Value::Null),
            })
        }
        FormId::UnboundGeneral => {
            let dns = get_path(doc, "dns")?;
            json!({
                "enabled": b(dns, "enabled", false),
                "port": match port_num(dns, "port") { Value::Null => json!(53), p => p },
                "interfaces": strings(dns, "listen_interfaces"),
                "dnssec": b(dns, "dnssec", false),
                "register_dhcp_leases": b(dns, "register_dhcp_leases", false),
                "register_dhcp_static": b(dns, "register_dhcp_static", false),
                "local_zone_type": s(dns, "local_zone_type"),
            })
        }
    })
}

/// Settings form: writes the view into `doc`. Returns the top-level sections touched.
pub fn form_from_view(
    form: FormId,
    doc: &mut Value,
    scope: &str,
    view: &Value,
) -> Result<Vec<&'static str>, Vec<FieldError>> {
    let root = obj(doc);
    match form {
        FormId::SystemGeneral => {
            let sys = obj(root.entry("system").or_insert_with(|| json!({})));
            for k in [
                "hostname",
                "domain",
                "timezone",
                "dns_allow_override",
                "ipv6_allow",
            ] {
                put(sys, k, view, k);
            }
            put_list(sys, "dns_servers", view, "dns_servers");
            Ok(vec!["system"])
        }
        FormId::Interface => {
            let ifs = obj(root.entry("interfaces").or_insert_with(|| json!({})));
            let base = ifs.get(scope).cloned();
            let Some(base) = base else {
                return Err(vec![FieldError::new(
                    "",
                    format!("Interface {scope} does not exist."),
                )]);
            };
            ifs.insert(scope.to_owned(), interface_from_view(Some(&base), view));
            Ok(vec!["interfaces"])
        }
        FormId::SourceNatMode => {
            let nat = obj(root.entry("nat").or_insert_with(|| json!({})));
            let out = obj(nat.entry("outbound").or_insert_with(|| json!({})));
            put(out, "mode", view, "mode");
            Ok(vec!["nat"])
        }
        FormId::DhcpSettings => {
            let iface_net = get_path(
                &Value::Object(root.clone()),
                &format!("interfaces.{scope}.ipv4.address"),
            )
            .and_then(Value::as_str)
            .map(str::to_owned);
            let existing = subnet_for(&Value::Object(root.clone()), scope);
            let dhcp = obj(root.entry("dhcpv4").or_insert_with(|| json!({})));
            let enabled = b(view, "enabled", false);
            let mut ifs: Vec<Value> = arr(&Value::Object(dhcp.clone()), "interfaces")
                .into_iter()
                .filter(|i| i.as_str() != Some(scope))
                .collect();
            if enabled {
                ifs.push(Value::String(scope.to_owned()));
                dhcp.insert("enabled".into(), Value::Bool(true));
            }
            dhcp.insert("interfaces".into(), Value::Array(ifs));
            let subnets = obj(dhcp.entry("subnets").or_insert_with(|| json!({})));
            let key = match existing {
                Some(k) => k,
                None => {
                    let Some(net) = iface_net.as_deref().and_then(network_of) else {
                        return Err(vec![FieldError::new(
                            "enabled",
                            "This interface needs a static IPv4 address before it can serve DHCP.",
                        )]);
                    };
                    let k = crate::models::new_uuid();
                    subnets.insert(
                        k.clone(),
                        json!({"subnet": net, "interface": scope, "pools": []}),
                    );
                    k
                }
            };
            let sub = obj(subnets.get_mut(&key).expect("just ensured"));
            let opts = obj(sub.entry("options").or_insert_with(|| json!({})));
            put_list(opts, "dns_servers", view, "dns_servers");
            match s(view, "gateway").as_str() {
                "" => drop(opts.remove("routers")),
                gw => drop(opts.insert("routers".into(), json!([gw]))),
            }
            put_opt(opts, "domain_name", view, "domain");
            put_opt(sub, "valid_lifetime", view, "lease");
            Ok(vec!["dhcpv4"])
        }
        FormId::UnboundGeneral => {
            let dns = obj(root.entry("dns").or_insert_with(|| json!({})));
            for k in [
                "enabled",
                "dnssec",
                "register_dhcp_leases",
                "register_dhcp_static",
                "local_zone_type",
            ] {
                put(dns, k, view, k);
            }
            put_port(dns, "port", view, "port");
            put_list(dns, "listen_interfaces", view, "interfaces");
            Ok(vec!["dns"])
        }
    }
}

/// `192.168.1.1/24` → `192.168.1.0/24`.
fn network_of(cidr: &str) -> Option<String> {
    let (addr, len) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = addr.parse().ok()?;
    let len: u32 = len.parse().ok().filter(|l| *l <= 32)?;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some(format!(
        "{}/{len}",
        std::net::Ipv4Addr::from(u32::from(ip) & mask)
    ))
}

/// Schema path (relative to the form's section) → view field, for settings forms.
pub fn form_view_path(form: FormId, schema: &str) -> Option<&'static str> {
    let map: &[(&str, &'static str)] = match form {
        FormId::SystemGeneral => &[
            ("system.hostname", "hostname"),
            ("system.domain", "domain"),
            ("system.timezone", "timezone"),
            ("system.dns_servers", "dns_servers"),
        ],
        FormId::Interface => &[],
        FormId::SourceNatMode => &[("nat.outbound.mode", "mode")],
        FormId::DhcpSettings => &[
            ("options.dns_servers", "dns_servers"),
            ("options.routers", "gateway"),
            ("options.domain_name", "domain"),
            ("valid_lifetime", "lease"),
        ],
        FormId::UnboundGeneral => &[
            ("dns.port", "port"),
            ("dns.listen_interfaces", "interfaces"),
            ("dns.local_zone_type", "local_zone_type"),
        ],
    };
    map.iter()
        .find(|(k, _)| schema == *k || schema.starts_with(&format!("{k}.")) || schema.ends_with(k))
        .map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_round_trip() {
        let ep = endpoint_from_view(None, "!alias:nas", "web_ports");
        assert_eq!(
            ep,
            json!({"net": "alias:nas", "not": true, "port": "web_ports"})
        );
        assert_eq!(
            endpoint_to_view(&ep),
            ("!alias:nas".into(), "web_ports".into())
        );
        assert_eq!(
            endpoint_from_view(None, "", "any"),
            json!({"net": "any", "not": false})
        );
    }

    #[test]
    fn rule_scope_is_floating_unless_exactly_one_interface() {
        assert_eq!(
            rule_scope(&json!({"interfaces": ["lan"]}), "interfaces"),
            "lan"
        );
        assert_eq!(
            rule_scope(&json!({"interfaces": []}), "interfaces"),
            "floating"
        );
        assert_eq!(
            rule_scope(&json!({"interfaces": ["lan", "wan"]}), "interfaces"),
            "floating"
        );
        let multi = json!({"interfaces": ["lan", "wan"]});
        assert_eq!(
            rule_interfaces_from_view(Some(&multi), "floating"),
            json!(["lan", "wan"])
        );
    }

    #[test]
    fn alias_type_change_drops_old_content_keys() {
        let base = json!({"name": "x", "content": {"type": "url_table", "url": "https://a/b", "refresh": {"days": 1, "hours": 0}}});
        let view = json!({"enabled": true, "name": "x", "type": "host", "content": ["10.0.0.1"], "description": ""});
        let item = from_view(GridId::Aliases, &json!({}), "", Some(&base), &view);
        assert_eq!(
            item["content"],
            json!({"type": "host", "entries": ["10.0.0.1"]})
        );
        assert!(
            item.get("description").is_none(),
            "empty optional fields are omitted"
        );
    }

    #[test]
    fn view_paths_map_nested_schema_fields() {
        assert_eq!(
            view_path(GridId::FilterRules, "source.port"),
            Some("source_port")
        );
        assert_eq!(view_path(GridId::FilterRules, "source.net"), Some("source"));
        assert_eq!(
            view_path(GridId::Aliases, "content.entries[1]"),
            Some("content")
        );
        assert_eq!(
            view_path(GridId::HostOverrides, "record.address"),
            Some("server")
        );
    }

    #[test]
    fn networks() {
        assert_eq!(
            network_of("192.168.1.1/24").as_deref(),
            Some("192.168.1.0/24")
        );
        assert_eq!(network_of("10.1.2.3/8").as_deref(), Some("10.0.0.0/8"));
    }
}
