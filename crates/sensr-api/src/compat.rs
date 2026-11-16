//! OPNsense API compatibility façade (skeleton): the read endpoints the
//! routing slice can serve, in OPNsense's response shapes, so existing
//! scripts and the Terraform provider can read a sensr box.
//!
//! - `core/firmware/info` (FirmwareController::infoAction)
//! - `interfaces/overview/interfaces_info` (OverviewController::interfacesInfoAction)
//! - `firewall/alias/search_item` (AliasController::searchItemAction)
//!
//! Recordset endpoints return `{total, rowCount, current, rows}` and honour
//! `current`, `rowCount` (-1 = all) and `searchPhrase` like
//! `ApiControllerBase::searchRecordsetBase`.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use sensr_ipc::{ConfigPath, Op, Response, Source};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Caller;
use crate::error::ApiError;

/// Paging and search parameters of OPNsense grids.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchParams {
    current: Option<i64>,
    row_count: Option<i64>,
    search_phrase: Option<String>,
}

impl SearchParams {
    fn merge(self, body: Option<SearchParams>) -> SearchParams {
        match body {
            Some(b) => SearchParams {
                current: b.current.or(self.current),
                row_count: b.row_count.or(self.row_count),
                search_phrase: b.search_phrase.or(self.search_phrase),
            },
            None => self,
        }
    }
}

fn flatten_text(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Array(a) => a.iter().for_each(|v| flatten_text(v, out)),
        Value::Object(m) => m.values().for_each(|v| flatten_text(v, out)),
        Value::Null => {}
        other => {
            out.push_str(&other.to_string());
            out.push(' ');
        }
    }
}

/// `searchRecordsetBase`: every whitespace-separated clause must occur
/// (case-insensitively) in some field; then page.
pub fn recordset(rows: Vec<Value>, p: &SearchParams) -> Value {
    let clauses: Vec<String> = p
        .search_phrase
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let matching: Vec<Value> = rows
        .into_iter()
        .filter(|row| {
            let mut hay = String::new();
            flatten_text(row, &mut hay);
            let hay = hay.to_lowercase();
            clauses.iter().all(|c| hay.contains(c.as_str()))
        })
        .collect();
    let total = matching.len() as i64;
    let row_count = match p.row_count.unwrap_or(9999) {
        -1 => total.max(1),
        n if n < 1 => 9999,
        n => n,
    };
    let current = p.current.unwrap_or(1).max(1);
    let offset = ((current - 1) * row_count).clamp(0, total) as usize;
    let page: Vec<Value> = matching
        .into_iter()
        .skip(offset)
        .take(row_count as usize)
        .collect();
    json!({"total": total, "rowCount": page.len(), "current": current, "rows": page})
}

async fn section(
    state: &AppState,
    caller: &Caller,
    path: &str,
    source: Source,
) -> Result<Value, ApiError> {
    let path: ConfigPath = path
        .parse()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "bad section path"))?;
    match state
        .agent
        .call(caller.principal(), Op::ConfigGet { path, source })
        .await?
    {
        Response::Value(v) => Ok(v.unwrap_or(Value::Null)),
        other => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("unexpected reply {other:?}"),
        )),
    }
}

fn s(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn list(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other.clone()],
    }
}

/// `GET /api/core/firmware/info`.
pub async fn firmware_info() -> Json<Value> {
    let version = env!("CARGO_PKG_VERSION");
    Json(json!({
        "product_id": "sensr",
        "product_version": version,
        "package": [],
        "plugin": [],
        "changelog": [],
        "product": {
            "product_id": "sensr",
            "product_name": "sensr",
            "product_version": version,
            "product_arch": std::env::consts::ARCH,
            "product_series": version.rsplit_once('.').map_or(version, |(a, _)| a),
            "product_nickname": "",
            "product_copyright_owner": "sensr contributors",
            "product_website": "https://github.com/itpick/sensr",
        },
    }))
}

/// `GET|POST /api/interfaces/overview/interfaces_info` from the applied
/// document (what is running, not what is staged).
pub async fn interfaces_info(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<SearchParams>,
    body: Option<Json<SearchParams>>,
) -> Result<Json<Value>, ApiError> {
    let ifaces = section(&state, &caller, "interfaces", Source::Applied).await?;
    let rows = ifaces
        .as_object()
        .map(|m| m.iter().map(|(id, i)| interface_row(id, i)).collect())
        .unwrap_or_default();
    Ok(Json(recordset(rows, &q.merge(body.map(|Json(b)| b)))))
}

/// One `interfaces_info` row from a typed interface.
fn interface_row(id: &str, i: &Value) -> Value {
    let enabled = i.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let descr = s(i.get("description"));
    let v4 = i.get("ipv4");
    let v6 = i.get("ipv6");
    let mode = |v: Option<&Value>| s(v.and_then(|v| v.get("mode")));
    let static_addr = |v: Option<&Value>| {
        (mode(v) == "static")
            .then(|| s(v.and_then(|v| v.get("address"))))
            .filter(|a| !a.is_empty())
    };
    let addrs = |v: Option<&Value>| match static_addr(v) {
        Some(a) => json!([{"ipaddr": a}]),
        None => json!([]),
    };
    json!({
        "identifier": id,
        "device": s(i.get("device")),
        "description": if descr.is_empty() { id.to_uppercase() } else { descr },
        "enabled": enabled,
        "status": if enabled { "up" } else { "down" },
        "link_type": match mode(v4).as_str() {
            "" => "none".to_owned(),
            m => m.to_owned(),
        },
        "macaddr": s(i.get("spoof_mac").or_else(|| i.get("match_mac"))),
        "ipv4": addrs(v4),
        "ipv6": addrs(v6),
        "gateways": [],
        "routes": [],
    })
}

/// OPNsense's alias type names for the schema's content tags.
fn opnsense_alias_type(tag: &str) -> &str {
    match tag {
        "url_table" => "urltable",
        "geo_ip" => "geoip",
        "network_group" => "networkgroup",
        other => other,
    }
}

/// The content entries of a typed alias, as OPNsense lists them.
fn alias_content(c: Option<&Value>) -> Vec<String> {
    let Some(c) = c else { return Vec::new() };
    let field = ["entries", "urls", "countries", "members", "addresses"]
        .iter()
        .find_map(|k| c.get(*k));
    match (field, c.get("url")) {
        (Some(v), _) => list(Some(v)).iter().map(|e| s(Some(e))).collect(),
        (None, Some(u)) => vec![s(Some(u))],
        (None, None) => Vec::new(),
    }
}

/// `GET|POST /api/firewall/alias/search_item`.
pub async fn alias_search(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<SearchParams>,
    body: Option<Json<SearchParams>>,
) -> Result<Json<Value>, ApiError> {
    let aliases = section(&state, &caller, "firewall.aliases", Source::Head).await?;
    let rows = aliases
        .as_object()
        .into_iter()
        .flatten()
        .map(|(uuid, a)| {
            let content = a.get("content");
            json!({
                "uuid": uuid,
                "enabled": if a.get("enabled").and_then(Value::as_bool).unwrap_or(true) { "1" } else { "0" },
                "name": s(a.get("name")),
                "type": opnsense_alias_type(&s(content.and_then(|c| c.get("type")))),
                "description": s(a.get("description")),
                // OPNsense shows multi-value content comma-separated in the grid.
                "content": alias_content(content).join(","),
                "categories": "",
            })
        })
        .collect();
    Ok(Json(recordset(rows, &q.merge(body.map(|Json(b)| b)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(n: usize) -> Vec<Value> {
        (0..n)
            .map(|i| json!({"name": format!("alias{i}"), "type": "host"}))
            .collect()
    }

    #[test]
    fn gateway_widget_shape() {
        let view = json!({"gateways": [
            {"name": "WAN_DHCP", "next_hop": "192.0.2.1", "status_text": "none", "latency_ms": 4.25, "stddev_ms": 0.5, "loss_pct": 0.0, "active_default": true},
            {"name": "WAN_DHCP6", "next_hop": null, "status_text": "down"}
        ]});
        let v = gateway_items(&view);
        assert_eq!(v["items"][0]["status_translated"], "Online");
        assert_eq!(v["items"][0]["delay"], "4.2 ms");
        assert_eq!(v["items"][1]["status_translated"], "Offline");
        assert_eq!(v["items"][1]["loss"], "~");
    }

    #[test]
    fn paging_and_search() {
        let all = recordset(rows(25), &SearchParams::default());
        assert_eq!(
            (all["total"].as_i64(), all["rowCount"].as_i64()),
            (Some(25), Some(25))
        );
        let p = SearchParams {
            current: Some(3),
            row_count: Some(10),
            search_phrase: None,
        };
        let page = recordset(rows(25), &p);
        assert_eq!(page["rowCount"], 5);
        assert_eq!(page["rows"][0]["name"], "alias20");
        let p = SearchParams {
            search_phrase: Some("ALIAS1 host".into()),
            ..SearchParams::default()
        };
        // alias1, alias10..alias19
        assert_eq!(recordset(rows(25), &p)["total"], 11);
        let p = SearchParams {
            row_count: Some(-1),
            ..SearchParams::default()
        };
        assert_eq!(recordset(rows(3), &p)["rowCount"], 3);
    }
}

/// `GET /api/routes/gateway/status` (dashboard Gateways widget): OPNsense's
/// shape, `{"items": [{name, address, status, status_translated, loss,
/// delay, stddev, monitor}], "status": "ok"}`.
pub async fn gateway_status(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<Value>, ApiError> {
    let op = Op::Runtime {
        section: sensr_ipc::RuntimeSection::Gateways,
    };
    let v = match crate::native::call(&state, &caller, op).await? {
        Response::Value(v) => v.unwrap_or(Value::Null),
        _ => Value::Null,
    };
    Ok(Json(gateway_items(&v)))
}

/// The native gateways view in OPNsense's widget shape.
pub fn gateway_items(view: &Value) -> Value {
    let fmt = |v: Option<f64>, unit: &str| match v {
        Some(x) => format!("{x:.1} {unit}"),
        None => "~".to_owned(),
    };
    let items: Vec<Value> = view
        .get("gateways")
        .and_then(Value::as_array)
        .map(|gs| {
            gs.iter()
                .map(|g| {
                    let text = g.get("status_text").and_then(Value::as_str).unwrap_or("down");
                    let translated = match text {
                        "none" => "Online",
                        "delay" => "Latency",
                        "loss" => "Packetloss",
                        "delay+loss" => "Latency, Packetloss",
                        "force_down" => "Offline (forced)",
                        _ => "Offline",
                    };
                    json!({
                        "name": g.get("name"),
                        "address": g.get("next_hop").cloned().unwrap_or(json!("~")),
                        "monitor": g.get("monitor_address").cloned().unwrap_or_else(|| g.get("next_hop").cloned().unwrap_or(json!("~"))),
                        "status": text,
                        "status_translated": translated,
                        "loss": fmt(g.get("loss_pct").and_then(Value::as_f64), "%"),
                        "delay": fmt(g.get("latency_ms").and_then(Value::as_f64), "ms"),
                        "stddev": fmt(g.get("stddev_ms").and_then(Value::as_f64), "ms"),
                        "defaultgw": g.get("active_default").cloned().unwrap_or(json!(false)),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({"items": items, "status": "ok"})
}
