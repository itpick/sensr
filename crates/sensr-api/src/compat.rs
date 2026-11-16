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
        .map(|m| {
            m.iter()
                .filter(|(k, _)| !k.contains('@'))
                .map(|(id, i)| {
                    let addr = s(i.get("ipaddr"));
                    let subnet = s(i.get("subnet"));
                    let static4 = addr.parse::<std::net::Ipv4Addr>().is_ok();
                    let descr = s(i.get("descr"));
                    json!({
                        "identifier": id,
                        "device": s(i.get("if")),
                        "description": if descr.is_empty() { id.to_uppercase() } else { descr },
                        "enabled": s(i.get("enable")) == "1",
                        "status": if s(i.get("enable")) == "1" { "up" } else { "down" },
                        "link_type": if static4 { "static".to_owned() } else { addr.clone() },
                        "ipv4": if static4 {
                            json!([{"ipaddr": format!("{addr}/{subnet}")}])
                        } else {
                            json!([])
                        },
                        "ipv6": [],
                        "gateways": [],
                        "routes": [],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(recordset(rows, &q.merge(body.map(|Json(b)| b)))))
}

/// `GET|POST /api/firewall/alias/search_item`.
pub async fn alias_search(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<SearchParams>,
    body: Option<Json<SearchParams>>,
) -> Result<Json<Value>, ApiError> {
    let aliases = section(
        &state,
        &caller,
        "OPNsense.Firewall.Alias.aliases",
        Source::Head,
    )
    .await?;
    let rows = list(aliases.get("alias"))
        .iter()
        .map(|a| {
            json!({
                "uuid": s(a.pointer("/@attributes/uuid")),
                "enabled": s(a.get("enabled")),
                "name": s(a.get("name")),
                "type": s(a.get("type")),
                "description": s(a.get("description")),
                // OPNsense stores multi-value content newline-separated and
                // shows it comma-separated in the grid.
                "content": s(a.get("content")).lines().collect::<Vec<_>>().join(","),
                "categories": s(a.get("categories")),
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
