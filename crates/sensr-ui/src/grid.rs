//! Grid metadata and the pure list operations behind `<Grid<T>>`: search, sort, paging,
//! bulk enable/disable, delete and reorder.
//!
//! The server runs these over the list it reads from the backend, so the browser only ever
//! holds one page (10k rules stay fast).

use crate::form::{FormModel, get_path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;

/// How a column renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    /// Plain text.
    Text,
    /// Boolean shown as an on/off marker.
    Bool,
    /// Array shown comma-separated.
    List,
    /// Address selector (`any`, `net:lan`, `alias:x`, `!…`) shown the OPNsense way.
    Endpoint,
    /// Port or port alias; empty means any.
    Port,
    /// Run-time state: a string, or `{text, tone, badge, title}` where a `tone` of `bad`
    /// adds a red `badge` whose tooltip is `title` (e.g. a feed's last error).
    Status,
}

/// One grid column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    /// Field path in the row.
    pub path: &'static str,
    /// Header label.
    pub label: &'static str,
    /// Rendering.
    pub kind: ColumnKind,
}

impl Column {
    /// A text column.
    pub const fn text(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            label,
            kind: ColumnKind::Text,
        }
    }
    /// A boolean column.
    pub const fn bool(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            label,
            kind: ColumnKind::Bool,
        }
    }
    /// A list column.
    pub const fn list(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            label,
            kind: ColumnKind::List,
        }
    }
    /// An address-selector column.
    pub const fn endpoint(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            label,
            kind: ColumnKind::Endpoint,
        }
    }
    /// A run-time status column (not editable, filled by the server).
    pub const fn status(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            label,
            kind: ColumnKind::Status,
        }
    }
    /// A port column.
    pub const fn port(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            label,
            kind: ColumnKind::Port,
        }
    }
}

/// A row type shown in a grid and edited in its dialog.
pub trait GridModel: FormModel {
    /// Field that identifies a row.
    const KEY: &'static str = "uuid";
    /// Boolean field driven by the bulk enable/disable buttons.
    const TOGGLE: Option<&'static str> = Some("enabled");
    /// List order is meaningful (rules) and rows can be dragged.
    const ORDERED: bool = false;
    /// Columns in display order.
    fn columns() -> &'static [Column];
}

/// Sort direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDir {
    /// Ascending.
    #[default]
    Asc,
    /// Descending.
    Desc,
}

/// What the browser asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridQuery {
    /// Case-insensitive substring over all columns.
    pub search: String,
    /// Column path and direction; `None` keeps list order.
    pub sort: Option<(String, SortDir)>,
    /// Zero-based page.
    pub page: usize,
    /// Rows per page.
    pub per_page: usize,
}

impl Default for GridQuery {
    fn default() -> Self {
        Self {
            search: String::new(),
            sort: None,
            page: 0,
            per_page: 25,
        }
    }
}

impl GridQuery {
    /// Reordering only makes sense on the unfiltered list in list order.
    pub fn is_natural_order(&self) -> bool {
        self.sort.is_none() && self.search.trim().is_empty()
    }
}

/// One page of rows.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GridPage {
    /// Rows on this page.
    pub rows: Vec<Value>,
    /// Rows matching the search, across all pages.
    pub total: usize,
    /// The page actually returned (clamped).
    pub page: usize,
    /// Rows per page.
    pub per_page: usize,
}

impl GridPage {
    /// Number of pages (at least one).
    pub fn pages(&self) -> usize {
        self.total.div_ceil(self.per_page.max(1)).max(1)
    }
}

/// `net:lan` → `LAN net`, `addr:wan` → `WAN address`, `alias:x` → `x`, `any` → `*`.
pub fn pretty_endpoint(raw: &str) -> String {
    let (not, rest) = match raw.strip_prefix('!') {
        Some(r) => ("! ", r),
        None => ("", raw),
    };
    let body = match rest {
        "" | "any" => "*".to_owned(),
        "self" | "(self)" => "This Firewall".to_owned(),
        _ => match rest.split_once(':') {
            Some(("net", i)) => format!("{} net", i.to_uppercase()),
            Some(("addr", i)) => format!("{} address", i.to_uppercase()),
            Some(("alias", a)) => a.to_owned(),
            _ => rest.to_owned(),
        },
    };
    format!("{not}{body}")
}

/// Text of a cell as displayed and searched.
pub fn cell_text(row: &Value, col: &Column) -> String {
    if matches!(col.kind, ColumnKind::Endpoint | ColumnKind::Port) {
        let raw = get_path(row, col.path)
            .and_then(Value::as_str)
            .unwrap_or_default();
        return pretty_endpoint(raw);
    }
    if col.kind == ColumnKind::Status
        && let Some(Value::Object(o)) = get_path(row, col.path)
    {
        return o
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
    }
    match get_path(row, col.path) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => if *b { "yes" } else { "no" }.to_owned(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Some(other) => other.to_string(),
    }
}

fn compare(a: &Value, b: &Value, col: &Column) -> Ordering {
    match (get_path(a, col.path), get_path(b, col.path)) {
        (Some(Value::Number(x)), Some(Value::Number(y))) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        _ => {
            let (x, y) = (cell_text(a, col), cell_text(b, col));
            x.to_lowercase().cmp(&y.to_lowercase()).then(x.cmp(&y))
        }
    }
}

/// Runs search, sort and paging over `rows`.
pub fn run_query(rows: &[Value], columns: &[Column], q: &GridQuery) -> GridPage {
    let needle = q.search.trim().to_lowercase();
    let mut hits: Vec<&Value> = rows
        .iter()
        .filter(|r| {
            needle.is_empty()
                || columns
                    .iter()
                    .any(|c| cell_text(r, c).to_lowercase().contains(&needle))
        })
        .collect();
    if let Some((path, dir)) = &q.sort
        && let Some(col) = columns.iter().find(|c| c.path == path)
    {
        // Stable sort keeps rule order among equal keys.
        hits.sort_by(|a, b| {
            let o = compare(a, b, col);
            if *dir == SortDir::Desc {
                o.reverse()
            } else {
                o
            }
        });
    }
    let per_page = q.per_page.clamp(1, 500);
    let total = hits.len();
    let last = total.saturating_sub(1) / per_page;
    let page = q.page.min(last);
    let rows = hits
        .into_iter()
        .skip(page * per_page)
        .take(per_page)
        .cloned()
        .collect();
    GridPage {
        rows,
        total,
        page,
        per_page,
    }
}

fn key_of<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}

/// Sets `field` to `enabled` on every row whose key is in `keys`; returns how many changed.
pub fn set_enabled(
    rows: &mut [Value],
    key: &str,
    field: &str,
    keys: &[String],
    enabled: bool,
) -> usize {
    let mut n = 0;
    for row in rows.iter_mut() {
        if key_of(row, key).is_some_and(|k| keys.iter().any(|x| x == k))
            && let Some(obj) = row.as_object_mut()
            && obj.get(field) != Some(&Value::Bool(enabled))
        {
            obj.insert(field.to_owned(), Value::Bool(enabled));
            n += 1;
        }
    }
    n
}

/// Removes every row whose key is in `keys`; returns how many were removed.
pub fn delete(rows: &mut Vec<Value>, key: &str, keys: &[String]) -> usize {
    let before = rows.len();
    rows.retain(|r| !key_of(r, key).is_some_and(|k| keys.iter().any(|x| x == k)));
    before - rows.len()
}

/// Moves the row `moving` so it sits directly before `before` (or last when `None`).
///
/// Only rows passing `visible` count as neighbours, so moving a LAN rule above another LAN
/// rule never reorders it relative to WAN rules stored in between. Returns false if a key is
/// unknown.
pub fn move_before(
    rows: &mut Vec<Value>,
    key: &str,
    moving: &str,
    before: Option<&str>,
    visible: impl Fn(&Value) -> bool,
) -> bool {
    let Some(from) = rows.iter().position(|r| key_of(r, key) == Some(moving)) else {
        return false;
    };
    if before == Some(moving) {
        return true;
    }
    let item = rows.remove(from);
    let to = match before {
        Some(b) => match rows.iter().position(|r| key_of(r, key) == Some(b)) {
            Some(i) => i,
            None => {
                rows.insert(from, item);
                return false;
            }
        },
        None => rows
            .iter()
            .rposition(&visible)
            .map_or(rows.len(), |i| i + 1),
    };
    rows.insert(to, item);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const COLS: &[Column] = &[
        Column::bool("enabled", "Enabled"),
        Column::text("name", "Name"),
        Column::text("n", "N"),
    ];

    fn rows() -> Vec<Value> {
        (0..30)
            .map(|i| json!({"uuid": format!("u{i}"), "name": format!("host{:02}", 29 - i), "n": i, "enabled": i % 2 == 0, "if": if i < 15 {"lan"} else {"wan"}}))
            .collect()
    }

    #[test]
    fn endpoints_read_like_opnsense() {
        assert_eq!(pretty_endpoint("net:lan"), "LAN net");
        assert_eq!(pretty_endpoint("!addr:wan"), "! WAN address");
        assert_eq!(pretty_endpoint("alias:web_ports"), "web_ports");
        assert_eq!(pretty_endpoint(""), "*");
        assert_eq!(pretty_endpoint("10.0.0.0/8"), "10.0.0.0/8");
    }

    #[test]
    fn pages_and_clamps() {
        let r = rows();
        let p = run_query(
            &r,
            COLS,
            &GridQuery {
                page: 1,
                per_page: 25,
                ..Default::default()
            },
        );
        assert_eq!((p.total, p.rows.len(), p.pages()), (30, 5, 2));
        let p = run_query(
            &r,
            COLS,
            &GridQuery {
                page: 9,
                per_page: 25,
                ..Default::default()
            },
        );
        assert_eq!(p.page, 1, "out-of-range page clamps to the last");
    }

    #[test]
    fn searches_case_insensitively() {
        let p = run_query(
            &rows(),
            COLS,
            &GridQuery {
                search: "HOST0".into(),
                ..Default::default()
            },
        );
        assert_eq!(p.total, 10);
    }

    #[test]
    fn sorts_numbers_numerically_and_text_lexically() {
        let r = rows();
        let p = run_query(
            &r,
            COLS,
            &GridQuery {
                sort: Some(("n".into(), SortDir::Desc)),
                ..Default::default()
            },
        );
        assert_eq!(p.rows[0]["n"], 29);
        let p = run_query(
            &r,
            COLS,
            &GridQuery {
                sort: Some(("name".into(), SortDir::Asc)),
                ..Default::default()
            },
        );
        assert_eq!(p.rows[0]["name"], "host00");
    }

    #[test]
    fn bulk_toggle_and_delete() {
        let mut r = rows();
        let keys = vec!["u1".to_owned(), "u2".to_owned()];
        assert_eq!(set_enabled(&mut r, "uuid", "enabled", &keys, true), 1);
        assert_eq!(delete(&mut r, "uuid", &keys), 2);
        assert_eq!(r.len(), 28);
    }

    #[test]
    fn moves_within_visible_subset() {
        let mut r = rows();
        let lan = |v: &Value| v["if"] == "lan";
        assert!(move_before(&mut r, "uuid", "u5", Some("u0"), lan));
        assert_eq!(r[0]["uuid"], "u5");
        assert!(move_before(&mut r, "uuid", "u0", None, lan));
        // Last LAN position: right after u14, before the first WAN rule.
        let idx = r.iter().position(|v| v["uuid"] == "u0").unwrap();
        assert_eq!(r[idx + 1]["uuid"], "u15");
        assert!(!move_before(&mut r, "uuid", "nope", None, lan));
        assert_eq!(r.len(), 30);
    }
}
