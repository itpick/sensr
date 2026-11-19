//! Server functions, all under `/ui/fn/` so they never collide with the native API
//! (`/api/v1`) or the OPNsense compat paths (`/api/<module>/…`) sensr-api serves beside them.
//! They are the only calls the browser islands make. Each one runs on the server
//! against the [`crate::api::Backend`] in context, re-validating everything it receives.
//!
//! Grids and forms read the whole staged document, map it to view rows through
//! [`crate::adapt`], and write back the touched section; validation errors from the backend
//! come back with schema paths and are mapped to the view's field paths.

use crate::api::{AlertPage, FieldError, InsightReport, Pending, SystemStatus};
use crate::form::Inputs;
use crate::grid::{GridPage, GridQuery};
use crate::models::{FormId, GridId};
#[cfg(feature = "ssr")]
use crate::runtime::RuntimeSection;
use crate::runtime::{AliasFeed, GatewaysView, Ipv6Status};
use leptos::prelude::*;
use leptos::server_fn::codec::Json;

#[cfg(feature = "ssr")]
mod imp {
    use crate::adapt::{self, Store};
    use crate::api::{ApiError, BackendHandle, FieldError};
    use crate::form::get_path;
    use crate::models::GridId;
    use leptos::prelude::*;
    use serde_json::{Map, Value};

    /// The user a request was authenticated as (set by the session middleware).
    #[derive(Debug, Clone)]
    pub struct CurrentUser(pub String);

    /// The signed-in user's backend (set per request by the session gate).
    pub fn backend() -> Result<BackendHandle, ServerFnError> {
        use_context::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<BackendHandle>().cloned())
            .or_else(use_context::<BackendHandle>)
            .ok_or_else(|| ServerFnError::new("not signed in"))
    }

    pub fn sessions() -> Result<crate::api::SessionsHandle, ServerFnError> {
        use_context::<crate::api::SessionsHandle>()
            .ok_or_else(|| ServerFnError::new("no session store"))
    }

    pub fn user() -> String {
        use_context::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<CurrentUser>().cloned())
            .map_or_else(|| "root".to_owned(), |u| u.0)
    }

    pub fn err(e: ApiError) -> ServerFnError {
        ServerFnError::new(e.to_string())
    }

    pub async fn doc() -> Result<Value, ServerFnError> {
        backend()?.get("").await.map_err(err)
    }

    /// Alias feed state; empty when the agent has none (feeds not running) or refuses.
    pub async fn feeds() -> Vec<crate::runtime::AliasFeed> {
        match backend() {
            Ok(b) => b
                .runtime(crate::runtime::RuntimeSection::Aliases)
                .await
                .map(crate::runtime::parse)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// One grid row: its key, the stored item and the view.
    pub struct Row {
        pub key: String,
        pub item: Value,
        pub view: Value,
    }

    /// Rows of `grid` in `scope`, in display order (by `sequence` where the schema has one).
    pub fn rows(grid: GridId, scope: &str, doc: &Value) -> Vec<Row> {
        let key_field = grid.meta().key;
        let mut out: Vec<Row> = match adapt::store(grid, scope, doc) {
            Store::Map(path) => get_path(doc, &path)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .filter(|(_, item)| adapt::in_scope(grid, scope, doc, item))
                .map(|(k, item)| (k.clone(), item.clone()))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|(key, item)| {
                    let mut view = adapt::to_view(grid, doc, &item);
                    view[key_field] = Value::String(key.clone());
                    adapt::decorate(grid, doc, &key, &mut view);
                    Row { key, item, view }
                })
                .collect(),
            Store::Array(path) => get_path(doc, &path)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
                .map(|(i, item)| {
                    let key = i.to_string();
                    let mut view = adapt::to_view(grid, doc, item);
                    view[key_field] = Value::String(key.clone());
                    Row {
                        key,
                        item: item.clone(),
                        view,
                    }
                })
                .collect(),
        };
        if adapt::sequenced(grid) {
            out.sort_by_key(|r| r.item.get("sequence").and_then(Value::as_u64).unwrap_or(1));
        }
        out
    }

    /// The top-level section a path lives in.
    pub fn section(path: &str) -> &str {
        path.split('.').next().unwrap_or(path)
    }

    /// Writes one section back and maps validation errors to view fields under `prefix`
    /// (the edited item's schema path).
    pub async fn store(
        doc: &Value,
        sections: &[&str],
        map: impl Fn(&str) -> Option<String>,
    ) -> Result<Vec<FieldError>, ServerFnError> {
        let b = backend()?;
        for s in sections {
            let v = doc.get(*s).cloned().unwrap_or(Value::Object(Map::new()));
            match b.set(s, v).await {
                Ok(()) => {}
                Err(ApiError::Validation(errors)) => {
                    let mapped: Vec<FieldError> = errors
                        .iter()
                        .filter_map(|e| map(&e.path).map(|v| FieldError::new(v, e.message.clone())))
                        .collect();
                    // A uniqueness clash is reported on both items; the other one's copy
                    // adds nothing next to the field message.
                    let other = errors
                        .into_iter()
                        .filter(|e| map(&e.path).is_none())
                        .filter(|e| !mapped.iter().any(|m| m.message == e.message))
                        .map(|e| FieldError::new("", format!("{}: {}", e.path, e.message)))
                        .collect::<Vec<_>>();
                    return Ok(mapped.into_iter().chain(other).collect());
                }
                Err(e) => return Err(err(e)),
            }
        }
        Ok(Vec::new())
    }

    /// Mutable access to the collection a grid stores into.
    pub fn collection<'a>(doc: &'a mut Value, store: &Store) -> &'a mut Value {
        let (path, empty) = match store {
            Store::Map(p) => (p, Value::Object(Map::new())),
            Store::Array(p) => (p, Value::Array(Vec::new())),
        };
        let mut cur = doc;
        for k in path.split('.') {
            if !cur.is_object() {
                *cur = Value::Object(Map::new());
            }
            cur = cur
                .as_object_mut()
                .expect("just made it an object")
                .entry(k.to_owned())
                .or_insert(Value::Null);
        }
        if cur.is_null() {
            *cur = empty;
        }
        cur
    }

    /// Seconds since the Unix epoch.
    pub fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
    }

    /// The suppressions in force for the (staged) `ids` section: the defaults unless turned
    /// off, then the user's enabled ones.
    pub fn suppressions(ids: &Value) -> Vec<sensr_schema::models::ids::Suppression> {
        let ids = if ids.is_null() {
            Value::Object(Map::new())
        } else {
            ids.clone()
        };
        serde_json::from_value::<sensr_schema::models::ids::Ids>(ids)
            .map(|i| i.active_suppressions())
            .unwrap_or_default()
    }

    /// Whether one of `active` silences `alert`.
    pub fn is_suppressed(
        active: &[sensr_schema::models::ids::Suppression],
        alert: &crate::api::AlertRow,
    ) -> bool {
        use sensr_schema::models::ids::TrackBy;
        let ip = |s: &str| s.parse::<std::net::IpAddr>().ok();
        active.iter().any(|s| {
            s.gid == alert.gid
                && s.sid == alert.sid
                && match &s.track {
                    None => true,
                    Some(t) => {
                        let hit = |a: &str| ip(a).is_some_and(|a| t.net.contains(&a));
                        match t.by {
                            TrackBy::Src => hit(&alert.src_ip),
                            TrackBy::Dst => hit(&alert.dest_ip),
                            TrackBy::Either => hit(&alert.src_ip) || hit(&alert.dest_ip),
                        }
                    }
                }
        })
    }

    pub fn store_path(store: &Store) -> &str {
        match store {
            Store::Map(p) | Store::Array(p) => p,
        }
    }
}

#[cfg(feature = "ssr")]
pub use imp::CurrentUser;

/// One page of a grid.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn grid_fetch(
    grid: GridId,
    scope: Option<String>,
    query: GridQuery,
) -> Result<GridPage, ServerFnError> {
    let doc = imp::doc().await?;
    let mut rows: Vec<_> = imp::rows(grid, &grid.scope(&scope), &doc)
        .into_iter()
        .map(|r| r.view)
        .collect();
    if grid == GridId::Aliases {
        crate::adapt::add_feed_status(&mut rows, &imp::feeds().await);
    }
    Ok(crate::grid::run_query(&rows, grid.columns(), &query))
}

/// Adds (`key = None`) or updates a row. Returns field errors; empty means saved.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn grid_save(
    grid: GridId,
    scope: Option<String>,
    key: Option<String>,
    inputs: Inputs,
) -> Result<Vec<FieldError>, ServerFnError> {
    use crate::adapt::{self, Store};
    use serde_json::Value;
    let scope = grid.scope(&scope);
    let mut doc = imp::doc().await?;
    let rows = imp::rows(grid, &scope, &doc);
    let existing = match &key {
        Some(k) => Some(
            rows.iter()
                .find(|r| r.key == *k)
                .ok_or_else(|| ServerFnError::new("row not found"))?,
        ),
        None => None,
    };
    let view_base = existing.map_or_else(|| grid.new_row(), |r| r.view.clone());
    let mut view = match grid.apply(&view_base, &inputs) {
        Ok(v) => v,
        Err(errors) => return Ok(errors),
    };
    // A user's password is write-only: the field holds the clear text only
    // while the form is saved, and the document keeps the crypt(3) hash. An
    // empty field means "keep the stored hash", so it has to be left alone.
    let password_hash = if grid == GridId::Users {
        match view
            .get("password")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
        {
            Some(pw) => Some(
                sensr_auth::password::hash_password(pw)
                    .map_err(|e| ServerFnError::new(e.to_string()))?,
            ),
            None => None,
        }
    } else {
        None
    };
    if grid == GridId::FilterRules
        && view
            .get("interface")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        view["interface"] = Value::String(scope.clone());
    }
    let mut item = adapt::from_view(grid, &doc, &scope, existing.map(|r| &r.item), &view);
    if let Some(hash) = password_hash {
        item["password_hash"] = Value::String(hash);
    }
    let store = adapt::store(grid, &scope, &doc);
    let new_key = match (&key, &store) {
        (Some(k), _) => k.clone(),
        (None, Store::Array(_)) => rows.len().to_string(),
        (None, Store::Map(_)) if grid == GridId::Assignments => {
            let taken = |id: &str| rows.iter().any(|r| r.key == id);
            match (1..).map(|n| format!("opt{n}")).find(|id| !taken(id)) {
                Some(id) => id,
                None => return Err(ServerFnError::new("no free interface name")),
            }
        }
        (None, Store::Map(_)) => crate::models::new_uuid(),
    };
    if key.is_none() && adapt::sequenced(grid) {
        let next = rows
            .iter()
            .filter_map(|r| r.item.get("sequence").and_then(Value::as_u64))
            .max()
            .unwrap_or(0)
            + 10;
        item["sequence"] = Value::from(next);
    }
    // The user and group forms accept 0 as "assign one": a new account then
    // gets the next free id, and root keeps its 0.
    if key.is_none() {
        let field = match grid {
            GridId::Users => Some("uid"),
            GridId::UserGroups => Some("gid"),
            _ => None,
        };
        if let Some(field) = field
            && item.get(field).and_then(Value::as_u64).unwrap_or(0) == 0
        {
            let next = rows
                .iter()
                .filter_map(|r| r.item.get(field).and_then(Value::as_u64))
                .max()
                .unwrap_or(999)
                .max(999)
                + 1;
            item[field] = Value::from(next);
        }
    }
    match imp::collection(&mut doc, &store) {
        Value::Object(m) => {
            m.insert(new_key.clone(), item);
        }
        Value::Array(a) => match new_key.parse::<usize>() {
            Ok(i) if i < a.len() => a[i] = item,
            _ => a.push(item),
        },
        _ => return Err(ServerFnError::new("unexpected document shape")),
    }
    let prefix = format!("{}.{new_key}.", imp::store_path(&store));
    let sections = [imp::section(imp::store_path(&store))];
    imp::store(&doc, &sections, |p| {
        p.strip_prefix(&prefix)
            .and_then(|rel| adapt::view_path(grid, rel))
            .map(str::to_owned)
    })
    .await
}

/// Deletes rows by key.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn grid_delete(
    grid: GridId,
    scope: Option<String>,
    keys: Vec<String>,
) -> Result<usize, ServerFnError> {
    use serde_json::Value;
    let scope = grid.scope(&scope);
    let mut doc = imp::doc().await?;
    let visible: Vec<String> = imp::rows(grid, &scope, &doc)
        .into_iter()
        .map(|r| r.key)
        .collect();
    let keys: Vec<String> = keys.into_iter().filter(|k| visible.contains(k)).collect();
    let store = crate::adapt::store(grid, &scope, &doc);
    let n = match imp::collection(&mut doc, &store) {
        Value::Object(m) => keys
            .iter()
            .filter(|k| m.shift_remove(k.as_str()).is_some())
            .count(),
        Value::Array(a) => {
            let mut idx: Vec<usize> = keys
                .iter()
                .filter_map(|k| k.parse().ok())
                .filter(|i| *i < a.len())
                .collect();
            idx.sort_unstable_by(|x, y| y.cmp(x));
            idx.dedup();
            for i in &idx {
                a.remove(*i);
            }
            idx.len()
        }
        _ => 0,
    };
    if n > 0 {
        let errors = imp::store(&doc, &[imp::section(imp::store_path(&store))], |_| None).await?;
        if let Some(e) = errors.first() {
            return Err(ServerFnError::new(e.message.clone()));
        }
    }
    Ok(n)
}

/// Bulk enable or disable.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn grid_toggle(
    grid: GridId,
    scope: Option<String>,
    keys: Vec<String>,
    enabled: bool,
) -> Result<usize, ServerFnError> {
    use serde_json::Value;
    let Some(field) = grid.meta().toggle else {
        return Err(ServerFnError::new("this grid has no enable switch"));
    };
    let scope = grid.scope(&scope);
    let mut doc = imp::doc().await?;
    let visible: Vec<String> = imp::rows(grid, &scope, &doc)
        .into_iter()
        .map(|r| r.key)
        .collect();
    let store = crate::adapt::store(grid, &scope, &doc);
    let mut n = 0;
    if let Value::Object(m) = imp::collection(&mut doc, &store) {
        for k in keys.iter().filter(|k| visible.contains(k)) {
            if let Some(Value::Object(item)) = m.get_mut(k.as_str())
                && item.get(field).and_then(Value::as_bool).unwrap_or(true) != enabled
            {
                item.insert(field.to_owned(), Value::Bool(enabled));
                n += 1;
            }
        }
    }
    if n > 0 {
        let errors = imp::store(&doc, &[imp::section(imp::store_path(&store))], |_| None).await?;
        if let Some(e) = errors.first() {
            return Err(ServerFnError::new(e.message.clone()));
        }
    }
    Ok(n)
}

/// Moves a row before another (or to the end of its scope). Rows in other scopes keep their
/// positions: the scope's own `sequence` values are permuted, never renumbered.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn grid_move(
    grid: GridId,
    scope: Option<String>,
    key: String,
    before: Option<String>,
) -> Result<(), ServerFnError> {
    use serde_json::Value;
    if !grid.meta().ordered || !crate::adapt::sequenced(grid) {
        return Err(ServerFnError::new("this grid is not ordered"));
    }
    let scope = grid.scope(&scope);
    let mut doc = imp::doc().await?;
    let rows = imp::rows(grid, &scope, &doc);
    let mut order: Vec<Value> = rows.iter().map(|r| r.view.clone()).collect();
    let key_field = grid.meta().key;
    if !crate::grid::move_before(&mut order, key_field, &key, before.as_deref(), |_| true) {
        return Err(ServerFnError::new("row not found"));
    }
    let mut seqs: Vec<u64> = rows
        .iter()
        .map(|r| r.item.get("sequence").and_then(Value::as_u64).unwrap_or(1))
        .collect();
    seqs.sort_unstable();
    // Equal sequences would make the new order ambiguous; spread them out.
    for i in 1..seqs.len() {
        if seqs[i] <= seqs[i - 1] {
            seqs[i] = seqs[i - 1] + 1;
        }
    }
    let store = crate::adapt::store(grid, &scope, &doc);
    if let Value::Object(m) = imp::collection(&mut doc, &store) {
        for (row, seq) in order.iter().zip(seqs) {
            if let Some(k) = row.get(key_field).and_then(Value::as_str)
                && let Some(item) = m.get_mut(k)
            {
                item["sequence"] = Value::from(seq);
            }
        }
    }
    let errors = imp::store(&doc, &[imp::section(imp::store_path(&store))], |_| None).await?;
    match errors.first() {
        Some(e) => Err(ServerFnError::new(e.message.clone())),
        None => Ok(()),
    }
}

/// Saves a settings form. Returns field errors; empty means saved.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn form_save(
    form: FormId,
    scope: Option<String>,
    inputs: Inputs,
) -> Result<Vec<FieldError>, ServerFnError> {
    use crate::adapt;
    let scope = form.scope(&scope);
    let mut doc = imp::doc().await?;
    let Some(base) = adapt::form_to_view(form, &doc, &scope) else {
        return Err(ServerFnError::new("not found"));
    };
    let view = match form.apply(&base, &inputs) {
        Ok(v) => v,
        Err(e) => return Ok(e),
    };
    let sections = match adapt::form_from_view(form, &mut doc, &scope, &view) {
        Ok(s) => s,
        Err(e) => return Ok(e),
    };
    let iface_prefix = format!("interfaces.{scope}.");
    imp::store(&doc, &sections, |p| {
        if form == FormId::Interface {
            p.strip_prefix(&iface_prefix)
                .and_then(|rel| adapt::view_path(GridId::Assignments, rel))
                .map(str::to_owned)
        } else {
            adapt::form_view_path(form, p).map(str::to_owned)
        }
    })
    .await
}

/// Staged state for the Apply banner.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn pending_state() -> Result<Pending, ServerFnError> {
    imp::backend()?.pending().await.map_err(imp::err)
}

/// Commits staged changes, optionally with an automatic rollback window.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn apply_changes(confirm_secs: Option<u32>) -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    let secs = confirm_secs.map(|s| s.clamp(10, 600));
    b.commit(&imp::user(), "", secs).await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Keeps a commit made with a confirm window.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn confirm_changes() -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    b.confirm().await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Rolls back to the revision before a pending confirm, right now.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn revert_unconfirmed() -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    let history = b.history().await.map_err(imp::err)?;
    let p = b.pending().await.map_err(imp::err)?;
    let Some(w) = p.confirm else {
        return Err(ServerFnError::new("no change awaits confirmation"));
    };
    let prev = history
        .iter()
        .find(|r| r.id < w.revision)
        .ok_or_else(|| ServerFnError::new("no earlier revision"))?;
    b.rollback(&imp::user(), prev.id).await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Drops staged changes.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn discard_changes() -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    b.discard().await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Rolls back to a revision. A plain form post: works without JavaScript.
#[server(prefix = "/ui/fn", endpoint = "rollback_to")]
pub async fn rollback_to(revision: u64) -> Result<(), ServerFnError> {
    imp::backend()?
        .rollback(&imp::user(), revision)
        .await
        .map_err(imp::err)?;
    leptos_axum::redirect("/ui/core/backup/history");
    Ok(())
}

/// Live dashboard data, with the traffic graph from the insight database when the caller
/// may see it.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn live_status() -> Result<SystemStatus, ServerFnError> {
    let b = imp::backend()?;
    let mut status = b.status().await.map_err(imp::err)?;
    if b.may_access("/api/v1/insight/series") {
        let dir = b.insight_dir();
        let now = imp::now();
        status.history = tokio::task::spawn_blocking(move || crate::insight::history(&dir, now))
            .await
            .ok()
            .flatten();
    }
    // A missing gateway monitor (or a caller without the privilege) only empties the widget.
    if let Ok(v) = b.runtime(RuntimeSection::Gateways).await {
        status.gateways = crate::runtime::parse::<GatewaysView>(v).gateways;
    }
    Ok(status)
}

/// Reporting › Insight: top talkers and traffic over `range` (`2h`, `24h`, `7d`, `31d`,
/// `1y`), for every local host or for `host`.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn insight_data(
    range: String,
    host: Option<String>,
) -> Result<InsightReport, ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    if !b.may_access("/api/v1/insight/top") {
        return Err(ServerFnError::new("you may not view traffic reports"));
    }
    let (_, _, span) = crate::api::insight_range(&range);
    let host = host
        .filter(|h| h.parse::<std::net::IpAddr>().is_ok())
        .map(|h| h.trim().to_owned());
    let ifs = b.get("interfaces").await.map_err(imp::err)?;
    let labels: std::collections::HashMap<String, String> = ifs
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, i)| {
            let d = i
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (
                id.clone(),
                if d.is_empty() {
                    id.to_uppercase()
                } else {
                    d.to_owned()
                },
            )
        })
        .collect();
    let dir = b.insight_dir();
    let now = imp::now();
    tokio::task::spawn_blocking(move || {
        crate::insight::report(&dir, span, now, host.as_deref(), |id| {
            labels.get(id).cloned().unwrap_or_else(|| id.to_uppercase())
        })
    })
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?
    .map_err(ServerFnError::new)
}

/// Services › Intrusion Detection › Alerts: one page, newest first. `text` is a signature id
/// or part of the message; `host` an address on either side.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn ids_alerts(text: String, host: String, page: u32) -> Result<AlertPage, ServerFnError> {
    let b = imp::backend()?;
    if !b.may_access("/api/v1/ids/alerts") {
        return Err(ServerFnError::new("you may not view IDS alerts"));
    }
    let doc = b.get("ids").await.map_err(imp::err)?;
    let active = imp::suppressions(&doc);
    let dir = b.insight_dir();
    let mut p =
        tokio::task::spawn_blocking(move || crate::insight::alerts(&dir, &text, &host, page))
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .map_err(ServerFnError::new)?;
    for a in &mut p.rows {
        a.suppressed = imp::is_suppressed(&active, a);
    }
    Ok(p)
}

/// Suppresses an alert's signature (everywhere, or only from `src`) by staging a new
/// `ids.suppressions` item. A plain form post from the alerts tab; redirects back to `back`.
#[server(prefix = "/ui/fn", endpoint = "ids_suppress")]
pub async fn ids_suppress(
    sid: u32,
    gid: u32,
    signature: String,
    src: Option<String>,
    back: String,
) -> Result<(), ServerFnError> {
    use crate::adapt::Store;
    use serde_json::{Value, json};
    // Only ever back to the alerts tab, keeping its filter but not an old notice.
    let (path, query) = back.split_once('?').unwrap_or((&back, ""));
    let path = if path == "/ui/ids/alerts" {
        path
    } else {
        "/ui/ids/alerts"
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|kv| !kv.is_empty() && !kv.starts_with("staged=") && !kv.starts_with("error="))
        .collect();
    let to = |notice: String| {
        let mut q = kept.clone();
        q.push(&notice);
        leptos_axum::redirect(&format!("{path}?{}", q.join("&")));
    };
    let net = match src.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(ip) => match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => Some(format!("{a}/32")),
            Ok(std::net::IpAddr::V6(a)) => Some(format!("{a}/128")),
            Err(_) => {
                to(format!(
                    "error={}",
                    crate::pages::url_encode("Not an address.")
                ));
                return Ok(());
            }
        },
    };
    let mut doc = imp::doc().await?;
    let mut item = json!({"enabled": true, "gid": gid.max(1), "sid": sid});
    if let Some(net) = &net {
        item["track"] = json!({"by": "src", "net": net});
    }
    let why: String = signature
        .chars()
        .filter(|c| !c.is_control())
        .take(255)
        .collect();
    if !why.trim().is_empty() {
        item["description"] = Value::String(why.trim().to_owned());
    }
    let store = Store::Map("ids.suppressions".into());
    if let Value::Object(m) = imp::collection(&mut doc, &store) {
        let dup = m.values().any(|s| {
            s.get("sid") == item.get("sid")
                && s.get("gid").and_then(Value::as_u64).unwrap_or(1) == u64::from(gid.max(1))
                && s.get("track") == item.get("track")
        });
        if dup {
            to(format!(
                "error={}",
                crate::pages::url_encode(
                    "This signature is already suppressed for these addresses."
                )
            ));
            return Ok(());
        }
        m.insert(crate::models::new_uuid(), item);
    }
    let errors = imp::store(&doc, &["ids"], |_| None).await?;
    match errors.first() {
        None => to(format!("staged={sid}")),
        Some(e) => to(format!("error={}", crate::pages::url_encode(&e.message))),
    }
    Ok(())
}

/// System › Gateways › Status.
#[server(prefix = "/ui/fn")]
pub async fn gateways_status() -> Result<GatewaysView, ServerFnError> {
    let v = imp::backend()?
        .runtime(RuntimeSection::Gateways)
        .await
        .map_err(imp::err)?;
    Ok(crate::runtime::parse(v))
}

/// Feed state of URL, URL table, GeoIP and ASN aliases.
#[server(prefix = "/ui/fn")]
pub async fn alias_feeds() -> Result<Vec<AliasFeed>, ServerFnError> {
    Ok(imp::feeds().await)
}

/// IPv6 prefix delegation per uplink.
#[server(prefix = "/ui/fn")]
pub async fn pd_status() -> Result<Ipv6Status, ServerFnError> {
    let v = imp::backend()?
        .runtime(RuntimeSection::Ipv6)
        .await
        .map_err(imp::err)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok(Ipv6Status {
        uplinks: crate::runtime::parse(v),
        now,
    })
}

/// Blocklist and resolver statistics for Services › Unbound DNS › Blocklist.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn dns_stats() -> Result<crate::api::DnsStats, ServerFnError> {
    imp::backend()?.dns_stats().await.map_err(imp::err)
}

/// Session cookie name.
pub const SESSION_COOKIE: &str = "sensr_session";

/// Login form target. A plain form post: works without JavaScript.
#[server(prefix = "/ui/fn", endpoint = "login")]
pub async fn login(username: String, password: String) -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header::SET_COOKIE};
    let sessions = imp::sessions()?;
    match sessions.login(username.trim(), &password).await {
        Ok(token) => {
            let opts = expect_context::<leptos_axum::ResponseOptions>();
            let cookie = format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict");
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                opts.insert_header(SET_COOKIE, v);
            }
            leptos_axum::redirect("/");
        }
        Err(_) => leptos_axum::redirect("/login?failed=1"),
    }
    Ok(())
}

/// Change the signed-in user's password. A plain form post: works without
/// JavaScript, like the login form.
#[server(prefix = "/ui/fn", endpoint = "password")]
pub async fn change_password(
    new_password: String,
    confirm_password: String,
) -> Result<(), ServerFnError> {
    if new_password != confirm_password {
        leptos_axum::redirect("/ui/core/password?error=mismatch");
        return Ok(());
    }
    if new_password.chars().count() < 8 {
        leptos_axum::redirect("/ui/core/password?error=short");
        return Ok(());
    }
    let name = imp::user();
    let b = imp::backend()?;
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = system
        .get("users")
        .and_then(serde_json::Value::as_object)
        .and_then(|users| {
            users.iter().find_map(|(uuid, user)| {
                (user.get("name").and_then(serde_json::Value::as_str) == Some(name.as_str()))
                    .then(|| uuid.clone())
            })
        })
    else {
        leptos_axum::redirect("/ui/core/password?error=nouser");
        return Ok(());
    };
    let hash = sensr_auth::password::hash_password(&new_password)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    b.set(
        &format!("system.users.{uuid}.password_hash"),
        serde_json::Value::String(hash),
    )
    .await
    .map_err(imp::err)?;
    b.commit(&name, "change password", None)
        .await
        .map_err(imp::err)?;
    leptos_axum::redirect("/ui/core/password?changed=1");
    Ok(())
}

/// Logout form target.
#[server(prefix = "/ui/fn", endpoint = "logout")]
pub async fn logout() -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header::SET_COOKIE};
    if let Some(token) = crate::server::session_token() {
        imp::sessions()?.logout(&token).await;
    }
    let opts = expect_context::<leptos_axum::ResponseOptions>();
    opts.insert_header(
        SET_COOKIE,
        HeaderValue::from_static("sensr_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"),
    );
    leptos_axum::redirect("/login");
    Ok(())
}

/// What every page's chrome needs: user, menu interfaces and pending state.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LayoutData {
    /// Signed-in user.
    pub user: String,
    /// Assigned interfaces for the dynamic menu entries.
    pub interfaces: Vec<crate::menu::MenuInterface>,
    /// Staged state.
    pub pending: Pending,
}

/// Chrome data for the page being rendered.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn chrome_data() -> Result<LayoutData, ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let doc = b.get("interfaces").await.map_err(imp::err)?;
    let interfaces = doc
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, r)| {
            let desc = r
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            crate::menu::MenuInterface {
                id: id.clone(),
                description: if desc.is_empty() {
                    id.to_uppercase()
                } else {
                    desc.to_owned()
                },
                dhcp_capable: crate::form::get_path(r, "ipv4.mode").and_then(Value::as_str)
                    == Some("static"),
            }
        })
        .collect();
    Ok(LayoutData {
        user: imp::user(),
        interfaces,
        pending: b.pending().await.map_err(imp::err)?,
    })
}

/// Current value of a settings form, secrets blanked.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn form_load(
    form: FormId,
    scope: Option<String>,
) -> Result<serde_json::Value, ServerFnError> {
    let doc = imp::backend()?.get("").await.map_err(imp::err)?;
    crate::adapt::form_to_view(form, &doc, &form.scope(&scope))
        .ok_or_else(|| ServerFnError::new("not found"))
}

/// Commit history, newest first.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn revisions() -> Result<Vec<crate::api::Revision>, ServerFnError> {
    imp::backend()?.history().await.map_err(imp::err)
}

/// Diff between revisions; `to = None` is the staged document.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn revision_diff(
    from: u64,
    to: Option<u64>,
) -> Result<Vec<crate::api::DiffLine>, ServerFnError> {
    imp::backend()?.diff(from, to).await.map_err(imp::err)
}

/// Option lists computed from the document (assigned interfaces, …).
#[server(prefix = "/ui/fn", input = Json)]
pub async fn field_choices() -> Result<crate::form::Choices, ServerFnError> {
    use crate::form::ChoiceSet;
    use serde_json::Value;
    let backend = imp::backend()?;
    let ifs = backend.get("interfaces").await.map_err(imp::err)?;
    let list: Vec<(String, String)> = ifs
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, i)| {
            let d = i
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (
                id.clone(),
                if d.is_empty() {
                    id.to_uppercase()
                } else {
                    d.to_owned()
                },
            )
        })
        .collect();
    let mut rules = vec![("floating".to_owned(), "Floating".to_owned())];
    rules.extend(list.iter().cloned());
    // cards by MAC, then devices that are not cards (VLANs, WireGuard)
    let cards = backend.nics().await.unwrap_or_default();
    let mut devices: Vec<(String, String)> =
        cards.iter().map(|c| (c.mac.clone(), c.label())).collect();
    for i in ifs.as_object().into_iter().flatten().map(|(_, i)| i) {
        let dev = i.get("device").and_then(Value::as_str).unwrap_or_default();
        let pinned = i.get("match_mac").and_then(Value::as_str);
        if dev.is_empty()
            || devices
                .iter()
                .any(|(v, _)| Some(v.as_str()) == pinned || v == dev)
        {
            continue;
        }
        match pinned {
            // bound to a card that is not plugged in right now
            Some(mac) => devices.push((mac.to_owned(), format!("{dev} ({mac}, not present)"))),
            None if cards.iter().any(|c| c.name == dev) => {}
            None => devices.push((dev.to_owned(), dev.to_owned())),
        }
    }
    Ok([
        (ChoiceSet::Interfaces, list),
        (ChoiceSet::RuleInterfaces, rules),
        (ChoiceSet::Devices, devices),
    ]
    .into_iter()
    .collect())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::imp::{is_suppressed, suppressions};
    use serde_json::json;

    fn alert(sid: u32, src: &str) -> crate::api::AlertRow {
        crate::api::AlertRow {
            id: 1,
            ts: 0,
            gid: 1,
            sid,
            signature: String::new(),
            category: String::new(),
            severity: 3,
            action: String::new(),
            proto: "TCP".into(),
            src_ip: src.into(),
            src_port: None,
            dest_ip: "203.0.113.24".into(),
            dest_port: None,
            iface: String::new(),
            suppressed: false,
        }
    }

    #[test]
    fn suppressions_match_by_sid_and_tracked_address() {
        let ids = json!({"suppressions": {
            "e1000000-0000-4000-a000-000000000001": {"sid": 7, "track": {"by": "src", "net": "192.168.1.0/24"}},
            "e1000000-0000-4000-a000-000000000002": {"sid": 8, "enabled": false},
        }});
        let active = suppressions(&ids);
        assert!(is_suppressed(&active, &alert(7, "192.168.1.9")));
        assert!(
            !is_suppressed(&active, &alert(7, "10.0.0.1")),
            "other source"
        );
        assert!(!is_suppressed(&active, &alert(8, "10.0.0.1")), "disabled");
        // The defaults apply unless turned off; a missing section is all defaults.
        assert!(is_suppressed(
            &suppressions(&serde_json::Value::Null),
            &alert(2016149, "10.0.0.1")
        ));
        let off = json!({"default_suppressions": false});
        assert!(!is_suppressed(
            &suppressions(&off),
            &alert(2016149, "10.0.0.1")
        ));
    }
}
