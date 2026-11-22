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

    /// The origin the browser used, for WebAuthn's relying-party id.
    pub fn base() -> Result<String, ServerFnError> {
        let parts = use_context::<axum::http::request::Parts>()
            .ok_or_else(|| ServerFnError::new("no request"))?;
        Ok(crate::server::external_base(&parts.headers))
    }

    /// The client address, for group source-network restrictions.
    pub fn remote() -> Option<std::net::IpAddr> {
        use_context::<axum::http::request::Parts>()?
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(a)| a.ip())
    }

    /// Cookie carrying the secret while enrolment is pending: the API masks
    /// secrets on reads, so the browser that generated it is the only one
    /// that can show it before the first code arms the account.
    pub const TOTP_COOKIE: &str = "sensr_totp_pending";

    /// The pending enrolment secret from the request cookie, if any.
    pub fn pending_seed() -> Option<String> {
        let parts = use_context::<axum::http::request::Parts>()?;
        parts
            .headers
            .get_all(axum::http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|header| {
                header.split(';').find_map(|kv| {
                    let (k, v) = kv.trim().split_once('=')?;
                    (k == TOTP_COOKIE).then(|| v.to_owned())
                })
            })
    }

    /// Sets or clears the pending enrolment cookie on the response.
    pub fn set_pending_seed(value: Option<&str>) {
        use axum::http::{HeaderValue, header::SET_COOKIE};
        let opts = expect_context::<leptos_axum::ResponseOptions>();
        let cookie = match value {
            Some(seed) => {
                format!("{TOTP_COOKIE}={seed}; Path=/; HttpOnly; SameSite=Strict; Max-Age=600")
            }
            None => format!("{TOTP_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
        };
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            opts.append_header(SET_COOKIE, v);
        }
    }

    /// Finds `name` in the account list and returns its object id.
    pub fn user_uuid(system: &Value, name: &str) -> Option<String> {
        system
            .get("users")
            .and_then(Value::as_object)
            .and_then(|users| {
                users.iter().find_map(|(uuid, user)| {
                    (user.get("name").and_then(Value::as_str) == Some(name)).then(|| uuid.clone())
                })
            })
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

    /// Where `sensr-update` keeps its state (nix/modules/updates.nix).
    const UPDATE_DIR: &str = "/run/sensr/updates";

    /// The updater's status; the running version comes from the booted
    /// generation when the service has not written anything yet.
    pub async fn read_update_status() -> crate::runtime::UpdateStatus {
        let path = format!("{UPDATE_DIR}/status.json");
        let mut st: crate::runtime::UpdateStatus = match tokio::fs::read_to_string(&path).await {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => crate::runtime::UpdateStatus::default(),
        };
        if st.phase.is_empty() {
            st.phase = "idle".to_owned();
        }
        if st.message.is_empty() {
            st.message = "No check has run yet.".to_owned();
        }
        if st.current.version.is_empty() {
            st.current.version =
                match tokio::fs::read_to_string("/run/current-system/nixos-version").await {
                    Ok(v) => v.trim().to_owned(),
                    Err(_) => "unknown".to_owned(),
                };
        }
        st
    }

    /// Writes `{mode: …}` into the updater's request file. The path unit starts
    /// the root service; the rename publishes the file atomically.
    pub async fn write_update_request(mode: &str) -> Result<(), ServerFnError> {
        if !matches!(mode, "check" | "install" | "auto-on" | "auto-off") {
            return Err(ServerFnError::new(format!(
                "unknown update request: {mode}"
            )));
        }
        tokio::fs::create_dir_all(UPDATE_DIR)
            .await
            .map_err(|e| ServerFnError::new(format!("{UPDATE_DIR}: {e}")))?;
        let tmp = format!("{UPDATE_DIR}/request.json.tmp");
        let dst = format!("{UPDATE_DIR}/request.json");
        let body = serde_json::json!({ "mode": mode }).to_string();
        tokio::fs::write(&tmp, body)
            .await
            .map_err(|e| ServerFnError::new(format!("{tmp}: {e}")))?;
        tokio::fs::rename(&tmp, &dst)
            .await
            .map_err(|e| ServerFnError::new(format!("{dst}: {e}")))?;
        Ok(())
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

/// The lease table as the page renders it: the leases and the moment they were read, so
/// "expires in" is right at the time of the response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaseTable {
    /// Unix time the leases were read.
    pub now: u64,
    /// Leases, live ones first.
    pub leases: Vec<crate::api::DhcpLease>,
}

/// The DHCPv4 lease table, with each row marked when a static reservation already covers
/// the client.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn dhcp_leases() -> Result<LeaseTable, ServerFnError> {
    use serde_json::Value;
    let doc = imp::doc().await?;
    let mut leases = imp::backend()?.dhcp_leases().await.map_err(imp::err)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let reservations: Vec<&Value> = doc
        .pointer("/dhcpv4/reservations")
        .and_then(Value::as_object)
        .map(|m| m.values().collect())
        .unwrap_or_default();
    let field = |r: &Value, path: &[&str]| {
        path.iter()
            .try_fold(r, |v, k| v.get(k))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    for lease in &mut leases {
        let ip = lease.address.as_str();
        lease.reserved = reservations.iter().any(|r| {
            (lease.mac.is_some() && field(r, &["client", "hw_address"]) == lease.mac)
                || (lease.client_id.is_some()
                    && field(r, &["client", "client_id"]) == lease.client_id)
                || r.get("ip_address").and_then(Value::as_str) == Some(ip)
        });
    }
    Ok(LeaseTable { now, leases })
}

/// The dashboard's Hosts card: the inventory, whether the caller may act on it, and the
/// networks to filter by.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostCard {
    /// The inventory as the agent reports it.
    pub list: crate::runtime::HostList,
    /// The caller may not change anything: no Make static or Forget.
    pub read_only: bool,
    /// `(interface id, display name)` of each network with hosts, by id.
    pub networks: Vec<(String, String)>,
}

/// The host inventory for the dashboard, or `None` when the caller may not see it
/// (`page-sensr-hosts`), so the card is left out.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn hosts() -> Result<Option<HostCard>, ServerFnError> {
    let b = imp::backend()?;
    if !b.may_access("/api/v1/hosts") {
        return Ok(None);
    }
    let list: crate::runtime::HostList =
        crate::runtime::parse(b.runtime(RuntimeSection::Hosts).await.map_err(imp::err)?);
    let networks: std::collections::BTreeMap<String, String> = list
        .hosts
        .iter()
        .filter(|h| !h.interface.is_empty())
        .map(|h| {
            let name = if h.interface_name.is_empty() {
                h.interface.to_uppercase()
            } else {
                h.interface_name.clone()
            };
            (h.interface.clone(), name)
        })
        .collect();
    Ok(Some(HostCard {
        read_only: b.read_only(),
        networks: networks.into_iter().collect(),
        list,
    }))
}

/// Drops an unreserved host from the inventory (it comes back if still on the network).
#[server(prefix = "/ui/fn", input = Json)]
pub async fn forget_host(key: String) -> Result<(), ServerFnError> {
    let b = imp::backend()?;
    if !b.may_access("/api/v1/hosts/forget") {
        return Err(ServerFnError::new("you may not change the host inventory"));
    }
    b.forget_host(key).await.map_err(imp::err)
}

/// Stages a static reservation for a lease, mirroring the lease's MAC (or client id, when
/// the lease has no MAC) and host name. Nothing takes effect until the change is applied.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn reserve_lease(
    address: String,
    mac: Option<String>,
    client_id: Option<String>,
    hostname: String,
) -> Result<(), ServerFnError> {
    use serde_json::{Map, Value, json};
    let ip: std::net::Ipv4Addr = address
        .parse()
        .map_err(|_| ServerFnError::new(format!("{address} is not an IPv4 address")))?;
    let client = match (mac, client_id) {
        (Some(mac), _) if !mac.is_empty() => json!({ "hw_address": mac.to_ascii_lowercase() }),
        (_, Some(id)) if !id.is_empty() => json!({ "client_id": id.to_ascii_lowercase() }),
        _ => {
            return Err(ServerFnError::new(
                "this lease has no MAC address or client identifier to reserve for",
            ));
        }
    };
    let mut doc = imp::doc().await?;
    // The reservation has to name the subnet it belongs to, and Kea resolves that by the
    // address: the first configured subnet that contains it.
    let subnet = doc
        .pointer("/dhcpv4/subnets")
        .and_then(Value::as_object)
        .and_then(|subnets| {
            subnets.iter().find_map(|(id, s)| {
                let net: ipnet::Ipv4Net = s.get("subnet")?.as_str()?.parse().ok()?;
                net.contains(&ip).then(|| id.clone())
            })
        })
        .ok_or_else(|| ServerFnError::new(format!("no configured DHCP subnet contains {ip}")))?;
    let mut item = Map::new();
    item.insert("subnet".into(), Value::String(subnet));
    item.insert("client".into(), client);
    item.insert("ip_address".into(), Value::String(ip.to_string()));
    let hostname = hostname.trim();
    if !hostname.is_empty()
        && hostname.len() <= 63
        && hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        item.insert("hostname".into(), Value::String(hostname.to_owned()));
    }
    item.insert(
        "description".into(),
        Value::String("Reserved from the lease table".into()),
    );
    let reservations = doc
        .as_object_mut()
        .and_then(|d| d.get_mut("dhcpv4"))
        .and_then(Value::as_object_mut)
        .map(|d| d.entry("reservations").or_insert(json!({})));
    let Some(Value::Object(map)) = reservations else {
        return Err(ServerFnError::new(
            "dhcpv4.reservations has an unexpected shape",
        ));
    };
    map.insert(crate::models::new_uuid(), Value::Object(item));
    let errors = imp::store(&doc, &["dhcpv4"], |p| {
        p.strip_prefix("dhcpv4.").map(str::to_owned)
    })
    .await?;
    match errors.first() {
        Some(e) => Err(ServerFnError::new(e.message.clone())),
        None => Ok(()),
    }
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

/// System › Updates: what `sensr-update` last wrote and what the running
/// generation is. A missing status file (first boot, or the module disabled)
/// yields an idle status rather than an error.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn update_status() -> Result<crate::runtime::UpdateStatus, ServerFnError> {
    Ok(imp::read_update_status().await)
}

/// Asks `sensr-update` to run. `mode` is `check`, `install`, `auto-on` or
/// `auto-off`; the service owns every privileged step, the API only drops the
/// request file and reads the status back.
#[server(prefix = "/ui/fn", input = Json)]
pub async fn update_request(mode: String) -> Result<crate::runtime::UpdateStatus, ServerFnError> {
    imp::write_update_request(&mode).await?;
    Ok(imp::read_update_status().await)
}

/// Session cookie name.
pub const SESSION_COOKIE: &str = "sensr_session";

/// Login form target. A plain form post: works without JavaScript.
#[server(prefix = "/ui/fn", endpoint = "login")]
pub async fn login(
    username: String,
    password: String,
    otp: Option<String>,
) -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header::SET_COOKIE};
    let sessions = imp::sessions()?;
    let otp = otp.as_deref().map(str::trim).filter(|c| !c.is_empty());
    match sessions.login(username.trim(), &password, otp).await {
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

/// The OpenID Connect buttons the login page offers. Empty when the service
/// is disabled or nothing is configured.
#[server(prefix = "/ui/fn", endpoint = "login/providers", input = Json)]
pub async fn login_providers() -> Result<Vec<crate::api::LoginProvider>, ServerFnError> {
    let sessions = imp::sessions()?;
    let mut providers = sessions.oidc_providers().await;
    providers.extend(sessions.saml_providers().await);
    providers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(providers)
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
    let Some(uuid) = imp::user_uuid(&system, &name) else {
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

/// Two-factor enrolment state for the signed-in account.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TotpState {
    /// A code is required at password login.
    pub enabled: bool,
    /// The base32 secret, while enrolment is pending or complete.
    pub secret: Option<String>,
    /// The `otpauth://` URI an authenticator app imports.
    pub uri: Option<String>,
}

/// Reads the signed-in account's two-factor state.
#[server(prefix = "/ui/fn", endpoint = "totp/status")]
pub async fn totp_status() -> Result<TotpState, ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let name = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &name) else {
        return Err(ServerFnError::new("could not find your account"));
    };
    let user = system
        .get("users")
        .and_then(|u| u.get(&uuid))
        .cloned()
        .unwrap_or(Value::Null);
    let enabled = user
        .get("otp_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Secrets are masked on reads; while enrolment is pending the browser
    // holds the real one in a short-lived cookie.
    let secret = (!enabled).then(imp::pending_seed).flatten();
    Ok(TotpState {
        enabled,
        uri: secret
            .as_ref()
            .map(|s| sensr_auth::totp::provisioning_uri("sensr", &name, s)),
        secret,
    })
}

/// Generates a new secret for the signed-in account and shows it for
/// enrolment. The account keeps password-only login until the first code is
/// confirmed.
#[server(prefix = "/ui/fn", endpoint = "totp/start")]
pub async fn totp_start() -> Result<(), ServerFnError> {
    let b = imp::backend()?;
    let name = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &name) else {
        leptos_axum::redirect("/ui/core/password?otp=nouser");
        return Ok(());
    };
    let secret = sensr_auth::totp::generate_seed();
    imp::set_pending_seed(Some(&secret));
    b.set(
        &format!("system.users.{uuid}.otp_seed"),
        serde_json::Value::String(secret),
    )
    .await
    .map_err(imp::err)?;
    b.set(
        &format!("system.users.{uuid}.otp_enabled"),
        serde_json::Value::Bool(false),
    )
    .await
    .map_err(imp::err)?;
    b.commit(&name, "start two-factor authentication", None)
        .await
        .map_err(imp::err)?;
    leptos_axum::redirect("/ui/core/password?otp=scan");
    Ok(())
}

/// Confirms the first code from the new secret and turns two-factor login on.
#[server(prefix = "/ui/fn", endpoint = "totp/confirm")]
pub async fn totp_confirm(code: String) -> Result<(), ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let name = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &name) else {
        leptos_axum::redirect("/ui/core/password?otp=nouser");
        return Ok(());
    };
    let Some(secret) = imp::pending_seed() else {
        leptos_axum::redirect("/ui/core/password?otp=expired");
        return Ok(());
    };
    if !sensr_auth::totp::verify(&secret, &code, std::time::SystemTime::now()) {
        leptos_axum::redirect("/ui/core/password?otp=bad");
        return Ok(());
    }
    imp::set_pending_seed(None);
    b.set(
        &format!("system.users.{uuid}.otp_enabled"),
        Value::Bool(true),
    )
    .await
    .map_err(imp::err)?;
    b.commit(&name, "enable two-factor authentication", None)
        .await
        .map_err(imp::err)?;
    leptos_axum::redirect("/ui/core/password?otp=enabled");
    Ok(())
}

/// Turns two-factor login off and drops the secret.
#[server(prefix = "/ui/fn", endpoint = "totp/disable")]
pub async fn totp_disable() -> Result<(), ServerFnError> {
    let b = imp::backend()?;
    let name = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &name) else {
        leptos_axum::redirect("/ui/core/password?otp=nouser");
        return Ok(());
    };
    b.set(
        &format!("system.users.{uuid}.otp_enabled"),
        serde_json::Value::Bool(false),
    )
    .await
    .map_err(imp::err)?;
    b.set(
        &format!("system.users.{uuid}.otp_seed"),
        serde_json::Value::Null,
    )
    .await
    .map_err(imp::err)?;
    b.commit(&name, "disable two-factor authentication", None)
        .await
        .map_err(imp::err)?;
    imp::set_pending_seed(None);
    leptos_axum::redirect("/ui/core/password?otp=disabled");
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

/// One passkey on the signed-in account.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PasskeyView {
    /// Credential id (base64url).
    pub id: String,
    /// Device label.
    pub name: String,
}

#[cfg(feature = "ssr")]
fn passkeys_of(user: &serde_json::Value) -> Vec<PasskeyView> {
    user.get("passkeys")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|p| {
                    Some(PasskeyView {
                        id: p.get("credential")?.get("cred_id")?.as_str()?.to_owned(),
                        name: p.get("name")?.as_str()?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The signed-in account's registered passkeys.
#[server(prefix = "/ui/fn", endpoint = "passkey/list")]
pub async fn passkey_list() -> Result<Vec<PasskeyView>, ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let name = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &name) else {
        return Ok(Vec::new());
    };
    let user = system
        .get("users")
        .and_then(|u| u.get(&uuid))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(passkeys_of(&user))
}

/// Starts a passkey registration; the browser answers with
/// `passkey_register_finish`.
#[server(prefix = "/ui/fn", endpoint = "passkey/register/start", input = Json)]
pub async fn passkey_register_start() -> Result<serde_json::Value, ServerFnError> {
    let b = imp::backend()?;
    let name = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &name) else {
        return Err(ServerFnError::new("could not find your account"));
    };
    let user = system
        .get("users")
        .and_then(|u| u.get(&uuid))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let exclude: Vec<String> = passkeys_of(&user).into_iter().map(|p| p.id).collect();
    let base = imp::base()?;
    imp::sessions()?
        .passkey_register_start(&name, &uuid, &base, &exclude)
        .await
        .map_err(imp::err)
}

/// Verifies the registration and appends the credential to the account.
#[server(prefix = "/ui/fn", endpoint = "passkey/register/finish", input = Json)]
pub async fn passkey_register_finish(
    state: String,
    name: String,
    credential: serde_json::Value,
) -> Result<(), ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let user = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &user) else {
        return Err(ServerFnError::new("could not find your account"));
    };
    let base = imp::base()?;
    let credential = imp::sessions()?
        .passkey_register_finish(&uuid, &state, &credential, &base)
        .await
        .map_err(imp::err)?;
    let label = name.trim();
    let label = if label.is_empty() { "Passkey" } else { label };
    let mut list = system
        .get("users")
        .and_then(|u| u.get(&uuid))
        .and_then(|u| u.get("passkeys"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    list.push(serde_json::json!({"name": label, "credential": credential}));
    b.set(&format!("system.users.{uuid}.passkeys"), Value::Array(list))
        .await
        .map_err(imp::err)?;
    b.commit(&user, "add a passkey", None)
        .await
        .map_err(imp::err)?;
    Ok(())
}

/// Removes one passkey from the signed-in account.
#[server(prefix = "/ui/fn", endpoint = "passkey/remove")]
pub async fn passkey_remove(id: String) -> Result<(), ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let user = imp::user();
    let system = b.get("system").await.map_err(imp::err)?;
    let Some(uuid) = imp::user_uuid(&system, &user) else {
        leptos_axum::redirect("/ui/core/password?passkey=error");
        return Ok(());
    };
    let mut list = system
        .get("users")
        .and_then(|u| u.get(&uuid))
        .and_then(|u| u.get("passkeys"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    list.retain(|p| {
        p.get("credential")
            .and_then(|c| c.get("cred_id"))
            .and_then(Value::as_str)
            != Some(id.as_str())
    });
    b.set(&format!("system.users.{uuid}.passkeys"), Value::Array(list))
        .await
        .map_err(imp::err)?;
    b.commit(&user, "remove a passkey", None)
        .await
        .map_err(imp::err)?;
    leptos_axum::redirect("/ui/core/password?passkey=removed");
    Ok(())
}

/// Starts a passkey login and returns `{state, options}` for the browser.
#[server(prefix = "/ui/fn", endpoint = "passkey/login/start", input = Json)]
pub async fn passkey_login_start() -> Result<serde_json::Value, ServerFnError> {
    let base = imp::base()?;
    imp::sessions()?
        .passkey_login_start(&base)
        .await
        .map_err(imp::err)
}

/// Verifies a passkey login and sets the session cookie.
#[server(prefix = "/ui/fn", endpoint = "passkey/login/finish", input = Json)]
pub async fn passkey_login_finish(
    state: String,
    credential: serde_json::Value,
) -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header::SET_COOKIE};
    let base = imp::base()?;
    let remote = imp::remote();
    let token = imp::sessions()?
        .passkey_login_finish(&state, &credential, &base, remote)
        .await
        .map_err(imp::err)?;
    let opts = expect_context::<leptos_axum::ResponseOptions>();
    let cookie = format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict");
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        opts.insert_header(SET_COOKIE, v);
    }
    Ok(())
}
