//! Server functions: the only calls the browser islands make. Each one runs on the server
//! against the [`crate::api::Backend`] in context, re-validating everything it receives.

use crate::api::{FieldError, Pending, SystemStatus};
use crate::form::Inputs;
use crate::grid::{GridPage, GridQuery};
use crate::models::{FormId, GridId};
use leptos::prelude::*;
use leptos::server_fn::codec::Json;

#[cfg(feature = "ssr")]
mod imp {
    use crate::api::{ApiError, BackendHandle};
    use crate::form::get_path;
    use crate::models::{GridId, GridLocation};
    use leptos::prelude::*;
    use serde_json::Value;

    /// The user a request was authenticated as (set by the session middleware).
    #[derive(Debug, Clone)]
    pub struct CurrentUser(pub String);

    pub fn backend() -> Result<BackendHandle, ServerFnError> {
        use_context::<BackendHandle>().ok_or_else(|| ServerFnError::new("no backend in context"))
    }

    pub fn user() -> String {
        use_context::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<CurrentUser>().cloned())
            .map_or_else(|| "root".to_owned(), |u| u.0)
    }

    pub fn err(e: ApiError) -> ServerFnError {
        ServerFnError::new(e.to_string())
    }

    pub async fn load_list(path: &str) -> Result<Vec<Value>, ServerFnError> {
        let v = backend()?.get(path).await.map_err(err)?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    pub async fn store_list(path: &str, rows: Vec<Value>) -> Result<(), ServerFnError> {
        backend()?.set(path, Value::Array(rows)).await.map_err(err)
    }

    pub fn visible(loc: &GridLocation) -> impl Fn(&Value) -> bool + '_ {
        move |row| match &loc.filter {
            Some((field, want)) => get_path(row, field).and_then(Value::as_str) == Some(want),
            None => true,
        }
    }

    pub fn keys_in_scope(
        rows: &[Value],
        grid: GridId,
        loc: &GridLocation,
        keys: Vec<String>,
    ) -> Vec<String> {
        let key = grid.meta().key;
        let vis = visible(loc);
        keys.into_iter()
            .filter(|k| {
                rows.iter()
                    .any(|r| vis(r) && r.get(key).and_then(Value::as_str) == Some(k))
            })
            .collect()
    }
}

#[cfg(feature = "ssr")]
pub use imp::CurrentUser;

/// One page of a grid.
#[server(input = Json)]
pub async fn grid_fetch(
    grid: GridId,
    scope: Option<String>,
    query: GridQuery,
) -> Result<GridPage, ServerFnError> {
    let loc = grid.location(&scope);
    let rows = imp::load_list(&loc.list).await?;
    let vis = imp::visible(&loc);
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|r| vis(r))
        .map(|r| grid.redact(&r))
        .collect();
    Ok(crate::grid::run_query(&rows, grid.columns(), &query))
}

/// Adds (`key = None`) or updates a row. Returns field errors; empty means saved.
#[server(input = Json)]
pub async fn grid_save(
    grid: GridId,
    scope: Option<String>,
    key: Option<String>,
    inputs: Inputs,
) -> Result<Vec<FieldError>, ServerFnError> {
    use serde_json::Value;
    let loc = grid.location(&scope);
    let meta = grid.meta();
    let mut rows = imp::load_list(&loc.list).await?;
    let vis = imp::visible(&loc);
    let idx = match &key {
        Some(k) => Some(
            rows.iter()
                .position(|r| vis(r) && r.get(meta.key).and_then(Value::as_str) == Some(k))
                .ok_or_else(|| ServerFnError::new("row not found"))?,
        ),
        None => None,
    };
    let base = idx.map_or_else(|| grid.new_row(), |i| rows[i].clone());
    let mut row = match grid.apply(&base, &inputs) {
        Ok(v) => v,
        Err(errors) => return Ok(errors),
    };
    if let Some(obj) = row.as_object_mut() {
        if let Some((field, value)) = &loc.filter {
            obj.insert((*field).to_owned(), Value::String(value.clone()));
        }
        match (&key, meta.key) {
            (Some(k), field) => {
                obj.insert(field.to_owned(), Value::String(k.clone()));
            }
            (None, "uuid") => {
                obj.insert("uuid".into(), Value::String(crate::models::new_uuid()));
            }
            (None, field) => {
                // Natural keys (interface ids) must be unique.
                let k = obj
                    .get(field)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if k.is_empty() {
                    let n = rows.len();
                    obj.insert(field.to_owned(), Value::String(format!("opt{n}")));
                } else if rows
                    .iter()
                    .any(|r| r.get(field).and_then(Value::as_str) == Some(&k))
                {
                    return Ok(vec![FieldError::new(field, "This name is already in use.")]);
                }
            }
        }
    }
    match idx {
        Some(i) => rows[i] = row,
        None => rows.push(row),
    }
    imp::store_list(&loc.list, rows).await?;
    Ok(Vec::new())
}

/// Deletes rows by key.
#[server(input = Json)]
pub async fn grid_delete(
    grid: GridId,
    scope: Option<String>,
    keys: Vec<String>,
) -> Result<usize, ServerFnError> {
    let loc = grid.location(&scope);
    let mut rows = imp::load_list(&loc.list).await?;
    let keys = imp::keys_in_scope(&rows, grid, &loc, keys);
    let n = crate::grid::delete(&mut rows, grid.meta().key, &keys);
    if n > 0 {
        imp::store_list(&loc.list, rows).await?;
    }
    Ok(n)
}

/// Bulk enable or disable.
#[server(input = Json)]
pub async fn grid_toggle(
    grid: GridId,
    scope: Option<String>,
    keys: Vec<String>,
    enabled: bool,
) -> Result<usize, ServerFnError> {
    let meta = grid.meta();
    let Some(field) = meta.toggle else {
        return Err(ServerFnError::new("this grid has no enable switch"));
    };
    let loc = grid.location(&scope);
    let mut rows = imp::load_list(&loc.list).await?;
    let keys = imp::keys_in_scope(&rows, grid, &loc, keys);
    let n = crate::grid::set_enabled(&mut rows, meta.key, field, &keys, enabled);
    if n > 0 {
        imp::store_list(&loc.list, rows).await?;
    }
    Ok(n)
}

/// Moves a row before another (or to the end of its scope).
#[server(input = Json)]
pub async fn grid_move(
    grid: GridId,
    scope: Option<String>,
    key: String,
    before: Option<String>,
) -> Result<(), ServerFnError> {
    if !grid.meta().ordered {
        return Err(ServerFnError::new("this grid is not ordered"));
    }
    let loc = grid.location(&scope);
    let mut rows = imp::load_list(&loc.list).await?;
    let mut keys = vec![key.clone()];
    keys.extend(before.clone());
    if imp::keys_in_scope(&rows, grid, &loc, keys.clone()).len() != keys.len() {
        return Err(ServerFnError::new("row not found"));
    }
    if crate::grid::move_before(
        &mut rows,
        grid.meta().key,
        &key,
        before.as_deref(),
        imp::visible(&loc),
    ) {
        imp::store_list(&loc.list, rows).await?;
    }
    Ok(())
}

/// Saves a settings form. Returns field errors; empty means saved.
#[server(input = Json)]
pub async fn form_save(
    form: FormId,
    scope: Option<String>,
    inputs: Inputs,
) -> Result<Vec<FieldError>, ServerFnError> {
    use crate::models::Location;
    use serde_json::Value;
    let b = imp::backend()?;
    match form.location(&scope) {
        Location::Path(path) => {
            let base = b.get(&path).await.map_err(imp::err)?;
            match form.apply(&base, &inputs) {
                Ok(v) => b.set(&path, v).await.map_err(imp::err)?,
                Err(e) => return Ok(e),
            }
        }
        Location::Item { list, key, value } => {
            let mut rows = imp::load_list(&list).await?;
            let Some(i) = rows
                .iter()
                .position(|r| r.get(key).and_then(Value::as_str) == Some(&value))
            else {
                return Err(ServerFnError::new("not found"));
            };
            match form.apply(&rows[i], &inputs) {
                Ok(mut v) => {
                    if let Some(o) = v.as_object_mut() {
                        o.insert(key.to_owned(), Value::String(value));
                    }
                    rows[i] = v;
                }
                Err(e) => return Ok(e),
            }
            imp::store_list(&list, rows).await?;
        }
    }
    Ok(Vec::new())
}

/// Staged state for the Apply banner.
#[server(input = Json)]
pub async fn pending_state() -> Result<Pending, ServerFnError> {
    imp::backend()?.pending().await.map_err(imp::err)
}

/// Commits staged changes, optionally with an automatic rollback window.
#[server(input = Json)]
pub async fn apply_changes(confirm_secs: Option<u32>) -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    let secs = confirm_secs.map(|s| s.clamp(10, 600));
    b.commit(&imp::user(), "", secs).await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Keeps a commit made with a confirm window.
#[server(input = Json)]
pub async fn confirm_changes() -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    b.confirm().await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Rolls back to the revision before a pending confirm, right now.
#[server(input = Json)]
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
#[server(input = Json)]
pub async fn discard_changes() -> Result<Pending, ServerFnError> {
    let b = imp::backend()?;
    b.discard().await.map_err(imp::err)?;
    b.pending().await.map_err(imp::err)
}

/// Rolls back to a revision. A plain form post: works without JavaScript.
#[server(endpoint = "rollback_to")]
pub async fn rollback_to(revision: u64) -> Result<(), ServerFnError> {
    imp::backend()?
        .rollback(&imp::user(), revision)
        .await
        .map_err(imp::err)?;
    leptos_axum::redirect("/ui/core/backup/history");
    Ok(())
}

/// Live dashboard data.
#[server(input = Json)]
pub async fn live_status() -> Result<SystemStatus, ServerFnError> {
    imp::backend()?.status().await.map_err(imp::err)
}

/// Session cookie name.
pub const SESSION_COOKIE: &str = "sensr_session";

/// Login form target. A plain form post: works without JavaScript.
#[server(endpoint = "login")]
pub async fn login(username: String, password: String) -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header::SET_COOKIE};
    let b = imp::backend()?;
    match b.login(username.trim(), &password).await {
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

/// Logout form target.
#[server(endpoint = "logout")]
pub async fn logout() -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header::SET_COOKIE};
    if let Some(token) = crate::server::session_token() {
        let _ = imp::backend()?.logout(&token).await;
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
#[server(input = Json)]
pub async fn chrome_data() -> Result<LayoutData, ServerFnError> {
    use serde_json::Value;
    let b = imp::backend()?;
    let rows = imp::load_list("interfaces").await?;
    let interfaces = rows
        .iter()
        .map(|r| {
            let s = |k: &str| {
                r.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            crate::menu::MenuInterface {
                id: s("id"),
                description: if s("description").is_empty() {
                    s("id").to_uppercase()
                } else {
                    s("description")
                },
                dhcp_capable: s("ipv4_type") == "static",
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
#[server(input = Json)]
pub async fn form_load(
    form: FormId,
    scope: Option<String>,
) -> Result<serde_json::Value, ServerFnError> {
    use crate::models::Location;
    use serde_json::Value;
    let b = imp::backend()?;
    let v = match form.location(&scope) {
        Location::Path(p) => b.get(&p).await.map_err(imp::err)?,
        Location::Item { list, key, value } => imp::load_list(&list)
            .await?
            .into_iter()
            .find(|r| r.get(key).and_then(Value::as_str) == Some(&value))
            .ok_or_else(|| ServerFnError::new(format!("{value} not found")))?,
    };
    Ok(v)
}

/// Commit history, newest first.
#[server(input = Json)]
pub async fn revisions() -> Result<Vec<crate::api::Revision>, ServerFnError> {
    imp::backend()?.history().await.map_err(imp::err)
}

/// Diff between revisions; `to = None` is the staged document.
#[server(input = Json)]
pub async fn revision_diff(
    from: u64,
    to: Option<u64>,
) -> Result<Vec<crate::api::DiffLine>, ServerFnError> {
    imp::backend()?.diff(from, to).await.map_err(imp::err)
}
