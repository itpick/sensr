//! Islands: the only parts of the UI that hydrate. Everything else is server-rendered HTML.
//!
//! Islands share one wasm instance, so a mutation in a grid can nudge the Apply banner
//! through [`bump`] without either knowing about the other.

use crate::actions::*;
use crate::api::{DiffKind, FieldError, GatewayHealth, Pending, SystemStatus};
use crate::form::{Choices, FieldKind, FieldSpec, Inputs, to_inputs};
use crate::grid::{ColumnKind, GridPage, GridQuery, SortDir, cell_text};
use crate::models::{FormId, GridId};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::Value;
use std::collections::BTreeSet;

thread_local! {
    static PENDING_BUMP: ArcRwSignal<u64> = ArcRwSignal::new(0);
}

/// Tells the Apply banner that staged state changed.
pub fn bump() {
    PENDING_BUMP.with(|s| s.update(|n| *n += 1));
}

fn bump_signal() -> ArcRwSignal<u64> {
    PENDING_BUMP.with(Clone::clone)
}

/// Counts hydrated islands on `<html data-islands>`; the browser tests time interactivity
/// from it.
fn mark_hydrated() {
    Effect::new(|_| {
        #[cfg(feature = "hydrate")]
        if let Some(root) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.document_element())
        {
            let n: u32 = root
                .get_attribute("data-islands")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let _ = root.set_attribute("data-islands", &(n + 1).to_string());
        }
    });
}

#[allow(unused_variables)]
fn reload_page() {
    #[cfg(feature = "hydrate")]
    if let Some(w) = web_sys::window() {
        let _ = w.location().reload();
    }
}

// ------------------------------------------------------------------ top bar

/// Light/dark switch. Stores the choice in a cookie so the server renders the right theme on
/// the next load (no flash).
#[island]
pub fn ThemeToggle(initial: Option<String>) -> impl IntoView {
    mark_hydrated();
    let dark = RwSignal::new(initial.as_deref() == Some("dark"));
    let toggle = move |_| {
        let next = !dark.get_untracked();
        dark.set(next);
        #[cfg(feature = "hydrate")]
        {
            use wasm_bindgen::JsCast;
            let theme = if next { "dark" } else { "light" };
            if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                if let Some(root) = doc.document_element() {
                    let _ = root.set_attribute("data-theme", theme);
                }
                if let Ok(html) = doc.dyn_into::<web_sys::HtmlDocument>() {
                    let _ = html.set_cookie(&format!(
                        "sensr_theme={theme}; Path=/; Max-Age=31536000; SameSite=Strict"
                    ));
                }
            }
        }
    };
    view! {
        <button
            type="button"
            class="icon-btn"
            aria-pressed=move || dark.get().to_string()
            title=move || if dark.get() { "Switch to light theme" } else { "Switch to dark theme" }
            on:click=toggle
        >
            <span class="sr-only">"Dark theme"</span>
            <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true">
                <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zm0 1.5v10a5 5 0 0 1 0-10z" fill="currentColor"/>
            </svg>
        </button>
    }
}

/// Opens and closes the menu on narrow screens.
#[island]
pub fn NavToggle() -> impl IntoView {
    mark_hydrated();
    let open = RwSignal::new(false);
    let toggle = move |_| {
        let next = !open.get_untracked();
        open.set(next);
        #[cfg(feature = "hydrate")]
        if let Some(body) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.body())
        {
            let _ = body.class_list().toggle_with_force("nav-open", next);
        }
    };
    view! {
        <button
            type="button"
            class="icon-btn nav-toggle"
            aria-controls="sidebar"
            aria-expanded=move || open.get().to_string()
            on:click=toggle
        >
            <span class="sr-only">"Menu"</span>
            <svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true">
                <path d="M2 4h12M2 8h12M2 12h12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
            </svg>
        </button>
    }
}

// ------------------------------------------------------------------ apply banner

/// The pending-changes banner with commit-confirm.
#[island]
pub fn ApplyBanner(initial: Pending) -> impl IntoView {
    mark_hydrated();
    let state = RwSignal::new(initial.clone());
    // Seconds left in a confirm window, counted locally from the server's clock.
    let left = RwSignal::new(
        initial
            .confirm
            .as_ref()
            .map(|w| w.deadline.saturating_sub(initial.now)),
    );
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let with_rollback = RwSignal::new(true);

    let set_state = move |p: Pending| {
        left.set(p.confirm.as_ref().map(|w| w.deadline.saturating_sub(p.now)));
        state.set(p);
    };

    let bumps = bump_signal();
    Effect::new(move |prev: Option<u64>| {
        let n = bumps.get();
        if prev.is_some_and(|p| p != n) {
            spawn_local(async move {
                if let Ok(p) = pending_state().await {
                    set_state(p);
                }
            });
        }
        n
    });

    Effect::new(move |_| {
        set_interval(
            move || {
                if let Some(n) = left.get_untracked() {
                    if n <= 1 {
                        // The backend has rolled back; show the restored config.
                        left.set(Some(0));
                        reload_page();
                    } else {
                        left.set(Some(n - 1));
                    }
                }
            },
            std::time::Duration::from_secs(1),
        );
    });

    let run = move |reload: bool,
                    fut: std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Pending, ServerFnError>>>,
    >| {
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match fut.await {
                Ok(p) => {
                    set_state(p);
                    if reload {
                        reload_page();
                    }
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="banner-slot" role="region" aria-label="Pending changes" aria-live="polite">
            {move || state.get().alert.map(|a| view! {
                <div class="banner banner-warn" role="alert">
                    <p><strong>"First-boot seed: "</strong>{a}</p>
                </div>
            })}
            {move || {
                let p = state.get();
                if let Some(w) = p.confirm.clone() {
                    let secs = left.get().unwrap_or(0);
                    view! {
                        <div class="banner banner-warn">
                            <p>
                                <strong>{format!("Revision {} is active on probation. ", w.revision)}</strong>
                                {format!("It rolls back automatically in {secs} s unless you keep it.")}
                            </p>
                            <div class="banner-actions">
                                <button class="btn btn-primary" disabled=move || busy.get()
                                    on:click=move |_| run(false, Box::pin(confirm_changes()))>"Keep changes"</button>
                                <button class="btn" disabled=move || busy.get()
                                    on:click=move |_| run(true, Box::pin(revert_unconfirmed()))>"Roll back now"</button>
                            </div>
                        </div>
                    }.into_any()
                } else if p.dirty() {
                    view! {
                        <div class="banner banner-info">
                            <p>
                                "The configuration has been changed. You must apply the changes in order for them to take effect."
                                <span class="muted">{format!(" Changed: {}.", p.changed.join(", "))}</span>
                            </p>
                            <div class="banner-actions">
                                <label class="inline-check">
                                    <input type="checkbox" prop:checked=move || with_rollback.get()
                                        on:change=move |ev| with_rollback.set(event_target_checked(&ev))/>
                                    "Roll back unless confirmed within 60 s"
                                </label>
                                <button class="btn btn-primary" disabled=move || busy.get()
                                    on:click=move |_| {
                                        let secs = with_rollback.get_untracked().then_some(60);
                                        run(false, Box::pin(apply_changes(secs)))
                                    }>"Apply"</button>
                                <a class="btn" href="/ui/core/backup/history?to=staged">"Show changes"</a>
                                <button class="btn btn-ghost" disabled=move || busy.get()
                                    on:click=move |_| run(true, Box::pin(discard_changes()))>"Discard"</button>
                            </div>
                        </div>
                    }.into_any()
                } else {
                    ().into_any()
                }
            }}
            {move || error.get().map(|e| view! { <p class="banner banner-error" role="alert">{e}</p> })}
        </div>
    }
}

// ------------------------------------------------------------------ form fields

/// Inputs for `fields`, bound to `values`, showing `errors` under the matching field.
#[component]
pub fn FormFields(
    fields: &'static [FieldSpec],
    form_id: String,
    values: RwSignal<Inputs>,
    errors: RwSignal<Vec<FieldError>>,
    /// Runtime option lists for [`FieldKind::Choice`] fields.
    #[prop(optional)]
    choices: Choices,
) -> impl IntoView {
    fields
        .iter()
        .map(|f| {
            let path = f.path;
            let id = f.dom_id(&form_id);
            let help_id = format!("{id}-help");
            let err_id = format!("{id}-err");
            let err = move || {
                errors.with(|e| e.iter().find(|x| x.path == path).map(|x| x.message.clone()))
            };
            let described = {
                let (h, e) = (help_id.clone(), err_id.clone());
                let has_help = !f.help.is_empty();
                move || {
                    let mut ids = Vec::new();
                    if has_help {
                        ids.push(h.clone());
                    }
                    if err().is_some() {
                        ids.push(e.clone());
                    }
                    (!ids.is_empty()).then(|| ids.join(" "))
                }
            };
            let invalid = move || err().is_some().then_some("true");
            let get = move || values.with(|v| v.get(path).cloned().unwrap_or_default());
            let set = move |s: String| values.update(|v| {
                v.insert(path.to_owned(), s);
            });
            let required = f.required;
            let input = match f.kind {
                FieldKind::Checkbox => view! {
                    <input type="checkbox" id=id.clone() aria-describedby=described aria-invalid=invalid
                        prop:checked=move || get() == "true"
                        on:change=move |ev| set(event_target_checked(&ev).to_string())/>
                }
                .into_any(),
                FieldKind::Select(options) => view! {
                    <select id=id.clone() aria-describedby=described aria-invalid=invalid required=required
                        prop:value=get
                        on:change=move |ev| set(event_target_value(&ev))>
                        {options.iter().map(|(v, l)| view! {
                            <option value=*v selected=move || get() == *v>{*l}</option>
                        }).collect_view()}
                    </select>
                }
                .into_any(),
                FieldKind::Choice(choice_set) => {
                    let mut options = choices.get(&choice_set).cloned().unwrap_or_default();
                    // Keep a stored value selectable even if it is not (or no longer) listed.
                    let current = get();
                    if !current.is_empty() && !options.iter().any(|(v, _)| *v == current) {
                        options.push((current.clone(), current));
                    }
                    view! {
                        <select id=id.clone() aria-describedby=described aria-invalid=invalid required=required
                            prop:value=get
                            on:change=move |ev| set(event_target_value(&ev))>
                            {options.into_iter().map(|(v, l)| {
                                let v2 = v.clone();
                                view! { <option value=v selected=move || get() == v2>{l}</option> }
                            }).collect_view()}
                        </select>
                    }
                    .into_any()
                }
                FieldKind::MultiSelect(groups) => {
                    let label_id = format!("{id}-label");
                    let groups_view = groups
                        .iter()
                        .map(|(group, opts)| {
                            let boxes = opts
                                .iter()
                                .map(|(v, l)| {
                                    let v: &'static str = v;
                                    let has = move || get().lines().any(|x| x.trim() == v);
                                    let toggle = move |ev| {
                                        let on = event_target_checked(&ev);
                                        let mut cur: Vec<String> = get()
                                            .lines()
                                            .map(str::trim)
                                            .filter(|x| !x.is_empty() && *x != v)
                                            .map(str::to_owned)
                                            .collect();
                                        if on {
                                            cur.push(v.to_owned());
                                        }
                                        set(cur.join("\n"));
                                    };
                                    view! {
                                        <label class="multi-opt">
                                            <input type="checkbox" value=v prop:checked=has checked=has() on:change=toggle/>
                                            <span>{*l}</span>
                                        </label>
                                    }
                                })
                                .collect_view();
                            view! {
                                <fieldset class="multi-group">
                                    <legend>{*group}</legend>
                                    {boxes}
                                </fieldset>
                            }
                        })
                        .collect_view();
                    view! {
                        <div class="multi" id=id.clone() role="group" aria-labelledby=label_id
                            aria-describedby=described aria-invalid=invalid>
                            {groups_view}
                        </div>
                    }
                    .into_any()
                }
                FieldKind::Lines
                | FieldKind::CidrLines
                | FieldKind::IpLines
                | FieldKind::HostnameLines
                | FieldKind::ListedNameLines
                | FieldKind::TextArea => view! {
                    <textarea id=id.clone() rows="3" aria-describedby=described aria-invalid=invalid required=required
                        prop:value=get
                        on:input=move |ev| set(event_target_value(&ev))>{get()}</textarea>
                }
                .into_any(),
                FieldKind::Secret => view! {
                    <input type="password" id=id.clone() autocomplete="new-password" placeholder="(unchanged)"
                        aria-describedby=described aria-invalid=invalid
                        prop:value=get on:input=move |ev| set(event_target_value(&ev))/>
                }
                .into_any(),
                kind => {
                    let mode = match kind {
                        FieldKind::Number { .. } => "numeric",
                        FieldKind::Ip | FieldKind::Ipv4 | FieldKind::Cidr => "decimal",
                        _ => "text",
                    };
                    view! {
                        <input type="text" id=id.clone() inputmode=mode spellcheck="false" required=required
                            aria-describedby=described aria-invalid=invalid
                            prop:value=get value=get() on:input=move |ev| set(event_target_value(&ev))/>
                    }
                    .into_any()
                }
            };
            let check = matches!(f.kind, FieldKind::Checkbox);
            let req_mark = required.then(|| view! { <span class="req" aria-hidden="true">" *"</span> });
            // A group of checkboxes has no single control to point a <label for> at.
            let label = if matches!(f.kind, FieldKind::MultiSelect(_)) {
                view! { <span class="field-label" id=format!("{id}-label")>{f.label}{req_mark}</span> }.into_any()
            } else {
                view! { <label for=id.clone()>{f.label}{req_mark}</label> }.into_any()
            };
            view! {
                <div class="field" class:field-check=check class:has-error=move || err().is_some()>
                    {label}
                    <div class="control">
                        {input}
                        {(!f.help.is_empty()).then(|| view! { <p class="help" id=help_id.clone()>{f.help}</p> })}
                        {move || err().map(|m| view! { <p class="field-error" id=err_id.clone()>{m}</p> })}
                    </div>
                </div>
            }
        })
        .collect_view()
}

fn general_errors(
    errors: RwSignal<Vec<FieldError>>,
    fields: &'static [FieldSpec],
) -> impl IntoView {
    move || {
        errors.with(|e| {
            e.iter()
                .filter(|x| !fields.iter().any(|f| f.path == x.path))
                .map(|x| view! { <p class="field-error" role="alert">{x.message.clone()}</p> })
                .collect_view()
        })
    }
}

// ------------------------------------------------------------------ settings form

/// A generated settings form (`<SettingsForm<T>>` renders this with `T`'s id).
#[island]
pub fn SettingsFormIsland(
    form: FormId,
    scope: Option<String>,
    initial: Value,
    choices: Choices,
) -> impl IntoView {
    mark_hydrated();
    let fields = form.fields();
    let values = RwSignal::new(to_inputs(fields, &initial));
    let errors = RwSignal::new(Vec::<FieldError>::new());
    let status = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let form_dom = format!("form-{form:?}").to_lowercase();
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let inputs = values.get_untracked();
        // Instant feedback; the server checks again against the stored value.
        if let Err(e) = form.apply(&initial, &inputs) {
            errors.set(e);
            status.set("Please correct the highlighted fields.".into());
            return;
        }
        busy.set(true);
        let scope = scope.clone();
        spawn_local(async move {
            match form_save(form, scope, inputs).await {
                Ok(e) if e.is_empty() => {
                    errors.set(vec![]);
                    status.set("Saved. Apply the changes to activate them.".into());
                    bump();
                }
                Ok(e) => {
                    errors.set(e);
                    status.set("Please correct the highlighted fields.".into());
                }
                Err(e) => status.set(format!("Could not save: {e}")),
            }
            busy.set(false);
        });
    };
    view! {
        <form class="settings-form" id=form_dom.clone() on:submit=submit novalidate>
            {general_errors(errors, fields)}
            <FormFields fields form_id=form_dom.clone() values errors choices/>
            <div class="form-actions">
                <button type="submit" class="btn btn-primary" disabled=move || busy.get()>"Save"</button>
                <p class="status" role="status">{move || status.get()}</p>
            </div>
        </form>
    }
}

// ------------------------------------------------------------------ grid

const ICON_EDIT: &str = "M11 2.5l2.5 2.5L6 12.5H3.5V10zM9.5 4l2.5 2.5";
const ICON_TRASH: &str = "M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.7 9h5.6l.7-9M7 7v4.5M9 7v4.5";
const ICON_UP: &str = "M8 13V3M4 7l4-4 4 4";
const ICON_DOWN: &str = "M8 3v10M4 9l4 4 4-4";
const ICON_GRIP: &str = "M6 3.5h.01M10 3.5h.01M6 8h.01M10 8h.01M6 12.5h.01M10 12.5h.01";

fn icon(d: &'static str) -> impl IntoView {
    view! {
        <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
            <path d=d fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[derive(Clone, PartialEq)]
enum Editing {
    Closed,
    New,
    Row(String, Value),
}

/// A searchable, sortable, paged grid with bulk actions and an add/edit dialog.
#[island]
pub fn GridIsland(
    grid: GridId,
    scope: Option<String>,
    initial: GridPage,
    label: String,
    choices: Choices,
) -> impl IntoView {
    mark_hydrated();
    let meta = grid.meta();
    let columns = meta.columns;
    let fields = meta.fields;
    let key_field = meta.key;
    let toggle = meta.toggle;
    let ordered = meta.ordered;

    let query = RwSignal::new(GridQuery {
        per_page: initial.per_page,
        ..Default::default()
    });
    let page = RwSignal::new(initial);
    let selected = RwSignal::new(BTreeSet::<String>::new());
    let status = RwSignal::new(String::new());
    let editing = RwSignal::new(Editing::Closed);
    let values = RwSignal::new(Inputs::new());
    let errors = RwSignal::new(Vec::<FieldError>::new());
    let dragging = RwSignal::new(None::<String>);
    let dialog_ref = NodeRef::<leptos::html::Dialog>::new();
    let dom_id = format!("grid-{grid:?}").to_lowercase();
    let scope = StoredValue::new(scope);
    let choice_lists = StoredValue::new(choices.clone());

    let key_of = move |row: &Value| {
        row.get(key_field)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    let refresh = move || {
        let q = query.get_untracked();
        spawn_local(async move {
            match grid_fetch(grid, scope.get_value(), q).await {
                Ok(p) => {
                    selected.update(|s| s.retain(|k| p.rows.iter().any(|r| key_of(r) == *k)));
                    page.set(p);
                }
                Err(e) => status.set(format!("Could not load: {e}")),
            }
        });
    };

    let after_change = move |msg: String| {
        status.set(msg);
        bump();
        refresh();
    };

    let open_dialog = move |e: Editing| {
        let base = match &e {
            Editing::Row(_, v) => v.clone(),
            _ => grid.new_row(),
        };
        let mut inputs = to_inputs(fields, &base);
        // Runtime selects start on the grid's scope (the interface tab) or the first option.
        for f in fields {
            if let FieldKind::Choice(set) = f.kind
                && inputs.get(f.path).is_none_or(String::is_empty)
            {
                let first = choice_lists
                    .with_value(|c| c.get(&set).and_then(|o| o.first()).map(|o| o.0.clone()));
                let pick = scope
                    .get_value()
                    .filter(|s| !s.is_empty())
                    .or(first)
                    .unwrap_or_default();
                inputs.insert(f.path.to_owned(), pick);
            }
        }
        values.set(inputs);
        errors.set(vec![]);
        editing.set(e);
        #[cfg(feature = "hydrate")]
        if let Some(d) = dialog_ref.get_untracked() {
            let _ = d.show_modal();
        }
    };
    let close_dialog = move || {
        editing.set(Editing::Closed);
        #[cfg(feature = "hydrate")]
        if let Some(d) = dialog_ref.get_untracked() {
            d.close();
        }
    };

    let save = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let (key, base) = match editing.get_untracked() {
            Editing::Row(k, v) => (Some(k), v),
            Editing::New => (None, grid.new_row()),
            Editing::Closed => return,
        };
        let inputs = values.get_untracked();
        if let Err(e) = grid.apply(&base, &inputs) {
            errors.set(e);
            return;
        }
        spawn_local(async move {
            match grid_save(grid, scope.get_value(), key.clone(), inputs).await {
                Ok(e) if e.is_empty() => {
                    close_dialog();
                    after_change(if key.is_some() { "Saved." } else { "Added." }.into());
                }
                Ok(e) => errors.set(e),
                Err(e) => errors.set(vec![FieldError::new("", e.to_string())]),
            }
        });
    };

    let bulk_toggle = move |enabled: bool| {
        let keys: Vec<String> = selected.get_untracked().into_iter().collect();
        if keys.is_empty() {
            return;
        }
        spawn_local(async move {
            match grid_toggle(grid, scope.get_value(), keys, enabled).await {
                Ok(n) => after_change(format!(
                    "{n} {} {}.",
                    if n == 1 { "row" } else { "rows" },
                    if enabled { "enabled" } else { "disabled" }
                )),
                Err(e) => status.set(e.to_string()),
            }
        });
    };
    let remove = move |keys: Vec<String>| {
        if keys.is_empty() {
            return;
        }
        #[cfg(feature = "hydrate")]
        {
            let msg = format!("Delete {} selected item(s)?", keys.len());
            if !web_sys::window()
                .and_then(|w| w.confirm_with_message(&msg).ok())
                .unwrap_or(false)
            {
                return;
            }
        }
        spawn_local(async move {
            match grid_delete(grid, scope.get_value(), keys).await {
                Ok(n) => after_change(format!("{n} deleted.")),
                Err(e) => status.set(e.to_string()),
            }
        });
    };
    let move_row = move |key: String, before: Option<String>| {
        spawn_local(async move {
            match grid_move(grid, scope.get_value(), key, before).await {
                Ok(()) => after_change("Order changed.".into()),
                Err(e) => status.set(e.to_string()),
            }
        });
    };

    let can_reorder =
        move || ordered && query.with(GridQuery::is_natural_order) && page.with(|p| p.pages() == 1);

    let sort_by = move |path: &'static str| {
        query.update(|q| {
            q.sort = match &q.sort {
                Some((p, SortDir::Asc)) if p == path => Some((path.to_owned(), SortDir::Desc)),
                Some((p, SortDir::Desc)) if p == path => None,
                _ => Some((path.to_owned(), SortDir::Asc)),
            };
        });
        refresh();
    };

    let all_selected = move || {
        page.with(|p| {
            !p.rows.is_empty()
                && p.rows
                    .iter()
                    .all(|r| selected.with(|s| s.contains(&key_of(r))))
        })
    };

    let header = columns
        .iter()
        .map(|c| {
            let path = c.path;
            let aria = move || {
                query.with(|q| match &q.sort {
                    Some((p, SortDir::Asc)) if p == path => "ascending",
                    Some((p, SortDir::Desc)) if p == path => "descending",
                    _ => "none",
                })
            };
            let arrow = move || match aria() {
                "ascending" => "▲",
                "descending" => "▼",
                _ => "",
            };
            view! {
                <th scope="col" aria-sort=aria>
                    <button type="button" class="th-sort" on:click=move |_| sort_by(path)>
                        {c.label}<span class="sort-arrow" aria-hidden="true">{arrow}</span>
                    </button>
                </th>
            }
        })
        .collect_view();

    let rows = move || {
        let p = page.get();
        let n = p.rows.len();
        let reorder = can_reorder();
        if n == 0 {
            return view! { <tr><td class="empty" colspan={columns.len() + 2}>"No items."</td></tr> }.into_any();
        }
        let keys: Vec<String> = p.rows.iter().map(key_of).collect();
        p.rows.into_iter().enumerate().map(|(i, row)| {
            let key = key_of(&row);
            let k_sel = key.clone();
            let k_chk = key.clone();
            let enabled = toggle.map(|t| row.get(t) != Some(&Value::Bool(false))).unwrap_or(true);
            let label_txt = columns.iter().find(|c| c.kind == ColumnKind::Text).map(|c| cell_text(&row, c)).unwrap_or_default();
            let edit_row = row.clone();
            let k_edit = key.clone();
            let k_del = key.clone();
            let up = (i > 0).then(|| keys[i - 1].clone());
            let down_before = if i + 2 < n { Some(keys[i + 2].clone()) } else { None };
            let is_last = i + 1 == n;
            let (k_up, k_down) = (key.clone(), key.clone());
            let (k_drag, k_drop) = (key.clone(), key.clone());
            let cells = columns.iter().map(|c| {
                let txt = cell_text(&row, c);
                match c.kind {
                    ColumnKind::Bool => {
                        let on = txt == "yes";
                        view! { <td><span class=if on { "pill pill-on" } else { "pill pill-off" }>{if on { "on" } else { "off" }}</span></td> }.into_any()
                    }
                    _ => view! { <td>{txt}</td> }.into_any(),
                }
            }).collect_view();
            view! {
                <tr class:disabled=!enabled
                    draggable=move || if reorder { "true" } else { "false" }
                    on:dragstart=move |_| dragging.set(Some(k_drag.clone()))
                    on:dragover=move |ev| if reorder { ev.prevent_default() }
                    on:drop=move |ev| {
                        ev.prevent_default();
                        if let Some(from) = dragging.get_untracked() && from != k_drop {
                            dragging.set(None);
                            move_row(from, Some(k_drop.clone()));
                        }
                    }>
                    <td class="col-select">
                        <input type="checkbox" aria-label=format!("Select {label_txt}")
                            prop:checked=move || selected.with(|s| s.contains(&k_chk))
                            on:change=move |ev| {
                                let on = event_target_checked(&ev);
                                selected.update(|s| { if on { s.insert(k_sel.clone()); } else { s.remove(&k_sel); } });
                            }/>
                    </td>
                    {cells}
                    <td class="col-actions">
                        {reorder.then(|| view! {
                            <span class="drag-handle" aria-hidden="true" title="Drag to reorder">{icon(ICON_GRIP)}</span>
                            <button type="button" class="icon-btn" aria-label="Move up" disabled=up.is_none()
                                on:click=move |_| if let Some(b) = up.clone() { move_row(k_up.clone(), Some(b)) }>{icon(ICON_UP)}</button>
                            <button type="button" class="icon-btn" aria-label="Move down" disabled=is_last
                                on:click=move |_| move_row(k_down.clone(), down_before.clone())>{icon(ICON_DOWN)}</button>
                        })}
                        <button type="button" class="icon-btn" aria-label="Edit"
                            on:click=move |_| open_dialog(Editing::Row(k_edit.clone(), edit_row.clone()))>{icon(ICON_EDIT)}</button>
                        <button type="button" class="icon-btn danger" aria-label="Delete"
                            on:click=move |_| remove(vec![k_del.clone()])>{icon(ICON_TRASH)}</button>
                    </td>
                </tr>
            }
        }).collect_view().into_any()
    };

    let pager = move || {
        let p = page.get();
        let first = if p.total == 0 {
            0
        } else {
            p.page * p.per_page + 1
        };
        let last = (p.page * p.per_page + p.rows.len()).min(p.total);
        let pages = p.pages();
        let cur = p.page;
        view! {
            <div class="pager">
                <span class="muted">{format!("Showing {first} to {last} of {} entries", p.total)}</span>
                <div class="pager-buttons">
                    <label class="inline">
                        <span class="sr-only">"Rows per page"</span>
                        <select prop:value=move || query.with(|q| q.per_page.to_string())
                            on:change=move |ev| {
                                let n = event_target_value(&ev).parse().unwrap_or(25);
                                query.update(|q| { q.per_page = n; q.page = 0; });
                                refresh();
                            }>
                            {[10usize, 25, 50, 100].into_iter().map(|n| view! { <option value=n.to_string() selected={n == p.per_page}>{n}</option> }).collect_view()}
                        </select>
                    </label>
                    <button type="button" class="btn btn-sm" disabled={cur == 0} aria-label="Previous page"
                        on:click=move |_| { query.update(|q| q.page = cur.saturating_sub(1)); refresh(); }>"‹"</button>
                    <span aria-current="page">{format!("{} / {pages}", cur + 1)}</span>
                    <button type="button" class="btn btn-sm" disabled={cur + 1 >= pages} aria-label="Next page"
                        on:click=move |_| { query.update(|q| q.page = cur + 1); refresh(); }>"›"</button>
                </div>
            </div>
        }
    };

    let label_for_aria = label.clone();
    let dialog_title = move || match editing.get() {
        Editing::New => format!("Add {label}"),
        _ => format!("Edit {label}"),
    };

    view! {
        <div class="grid" id=dom_id.clone()>
            <div class="grid-toolbar">
                <label class="search">
                    <span class="sr-only">{format!("Search {label_for_aria}")}</span>
                    <input type="search" placeholder="Search"
                        prop:value=move || query.with(|q| q.search.clone())
                        on:input=move |ev| {
                            let s = event_target_value(&ev);
                            query.update(|q| { q.search = s; q.page = 0; });
                            refresh();
                        }/>
                </label>
                <div class="toolbar-buttons">
                    {toggle.map(|_| view! {
                        <button type="button" class="btn btn-sm" disabled=move || selected.with(BTreeSet::is_empty)
                            on:click=move |_| bulk_toggle(true)>"Enable"</button>
                        <button type="button" class="btn btn-sm" disabled=move || selected.with(BTreeSet::is_empty)
                            on:click=move |_| bulk_toggle(false)>"Disable"</button>
                    })}
                    <button type="button" class="btn btn-sm" disabled=move || selected.with(BTreeSet::is_empty)
                        on:click=move |_| remove(selected.get_untracked().into_iter().collect())>"Delete"</button>
                    <button type="button" class="btn btn-sm btn-primary" on:click=move |_| open_dialog(Editing::New)>
                        <span aria-hidden="true">"+ "</span>"Add"
                    </button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th scope="col" class="col-select">
                                <input type="checkbox" aria-label="Select all"
                                    prop:checked=all_selected
                                    on:change=move |ev| {
                                        let on = event_target_checked(&ev);
                                        let keys: Vec<String> = page.with_untracked(|p| p.rows.iter().map(key_of).collect());
                                        selected.update(|s| for k in keys { if on { s.insert(k); } else { s.remove(&k); } });
                                    }/>
                            </th>
                            {header}
                            <th scope="col" class="col-actions"><span class="sr-only">"Actions"</span></th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            {pager}
            <p class="status" role="status">{move || status.get()}</p>
            <dialog node_ref=dialog_ref class="modal" aria-labelledby=format!("{dom_id}-title")
                on:close=move |_| editing.set(Editing::Closed)>
                <form on:submit=save novalidate>
                    <header class="modal-head">
                        <h2 id=format!("{dom_id}-title")>{dialog_title}</h2>
                        <button type="button" class="icon-btn" aria-label="Close" on:click=move |_| close_dialog()>"✕"</button>
                    </header>
                    <div class="modal-body">
                        {general_errors(errors, fields)}
                        <FormFields fields form_id=format!("{dom_id}-dlg") values errors choices=choices.clone()/>
                    </div>
                    <footer class="modal-foot">
                        <button type="button" class="btn" on:click=move |_| close_dialog()>"Cancel"</button>
                        <button type="submit" class="btn btn-primary">"Save"</button>
                    </footer>
                </form>
            </dialog>
        </div>
    }
}

// ------------------------------------------------------------------ dashboard

fn bps(v: u64) -> String {
    let v = v as f64;
    if v >= 1e9 {
        format!("{:.2} Gbit/s", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.1} Mbit/s", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.0} kbit/s", v / 1e3)
    } else {
        format!("{v:.0} bit/s")
    }
}

fn bytes(v: u64) -> String {
    format!("{:.1} GiB", v as f64 / 1_073_741_824.0)
}

fn uptime(s: u64) -> String {
    format!(
        "{} days {:02}:{:02}:{:02}",
        s / 86_400,
        s / 3_600 % 24,
        s / 60 % 60,
        s % 60
    )
}

fn sparkline(rx: &[u64], tx: &[u64]) -> impl IntoView + use<> {
    let max = rx.iter().chain(tx).copied().max().unwrap_or(1).max(1) as f64;
    let pts = |s: &[u64]| {
        let n = s.len().max(2) - 1;
        s.iter()
            .enumerate()
            .map(|(i, v)| {
                format!(
                    "{:.1},{:.1}",
                    i as f64 * 300.0 / n as f64,
                    60.0 - *v as f64 / max * 56.0
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let (rx_pts, tx_pts) = (pts(rx), pts(tx));
    view! {
        <svg class="spark" viewBox="0 0 300 60" preserveAspectRatio="none" role="img" aria-label="Traffic over the last two minutes">
            <polyline points=rx_pts class="spark-rx" fill="none"/>
            <polyline points=tx_pts class="spark-tx" fill="none"/>
        </svg>
    }
}

/// The dashboard widgets, refreshed every few seconds.
#[island]
pub fn DashboardLive(initial: SystemStatus) -> impl IntoView {
    mark_hydrated();
    let st = RwSignal::new(initial);
    Effect::new(move |_| {
        set_interval(
            move || {
                spawn_local(async move {
                    if let Ok(s) = live_status().await {
                        st.set(s);
                    }
                });
            },
            std::time::Duration::from_secs(3),
        );
    });
    view! {
        <div class="dashboard">
            <section class="card" aria-labelledby="w-sys">
                <h2 id="w-sys">"System information"</h2>
                <dl class="kv">
                    <dt>"Name"</dt><dd>{move || st.with(|s| s.hostname.clone())}</dd>
                    <dt>"Version"</dt><dd>{move || st.with(|s| s.version.clone())}</dd>
                    <dt>"Kernel"</dt><dd>{move || st.with(|s| s.kernel.clone())}</dd>
                    <dt>"CPU type"</dt><dd>{move || st.with(|s| s.cpu_model.clone())}</dd>
                    <dt>"Uptime"</dt><dd>{move || st.with(|s| uptime(s.uptime_secs))}</dd>
                    <dt>"Load average"</dt><dd>{move || st.with(|s| format!("{:.2}, {:.2}, {:.2}", s.load[0], s.load[1], s.load[2]))}</dd>
                </dl>
            </section>
            <section class="card" aria-labelledby="w-cpu">
                <h2 id="w-cpu">"CPU and memory"</h2>
                <div class="meter-row">
                    <span id="m-cpu">"CPU usage"</span>
                    <meter aria-labelledby="m-cpu" min="0" max="100" low="70" high="90" optimum="10"
                        value=move || st.with(|s| s.cpu_pct.to_string())></meter>
                    <span class="num">{move || st.with(|s| format!("{:.0} %", s.cpu_pct))}</span>
                </div>
                <div class="meter-row">
                    <span id="m-mem">"Memory usage"</span>
                    <meter aria-labelledby="m-mem" min="0" max="100" low="75" high="90" optimum="10"
                        value=move || st.with(|s| (s.mem_used as f64 / s.mem_total.max(1) as f64 * 100.0).to_string())></meter>
                    <span class="num">{move || st.with(|s| format!("{} / {}", bytes(s.mem_used), bytes(s.mem_total)))}</span>
                </div>
            </section>
            <section class="card card-wide" aria-labelledby="w-if">
                <h2 id="w-if">"Interfaces"</h2>
                <div class="table-wrap">
                <table>
                    <thead><tr><th scope="col">"Interface"</th><th scope="col">"Status"</th><th scope="col">"Address"</th><th scope="col">"In"</th><th scope="col">"Out"</th></tr></thead>
                    <tbody>
                        {move || st.with(|s| s.interfaces.iter().map(|i| view! {
                            <tr>
                                <td><strong>{i.name.clone()}</strong><span class="muted">{format!(" {}", i.device)}</span></td>
                                <td><span class=if i.up { "pill pill-on" } else { "pill pill-off" }>{if i.up { "up" } else { "down" }}</span>
                                    {i.speed_mbps.map(|m| view! { <span class="muted">{format!(" {m} Mbit/s")}</span> })}</td>
                                <td>{i.ipv4.clone().unwrap_or_default()}<br/><span class="muted">{i.ipv6.clone().unwrap_or_default()}</span></td>
                                <td class="num">{bps(i.rx_bps)}</td>
                                <td class="num">{bps(i.tx_bps)}</td>
                            </tr>
                        }).collect_view())}
                    </tbody>
                </table>
                </div>
            </section>
            <section class="card" aria-labelledby="w-gw">
                <h2 id="w-gw">"Gateways"</h2>
                <table>
                    <thead><tr><th scope="col">"Name"</th><th scope="col">"RTT"</th><th scope="col">"Loss"</th><th scope="col">"Status"</th></tr></thead>
                    <tbody>
                        {move || st.with(|s| s.gateways.iter().map(|g| {
                            let (class, text) = match g.health {
                                GatewayHealth::Online => ("pill pill-on", "Online"),
                                GatewayHealth::Degraded => ("pill pill-warn", "Latency"),
                                GatewayHealth::Down => ("pill pill-off", "Offline"),
                            };
                            view! {
                                <tr>
                                    <td>{g.name.clone()}<br/><span class="muted">{g.address.clone()}</span></td>
                                    <td class="num">{format!("{:.1} ms", g.rtt_ms)}</td>
                                    <td class="num">{format!("{:.0} %", g.loss_pct)}</td>
                                    <td><span class=class>{text}</span></td>
                                </tr>
                            }
                        }).collect_view())}
                    </tbody>
                </table>
            </section>
            <section class="card card-wide" aria-labelledby="w-tr">
                <h2 id="w-tr">"Traffic"</h2>
                <p class="legend"><span class="key key-rx"></span>"In "<span class="key key-tx"></span>"Out"</p>
                <div class="traffic">
                    {move || st.with(|s| s.traffic.iter().map(|t| view! {
                        <figure>
                            <figcaption>{t.name.clone()}
                                <span class="muted">{format!(" in {} · out {}", bps(*t.rx.last().unwrap_or(&0)), bps(*t.tx.last().unwrap_or(&0)))}</span>
                            </figcaption>
                            {sparkline(&t.rx, &t.tx)}
                        </figure>
                    }).collect_view())}
                </div>
            </section>
        </div>
    }
}

/// Keeps `DiffKind` in the bundle's public surface for the history page CSS classes.
pub fn diff_class(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "diff-add",
        DiffKind::Removed => "diff-del",
        DiffKind::Context => "diff-ctx",
    }
}
