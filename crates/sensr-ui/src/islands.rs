//! Islands: the only parts of the UI that hydrate. Everything else is server-rendered HTML.
//!
//! Islands share one wasm instance, so a mutation in a grid can nudge the Apply banner
//! through [`bump`] without either knowing about the other.

use crate::actions::*;
use crate::api::{DiffKind, FieldError, Pending, SystemStatus, TrafficSeries};
pub use crate::chart::bps;
use crate::chart::{Sample, TrafficChart};
use crate::form::{Choices, FieldKind, FieldSpec, Inputs, to_inputs};
use crate::grid::{ColumnKind, GridPage, GridQuery, SortDir, cell_text};
use crate::models::{FormId, GridId};
use crate::runtime::{GatewayRow, GatewayState, GatewaysView, UpdateStatus, ms, pct, until};
use crate::search::{SearchGroup, SearchResults};
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

/// Sets the drawer state on the signal and the body class the CSS reacts to.
fn set_nav(open: RwSignal<bool>, next: bool) {
    open.set(next);
    #[cfg(feature = "hydrate")]
    if let Some(body) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.body())
    {
        let _ = body.class_list().toggle_with_force("nav-open", next);
    }
}

/// Opens and closes the menu on narrow screens.
#[island]
pub fn NavToggle() -> impl IntoView {
    mark_hydrated();
    let open = RwSignal::new(false);
    let toggle = move |_| set_nav(open, !open.get_untracked());
    // Escape, a menu link and a tap on the dimmed page behind the drawer all
    // close it, the way a phone menu is expected to behave.
    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::JsCast as _;
        let esc = window_event_listener(leptos::ev::keydown, move |ev| {
            if ev.key() == "Escape" && open.get_untracked() {
                set_nav(open, false);
            }
        });
        on_cleanup(move || drop(esc));
        let click = window_event_listener(leptos::ev::click, move |ev| {
            if !open.get_untracked() {
                return;
            }
            let Some(el) = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            else {
                return;
            };
            let hit = |sel: &str| el.closest(sel).ok().flatten().is_some();
            if hit("#sidebar a") || hit(".nav-scrim") {
                set_nav(open, false);
            }
        });
        on_cleanup(move || drop(click));
    }
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

// ------------------------------------------------------------------ global search

/// The "Show all" link of a group that has more matches than it shows.
fn gsearch_more(g: &SearchGroup) -> Option<&str> {
    g.more_url.as_deref().filter(|_| g.total > g.hits.len())
}

/// Where each option of `r` leads, in the order [`gsearch_results`] numbers them.
fn gsearch_urls(r: &SearchResults) -> Vec<String> {
    r.groups
        .iter()
        .flat_map(|g| {
            g.hits
                .iter()
                .map(|h| h.url.as_str())
                .chain(gsearch_more(g))
                .map(str::to_owned)
        })
        .collect()
}

/// The grouped options of the global search listbox, plain views from data: config text goes
/// in as text nodes and never becomes markup. Option `N` is `#gsearch-opt-N`; a click finds
/// its target in `data-url`.
pub fn gsearch_results(r: &SearchResults, active: Option<usize>) -> impl IntoView + use<> {
    let mut n = 0usize;
    r.groups
        .iter()
        .map(|g| {
            let options = g
                .hits
                .iter()
                .map(|h| (h.title.clone(), Some(h.detail.clone()), h.url.clone()))
                .chain(
                    gsearch_more(g)
                        .map(|u| (format!("Show all ({})", g.total), None, u.to_owned())),
                )
                .map(|(title, detail, url)| {
                    let i = n;
                    n += 1;
                    let more = detail.is_none();
                    view! {
                        <div role="option" id=format!("gsearch-opt-{i}") class="gsearch-opt"
                            class:gsearch-more=more aria-selected=(active == Some(i)).to_string()
                            data-url=url>
                            <span class="gsearch-title">{title}</span>
                            {detail.map(|d| view! { <span class="gsearch-detail">{d}</span> })}
                        </div>
                    }
                })
                .collect_view();
            view! {
                <div role="group" aria-label=g.name.clone() class="gsearch-group">
                    <div class="gsearch-head" aria-hidden="true">{g.name.clone()}</div>
                    {options}
                </div>
            }
        })
        .collect_view()
}

/// What the search box last got back: results or the server's message.
type Found = Option<Result<SearchResults, String>>;

/// The search box's state, shared by its handlers.
#[derive(Clone, Copy)]
struct Gs {
    query: RwSignal<String>,
    found: RwSignal<Found>,
    open: RwSignal<bool>,
    active: RwSignal<Option<usize>>,
    sheet: RwSignal<bool>,
    /// A request is out.
    busy: StoredValue<bool>,
    /// The debounce fired while one was out: ask again when it is back.
    again: StoredValue<bool>,
}

fn gsearch_short(q: &str) -> bool {
    q.trim().chars().count() < crate::search::MIN_QUERY
}

/// Asks the server for the current query: one request at a time, and a response for a query
/// that has changed since is dropped.
fn gsearch_fetch(s: Gs) {
    if s.busy.get_value() {
        s.again.set_value(true);
        return;
    }
    let q = s.query.get_untracked();
    if gsearch_short(&q) {
        return;
    }
    s.busy.set_value(true);
    spawn_local(async move {
        let r = global_search(q.clone()).await;
        s.busy.set_value(false);
        if s.query.get_untracked() == q {
            s.active.set(None);
            s.found.set(Some(
                r.map(|mut r| {
                    q.trim().clone_into(&mut r.query);
                    r
                })
                .map_err(|e| server_message(&e)),
            ));
        }
        if s.again.get_value() {
            s.again.set_value(false);
            gsearch_fetch(s);
        }
    });
}

/// Opens a hit. A full navigation, so the target page's own deep-link readers run; on the
/// page already open only the hash moves, and the settings form flashes on `hashchange`.
#[allow(unused_variables)]
fn gsearch_go(s: Gs, url: &str) {
    s.open.set(false);
    s.sheet.set(false);
    #[cfg(feature = "hydrate")]
    if let Some(w) = web_sys::window() {
        let loc = w.location();
        let here = format!(
            "{}{}",
            loc.pathname().unwrap_or_default(),
            loc.search().unwrap_or_default()
        );
        match url.split_once('#') {
            Some((page, hash)) if page == here => {
                if loc.hash().ok().as_deref() == Some(&format!("#{hash}")) {
                    // same hash: no event of its own, so send one
                    if let Ok(e) = web_sys::Event::new("hashchange") {
                        let _ = w.dispatch_event(&e);
                    }
                } else {
                    let _ = loc.set_hash(hash);
                }
            }
            _ => {
                let _ = loc.assign(url);
            }
        }
    }
}

/// Keeps the active option inside the scrolled dropdown.
#[allow(unused_variables)]
fn gsearch_reveal(i: usize) {
    #[cfg(feature = "hydrate")]
    request_animation_frame(move || {
        use wasm_bindgen::JsCast;
        let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
            return;
        };
        let (Some(pop), Some(opt)) = (
            doc.get_element_by_id("gsearch-pop"),
            doc.get_element_by_id(&format!("gsearch-opt-{i}"))
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok()),
        ) else {
            return;
        };
        let (top, h) = (opt.offset_top(), opt.offset_height());
        let (scroll, view) = (pop.scroll_top(), pop.client_height());
        if top < scroll {
            pop.set_scroll_top(top);
        } else if top + h > scroll + view {
            pop.set_scroll_top(top + h - view);
        }
    });
}

/// The search box right of the wordmark: pages, settings, objects and hosts as you type.
/// `/` and Ctrl/⌘K focus it; on phones it is a magnifier that opens a full-width sheet.
#[island]
pub fn GlobalSearch() -> impl IntoView {
    mark_hydrated();
    let s = Gs {
        query: RwSignal::new(String::new()),
        found: RwSignal::new(None),
        open: RwSignal::new(false),
        active: RwSignal::new(None),
        sheet: RwSignal::new(false),
        busy: StoredValue::new(false),
        again: StoredValue::new(false),
    };
    let input = NodeRef::<leptos::html::Input>::new();
    let opener = NodeRef::<leptos::html::Button>::new();
    let timer = StoredValue::new(None::<TimeoutHandle>);
    let urls = Memo::new(move |_| {
        s.found.with(|f| match f {
            Some(Ok(r)) => gsearch_urls(r),
            _ => vec![],
        })
    });
    let shown = move || s.open.get() && s.found.with(Option::is_some);

    // Focus the box at once, so keys typed right after the shortcut land in it. On a phone
    // the box is hidden until the sheet opens: show it on the element itself first, as
    // the reactive class only lands on the next tick.
    let focus = move || {
        let Some(el) = input.get_untracked() else {
            return;
        };
        #[cfg(feature = "hydrate")]
        if web_sys::window()
            .and_then(|w| w.inner_width().ok())
            .and_then(|v| v.as_f64())
            .is_some_and(|w| w <= 600.0)
        {
            s.sheet.set(true);
            if let Ok(Some(gs)) = el.closest(".gsearch") {
                let _ = gs.class_list().add_1("sheet");
            }
        }
        let _ = el.focus();
        el.select();
    };
    let close_sheet = move || {
        s.sheet.set(false);
        s.open.set(false);
        request_animation_frame(move || {
            if let Some(b) = opener.get_untracked() {
                let _ = b.focus();
            }
        });
    };

    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::JsCast;
        let keys = window_event_listener(leptos::ev::keydown, move |ev| {
            let k = ev.key();
            let typing = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlElement>().ok())
                .is_some_and(|el| {
                    el.is_content_editable()
                        || matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT")
                });
            let slash = k == "/" && !typing && !ev.ctrl_key() && !ev.meta_key() && !ev.alt_key();
            let cmd_k = (ev.ctrl_key() || ev.meta_key()) && k.eq_ignore_ascii_case("k");
            if slash || cmd_k {
                ev.prevent_default();
                focus();
            }
        });
        on_cleanup(move || drop(keys));
        let click = window_event_listener(leptos::ev::click, move |ev| {
            let inside = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                .is_some_and(|el| el.closest(".gsearch").ok().flatten().is_some());
            if !inside {
                s.open.set(false);
                s.sheet.set(false);
            }
        });
        on_cleanup(move || drop(click));
    }

    let on_input = move |ev: leptos::ev::Event| {
        let v = event_target_value(&ev);
        s.query.set(v.clone());
        if let Some(h) = timer.get_value() {
            h.clear();
        }
        timer.set_value(None);
        if gsearch_short(&v) {
            s.found.set(None);
            s.active.set(None);
            return;
        }
        s.open.set(true);
        timer.set_value(
            set_timeout_with_handle(
                move || gsearch_fetch(s),
                std::time::Duration::from_millis(150),
            )
            .ok(),
        );
    };
    let on_key = move |ev: leptos::ev::KeyboardEvent| {
        let n = urls.with_untracked(Vec::len);
        match ev.key().as_str() {
            k @ ("ArrowDown" | "ArrowUp") if n > 0 => {
                ev.prevent_default();
                s.open.set(true);
                let i = match (s.active.get_untracked(), k == "ArrowDown") {
                    (None, true) => 0,
                    (None, false) => n - 1,
                    (Some(i), true) => (i + 1) % n,
                    (Some(i), false) => (i + n - 1) % n,
                };
                s.active.set(Some(i));
                gsearch_reveal(i);
            }
            "Enter" if n > 0 && s.open.get_untracked() => {
                ev.prevent_default();
                let i = s.active.get_untracked().unwrap_or(0).min(n - 1);
                if let Some(url) = urls.with_untracked(|u| u.get(i).cloned()) {
                    gsearch_go(s, &url);
                }
            }
            "Escape" => {
                ev.prevent_default();
                if s.sheet.get_untracked() {
                    close_sheet();
                } else if s.open.get_untracked() && s.found.with_untracked(Option::is_some) {
                    s.open.set(false);
                    s.active.set(None);
                } else {
                    s.query.set(String::new());
                    s.found.set(None);
                    s.active.set(None);
                }
            }
            _ => {}
        }
    };
    let on_pick = move |ev: leptos::ev::MouseEvent| {
        #[cfg(not(feature = "hydrate"))]
        let _ = (ev, s);
        #[cfg(feature = "hydrate")]
        {
            use wasm_bindgen::JsCast;
            if let Some(url) = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                .and_then(|el| el.closest("[role=option]").ok().flatten())
                .and_then(|o| o.get_attribute("data-url"))
            {
                gsearch_go(s, &url);
            }
        }
    };
    let status = move || {
        s.found.with(|f| match f {
            Some(Ok(r)) if r.groups.is_empty() => format!("No matches for “{}”", r.query),
            Some(Err(e)) => format!("Search failed: {e}"),
            _ => String::new(),
        })
    };
    let magnifier = "M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM10.3 10.3l3.2 3.2";

    view! {
        <div class="gsearch" class:sheet=move || s.sheet.get()>
            <button type="button" class="icon-btn gsearch-open" aria-label="Search" node_ref=opener
                on:click=move |_| focus()>
                {icon(magnifier)}
            </button>
            <div class="gsearch-box">
                <span class="gsearch-icon">{icon(magnifier)}</span>
                <input type="search" role="combobox" aria-label="Search sensr" aria-autocomplete="list"
                    aria-controls="gsearch-list" placeholder="Search  /" autocomplete="off"
                    spellcheck="false" node_ref=input
                    aria-expanded=move || shown().to_string()
                    aria-activedescendant=move || {
                        s.active.get().filter(|_| shown()).map(|i| format!("gsearch-opt-{i}"))
                    }
                    prop:value=move || s.query.get()
                    on:input=on_input on:keydown=on_key
                    on:focus=move |_| {
                        if !gsearch_short(&s.query.get_untracked()) {
                            s.open.set(true);
                        }
                    }/>
                <button type="button" class="icon-btn gsearch-close" aria-label="Close search"
                    on:click=move |_| close_sheet()>
                    {icon("M4 4l8 8M12 4l-8 8")}
                </button>
                // mousedown would blur the box (and shrink it under the pointer) before the click.
                // Arrows move through the options from the box; tabindex lets a keyboard
                // also scroll a long list.
                <div id="gsearch-pop" class="gsearch-pop" tabindex="0" hidden=move || !shown()
                    on:mousedown=|ev| ev.prevent_default() on:click=on_pick>
                    <div id="gsearch-list" role="listbox" aria-label="Search results">
                        {move || s.found.with(|f| match f {
                            Some(Ok(r)) => Some(gsearch_results(r, s.active.get())),
                            _ => None,
                        })}
                    </div>
                    <p class="gsearch-status" class:error=move || s.found.with(|f| matches!(f, Some(Err(_))))
                        role="status" hidden=move || status().is_empty()>{status}</p>
                </div>
            </div>
        </div>
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

/// A `#<field dom id>` link (a global search hit) into this form: scroll to the field,
/// focus it and flash its row for 2 s.
#[cfg(feature = "hydrate")]
fn flash_field(form: &str) {
    use wasm_bindgen::JsCast;
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let hash = doc
        .location()
        .and_then(|l| l.hash().ok())
        .unwrap_or_default();
    let Some(id) = hash
        .strip_prefix('#')
        .filter(|id| id.strip_prefix(form).is_some_and(|r| r.starts_with("--")))
    else {
        return;
    };
    let Some(el) = doc.get_element_by_id(id) else {
        return;
    };
    el.scroll_into_view();
    if let Some(h) = el.dyn_ref::<web_sys::HtmlElement>() {
        let _ = h.focus();
    }
    if let Ok(Some(row)) = el.closest(".field") {
        let _ = row.class_list().add_1("field-flash");
        set_timeout(
            move || {
                let _ = row.class_list().remove_1("field-flash");
            },
            std::time::Duration::from_secs(2),
        );
    }
}

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
    let form_dom = form.dom_id();
    #[cfg(feature = "hydrate")]
    {
        let form_dom = form_dom.clone();
        let on_hash = form_dom.clone();
        Effect::new(move || flash_field(&form_dom));
        // A search hit on this very page moves only the hash: no reload, so flash here.
        let hash = window_event_listener(leptos::ev::hashchange, move |_| flash_field(&on_hash));
        on_cleanup(move || drop(hash));
    }
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
    /// `?q=`: the initial search (`initial` is already filtered by it).
    #[prop(optional)]
    search: Option<String>,
    /// `?edit=`: the row whose edit dialog opens on hydrate, and the page URL without
    /// `edit` (built on the server, keeping the wasm small) to `replaceState` to.
    #[prop(optional_no_strip)]
    edit: Option<(Value, String)>,
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
        search: search.clone().unwrap_or_default(),
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
    // A `?edit=` deep link opens the row as its Edit button would, then leaves the URL
    // so a reload does not reopen it.
    #[cfg(feature = "hydrate")]
    if let Some((row, url)) = edit {
        Effect::new(move || {
            untrack(|| open_dialog(Editing::Row(key_of(&row), row.clone())));
            if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
                let _ = h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&url));
            }
        });
    }
    #[cfg(not(feature = "hydrate"))]
    let _ = edit;
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
                    ColumnKind::Status => {
                        let cell = crate::form::get_path(&row, c.path);
                        let field = |k: &str| cell.and_then(|v| v.get(k)).and_then(Value::as_str).map(str::to_owned);
                        let badge = (field("tone").as_deref() == Some("bad")).then(|| {
                            let title = field("title").unwrap_or_default();
                            let word = field("badge").unwrap_or_else(|| "error".to_owned());
                            view! {
                                " "<span class="pill pill-off" title=title.clone()>{word}</span>
                                <span class="sr-only">{format!(": {title}")}</span>
                            }
                        });
                        view! { <td>{txt}{badge}</td> }.into_any()
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
                    <input type="search" placeholder="Search" value=search
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

/// Status badge of a gateway, in the OPNsense colours.
pub fn gateway_badge(state: GatewayState) -> impl IntoView {
    view! { <span class=state.tone().pill()>{state.label()}</span> }
}

/// One compact entry of the dashboard Gateways widget.
fn gateway_item(g: &GatewayRow) -> impl IntoView + use<> {
    view! {
        <li class="gw-item">
            <div class="gw-name">
                <strong>{g.name.clone()}</strong>
                {g.active_default.then(|| view! { <span class="muted">" (active)"</span> })}
                <br/><span class="muted">{g.next_hop.clone().unwrap_or_else(|| "~".to_owned())}</span>
            </div>
            <dl class="gw-stats">
                <dt>"RTT"</dt><dd>{ms(g.latency_ms)}</dd>
                <dt>"RTTd"</dt><dd>{ms(g.stddev_ms)}</dd>
                <dt>"Loss"</dt><dd>{pct(g.loss_pct)}</dd>
            </dl>
            {gateway_badge(g.status)}
        </li>
    }
}

/// System › Gateways › Status: every gateway with its monitor figures, and the gateway
/// groups with their active members; refreshed every 5 s.
#[island]
pub fn GatewaysLive(initial: GatewaysView) -> impl IntoView {
    mark_hydrated();
    let st = RwSignal::new(initial);
    let error = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        set_interval(
            move || {
                spawn_local(async move {
                    match gateways_status().await {
                        Ok(v) => {
                            error.set(None);
                            st.set(v);
                        }
                        Err(e) => error.set(Some(format!("Could not refresh: {e}"))),
                    }
                });
            },
            std::time::Duration::from_secs(5),
        );
    });
    let rows = move || {
        st.with(|v| {
            if v.gateways.is_empty() {
                return view! { <tr><td class="empty" colspan="9">"No gateways are monitored."</td></tr> }.into_any();
            }
            v.gateways
                .iter()
                .map(|g| {
                    let fam = g.family_label();
                    view! {
                        <tr>
                            <td>
                                <strong>{g.name.clone()}</strong>
                                {g.active_default.then(|| view! {
                                    " "<span class="pill pill-info" title=format!("Default {fam} gateway")>"active"</span>
                                })}
                                {g.dynamic.then(|| view! { <br/><span class="muted small">"automatic"</span> })}
                            </td>
                            <td>{g.interface.to_uppercase()}<span class="muted">{format!(" {fam}")}</span></td>
                            <td>{g.next_hop.clone().unwrap_or_else(|| "~".to_owned())}</td>
                            <td>{g.monitor_address.clone().or_else(|| g.next_hop.clone()).unwrap_or_else(|| "~".to_owned())}</td>
                            <td class="num">{g.priority}</td>
                            <td class="num">{ms(g.latency_ms)}</td>
                            <td class="num">{ms(g.stddev_ms)}</td>
                            <td class="num">{pct(g.loss_pct)}</td>
                            <td>
                                {gateway_badge(g.status)}
                                {g.error.clone().map(|e| view! { <br/><span class="field-error small">{e}</span> })}
                            </td>
                        </tr>
                    }
                })
                .collect_view()
                .into_any()
        })
    };
    let groups = move || {
        st.with(|v| {
            if v.groups.is_empty() {
                return view! { <p class="muted">"No gateway groups."</p> }.into_any();
            }
            view! {
                <div class="table-wrap">
                <table>
                    <thead><tr><th scope="col">"Group"</th><th scope="col">"Active members"</th></tr></thead>
                    <tbody>
                        {v.groups.iter().map(|(name, members)| {
                            let members = if members.is_empty() {
                                view! { <span class="pill pill-off">"none"</span> }.into_any()
                            } else {
                                members.iter().map(|m| {
                                    let state = v.gateways.iter().find(|g| &g.name == m).map(|g| g.status);
                                    view! {
                                        <span class="gw-member">{m.clone()}" "{state.map(gateway_badge)}</span>
                                    }
                                }).collect_view().into_any()
                            };
                            view! { <tr><td><strong>{name.clone()}</strong></td><td>{members}</td></tr> }
                        }).collect_view()}
                    </tbody>
                </table>
                </div>
            }
            .into_any()
        })
    };
    view! {
        <section class="card" aria-labelledby="gw-status">
            <h2 id="gw-status">"Gateways"</h2>
            <div class="table-wrap">
            <table class="gw-table">
                <thead><tr>
                    <th scope="col">"Name"</th><th scope="col">"Interface"</th>
                    <th scope="col">"Gateway"</th><th scope="col">"Monitor IP"</th>
                    <th scope="col">"Priority"</th><th scope="col">"RTT"</th>
                    <th scope="col">"RTTd"</th><th scope="col">"Loss"</th><th scope="col">"Status"</th>
                </tr></thead>
                <tbody aria-live="polite">{rows}</tbody>
            </table>
            </div>
            <p class="muted small">
                {move || st.with(|v| if v.switch_default {
                    "Default gateway switching is on: the default route follows the highest-priority gateway that is up."
                } else {
                    "Default gateway switching is off."
                })}
            </p>
            {move || error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
        </section>
        <section class="card" aria-labelledby="gw-groups">
            <h2 id="gw-groups">"Gateway groups"</h2>
            {groups}
        </section>
    }
}

/// The dashboard widgets, refreshed every few seconds.
#[island]
pub fn DashboardLive(initial: SystemStatus) -> impl IntoView {
    mark_hydrated();
    let st = RwSignal::new(initial);
    // Traffic graph: 10 s samples of the last ten minutes, or the last hour per minute.
    let live = RwSignal::new(true);
    let names = Memo::new(move |_| {
        st.with(|s| s.traffic.iter().map(|t| t.name.clone()).collect::<Vec<_>>())
    });
    let has_history = Memo::new(move |_| st.with(|s| s.history.is_some()));
    let graph = Memo::new(move |_| {
        let live = live.get();
        st.with(|s| {
            s.history.as_ref().map_or_else(Vec::new, |h| {
                let pts = if live { &h.live } else { &h.hour };
                pts.iter()
                    .map(|p| Sample {
                        ts: p.ts,
                        rx: p.down_bps(),
                        tx: p.up_bps(),
                    })
                    .collect()
            })
        })
    });
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
                    <dt>"WAN address"</dt><dd class="wan-addr">{move || st.with(|s| s.wan_ipv4().map_or_else(|| "none".to_owned(), str::to_owned))}</dd>
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
                <h2 id="w-gw"><a href="/ui/routing/status">"Gateways"</a></h2>
                {move || st.with(|s| if s.gateways.is_empty() {
                    view! { <p class="muted">"No gateway data."</p> }.into_any()
                } else {
                    view! { <ul class="gw-list">{s.gateways.iter().map(gateway_item).collect_view()}</ul> }.into_any()
                })}
            </section>
            <section class="card card-wide" aria-labelledby="w-tr">
                <h2 id="w-tr">"Traffic"</h2>
                <p class="legend"><span class="key key-rx"></span>"In "<span class="key key-tx"></span>"Out"</p>
                <div class="traffic">
                    // Rebuilt only when the set of interfaces changes, so a chart keeps its
                    // crosshair and focus across refreshes.
                    {move || names.get().into_iter().map(|name| {
                            let series = {
                                let name = name.clone();
                                Memo::new(move |_| st.with(|s| s.traffic.iter().find(|t| t.name == name).map(series_samples).unwrap_or_default()))
                            };
                            let now = move || series.with(|s| s.last().map_or((0, 0), |p| (p.rx, p.tx)));
                            view! {
                                <figure>
                                    <figcaption>{name.clone()}
                                        <span class="muted">{move || format!(" in {} · out {}", bps(now().0), bps(now().1))}</span>
                                    </figcaption>
                                    <TrafficChart samples=series class="tchart-sm"
                                        label=format!("{name} traffic, last two minutes")/>
                                </figure>
                            }
                    }).collect_view()}
                </div>
            </section>
            <section class="card card-wide" aria-labelledby="w-tg">
                <h2 id="w-tg">"Traffic graph"</h2>
                {move || if has_history.get() {
                    let now = move || graph.with(|s| s.last().map_or((0, 0), |p| (p.rx, p.tx)));
                    view! {
                        <div class="graph-head">
                            <p class="legend"><span class="key key-rx"></span>{move || format!("In {}", bps(now().0))}
                                <span class="key key-tx"></span>{move || format!("Out {}", bps(now().1))}
                                <span class="muted">" · all interfaces"</span></p>
                            <div class="seg" role="group" aria-label="Graph period">
                                <button type="button" class="btn btn-sm" aria-pressed=move || live.get().to_string()
                                    on:click=move |_| live.set(true)>"Live (10 s)"</button>
                                <button type="button" class="btn btn-sm" aria-pressed=move || (!live.get()).to_string()
                                    on:click=move |_| live.set(false)>"Last hour"</button>
                            </div>
                        </div>
                        <TrafficChart samples=graph
                            label=Signal::derive(move || if live.get() { "Traffic, all interfaces, last ten minutes" } else { "Traffic, all interfaces, last hour" }.to_owned())/>
                    }.into_any()
                } else {
                    view! {
                        <p class="muted">"The traffic graph appears once traffic accounting (Reporting › Insight) has collected data."</p>
                    }.into_any()
                }}
            </section>
        </div>
    }
}

/// A dashboard interface series as chart samples.
/// Without a timestamp per sample, every one is 0 and the chart shows no times.
fn series_samples(t: &TrafficSeries) -> Vec<Sample> {
    let timed = t.ts.len() == t.rx.len();
    t.rx.iter()
        .zip(&t.tx)
        .enumerate()
        .map(|(i, (rx, tx))| Sample {
            ts: if timed { t.ts[i] } else { 0 },
            rx: *rx,
            tx: *tx,
        })
        .collect()
}

/// System › Updates: the running generation, what the release manifest offers, and
/// automatic installs. Polls while the update service is checking, downloading or
/// switching.
#[island]
pub fn UpdatesLive(initial: UpdateStatus) -> impl IntoView {
    mark_hydrated();
    let st = RwSignal::new(initial);
    let error = RwSignal::new(None::<String>);
    let pending = RwSignal::new(false);
    // Extra refreshes after a request: the path unit starts the root service
    // asynchronously, so the status it writes appears a moment later.
    let settle = RwSignal::new(0u32);

    let refresh = move || {
        spawn_local(async move {
            match update_status().await {
                Ok(v) => {
                    st.set(v);
                    error.set(None);
                }
                Err(e) => error.set(Some(format!("Could not read update status: {e}"))),
            }
        });
    };

    // A check or switch is quick, but the download is not: poll while the
    // service is working so the page shows the progress it wrote.
    Effect::new(move |_| {
        refresh();
        set_interval(
            move || {
                let left = settle.get_untracked();
                if st.with(UpdateStatus::busy) || pending.get_untracked() || left > 0 {
                    if left > 0 {
                        settle.set(left - 1);
                    }
                    refresh();
                }
            },
            std::time::Duration::from_secs(3),
        );
    });

    let send = move |mode: &'static str| {
        pending.set(true);
        spawn_local(async move {
            match update_request(mode.to_owned()).await {
                Ok(v) => {
                    st.set(v);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            settle.set(4);
            pending.set(false);
        });
    };

    let phase_pill = move || {
        st.with(|s| {
            let (class, label) = match s.phase.as_str() {
                "error" => ("pill pill-off", "error"),
                "update-available" => ("pill pill-info", "update available"),
                "up-to-date" | "done" => ("pill pill-on", "up to date"),
                "checking" | "downloading" | "installing" => ("pill pill-info", "working"),
                _ => ("pill", "idle"),
            };
            view! { <span class=class>{label}</span> }
        })
    };

    view! {
        <div class="card">
            <h2>"System updates"</h2>
            <p class="intro">
                "An update replaces the whole system closure: the sensr binaries, the daemons and every package they use, atomically, with no reboot: the switch takes effect at once and only restarts the services it changes. A new kernel starts at the next reboot you choose. The previous generation stays on the box for rollback."
            </p>
            <dl class="stat-tiles" aria-label="Update state">
                <div>
                    <dt>"Running release"</dt>
                    <dd id="update-current">{move || st.with(|s| s.current.label().to_string())}</dd>
                </div>
                <div>
                    <dt>"Image"</dt>
                    <dd>{move || st.with(|s| s.current.image.clone())}</dd>
                </div>
                <div>
                    <dt>"Status"</dt>
                    <dd>{phase_pill()} " " {move || st.with(|s| s.message.clone())}</dd>
                </div>
                <div>
                    <dt>"Last check"</dt>
                    <dd>{move || st.with(|s| s.last_check.clone()).unwrap_or_else(|| "never".to_owned())}</dd>
                </div>
            </dl>

            {move || st.with(|s| match &s.available {
                None => view! {
                    <p class="muted" id="update-available-none">"No newer system has been found."</p>
                }.into_any(),
                Some(a) => view! {
                    <div class="card" id="update-available">
                        <h3>{format!("Release {} is available", a.label())}</h3>
                        {(!a.notes.is_empty()).then(|| view! { <p>{a.notes.clone()}</p> })}
                        <p class="muted small">
                            "sha256 " <code>{a.sha256.trim_start_matches("sha256:").chars().take(16).collect::<String>()}</code>
                        </p>
                    </div>
                }.into_any(),
            })}

            <div class="banner-actions">
                <button type="button" class="btn secondary"
                    disabled=move || pending.get()
                    on:click=move |_| send("check")>"Check for updates"</button>
                <button type="button" class="btn"
                    disabled=move || pending.get() || st.with(|s| s.busy() || !s.has_update())
                    on:click=move |_| send("install")>"Install update"</button>
            </div>

            <h3>"Automatic updates"</h3>
            <p>
                {move || if st.with(|s| s.auto) {
                    "On: the timer checks the manifest and installs a newer system. sensr restarts its services for a few seconds while it switches."
                } else {
                    "Off: the timer only checks, and an update waits for the button above."
                }}
            </p>
            <button type="button" class="btn secondary"
                aria-pressed=move || st.with(|s| s.auto).to_string()
                disabled=move || pending.get()
                on:click=move |_| send(if st.get_untracked().auto { "auto-off" } else { "auto-on" })>
                {move || if st.with(|s| s.auto) { "Turn automatic updates off" } else { "Turn automatic updates on" }}
            </button>

            {move || error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
        </div>
    }
}

/// The DHCPv4 lease table: what Kea has handed out, with a button that stages a static
/// reservation for a client.
#[island]
pub fn DhcpLeases(initial: LeaseTable) -> impl IntoView {
    mark_hydrated();
    let table = RwSignal::new(initial);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(None::<String>);

    let refresh = move || {
        spawn_local(async move {
            match dhcp_leases().await {
                Ok(t) => {
                    table.set(t);
                    error.set(None);
                }
                Err(e) => error.set(Some(format!("Could not read the lease table: {e}"))),
            }
        });
    };

    let reserve = move |lease: crate::api::DhcpLease| {
        busy.set(Some(lease.address.clone()));
        spawn_local(async move {
            match reserve_lease(
                lease.address.clone(),
                lease.mac.clone(),
                lease.client_id.clone(),
                lease.hostname.clone(),
            )
            .await
            {
                Ok(()) => {
                    error.set(None);
                    // The Apply banner owns the staged document; a stage from here has to
                    // tell it, the way a grid does.
                    bump();
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(None);
        });
    };

    view! {
        <div class="card">
            <h2>"Leases"</h2>
            <p class="intro">
                "Addresses Kea has handed out, live ones first. Making a lease static stages a reservation for that client with the same address and host name; nothing changes until you apply it."
            </p>
            {move || {
                let t = table.get();
                if t.leases.is_empty() {
                    view! {
                        <p class="muted" id="leases-none">
                            "No leases yet: no client has asked this DHCP server for an address."
                        </p>
                    }
                    .into_any()
                } else {
                    let rows = t
                        .leases
                        .iter()
                        .map(|l| {
                            let lease = l.clone();
                            let address = l.address.clone();
                            let age = match l.state {
                                crate::api::LeaseState::Active => until(t.now, l.expire),
                                crate::api::LeaseState::Expired => "expired".to_owned(),
                                _ => until(t.now, l.expire),
                            };
                            let (pill, label) = match l.state {
                                crate::api::LeaseState::Active => ("pill pill-on", "active"),
                                crate::api::LeaseState::Expired => ("pill pill-off", "expired"),
                                crate::api::LeaseState::Released => ("pill", "released"),
                                crate::api::LeaseState::Declined => ("pill pill-off", "declined"),
                                crate::api::LeaseState::Reclaimed => ("pill", "reclaimed"),
                            };
                            let action = if l.reserved {
                                view! { <span class="pill pill-on">"static"</span> }.into_any()
                            } else if l.mac.is_none() && l.client_id.is_none() {
                                view! { <span class="muted">"no client id"</span> }.into_any()
                            } else {
                                let for_row = lease.clone();
                                view! {
                                    <button type="button" class="btn btn-sm"
                                        disabled=move || busy.get().as_deref() == Some(address.as_str())
                                        on:click=move |_| reserve(for_row.clone())>
                                        "Make static"
                                    </button>
                                }
                                .into_any()
                            };
                            view! {
                                <tr class:dimmed=!l.active()>
                                    <td class="num">{l.address.clone()}</td>
                                    <td class="num">{l.mac.clone().unwrap_or_else(|| "—".to_owned())}</td>
                                    <td>{if l.hostname.is_empty() { "—".to_owned() } else { l.hostname.clone() }}</td>
                                    <td class="num">{l.subnet_id.to_string()}</td>
                                    <td>{age}</td>
                                    <td><span class=pill>{label}</span></td>
                                    <td>{action}</td>
                                </tr>
                            }
                        })
                        .collect_view();
                    view! {
                        <div class="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th scope="col">"Address"</th>
                                        <th scope="col">"MAC address"</th>
                                        <th scope="col">"Host name"</th>
                                        <th scope="col">"Subnet"</th>
                                        <th scope="col">"Expires"</th>
                                        <th scope="col">"State"</th>
                                        <th scope="col">"Reservation"</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </table>
                        </div>
                    }
                    .into_any()
                }
            }}
            <div class="banner-actions">
                <button type="button" class="btn" on:click=move |_| refresh()>"Refresh"</button>
            </div>
            {move || error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
        </div>
    }
}

/// Dashboard › Hosts: every client the router knows of, searchable and filterable by
/// network, with Make static for leased hosts, Forget for unreserved ones and a Mode
/// (Normal / Isolated / Quarantine) for hosts with a MAC. Refreshed with the other
/// dashboard widgets; renders nothing when the caller may not see hosts.
#[island]
pub fn HostsCard(
    initial: Option<HostCard>,
    /// `?host=`: the initial search.
    #[prop(optional)]
    search: Option<String>,
) -> impl IntoView {
    if initial.is_none() {
        return ().into_any();
    }
    mark_hydrated();
    let card = RwSignal::new(initial);
    let search = RwSignal::new(search.unwrap_or_default());
    let network = RwSignal::new(String::new());
    let show_all = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(None::<String>);
    // The last Mode or label change's refusal; kept across refreshes (which clear `error`).
    let mode_error = RwSignal::new(None::<String>);
    // The label editor: the MAC it is open for and its unsaved (type, maker), which a
    // re-render of the row puts back.
    let labels = LabelEditor {
        card,
        error,
        busy,
        mode_error,
        editing: RwSignal::new(None),
        draft: RwSignal::new(Default::default()),
    };
    let editing = labels.editing;

    let refresh = move || reload_hosts(card, error);
    Effect::new(move |_| {
        // only the periodic refresh waits while an editor is open
        set_interval(
            move || {
                if editing.with_untracked(Option::is_none) {
                    refresh();
                }
            },
            std::time::Duration::from_secs(3),
        );
    });

    let make_static = move |h: crate::runtime::HostRow| {
        let (Some(ip), Some(mac)) = (h.ipv4.clone(), h.mac.clone()) else {
            return;
        };
        busy.set(Some(h.key.clone()));
        spawn_local(async move {
            match reserve_lease(ip, Some(mac), None, h.name.clone().unwrap_or_default()).await {
                Ok(()) => {
                    error.set(None);
                    bump();
                    // Stay busy until the card shows the row as staged, so a second
                    // click cannot stage the reservation twice.
                    match hosts().await {
                        Ok(c) => card.set(c),
                        Err(e) => error.set(Some(format!("Could not read the hosts: {e}"))),
                    }
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(None);
        });
    };
    let forget = move |h: crate::runtime::HostRow| {
        #[cfg(feature = "hydrate")]
        {
            let msg = format!(
                "Forget {}? It reappears if it is still on the network.",
                h.label()
            );
            if !web_sys::window()
                .and_then(|w| w.confirm_with_message(&msg).ok())
                .unwrap_or(false)
            {
                return;
            }
        }
        busy.set(Some(h.key.clone()));
        spawn_local(async move {
            match forget_host(h.key.clone()).await {
                Ok(()) => {
                    error.set(None);
                    refresh();
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            busy.set(None);
        });
    };

    let set_mode = move |mac: String, mode: String, select: NodeRef<leptos::html::Select>| {
        let mode = (mode != "normal").then_some(mode);
        busy.set(Some(mac.clone()));
        spawn_local(async move {
            match set_host_mode(mac.clone(), mode).await {
                // a staged mode shows on its row (from the staged document)
                Ok(_) => {
                    mode_error.set(None);
                    bump();
                }
                Err(e) => mode_error.set(Some(server_message(&e))),
            }
            // also on a refusal: the select goes back to the host's actual mode. The row
            // is patched in place and its `selected` attributes may not change, so the
            // value the user picked is reset by hand.
            match hosts().await {
                Ok(c) => {
                    let shown = c.as_ref().and_then(|c| {
                        c.list
                            .hosts
                            .iter()
                            .find(|h| h.mac.as_deref() == Some(mac.as_str()))
                            .map(|h| mode_shown(h).to_owned())
                    });
                    card.set(c);
                    if let (Some(el), Some(v)) = (select.get_untracked(), shown) {
                        el.set_value(&v);
                        el.set_class_name(mode_select_class(&v));
                    }
                }
                Err(e) => error.set(Some(format!("Could not read the hosts: {e}"))),
            }
            busy.set(None);
        });
    };

    // The MAC cell: the MAC, the label line under it with ✎ after the text, and the
    // label editor. It is markup with delegated event handlers rather than a view tree,
    // which keeps the island bundle small.
    let mac_cell = move |h: &crate::runtime::HostRow, read_only: bool| {
        let mac = h.mac.clone().unwrap_or_default();
        // `id:` rows have no MAC to label
        let edit = !read_only && h.mac.is_some() && !h.key.starts_with("id:");
        let (closed, open) = (mac_cell_html(h, edit, false), mac_cell_html(h, edit, true));
        let name = h.label();
        let m = mac.clone();
        let html = move || {
            if !edit || labels.editing.with(|e| e.as_deref() != Some(m.as_str())) {
                return closed.clone();
            }
            // untracked: typing updates the draft without rebuilding the editor
            let (kind, maker) = labels.draft.get_untracked();
            let busy = labels.busy.with(|b| b.as_deref() == Some(m.as_str()));
            open.clone() + &host_label_editor_html(&name, &kind, &maker, busy)
        };
        let (m1, m2, m3) = (mac.clone(), mac.clone(), mac.clone());
        view! {
            <td class="num host-mac" id=edit.then(|| label_cell_id(&mac)) inner_html=html
                on:click=move |ev| labels.event(&m1, &ev)
                on:submit=move |ev| labels.event(&m2, &ev)
                on:input=move |ev| labels.event(&m3, &ev)
                on:keydown=move |ev| labels.event(&mac, &ev)></td>
        }
    };

    let mode_cell = move |h: &crate::runtime::HostRow, read_only: bool| {
        // `id:` rows have no MAC to match on
        let Some(mac) = h.mac.clone().filter(|_| !h.key.starts_with("id:")) else {
            return view! { <span class="muted">"—"</span> }.into_any();
        };
        let current = h.locked_mode().unwrap_or("normal");
        let badge = match current {
            "isolated" => Some(view! { <span class="pill pill-warn">"Isolated"</span> }),
            "quarantine" => Some(view! { <span class="pill pill-off">"Quarantine"</span> }),
            _ => None,
        };
        let staged_note = h.staged_mode.is_some().then(|| {
            view! { <span class="muted host-mode-staged">"Staged — Apply to take effect"</span> }
        });
        if read_only {
            return view! { {badge} {staged_note} }.into_any();
        }
        let shown = mode_shown(h);
        let class = mode_select_class(shown);
        let select = NodeRef::<leptos::html::Select>::new();
        let label = format!("Mode for {}", h.label());
        let options = [
            ("normal", "Normal"),
            ("isolated", "Isolated"),
            ("quarantine", "Quarantine"),
        ]
        .map(|(v, t)| view! { <option value=v selected=v == shown>{t}</option> });
        let m = mac.clone();
        view! {
            <select aria-label=label node_ref=select class=class
                disabled=move || busy.get().as_deref() == Some(m.as_str())
                on:change=move |ev| {
                    let v = event_target_value(&ev);
                    // tint at once; the refresh in set_mode settles it
                    if let Some(el) = select.get_untracked() {
                        el.set_class_name(mode_select_class(&v));
                    }
                    set_mode(mac.clone(), v, select)
                }>
                {options}
            </select>
            {staged_note}
        }
        .into_any()
    };

    let row = move |h: &crate::runtime::HostRow, now: u64, read_only: bool| {
        let key = h.key.clone();
        let actions = if read_only {
            ().into_any()
        } else {
            let offer_static = h.leased_only() && !h.staged && h.mac.is_some() && h.ipv4.is_some();
            let staged = h.leased_only() && h.staged;
            let (for_static, for_forget) = (h.clone(), h.clone());
            let (k1, k2) = (key.clone(), key.clone());
            view! {
                {offer_static.then(|| view! {
                    <button type="button" class="btn btn-sm"
                        disabled=move || busy.get().as_deref() == Some(k1.as_str())
                        on:click=move |_| make_static(for_static.clone())>"Make static"</button>
                })}
                {staged.then(|| view! {
                    <span class="muted" title="A reservation is staged; apply it to make this host static">"staged"</span>
                })}
                {if h.reserved() {
                    view! {
                        <span class="muted host-reserved"
                            title="Remove the reservation on the DHCP page to forget this host">"Reserved"</span>
                    }.into_any()
                } else {
                    view! {
                        <button type="button" class="btn btn-sm"
                            disabled=move || busy.get().as_deref() == Some(k2.as_str())
                            on:click=move |_| forget(for_forget.clone())>"Forget"</button>
                    }.into_any()
                }}
            }
            .into_any()
        };
        view! {
            <tr class:dimmed=!h.online>
                <td>{h.label()}</td>
                {mac_cell(h, read_only)}
                <td class="num">{h.ipv4.clone().unwrap_or_default()}
                    {h.ipv6.first().map(|v6| view! { <br/><span class="muted">{v6.clone()}</span> })}</td>
                <td>{h.interface_name.clone()}</td>
                <td>{h.source()}</td>
                <td>{h.seen(now)}</td>
                <td class="host-mode">{mode_cell(h, read_only)}</td>
                <td class="host-actions">{actions}</td>
            </tr>
        }
    };

    // Rebuilt only when the card appears or disappears, so typing keeps focus.
    let visible = Memo::new(move |_| card.with(Option::is_some));
    let any =
        Memo::new(move |_| card.with(|c| c.as_ref().is_some_and(|c| !c.list.hosts.is_empty())));
    let body = move || {
        card.with(|c| {
            let c = c.as_ref()?;
            if c.list.hosts.is_empty() {
                return Some(view! { <p class="muted">"No hosts seen yet."</p> }.into_any());
            }
            let all = show_all.get();
            let (rows, m) = network.with(|n| search.with(|q| c.visible(n, q, all)));
            let rows = rows
                .into_iter()
                .map(|h| row(h, c.list.now, c.read_only))
                .collect_view();
            Some(
                view! {
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th scope="col">"Name"</th>
                                    <th scope="col">"MAC"</th>
                                    <th scope="col">"IP"</th>
                                    <th scope="col">"Network"</th>
                                    <th scope="col">"Source"</th>
                                    <th scope="col">"Seen"</th>
                                    <th scope="col">"Mode"</th>
                                    <th scope="col" aria-label="Actions"></th>
                                </tr>
                            </thead>
                            <tbody>{rows}</tbody>
                        </table>
                    </div>
                    {(!all && m > HostCard::SHOWN).then(|| view! {
                        <div class="banner-actions">
                            <button type="button" class="btn" on:click=move |_| show_all.set(true)>
                                {format!("Show all ({m})")}
                            </button>
                        </div>
                    })}
                }
                .into_any(),
            )
        })
    };
    let toolbar = move || {
        any.get().then(|| view! {
            <div class="grid-toolbar">
                <label class="search">
                    <span class="sr-only">"Search hosts"</span>
                    <input type="search" placeholder="Search name, MAC or IP" value=search.get_untracked()
                        prop:value=move || search.get()
                        on:input=move |ev| { search.set(event_target_value(&ev)); show_all.set(false); }/>
                </label>
                <label>
                    <span class="sr-only">"Network"</span>
                    <select prop:value=move || network.get()
                        on:change=move |ev| { network.set(event_target_value(&ev)); show_all.set(false); }>
                        <option value="">"All networks"</option>
                        {move || card.with(|c| c.as_ref().map(|c| c.networks.clone()).unwrap_or_default())
                            .into_iter()
                            .map(|(id, name)| view! { <option value=id>{name}</option> })
                            .collect_view()}
                    </select>
                </label>
            </div>
        })
    };
    let footer = move || {
        card.with(|c| {
            let c = c.as_ref()?;
            let locked = c.list.hosts.iter().any(|h| h.locked_mode().is_some());
            let error = c.arp_error.clone();
            (locked || error.is_some()).then(|| view! {
                <div class="hosts-footer">
                    {locked.then(|| view! {
                        <p class="muted">"Same-network blocking works by redirecting the device's local traffic through the router (IPv4). It stops ordinary devices, not ones configured to bypass it."</p>
                    })}
                    {error.map(|e| view! {
                        <p class="field-error">{format!("Same-network blocking is off: {e}")}</p>
                    })}
                </div>
            })
        })
    };
    view! {
        {move || visible.get().then(|| view! {
            <section class="card card-wide hosts-card" aria-labelledby="w-hosts">
                <h2 id="w-hosts">{move || card.with(|c| format!("Hosts ({})", c.as_ref().map_or(0, |c| network.with(|n| c.count_in(n)))))}</h2>
                {toolbar}
                {body}
                {footer}
                {move || mode_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                {move || error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
            </section>
        })}
    }
    .into_any()
}

/// The Hosts card's label editor state, shared by every row's MAC cell.
// Saving only happens in the browser; the server build never reads the save-side fields.
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
#[derive(Clone, Copy)]
struct LabelEditor {
    card: RwSignal<Option<HostCard>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<Option<String>>,
    mode_error: RwSignal<Option<String>>,
    /// The MAC whose editor is open.
    editing: RwSignal<Option<String>>,
    /// The open editor's (type, maker) as typed.
    draft: RwSignal<(String, String)>,
}

impl LabelEditor {
    /// A click, submit, input or key event in the MAC cell of `mac`; events only reach
    /// here in the browser, so the server build ignores them.
    #[cfg(not(feature = "hydrate"))]
    fn event<E>(&self, _mac: &str, _ev: &E) {}

    #[cfg(feature = "hydrate")]
    fn event<E: AsRef<web_sys::Event>>(&self, mac: &str, ev: &E) {
        self.handle(mac, ev.as_ref());
    }

    #[cfg(feature = "hydrate")]
    fn handle(&self, mac: &str, ev: &web_sys::Event) {
        use wasm_bindgen::JsCast;
        let Some(el) = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
        else {
            return;
        };
        let open = self.editing.with_untracked(|e| e.as_deref() == Some(mac));
        let busy = self.busy.with_untracked(|b| b.as_deref() == Some(mac));
        match ev.type_().as_str() {
            "click" if el.has_attribute("data-edit") => {
                if open {
                    self.editing.set(None);
                    focus_in(mac, "[data-edit]");
                } else {
                    let data = |k| el.get_attribute(k).unwrap_or_default();
                    self.draft.set((data("data-kind"), data("data-maker")));
                    self.editing.set(Some(mac.to_owned()));
                    focus_in(mac, "select");
                }
            }
            "click" if el.has_attribute("data-reset") && !busy => self.save(mac, None, None),
            "submit" => {
                ev.prevent_default();
                let value = |sel| {
                    let e = el.query_selector(sel).ok()??;
                    if let Some(s) = e.dyn_ref::<web_sys::HtmlSelectElement>() {
                        return Some(s.value());
                    }
                    Some(e.dyn_ref::<web_sys::HtmlInputElement>()?.value())
                };
                if let (false, Some(kind), Some(maker)) = (busy, value("select"), value("input")) {
                    self.draft.set((kind.clone(), maker.clone()));
                    self.save(mac, Some(kind), Some(maker));
                }
            }
            "input" => {
                if let Some(s) = el.dyn_ref::<web_sys::HtmlSelectElement>() {
                    self.draft.update(|d| d.0 = s.value());
                } else if let Some(i) = el.dyn_ref::<web_sys::HtmlInputElement>() {
                    self.draft.update(|d| d.1 = i.value());
                }
            }
            "keydown"
                if open
                    && ev
                        .dyn_ref::<web_sys::KeyboardEvent>()
                        .is_some_and(|k| k.key() == "Escape") =>
            {
                self.editing.set(None);
                focus_in(mac, "[data-edit]");
            }
            _ => {}
        }
    }

    /// Saves the label (`None`, `None` is Reset to auto), then re-reads the hosts. Focus
    /// goes back to ✎ when it worked, to the type select when it did not.
    #[cfg(feature = "hydrate")]
    fn save(&self, mac: &str, kind: Option<String>, maker: Option<String>) {
        let s = *self;
        let mac = mac.to_owned();
        s.busy.set(Some(mac.clone()));
        spawn_local(async move {
            let ok = match set_host_label(mac.clone(), kind, maker).await {
                // a staged label shows its note on the row (from the staged document)
                Ok(_) => {
                    s.mode_error.set(None);
                    bump();
                    true
                }
                Err(e) => {
                    s.mode_error.set(Some(server_message(&e)));
                    false
                }
            };
            if ok
                && s.editing
                    .with_untracked(|e| e.as_deref() == Some(mac.as_str()))
            {
                s.editing.set(None);
            }
            s.busy.set(None);
            match hosts().await {
                Ok(c) => s.card.set(c),
                Err(e) => s.error.set(Some(format!("Could not read the hosts: {e}"))),
            }
            focus_in(&mac, if ok { "[data-edit]" } else { "select" });
        });
    }
}

/// Re-reads the hosts into `card`.
fn reload_hosts(card: RwSignal<Option<HostCard>>, error: RwSignal<Option<String>>) {
    spawn_local(async move {
        match hosts().await {
            Ok(c) => {
                card.set(c);
                error.set(None);
            }
            Err(e) => error.set(Some(format!("Could not read the hosts: {e}"))),
        }
    });
}

/// The `id` of the MAC cell of `mac`, for moving focus into it.
fn label_cell_id(mac: &str) -> String {
    format!("host-label-{}", mac.replace(':', ""))
}

/// Focuses the first `selector` match in the MAC cell of `mac` once the DOM has caught up.
#[cfg(feature = "hydrate")]
fn focus_in(mac: &str, selector: &'static str) {
    use wasm_bindgen::JsCast;
    let id = label_cell_id(mac);
    request_animation_frame(move || {
        if let Some(el) = document()
            .get_element_by_id(&id)
            .and_then(|c| c.query_selector(selector).ok().flatten())
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
        {
            let _ = el.focus();
        }
    });
}

/// Markup of a Hosts row's MAC cell: the MAC, then a line with the label (`title` holds
/// the reasons, one per line) and, with `edit`, the ✎ button (`open`: its editor is
/// shown; it carries the owner's type and maker to fill the editor with), then the
/// staged note. Agent strings are escaped: names and makers come off the network.
fn mac_cell_html(h: &crate::runtime::HostRow, edit: bool, open: bool) -> String {
    let mut out = escape_html(h.mac.as_deref().unwrap_or_default());
    let text = h.host_label.as_ref().map(|l| l.text()).unwrap_or_default();
    if !text.is_empty() || edit {
        out += r#"<span class="host-label-line">"#;
        if let Some(l) = h.host_label.as_ref().filter(|_| !text.is_empty()) {
            out += &format!(
                r#"<span class="host-label{}" title="{}"><span class="host-kind-icon" aria-hidden="true">{}</span>{}</span>"#,
                if l.guess() { " host-label-guess" } else { "" },
                escape_html(&l.reasons.join("\n")),
                l.kind_display().1,
                escape_html(&text)
            );
        }
        if edit {
            out += &format!(
                r#"<button type="button" class="icon-btn host-label-edit" aria-label="Edit label for {}" aria-expanded="{open}" data-edit="" data-kind="{}" data-maker="{}">✎</button>"#,
                escape_html(&h.label()),
                escape_html(h.owner_kind.as_deref().unwrap_or_default()),
                escape_html(h.owner_maker.as_deref().unwrap_or_default()),
            );
        }
        out += "</span>";
    }
    if h.staged_label {
        out += r#"<span class="muted host-label-staged">Staged — Apply to take effect</span>"#;
    }
    out
}

/// The label editor for the host called `name`: a form with a type select (Auto, then
/// every kind) and a maker field holding `kind` and `maker`, then Save (submit, so Enter
/// saves) and Reset to auto, disabled while `busy`. `name` and `maker` are escaped.
pub fn host_label_editor_html(name: &str, kind: &str, maker: &str, busy: bool) -> String {
    let name = escape_html(name);
    let sel = |on: bool| if on { " selected" } else { "" };
    let mut h = format!(
        r#"<form class="host-label-editor"><select aria-label="Type for {name}"><option value=""{}>Auto</option>"#,
        sel(kind.is_empty())
    );
    for (v, t, _) in crate::runtime::HOST_KINDS {
        h += &format!(r#"<option value="{v}"{}>{t}</option>"#, sel(v == kind));
    }
    let off = if busy { " disabled" } else { "" };
    h + &format!(
        r#"</select><input type="text" aria-label="Maker for {name}" placeholder="Auto" maxlength="64" value="{}"><button type="submit" class="btn btn-sm"{off}>Save</button><button type="button" class="btn btn-sm" data-reset=""{off}>Reset to auto</button></form>"#,
        escape_html(maker)
    )
}

/// `s` safe inside markup and quoted attributes.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The mode select's classes: compact, tinted for a locked mode.
fn mode_select_class(mode: &str) -> &'static str {
    match mode {
        "isolated" => "mode-select mode-isolated",
        "quarantine" => "mode-select mode-quarantine",
        _ => "mode-select",
    }
}

/// The mode a host's Mode select shows: the staged one, else the one in force.
fn mode_shown(h: &crate::runtime::HostRow) -> &str {
    h.staged_mode
        .as_deref()
        .unwrap_or_else(|| h.locked_mode().unwrap_or("normal"))
}

/// Keeps `DiffKind` in the bundle's public surface for the history page CSS classes.
pub fn diff_class(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "diff-add",
        DiffKind::Removed => "diff-del",
        DiffKind::Context => "diff-ctx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{HostLabelView, HostRow};

    /// Hostile maker, reasons and names reach the cell's markup only escaped.
    #[test]
    fn mac_cell_escapes_hostile_label_text() {
        const BAD: &str = r#""><script>alert(1)</script>&'"#;
        let h = HostRow {
            mac: Some("aa:bb:cc:dd:ee:01".into()),
            name: Some(BAD.into()),
            host_label: Some(HostLabelView {
                maker: Some(BAD.into()),
                kind: "camera".into(),
                confidence: "low".into(),
                reasons: vec![format!("Host name: {BAD}"), BAD.into()],
                by: "auto".into(),
            }),
            owner_kind: Some(BAD.into()),
            owner_maker: Some(BAD.into()),
            staged_label: true,
            ..HostRow::default()
        };
        let html = mac_cell_html(&h, true, false);
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains(BAD), "{html}");
        assert!(!html.contains("&'"), "{html}");
        let escaped = "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;&#39;";
        // maker (in the text), reasons (title), name (aria-label), owner fields (data-*)
        assert!(html.matches(escaped).count() >= 5, "{html}");
        assert!(
            html.contains(&format!("data-maker=\"{escaped}\"")),
            "{html}"
        );
        assert!(
            html.contains(&format!("aria-label=\"Edit label for {escaped}\"")),
            "{html}"
        );
        let editor = host_label_editor_html(BAD, BAD, BAD, false);
        assert!(!editor.contains("<script"), "{editor}");
        assert!(editor.contains(&format!("value=\"{escaped}\"")), "{editor}");
    }
}
