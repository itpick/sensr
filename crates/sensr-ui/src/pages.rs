//! Pages of the routing slice, plus the generic `<SettingsForm<T>>` and `<Grid<T>>`.
//!
//! Pages are server-rendered; only the form, grid, banner and dashboard islands hydrate.

use crate::actions::{form_load, grid_fetch, live_status, revision_diff, revisions};
use crate::api::DiffLine;
use crate::grid::GridQuery;
use crate::islands::{DashboardLive, GridIsland, SettingsFormIsland, diff_class};
use crate::models::*;
use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_query_map};
use std::marker::PhantomData;

fn load_error(e: ServerFnError) -> AnyView {
    view! { <div class="card"><p class="field-error" role="alert">{format!("Could not load: {e}")}</p></div> }.into_any()
}

/// A settings form generated from `T`'s field metadata, saved through the staged config.
#[component]
pub fn SettingsForm<T: FormKind>(
    /// Scope, e.g. the interface id for per-interface forms.
    #[prop(optional, into)]
    scope: Option<String>,
    /// Card heading.
    #[prop(into)]
    title: String,
    #[prop(optional)] _t: PhantomData<T>,
) -> impl IntoView {
    let load = move || {
        let scope = scope.clone();
        let title = title.clone();
        Suspend::new(async move {
            match form_load(T::ID, scope.clone()).await {
                Ok(initial) => view! {
                    <section class="card">
                        <h2>{title}</h2>
                        <SettingsFormIsland form=T::ID scope initial/>
                    </section>
                }
                .into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// A grid of `T` rows with search, sort, paging, bulk actions and an add/edit dialog.
#[component]
pub fn Grid<T: GridKind>(
    /// Scope, e.g. the interface whose rules are shown.
    #[prop(optional, into)]
    scope: Option<String>,
    /// Card heading; omitted for a bare grid.
    #[prop(optional, into)]
    title: Option<String>,
    #[prop(optional)] _t: PhantomData<T>,
) -> impl IntoView {
    let load = move || {
        let scope = scope.clone();
        let title = title.clone();
        Suspend::new(async move {
            match grid_fetch(T::ID, scope.clone(), GridQuery::default()).await {
                Ok(initial) => view! {
                    <section class="card">
                        {title.map(|t| view! { <h2>{t}</h2> })}
                        <GridIsland grid=T::ID scope initial label=T::NOUN.to_owned()/>
                    </section>
                }
                .into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

fn param(name: &'static str) -> Option<String> {
    use_params_map().with_untracked(|p| p.get(name))
}

/// Lobby › Dashboard.
#[component]
pub fn Dashboard() -> impl IntoView {
    let load = || {
        Suspend::new(async move {
            match live_status().await {
                Ok(initial) => view! { <DashboardLive initial/> }.into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// Interfaces › Assignments.
#[component]
pub fn Assignments() -> impl IntoView {
    view! {
        <p class="intro">"Assign network devices to interfaces. New assignments start disabled with no addressing; configure them under their own menu entry."</p>
        <Grid<Interface> title="Interface assignments"/>
    }
}

/// Interfaces › [WAN], [LAN], ….
#[component]
pub fn InterfacePage() -> impl IntoView {
    let id = param("id").unwrap_or_default();
    view! { <SettingsForm<Interface> scope=id title="Basic configuration"/> }
}

/// Firewall › Aliases.
#[component]
pub fn Aliases() -> impl IntoView {
    view! { <Grid<Alias>/> }
}

/// Firewall › Rules, one tab per interface; drag rows to reorder.
#[component]
pub fn Rules() -> impl IntoView {
    let current = param("if").unwrap_or_else(|| "lan".to_owned());
    let tabs = RULE_INTERFACES
        .iter()
        .map(|(id, label)| {
            let active = *id == current;
            view! {
                <a class="tab" class:active=active aria-current=active.then_some("page")
                    href=format!("/ui/firewall/filter/{id}")>{*label}</a>
            }
        })
        .collect_view();
    view! {
        <nav class="tabs" aria-label="Interface">{tabs}</nav>
        <p class="intro">"Rules are evaluated top to bottom; with Quick set, the first match wins. Drag a row or use the arrows to change the order."</p>
        <Grid<FilterRule> scope=current/>
    }
}

/// Firewall › NAT › Source NAT (outbound).
#[component]
pub fn SourceNat() -> impl IntoView {
    view! {
        <SettingsForm<SourceNatMode> title="Mode"/>
        <Grid<SourceNatRule> title="Manual rules"/>
    }
}

/// Firewall › NAT › Destination NAT (port forwards).
#[component]
pub fn DestinationNat() -> impl IntoView {
    view! { <Grid<PortForward>/> }
}

/// Services › DHCPv4 › [LAN].
#[component]
pub fn Dhcpv4() -> impl IntoView {
    let iface = param("if").unwrap_or_else(|| "lan".to_owned());
    view! {
        <SettingsForm<DhcpSettings> scope=iface.clone() title="General settings"/>
        <Grid<DhcpRange> scope=iface.clone() title="Additional pools"/>
        <Grid<StaticMap> scope=iface title="Static mappings"/>
    }
}

/// Services › Unbound DNS › General.
#[component]
pub fn UnboundGeneralPage() -> impl IntoView {
    view! { <SettingsForm<UnboundGeneral> title="General settings"/> }
}

/// Services › Unbound DNS › Overrides.
#[component]
pub fn UnboundOverrides() -> impl IntoView {
    view! { <Grid<HostOverride> title="Host overrides"/> }
}

/// VPN › WireGuard › Instances.
#[component]
pub fn WireguardInstances() -> impl IntoView {
    view! { <Grid<WgInstance>/> }
}

/// VPN › WireGuard › Peers.
#[component]
pub fn WireguardPeers() -> impl IntoView {
    view! { <Grid<WgPeer>/> }
}

/// System › Settings › General.
#[component]
pub fn SystemGeneralPage() -> impl IntoView {
    view! { <SettingsForm<SystemGeneral> title="System"/> }
}

fn fmt_time(t: u64) -> String {
    // UTC, no tz database needed: civil-from-days (Howard Hinnant's algorithm).
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// System › Configuration › History: revisions, diff between any two, rollback.
#[component]
pub fn History() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let from_q = q.get("from").and_then(|s| s.parse::<u64>().ok());
    let to_raw = q.get("to");
    let load = move || {
        let to_raw = to_raw.clone();
        Suspend::new(async move {
            let revs = match revisions().await {
                Ok(r) => r,
                Err(e) => return load_error(e),
            };
            let head = revs.first().map_or(0, |r| r.id);
            // `to=staged` compares the head with what the Apply banner would commit.
            let to: Option<u64> = match to_raw.as_deref() {
                Some("staged") => None,
                Some(s) => s.parse().ok().or(Some(head)),
                None => Some(head),
            };
            let from = from_q.unwrap_or_else(|| match to {
                None => head,
                Some(t) => revs.iter().find(|r| r.id < t).map_or(t, |r| r.id),
            });
            let diff: Vec<DiffLine> = revision_diff(from, to).await.unwrap_or_default();
            let to_label =
                to.map_or_else(|| "staged changes".to_owned(), |t| format!("revision {t}"));
            let rows = revs
                .iter()
                .map(|r| {
                    let id = r.id;
                    let is_head = id == head;
                    view! {
                        <tr>
                            <td><input type="radio" name="from" value=id.to_string() checked={id == from}
                                aria-label=format!("Compare from revision {id}")/></td>
                            <td><input type="radio" name="to" value=id.to_string() checked={to == Some(id)}
                                aria-label=format!("Compare to revision {id}")/></td>
                            <td class="num">{id}</td>
                            <td>{fmt_time(r.time)}</td>
                            <td>{r.user.clone()}</td>
                            <td>{r.message.clone()}</td>
                            <td>
                                {(!is_head).then(|| view! {
                                    <button type="submit" class="btn btn-sm" form=format!("rb-{id}")>"Revert to this"</button>
                                })}
                                {is_head.then(|| view! { <span class="pill pill-on">"active"</span> })}
                            </td>
                        </tr>
                    }
                })
                .collect_view();
            let rollback_forms = revs
                .iter()
                .filter(|r| r.id != head)
                .map(|r| view! {
                    <form id=format!("rb-{}", r.id) method="post" action="/api/rollback_to" hidden>
                        <input type="hidden" name="revision" value=r.id.to_string()/>
                    </form>
                })
                .collect_view();
            let empty = diff.is_empty();
            let lines = diff
                .into_iter()
                .map(|l| {
                    let sign = match l.kind {
                        crate::api::DiffKind::Added => "+ ",
                        crate::api::DiffKind::Removed => "- ",
                        crate::api::DiffKind::Context => "  ",
                    };
                    view! { <span class=diff_class(l.kind)>{sign}{l.text}"\n"</span> }
                })
                .collect_view();
            view! {
                <section class="card">
                    <h2>"Revisions"</h2>
                    <form method="get" action="/ui/core/backup/history">
                        <div class="table-wrap">
                        <table>
                            <thead><tr>
                                <th scope="col">"From"</th><th scope="col">"To"</th><th scope="col">"Rev."</th>
                                <th scope="col">"Date"</th><th scope="col">"User"</th><th scope="col">"Description"</th>
                                <th scope="col"><span class="sr-only">"Actions"</span></th>
                            </tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                        </div>
                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary">"Show differences"</button>
                            <a class="btn" href="/ui/core/backup/history?to=staged">"Compare with staged changes"</a>
                        </div>
                    </form>
                    {rollback_forms}
                </section>
                <section class="card">
                    <h2>{format!("Differences: revision {from} → {to_label}")}</h2>
                    {if empty {
                        view! { <p class="muted">"No differences."</p> }.into_any()
                    } else {
                        view! { <pre class="diff" tabindex="0" aria-label="Configuration diff">{lines}</pre> }.into_any()
                    }}
                </section>
            }
            .into_any()
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// Menu entries sensr does not implement yet.
#[component]
pub fn NotYet() -> impl IntoView {
    let path = leptos_router::hooks::use_location()
        .pathname
        .get_untracked();
    view! {
        <section class="card">
            <h2>"Not available yet"</h2>
            <p>"This page is part of the OPNsense menu sensr mirrors, but it is not implemented yet."</p>
            <p class="muted"><code>{path}</code></p>
            <p><a href="/">"Back to the dashboard"</a></p>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::fmt_time;

    #[test]
    fn formats_utc() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_time(1_794_787_200), "2026-11-16 00:00:00 UTC");
    }
}
