//! Pages of the routing slice, plus the generic `<SettingsForm<T>>` and `<Grid<T>>`.
//!
//! Pages are server-rendered; only the form, grid, banner and dashboard islands hydrate.

use crate::actions::{
    alias_feeds, field_choices, form_load, gateways_status, grid_fetch, live_status, pd_status,
    revision_diff, revisions,
};
use crate::api::DiffLine;
use crate::grid::GridQuery;
use crate::islands::{DashboardLive, GatewaysLive, GridIsland, SettingsFormIsland, diff_class};
use crate::models::*;
use crate::runtime::{Ipv6Status, fmt_time, lifetime, until};
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
            let choices = field_choices().await.unwrap_or_default();
            match form_load(T::ID, scope.clone()).await {
                Ok(initial) => view! {
                    <section class="card">
                        <h2>{title}</h2>
                        <SettingsFormIsland form=T::ID scope initial choices/>
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
            let choices = field_choices().await.unwrap_or_default();
            match grid_fetch(T::ID, scope.clone(), GridQuery::default()).await {
                Ok(initial) => view! {
                    <section class="card">
                        {title.map(|t| view! { <h2>{t}</h2> })}
                        <GridIsland grid=T::ID scope initial label=T::NOUN.to_owned() choices/>
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

/// Firewall › Aliases. Feed-backed aliases show what is loaded; GeoIP data carries the
/// attribution its licence (CC BY 4.0) requires.
#[component]
pub fn Aliases() -> impl IntoView {
    let credits = || {
        Suspend::new(async move {
            let mut notes: Vec<String> = alias_feeds()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|f| f.attribution)
                .collect();
            notes.sort();
            notes.dedup();
            notes
                .into_iter()
                .map(|n| view! { <p class="muted small attribution">{n}</p> })
                .collect_view()
        })
    };
    view! {
        <Grid<Alias>/>
        <Suspense fallback=|| ()>{credits}</Suspense>
    }
}

/// System › Gateways › Status.
#[component]
pub fn GatewayStatusPage() -> impl IntoView {
    let load = || {
        Suspend::new(async move {
            match gateways_status().await {
                Ok(initial) => view! { <GatewaysLive initial/> }.into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// The IPv6 prefix delegation panel: delegated prefix and lifetimes per uplink, and the /64
/// each LAN advertises (subnets of a withdrawn prefix flagged deprecated).
#[component]
pub fn Ipv6Prefixes(status: Ipv6Status) -> impl IntoView {
    let now = status.now;
    let body = if status.uplinks.is_empty() {
        view! { <p class="muted">"No interface requests a delegated prefix."</p> }.into_any()
    } else {
        status
            .uplinks
            .into_iter()
            .map(|u| {
                let up = u.interface.to_uppercase();
                let current = match u.state.current {
                    Some(c) => view! {
                        <dl class="kv">
                            <dt>"Delegated prefix"</dt><dd><code>{c.prefix}</code></dd>
                            <dt>"Preferred for"</dt><dd>{until(now, c.preferred_until)}</dd>
                            <dt>"Valid for"</dt><dd>{until(now, c.valid_until)}</dd>
                        </dl>
                    }
                    .into_any(),
                    None => view! { <p class="muted">"No prefix delegated."</p> }.into_any(),
                };
                let stale = u
                    .state
                    .stale
                    .into_iter()
                    .map(|p| view! {
                        <li><code>{p.prefix}</code>" "<span class="pill pill-warn">"deprecated"</span>
                            <span class="muted">{format!(" withdrawn; advertised until {}", fmt_time(p.deprecate_until))}</span></li>
                    })
                    .collect_view();
                let rows = u
                    .advertised
                    .into_iter()
                    .flat_map(|(lan, list)| list.into_iter().map(move |a| (lan.clone(), a)))
                    .map(|(lan, a)| view! {
                        <tr class:disabled=a.deprecated>
                            <td>{lan.to_uppercase()}</td>
                            <td><code>{a.prefix}</code></td>
                            <td class="num">{lifetime(a.preferred_lifetime_secs)}</td>
                            <td class="num">{lifetime(a.valid_lifetime_secs)}</td>
                            <td>{if a.deprecated {
                                view! { <span class="pill pill-warn">"deprecated"</span> }.into_any()
                            } else {
                                view! { <span class="pill pill-on">"preferred"</span> }.into_any()
                            }}</td>
                        </tr>
                    })
                    .collect_view();
                view! {
                    <h3>{format!("Uplink {up}")}</h3>
                    {current}
                    <ul class="plain">{stale}</ul>
                    <div class="table-wrap">
                    <table>
                        <caption class="sr-only">{format!("Prefixes advertised from {up}")}</caption>
                        <thead><tr>
                            <th scope="col">"Interface"</th><th scope="col">"Prefix"</th>
                            <th scope="col">"Preferred lifetime"</th><th scope="col">"Valid lifetime"</th>
                            <th scope="col">"State"</th>
                        </tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                    </div>
                }
            })
            .collect_view()
            .into_any()
    };
    view! {
        <section class="card" aria-labelledby="pd-head">
            <h2 id="pd-head">"IPv6 prefix delegation"</h2>
            {body}
        </section>
    }
}

/// Interfaces › Overview: link state and addresses, plus IPv6 prefix delegation.
#[component]
pub fn InterfacesOverview() -> impl IntoView {
    let load = || {
        Suspend::new(async move {
            let st = match live_status().await {
                Ok(s) => s,
                Err(e) => return load_error(e),
            };
            let pd = pd_status().await.unwrap_or_default();
            let rows = st
                .interfaces
                .into_iter()
                .map(|i| view! {
                    <tr>
                        <td><strong>{i.name}</strong></td>
                        <td>{i.device}</td>
                        <td><span class=if i.up { "pill pill-on" } else { "pill pill-off" }>{if i.up { "up" } else { "down" }}</span></td>
                        <td>{i.ipv4.unwrap_or_default()}</td>
                        <td>{i.ipv6.unwrap_or_default()}</td>
                    </tr>
                })
                .collect_view();
            view! {
                <section class="card" aria-labelledby="if-head">
                    <h2 id="if-head">"Interfaces"</h2>
                    <div class="table-wrap">
                    <table>
                        <thead><tr>
                            <th scope="col">"Interface"</th><th scope="col">"Device"</th><th scope="col">"Status"</th>
                            <th scope="col">"IPv4 address"</th><th scope="col">"IPv6 address"</th>
                        </tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                    </div>
                </section>
                <Ipv6Prefixes status=pd/>
            }
            .into_any()
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// Firewall › Rules, one tab per interface; drag rows to reorder.
#[component]
pub fn Rules() -> impl IntoView {
    let current = param("if").unwrap_or_else(|| "lan".to_owned());
    let tabs = {
        let current = current.clone();
        move || {
            let current = current.clone();
            Suspend::new(async move {
                let choices = field_choices().await.unwrap_or_default();
                let tabs = choices
                    .get(&crate::form::ChoiceSet::RuleInterfaces)
                    .cloned()
                    .unwrap_or_else(|| {
                        RULE_INTERFACES
                            .iter()
                            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                            .collect()
                    });
                tabs.into_iter()
                    .map(|(id, label)| {
                        let active = id == current;
                        view! {
                            <a class="tab" class:active=active aria-current=active.then_some("page")
                                href=format!("/ui/firewall/filter/{id}")>{label}</a>
                        }
                    })
                    .collect_view()
            })
        }
    };
    view! {
        <nav class="tabs" aria-label="Interface"><Suspense fallback=|| ()>{tabs}</Suspense></nav>
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
                    <form id=format!("rb-{}", r.id) method="post" action="/ui/fn/rollback_to" hidden>
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
