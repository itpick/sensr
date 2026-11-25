//! Pages of the routing slice, plus the generic `<SettingsForm<T>>` and `<Grid<T>>`.
//!
//! Pages are server-rendered; only the form, grid, banner and dashboard islands hydrate.

use crate::actions::{
    alias_feeds, dhcp_leases, dns_stats, field_choices, form_load, gateways_status, grid_fetch,
    hosts, ids_alerts, insight_data, live_status, passkey_list, pd_status, revision_diff,
    revisions, totp_status, update_status,
};
use crate::api::{
    AlertPage, DiffLine, DnsStats, INSIGHT_RANGES, InsightReport, TrafficPoint, TrafficRow,
};
use crate::grid::GridQuery;
use crate::islands::{
    DashboardLive, DhcpLeases, GatewaysLive, GridIsland, HostsCard, SettingsFormIsland,
    UpdatesLive, bps, diff_class,
};
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
    // Deep links from the global search: `?q=` fills the search box, `?edit=<key>` opens
    // that row's edit dialog once the island hydrates (an unknown key is ignored).
    let (search, edit) =
        use_query_map().with_untracked(|q| (q.get("q").unwrap_or_default(), q.get("edit")));
    let here = leptos_router::hooks::use_location();
    let clean_url = format!(
        "{}{}",
        here.pathname.get_untracked(),
        crate::grid::without_param(&here.search.get_untracked(), "edit")
    );
    let load = move || {
        let scope = scope.clone();
        let title = title.clone();
        let search = search.clone();
        let edit = edit.clone();
        let clean_url = clean_url.clone();
        Suspend::new(async move {
            let choices = field_choices().await.unwrap_or_default();
            let query = GridQuery {
                search: search.clone(),
                ..Default::default()
            };
            match grid_fetch(T::ID, scope.clone(), query).await {
                Ok(initial) => {
                    let edit = match edit {
                        Some(k) => edit_row::<T>(&scope, &initial, &k)
                            .await
                            .map(|r| (r, clean_url)),
                        None => None,
                    };
                    view! {
                        <section class="card">
                            {title.map(|t| view! { <h2>{t}</h2> })}
                            <GridIsland grid=T::ID scope initial label=T::NOUN.to_owned() choices search edit/>
                        </section>
                    }
                    .into_any()
                }
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// The row a `?edit=<key>` deep link names: from the shown page, else from the whole grid
/// (it may sit on a later page or be filtered out by `?q=`).
async fn edit_row<T: GridKind>(
    scope: &Option<String>,
    shown: &crate::grid::GridPage,
    key: &str,
) -> Option<serde_json::Value> {
    let key_field = T::ID.meta().key;
    let find = |rows: &[serde_json::Value]| {
        let keys: Vec<String> = rows
            .iter()
            .map(|r| {
                r.get(key_field)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        crate::grid::edit_target(&keys, Some(key)).map(|i| rows[i].clone())
    };
    if let Some(r) = find(&shown.rows) {
        return Some(r);
    }
    let all = GridQuery {
        per_page: 500,
        ..Default::default()
    };
    let page = grid_fetch(T::ID, scope.clone(), all).await.ok()?;
    find(&page.rows)
}

fn param(name: &'static str) -> Option<String> {
    use_params_map().with_untracked(|p| p.get(name))
}

/// Lobby › Dashboard.
#[component]
pub fn Dashboard() -> impl IntoView {
    // `?host=` (a global search hit) fills the Hosts card's search box.
    let search = use_query_map().with_untracked(|q| q.get("host").unwrap_or_default());
    let load = move || {
        let search = search.clone();
        Suspend::new(async move {
            let (status, hosts) = futures::join!(live_status(), hosts());
            match status {
                Ok(initial) => {
                    // The Hosts card is optional: an inventory error only leaves it out.
                    let hosts = hosts.ok().flatten();
                    view! { <DashboardLive initial/><HostsCard initial=hosts search/> }.into_any()
                }
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
    let leases = || {
        Suspend::new(async move {
            match dhcp_leases().await {
                Ok(table) => view! { <DhcpLeases initial=table/> }.into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! {
        <SettingsForm<DhcpSettings> scope=iface.clone() title="General settings"/>
        <Grid<DhcpRange> scope=iface.clone() title="Additional pools"/>
        <Grid<StaticMap> scope=iface title="Static mappings"/>
        <Suspense fallback=|| ()>{leases}</Suspense>
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
    view! {
        <p class="intro">"Host overrides answer for a name with your own records instead of the upstream answer. To send a whole domain to another server (a domain override), add it under Query Forwarding."</p>
        <Grid<HostOverride> title="Host overrides"/>
    }
}

/// Services › Unbound DNS › Advanced.
#[component]
pub fn UnboundAdvancedPage() -> impl IntoView {
    view! {
        <SettingsForm<UnboundAdvanced> title="General settings"/>
        <SettingsForm<UnboundServeExpired> title="Serve expired settings"/>
        <SettingsForm<UnboundLogging> title="Logging settings"/>
        <SettingsForm<UnboundCache> title="Cache settings"/>
    }
}

/// Services › Unbound DNS › Access Lists.
#[component]
pub fn UnboundAcl() -> impl IntoView {
    view! {
        <SettingsForm<UnboundAclDefault> title="Default action"/>
        <Grid<AccessList> title="Access lists"/>
    }
}

/// Services › Unbound DNS › Query Forwarding: the system-nameserver switch and custom
/// forwarders, which with a domain are OPNsense's domain overrides.
#[component]
pub fn UnboundForward() -> impl IntoView {
    view! {
        <p class="intro">"Forward queries to other servers instead of resolving them from the root. With a domain, an entry only forwards names under that domain (a domain override). DNS over TLS servers are configured on their own page."</p>
        <SettingsForm<UnboundForwarding> title="Query forwarding"/>
        <Grid<Forwarder> title="Custom forwarding"/>
    }
}

/// Services › Unbound DNS › Blocklist: policies and what the last refresh compiled.
#[component]
pub fn UnboundBlocklist() -> impl IntoView {
    let stats = || {
        Suspend::new(async move {
            match dns_stats().await {
                Ok(stats) => view! { <DnsStatsPanel stats/> }.into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! {
        <p class="intro">"Each policy blocks the names on its lists for the clients in its source networks (all clients when empty); the most specific network wins. Lists are downloaded and compiled by sensr itself and cached for the refresh interval."</p>
        <Grid<Blocklist> title="Blocklist policies"/>
        <Suspense fallback=|| ()>{stats}</Suspense>
    }
}

/// `1234567` → `1,234,567`.
pub fn thousands(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::with_capacity(d.len() + d.len() / 3);
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// An RFC 3339 UTC time as `2026-11-16 03:00:15 UTC`; other offsets are shown as given.
pub fn rfc3339_display(t: &str) -> String {
    match t.strip_suffix('Z') {
        Some(base) => format!(
            "{} UTC",
            base.replacen('T', " ", 1).split('.').next().unwrap_or(base)
        ),
        None => t.replacen('T', " ", 1),
    }
}

fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {}s", secs % 60)
    }
}

/// The statistics card of the Blocklist page (server-rendered, no island).
#[component]
pub fn DnsStatsPanel(#[prop(default = 100)] top: usize, stats: DnsStats) -> impl IntoView {
    let problems = stats
        .problems
        .iter()
        .map(|p| view! { <p class="field-error" role="alert">{format!("Could not read {p}")}</p> })
        .collect_view();
    let lists = match stats.blocklists {
        None => view! {
            <p class="muted" id="dnsbl-no-data">"No data yet: the blocklists have not been compiled since the resolver started. Statistics appear after the first refresh."</p>
        }
        .into_any(),
        Some(b) => {
            let policies = b
                .policies
                .into_iter()
                .map(|p| {
                    let rows = p
                        .sources
                        .into_iter()
                        .map(|src| {
                            let fetched = src
                                .fetched
                                .as_deref()
                                .map_or_else(|| "never".to_owned(), rfc3339_display);
                            let status = match &src.error {
                                Some(e) => view! { <span class="pill pill-off">"error"</span>" "{e.clone()} }.into_any(),
                                None => view! { <span class="pill pill-on">"ok"</span> }.into_any(),
                            };
                            view! {
                                <tr>
                                    <td class="url">{src.url}</td>
                                    <td class="num">{thousands(src.entries)}</td>
                                    <td>{fetched}</td>
                                    <td>{if src.from_cache { "cache" } else { "downloaded" }}</td>
                                    <td>{status}</td>
                                </tr>
                            }
                        })
                        .collect_view();
                    view! {
                        <h3 class="stats-policy">{format!("{}: {} names", p.description, thousands(p.names))}</h3>
                        <div class="table-wrap">
                            <table>
                                <thead><tr>
                                    <th scope="col">"List"</th><th scope="col">"Entries"</th>
                                    <th scope="col">"Last fetched"</th><th scope="col">"Source"</th>
                                    <th scope="col">"Status"</th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        </div>
                    }
                })
                .collect_view();
            view! {
                <dl class="stat-tiles" aria-label="Blocklists">
                    <div><dt>"Names blocked"</dt><dd id="dnsbl-names">{thousands(b.names)}</dd></div>
                    <div><dt>"Last update"</dt><dd>{rfc3339_display(&b.updated)}</dd></div>
                    <div><dt>"Refresh took"</dt><dd>{format!("{:.1} s", b.duration_ms as f64 / 1000.0)}</dd></div>
                </dl>
                {policies}
            }
            .into_any()
        }
    };
    let resolver = match stats.unbound {
        None => view! {
            <p class="muted" id="unbound-no-data">"No resolver statistics yet. They are sampled every minute while Unbound runs with statistics enabled (General)."</p>
        }
        .into_any(),
        Some(u) => {
            let pct = if u.queries > 0 {
                format!(" ({:.0}%)", u.cache_hits as f64 * 100.0 / u.queries as f64)
            } else {
                String::new()
            };
            let domains = u
                .top_domains
                .iter()
                .take(top)
                .map(|h| {
                    view! {
                        <tr><td class="wrap">{h.name.clone()}</td><td class="num">{thousands(h.count)}</td></tr>
                    }
                })
                .collect_view();
            let clients = u
                .top_clients
                .iter()
                .take(top)
                .map(|h| {
                    view! {
                        <tr><td class="num">{h.name.clone()}</td><td class="num">{thousands(h.count)}</td></tr>
                    }
                })
                .collect_view();
            let recent = u
                .recent
                .iter()
                .map(|q| {
                    view! {
                        <tr>
                            <td class="num">{rfc3339_display(&q.at)}</td>
                            <td class="num">{q.client.clone()}</td>
                            <td class="wrap">{q.name.clone()}</td>
                            <td>{q.kind.clone()}</td>
                        </tr>
                    }
                })
                .collect_view();
            let hits = (!domains.is_empty() || !clients.is_empty()).then(|| {
                view! {
                    <div class="dns-cols">
                        <section aria-labelledby="top-domains-title">
                            <h3 class="stats-policy" id="top-domains-title">{format!("Top {top} names")}</h3>
                            <div class="table-wrap">
                                <table>
                                    <thead><tr><th scope="col">"Name"</th><th scope="col">"Queries"</th></tr></thead>
                                    <tbody>{domains}</tbody>
                                </table>
                            </div>
                        </section>
                        <section aria-labelledby="top-clients-title">
                            <h3 class="stats-policy" id="top-clients-title">{format!("Top {top} clients")}</h3>
                            <div class="table-wrap">
                                <table>
                                    <thead><tr><th scope="col">"Client"</th><th scope="col">"Queries"</th></tr></thead>
                                    <tbody>{clients}</tbody>
                                </table>
                            </div>
                        </section>
                    </div>
                }
            });
            let recent = (!recent.is_empty()).then(|| {
                view! {
                    <h3 class="stats-policy" id="recent-queries-title">"Recent queries"</h3>
                    <div class="table-wrap">
                        <table aria-labelledby="recent-queries-title">
                            <thead><tr>
                                <th scope="col">"Seen"</th><th scope="col">"Client"</th>
                                <th scope="col">"Name"</th><th scope="col">"Type"</th>
                            </tr></thead>
                            <tbody>{recent}</tbody>
                        </table>
                    </div>
                }
            });
            let log_state = if !u.log_queries {
                view! {
                    <p class="muted small" id="unbound-log-off">
                        "Query logging is off, so top names, top clients and recent queries are not collected. Turn on "
                        <a href="/ui/unbound/advanced">"Log queries"</a>
                        " under Services › Unbound DNS › Advanced."
                    </p>
                }
                .into_any()
            } else if u.logged_queries == 0 {
                view! {
                    <p class="muted small" id="unbound-log-none">"Query logging is on. No queries have been logged since the sampler started."</p>
                }
                .into_any()
            } else {
                ().into_any()
            };
            view! {
                <dl class="stat-tiles" aria-label="Resolver">
                    <div><dt>"Total queries"</dt><dd id="unbound-queries">{thousands(u.queries)}</dd></div>
                    <div><dt>"Cache hits"</dt><dd>{format!("{}{pct}", thousands(u.cache_hits))}</dd></div>
                    <div><dt>"NXDOMAIN answers"</dt><dd>{thousands(u.nxdomain)}</dd></div>
                    <div><dt>"Resolver uptime"</dt><dd>{duration(u.uptime_seconds.max(0.0) as u64)}</dd></div>
                </dl>
                <p class="muted small">{format!("Sampled {}.", rfc3339_display(&u.at))}</p>
                {log_state}
                {hits}
                {recent}
                <p class="muted small">
                    "Counts cover the period since the DNS sampler last started. Recent queries are kept in memory only."
                </p>
            }
            .into_any()
        }
    };
    view! {
        <section class="card" aria-labelledby="dns-stats-title">
            <h2 id="dns-stats-title">"Statistics"</h2>
            {problems}
            {lists}
            <h3 class="stats-policy">"Resolver"</h3>
            {resolver}
            <p class="muted small" id="dnsbl-blocked-note">"Unbound does not count blocked queries per blocklist, so no blocked-query figure is shown. NXDOMAIN answers include, but are not limited to, names blocked by policies that return NXDOMAIN."</p>
        </section>
    }
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

/// System › Gateways › Configuration: the next hops rules and routes use.
#[component]
pub fn GatewaysConfig() -> impl IntoView {
    view! {
        <p class="intro">"Gateways are next hops on an assigned interface: the default route, policy-routed rules and failover groups are built from them. A gateway with no address is learned from DHCP, PPP or router advertisements on its interface."</p>
        <Grid<Gateway> title="Gateways"/>
    }
}

/// Interfaces › Virtual IPs › Settings.
#[component]
pub fn VirtualIpsPage() -> impl IntoView {
    view! {
        <p class="intro">"An IP alias adds an address to an interface, proxy ARP answers for addresses the host does not hold, and a shared address fails over between two firewalls. Shared addresses need the same virtual host id and secret on both peers."</p>
        <Grid<VirtualIp> title="Virtual IPs"/>
    }
}

/// Firewall › Groups.
#[component]
pub fn FirewallGroups() -> impl IntoView {
    view! {
        <p class="intro">"An interface group can be named by a rule like an interface, so one rule covers several networks. Rules on a group with a lower sequence are evaluated first."</p>
        <Grid<InterfaceGroup> title="Interface groups"/>
    }
}

/// Firewall › Isolation.
#[component]
pub fn FirewallIsolation() -> impl IntoView {
    view! {
        <p class="intro">"Devices listed here can still reach the internet and the router's own services (DNS, DHCP, NTP, the web GUI), but not other hosts on the local networks: they cannot see the printer, the NAS, the television or each other. Describe the devices with a MAC alias (Firewall › Aliases) or an address, and pick the interface they are attached to. The rules run before the user rules, so a broad 'allow LAN' rule does not undo them."</p>
        <Grid<Isolation> title="Isolated devices"/>
    }
}

/// Interfaces › Devices › Bridge.
#[component]
pub fn Bridges() -> impl IntoView {
    view! {
        <p class="intro">"A bridge joins devices into one layer-2 segment. Assign the bridge itself under Interfaces › Assignments to give it addresses; the member devices lose theirs."</p>
        <Grid<Bridge> title="Bridges"/>
    }
}

/// Interfaces › Devices › LAGG.
#[component]
pub fn Laggs() -> impl IntoView {
    view! {
        <p class="intro">"A link aggregate bundles several devices into one link for bandwidth or redundancy. Assign it under Interfaces › Assignments once it exists."</p>
        <Grid<Lagg> title="Link aggregates"/>
    }
}

/// Interfaces › Devices › Loopback.
#[component]
pub fn Loopbacks() -> impl IntoView {
    view! {
        <p class="intro">"Extra loopback devices, for routing protocols and services that need an address of their own. Assign one under Interfaces › Assignments to put addresses on it."</p>
        <Grid<LoopbackDevice> title="Loopback devices"/>
    }
}

/// System › Gateways › Group: failover and load balancing across gateways.
#[component]
pub fn GatewayGroupsPage() -> impl IntoView {
    view! {
        <p class="intro">"A group fails over between gateways or shares the traffic over them: the lowest tier with a member that is up carries it, and members of one tier share it by weight. Rules and routes use the group name like a gateway name."</p>
        <Grid<GatewayGroup> title="Gateway groups"/>
    }
}

/// System › Routes › Configuration.
#[component]
pub fn RoutesConfig() -> impl IntoView {
    view! {
        <p class="intro">"Static routes send a destination network to a gateway or gateway group. Connected networks and the default route are derived from the interface and gateway configuration."</p>
        <Grid<StaticRoute> title="Static routes"/>
    }
}

/// System › Access › Users: local accounts.
#[component]
pub fn UsersPage() -> impl IntoView {
    view! {
        <p class="intro">"Local accounts for the web GUI and SSH. The password is write-only: it is stored as a hash and never shown again. The root account is the first entry and cannot be deleted."</p>
        <Grid<User> title="Users"/>
    }
}

/// System › Access › Groups: local groups and their privileges.
#[component]
pub fn UserGroupsPage() -> impl IntoView {
    view! {
        <p class="intro">"A group carries the privileges its members get in the web GUI. Privileges are named per page, for example page-all for the whole GUI or page-firewall-rules for one section."</p>
        <Grid<UserGroup> title="Groups"/>
    }
}

/// System › Access › OpenID Connect: external sign-in providers.
#[component]
pub fn OidcPage() -> impl IntoView {
    view! {
        <p class="intro">"Sign in through an identity provider instead of a local password. sensr is the relying party: it validates the provider's ID token and maps the identity to the privileges of the configured local group. Zitadel, Google, Apple and any standards-compliant OpenID Connect issuer work; the login page keeps offering local accounts."</p>
        <SettingsForm<OidcSettings> title="OpenID Connect"/>
        <Grid<OidcProvider> title="Providers"/>
    }
}

/// System › Access › SAML: SP-initiated sign-in through SAML 2.0 identity
/// providers.
#[component]
pub fn SamlPage() -> impl IntoView {
    view! {
        <p class="intro">"Sign in through a SAML 2.0 identity provider. sensr is the service provider: it accepts only signed assertions, checks the audience and maps the configured attributes to the privileges of a local group. Paste the identity provider's metadata here, then give its administrator the service provider metadata URL shown in the provider list."</p>
        <SettingsForm<SamlSettings> title="SAML"/>
        <Grid<SamlProvider> title="Providers"/>
    }
}

/// System › Settings › General.
#[component]
pub fn SystemGeneralPage() -> impl IntoView {
    view! { <SettingsForm<SystemGeneral> title="System"/> }
}

/// System › Updates: pull and install a prebuilt system, optionally on a timer.
#[component]
pub fn UpdatesPage() -> impl IntoView {
    let load = || {
        Suspend::new(async move {
            match update_status().await {
                Ok(initial) => view! { <UpdatesLive initial/> }.into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// Lobby › Password: change the signed-in account's password.
#[component]
pub fn PasswordPage() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let changed = q.get("changed").is_some();
    let error = match q.get("error").as_deref() {
        Some("mismatch") => Some("The two new passwords do not match."),
        Some("short") => Some("The new password must be at least 8 characters."),
        Some("nouser") => Some("Could not find your account in the configuration."),
        _ => None,
    };
    view! {
        <section class="card">
            <h2>"Change password"</h2>
            {changed.then(|| view! {
                <p class="notice" role="status">"Password changed. Use it the next time you sign in."</p>
            })}
            {error.map(|e| view! {
                <p class="field-error" role="alert">{e}</p>
            })}
            <form method="post" action="/ui/fn/password">
                <div class="field-stack">
                    <label for="new_password">"New password"</label>
                    <input id="new_password" name="new_password" type="password"
                        autocomplete="new-password" minlength="8" required/>
                    <p class="muted small">"At least 8 characters."</p>
                </div>
                <div class="field-stack">
                    <label for="confirm_password">"Confirm new password"</label>
                    <input id="confirm_password" name="confirm_password" type="password"
                        autocomplete="new-password" minlength="8" required/>
                </div>
                <button type="submit" class="btn btn-primary">"Change password"</button>
            </form>
        </section>
        <TotpCard/>
        <PasskeysCard/>
    }
}

/// Lobby › Password › two-factor enrolment for the signed-in account.
#[component]
fn TotpCard() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let notice = match q.get("otp").as_deref() {
        Some("scan") => Some(
            "Scan the code or copy the secret into your authenticator app, then enter the six-digit code it shows.",
        ),
        Some("enabled") => {
            Some("Two-factor authentication is on. Password logins now ask for a code as well.")
        }
        Some("disabled") => {
            Some("Two-factor authentication is off. Password logins no longer ask for a code.")
        }
        _ => None,
    };
    let error = match q.get("otp").as_deref() {
        Some("bad") => {
            Some("That code was not accepted. Check the time on your phone and try again.")
        }
        Some("expired") => {
            Some("The enrolment expired before it was confirmed. Show a new secret.")
        }
        Some("nouser") => Some("Could not find your account in the configuration."),
        _ => None,
    };
    let load = move || {
        Suspend::new(async move {
            let status = match totp_status().await {
                Ok(s) => s,
                Err(e) => return load_error(e),
            };
            let body = if status.enabled {
                view! {
                    <p class="notice" role="status">"Two-factor authentication is enabled for this account."</p>
                    <form method="post" action="/ui/fn/totp/disable">
                        <button type="submit" class="btn">"Turn off two-factor authentication"</button>
                    </form>
                }.into_any()
            } else if let Some(secret) = status.secret {
                let uri = status.uri.unwrap_or_default();
                view! {
                    <p>"Add this account to an authenticator app (Aegis, 1Password, Google Authenticator):"</p>
                    <p><code class="secret">{secret}</code></p>
                    <p class="muted small">"Or import the provisioning URI:"</p>
                    <p class="wrap"><code class="secret small">{uri}</code></p>
                    <form method="post" action="/ui/fn/totp/confirm">
                        <div class="field-stack">
                            <label for="otp_code">"Code from the app"</label>
                            <input id="otp_code" name="code" type="text" inputmode="numeric"
                                autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required/>
                        </div>
                        <button type="submit" class="btn btn-primary">"Enable two-factor authentication"</button>
                    </form>
                    <form method="post" action="/ui/fn/totp/start">
                        <button type="submit" class="btn">"Show a new secret"</button>
                    </form>
                }.into_any()
            } else {
                view! {
                    <p>"Ask for a six-digit code from an authenticator app in addition to your password."</p>
                    {status.uri.is_none().then(|| view! {
                        <p class="muted small">"The secret is only shown while you enrol. If it is not here, show a new one."</p>
                    })}
                    <form method="post" action="/ui/fn/totp/start">
                        <button type="submit" class="btn btn-primary">"Set up two-factor authentication"</button>
                    </form>
                }.into_any()
            };
            view! {
                {notice.map(|n| view! { <p class="notice" role="status">{n}</p> })}
                {error.map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                {body}
            }
            .into_any()
        })
    };
    view! {
        <section class="card">
            <h2>"Two-factor authentication"</h2>
            <Suspense fallback=|| ()>{load}</Suspense>
        </section>
    }
}

/// Lobby › Password › passkeys (WebAuthn credentials) for the signed-in account.
#[component]
fn PasskeysCard() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let notice = match q.get("passkey").as_deref() {
        Some("added") => Some("Passkey added. You can sign in with it from now on."),
        Some("removed") => Some("Passkey removed."),
        _ => None,
    };
    let error = match q.get("passkey").as_deref() {
        Some("error") => Some("Could not find your account in the configuration."),
        _ => None,
    };
    let load = move || {
        Suspend::new(async move {
            let passkeys = match passkey_list().await {
                Ok(p) => p,
                Err(e) => return load_error(e),
            };
            let rows = passkeys
                .iter()
                .map(|p| {
                    let id = p.id.clone();
                    view! {
                        <li class="passkey-row">
                            <span class="passkey-name">{p.name.clone()}</span>
                            <form method="post" action="/ui/fn/passkey/remove">
                                <input type="hidden" name="id" value=id/>
                                <button type="submit" class="btn btn-sm">"Remove"</button>
                            </form>
                        </li>
                    }
                })
                .collect_view();
            let empty = passkeys.is_empty();
            view! {
                {notice.map(|n| view! { <p class="notice" role="status">{n}</p> })}
                {error.map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                {empty.then(|| view! {
                    <p>"No passkeys are registered for this account yet."</p>
                })}
                {(!empty).then(|| view! {
                    <ul class="passkey-list">{rows}</ul>
                })}
                <div class="passkey-add">
                    <div class="field-stack">
                        <label for="passkey_name">"Name this passkey"</label>
                        <input id="passkey_name" name="name" type="text" maxlength="64"
                            placeholder="Work laptop, YubiKey…" autocomplete="off"/>
                    </div>
                    <button type="button" id="passkey-add" class="btn btn-primary" hidden>
                        "Add a passkey"
                    </button>
                    <p id="passkey-card-error" class="field-error" role="alert" hidden></p>
                    <p id="passkey-card-notice" class="notice" role="status" hidden></p>
                </div>
                <p class="muted small">
                    "Passkeys need the GUI to be opened by hostname, not by IP address, and
                    the browser must offer WebAuthn."
                </p>
            }
            .into_any()
        })
    };
    view! {
        <section class="card">
            <h2>"Passkeys"</h2>
            <Suspense fallback=|| ()>{load}</Suspense>
        </section>
    }
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

/// Undoes `%XX` escapes (a malformed escape stays as it is).
pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes a query parameter value.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Bytes in decimal units, as traffic is usually counted.
pub fn fmt_bytes(v: u64) -> String {
    let f = v as f64;
    if f >= 1e12 {
        format!("{:.2} TB", f / 1e12)
    } else if f >= 1e9 {
        format!("{:.2} GB", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} MB", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.0} kB", f / 1e3)
    } else {
        format!("{v} B")
    }
}

// ------------------------------------------------------------ Services › Intrusion Detection

const IDS_TABS: &[(&str, &str)] = &[
    ("/ui/ids", "Settings"),
    ("/ui/ids/rules", "Rules"),
    ("/ui/ids/userdefined", "User defined"),
    ("/ui/ids/alerts", "Alerts"),
];

/// The OPNsense tab strip of Services › Intrusion Detection › Administration.
#[component]
fn IdsTabs(current: &'static str) -> impl IntoView {
    view! {
        <nav class="tabs" aria-label="Intrusion detection">
            {IDS_TABS.iter().map(|(url, label)| {
                let active = *url == current;
                view! { <a class="tab" class:active=active aria-current=active.then_some("page") href=*url>{*label}</a> }
            }).collect_view()}
        </nav>
    }
}

/// Services › Intrusion Detection › Administration › Settings.
#[component]
pub fn IdsSettingsPage() -> impl IntoView {
    view! {
        <IdsTabs current="/ui/ids"/>
        <p class="intro">"Suricata inspects the selected interfaces. Detect mode only raises alerts; prevent mode also blocks what drop rules match."</p>
        <SettingsForm<IdsSettings> title="General settings"/>
    }
}

/// Services › Intrusion Detection › Administration › Rules: suppressions.
#[component]
pub fn IdsRulesPage() -> impl IntoView {
    view! {
        <IdsTabs current="/ui/ids/rules"/>
        <p class="intro">"A suppression silences a signature's alerts, everywhere or for some addresses. The rule keeps running and still drops in prevent mode. The default suppressions for chatty informational signatures are switched under Settings."</p>
        <Grid<IdsSuppression> title="Suppressions"/>
    }
}

/// Services › Intrusion Detection › Administration › User defined.
#[component]
pub fn IdsUserRulesPage() -> impl IntoView {
    view! {
        <IdsTabs current="/ui/ids/userdefined"/>
        <p class="intro">"Your own rules: alert on, drop, or pass traffic by address or by TLS certificate fingerprint."</p>
        <Grid<IdsUserRule> title="User defined rules"/>
    }
}

fn severity(sev: u8) -> AnyView {
    let (class, text) = match sev {
        1 => ("pill pill-off", "high"),
        2 => ("pill pill-warn", "medium"),
        _ => ("pill pill-info", "low"),
    };
    view! { <span class=class>{text}</span> }.into_any()
}

fn endpoint(ip: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if ip.contains(':') => format!("[{ip}]:{p}"),
        Some(p) => format!("{ip}:{p}"),
        None => ip.to_owned(),
    }
}

/// The alerts tab with a filter and page (each value percent-encoded).
pub fn alerts_url(text: &str, host: &str, page: u32) -> String {
    let mut q = Vec::new();
    if !text.is_empty() {
        q.push(format!("text={}", url_encode(text)));
    }
    if !host.is_empty() {
        q.push(format!("host={}", url_encode(host)));
    }
    if page > 0 {
        q.push(format!("page={page}"));
    }
    if q.is_empty() {
        "/ui/ids/alerts".to_owned()
    } else {
        format!("/ui/ids/alerts?{}", q.join("&"))
    }
}

fn alerts_table(p: AlertPage, text: &str, host: &str) -> AnyView {
    let (text_v, host_v, page_v) = (text.to_owned(), host.to_owned(), p.page.to_string());
    if p.rows.is_empty() {
        return view! { <p class="muted">"No alerts match."</p> }.into_any();
    }
    let rows = p
        .rows
        .into_iter()
        .map(|a| {
            let sid = a.sid.to_string();
            let src = a.src_ip.clone();
            let actions = if a.suppressed {
                view! { <span class="pill pill-info">"suppressed"</span> }.into_any()
            } else {
                view! {
                    <form method="post" action="/ui/fn/ids_suppress" class="row-actions">
                        <input type="hidden" name="sid" value=sid.clone()/>
                        <input type="hidden" name="gid" value=a.gid.to_string()/>
                        <input type="hidden" name="signature" value=a.signature.clone()/>
                        <input type="hidden" name="text" value=text_v.clone()/>
                        <input type="hidden" name="host" value=host_v.clone()/>
                        <input type="hidden" name="page" value=page_v.clone()/>
                        <button type="submit" class="btn btn-sm" aria-label=format!("Suppress sid {sid}")>"Suppress"</button>
                        <button type="submit" class="btn btn-sm" name="src" value=src.clone()
                            aria-label=format!("Source only: suppress sid {sid} from {src}")>"Source only"</button>
                    </form>
                }
                .into_any()
            };
            view! {
                <tr>
                    <td class="num">{fmt_time(u64::try_from(a.ts / 1000).unwrap_or(0)).trim_end_matches(" UTC").to_owned()}</td>
                    <td class="num">{a.sid}</td>
                    <td class="sig">{a.signature}<br/><span class="muted small">{a.category}</span></td>
                    <td>{severity(a.severity)}</td>
                    <td class="num">{endpoint(&a.src_ip, a.src_port)}<br/>{format!("→ {}", endpoint(&a.dest_ip, a.dest_port))}<br/>
                        <span class="muted small">{format!("{} on {}", a.proto, a.iface)}</span></td>
                    <td class="col-actions">{actions}</td>
                </tr>
            }
        })
        .collect_view();
    let pages = p.total.div_ceil(u64::from(p.per_page.max(1))).max(1);
    let first = u64::from(p.page) * u64::from(p.per_page) + 1;
    let last = (first - 1 + u64::from(p.per_page)).min(p.total);
    let prev = (p.page > 0).then(|| alerts_url(text, host, p.page - 1));
    let next = (u64::from(p.page) + 1 < pages).then(|| alerts_url(text, host, p.page + 1));
    let link = |href: Option<String>, label: &'static str, sym: &'static str| match href {
        Some(h) => view! { <a class="btn btn-sm" href=h aria-label=label>{sym}</a> }.into_any(),
        None => {
            view! { <span class="btn btn-sm" aria-disabled="true" aria-label=label>{sym}</span> }
                .into_any()
        }
    };
    view! {
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th scope="col">"Time (UTC)"</th><th scope="col">"Sid"</th><th scope="col">"Signature"</th>
                    <th scope="col">"Severity"</th><th scope="col">"Source → destination"</th>
                    <th scope="col" class="col-actions"><span class="sr-only">"Actions"</span></th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        <nav class="pager" aria-label="Alert pages">
            <span class="muted">{format!("Showing {first} to {last} of {} alerts", p.total)}</span>
            <div class="pager-buttons">
                {link(prev, "Previous page", "‹")}
                <span aria-current="page">{format!("{} / {pages}", p.page + 1)}</span>
                {link(next, "Next page", "›")}
            </div>
        </nav>
    }
    .into_any()
}

/// Services › Intrusion Detection › Administration › Alerts: what Suricata raised, newest
/// first. Plain forms: filtering, paging and suppressing work without JavaScript.
#[component]
pub fn IdsAlertsPage() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let text = q.get("text").unwrap_or_default().trim().to_owned();
    let host = q.get("host").unwrap_or_default().trim().to_owned();
    let page: u32 = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(0);
    let staged = q.get("staged").filter(|s| s.parse::<u32>().is_ok());
    let error = match q.get("error").as_deref() {
        Some("address") => Some("Not an address."),
        Some("duplicate") => Some("This signature is already suppressed for these addresses."),
        Some(_) => Some("The suppression could not be staged."),
        None => None,
    };
    let load = move || {
        let (text, host) = (text.clone(), host.clone());
        let (staged, error) = (staged.clone(), error);
        Suspend::new(async move {
            let p = match ids_alerts(text.clone(), host.clone(), page).await {
                Ok(p) => p,
                Err(e) => return load_error(e),
            };
            let filtered = !text.is_empty() || !host.is_empty();
            let available = p.available;
            view! {
                <section class="card">
                    <h2>"Alerts"</h2>
                    {staged.map(|sid| view! {
                        <p class="notice" role="status">{format!("A suppression for signature {sid} is staged. Apply the changes to activate it.")}</p>
                    })}
                    {error.map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <form method="get" action="/ui/ids/alerts" class="filters" role="search" aria-label="Filter alerts">
                        <div class="field-stack">
                            <label for="alert-text">"Signature or sid"</label>
                            <input id="alert-text" name="text" type="search" value=text.clone() spellcheck="false"/>
                        </div>
                        <div class="field-stack">
                            <label for="alert-host">"Host address"</label>
                            <input id="alert-host" name="host" type="search" value=host.clone() spellcheck="false"/>
                        </div>
                        <div class="filter-actions">
                            <button type="submit" class="btn btn-primary">"Filter"</button>
                            {filtered.then(|| view! { <a class="btn" href="/ui/ids/alerts">"Clear"</a> })}
                        </div>
                    </form>
                    {if available {
                        alerts_table(p, &text, &host)
                    } else {
                        view! {
                            <p class="muted">"No alert database yet. It appears once intrusion detection is enabled and Suricata has raised its first alert."</p>
                        }.into_any()
                    }}
                </section>
            }
            .into_any()
        })
    };
    view! {
        <IdsTabs current="/ui/ids/alerts"/>
        <Suspense fallback=|| ()>{load}</Suspense>
    }
}

// ------------------------------------------------------------ Services › Port Scanner

/// Services › Port Scanner: New scan, the queue (with Cancel), every device's latest scan
/// (with Scan now) and the range scans, then the settings and the devices never scanned.
/// Server-rendered with plain forms that come back here (see
/// [`crate::portscan::PortscanQuery`]).
#[component]
pub fn PortscanPage() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let q = crate::portscan::PortscanQuery::from_query(|k| q.get(k));
    let load = move || {
        let q = q.clone();
        Suspend::new(async move {
            match crate::actions::portscan_page().await {
                Ok(p) => portscan_body(p, &q),
                Err(e) => load_error(e),
            }
        })
    };
    view! {
        <p class="intro">"The port scanner finds what each device offers on the network: every TCP port, the well-known UDP services, and what each service says about itself (names, versions, page titles, certificates). It scans a device once when it first appears, and whenever you ask."</p>
        <Suspense fallback=|| ()>{load}</Suspense>
        <SettingsForm<PortscanSettings> title="Settings"/>
        <Grid<PortscanExclude> title="Never scanned"/>
    }
}

/// The Port Scanner page's cards for `p`, with the message `q` came back with. Device text
/// is rendered as text only.
pub fn portscan_body(
    p: crate::portscan::PortscanView,
    q: &crate::portscan::PortscanQuery,
) -> AnyView {
    use crate::islands::{chip_html, ports_line_html};
    let can = p.can_scan;
    let message = q.message().map(|(bad, m)| {
        if bad {
            view! { <p class="field-error" role="alert">{m}</p> }.into_any()
        } else {
            view! { <p class="notice" role="status">{m}</p> }.into_any()
        }
    });
    let new_scan = can.then(|| {
        view! {
            <section class="card" aria-labelledby="ps-new">
                <h2 id="ps-new">"New scan"</h2>
                <form method="post" action="/ui/fn/portscan_submit" class="scan-form">
                    <div class="field-stack">
                        <label for="ps-target">"Address, network or range"</label>
                        <input id="ps-target" name="target" type="text" required spellcheck="false"
                            placeholder="192.168.1.20, 192.168.1.0/24 or 192.168.1.10-40" value=q.target.clone()/>
                    </div>
                    <label class="check">
                        <input type="checkbox" name="public_ok" value="on"/>
                        " Scan addresses outside the local networks"
                    </label>
                    <div class="filter-actions">
                        <button type="submit" class="btn btn-primary">"Scan"</button>
                    </div>
                </form>
                {message}
            </section>
        }
    });
    let cancel = move |id: u64, what: &str| {
        can.then(|| {
            view! {
                <form method="post" action="/ui/fn/portscan_cancel_form" class="row-actions">
                    <input type="hidden" name="job_id" value=id.to_string()/>
                    <button type="submit" class="btn btn-sm" aria-label=format!("Cancel the scan of {what}")>"Cancel"</button>
                </form>
            }
        })
    };
    let queue = if let Some(n) = &p.note {
        view! { <p class="field-error" role="alert">{n.clone()}</p> }.into_any()
    } else if p.jobs.is_empty() {
        view! { <p class="muted">"Nothing is being scanned."</p> }.into_any()
    } else {
        let rows = p
            .jobs
            .iter()
            .map(|j| {
                view! {
                    <tr>
                        <td class="num">{j.target.clone()}</td>
                        <td>{j.kind.clone()}</td>
                        <td>{j.progress.clone()}</td>
                        <td class="col-actions">{cancel(j.job_id, &j.target)}</td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <div class="table-wrap">
                <table class="scan-queue">
                    <caption class="sr-only">"Running and queued scans"</caption>
                    <thead><tr>
                        <th scope="col">"Target"</th><th scope="col">"Kind"</th>
                        <th scope="col">"Progress"</th>
                        <th scope="col" class="col-actions"><span class="sr-only">"Actions"</span></th>
                    </tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        }
        .into_any()
    };
    let devices = p
        .devices
        .iter()
        .map(|d| {
            let scan = (can && !d.ports.scanning)
                .then_some(())
                .and(d.ipv4.clone())
                .map(|ip| {
                    view! {
                        <form method="post" action="/ui/fn/portscan_submit" class="row-actions">
                            <input type="hidden" name="target" value=ip/>
                            <input type="hidden" name="mac" value=d.mac.clone()/>
                            <button type="submit" class="btn btn-sm" aria-label=format!("Scan {} now", d.name)>"Scan now"</button>
                        </form>
                    }
                });
            let line = ports_line_html(&d.ports, &d.key, None);
            let line = if line.is_empty() { "not scanned".to_owned() } else { line };
            view! {
                <tr>
                    <td><a href=crate::runtime::host_href(&d.key)>{d.name.clone()}</a></td>
                    <td class="num">{d.ipv4.clone().unwrap_or_default()}</td>
                    <td class="muted" inner_html=line></td>
                    <td class="col-actions">{scan}</td>
                </tr>
            }
        })
        .collect_view();
    let ranges = p
        .ranges
        .iter()
        .map(|j| {
            let results = j
                .results
                .iter()
                .map(|x| {
                    let ports = x.open.iter().map(chip_html).collect::<Vec<_>>().join(" · ");
                    let ports = if ports.is_empty() { "nothing open".to_owned() } else { ports };
                    view! { <li><span class="num">{x.address.clone()}</span>": "<span inner_html=ports></span></li> }
                })
                .collect_view();
            view! {
                <tr>
                    <td class="num">{j.target.clone()}</td>
                    <td class="num">{j.started.clone()}</td>
                    <td>{j.status.clone()}</td>
                    <td class="num">{j.alive}</td>
                    <td><ul class="range-results">{results}</ul></td>
                </tr>
            }
        })
        .collect_view();
    // without New scan, the message goes on its own
    let message = (!can).then(|| q.message()).flatten().map(|(_, m)| {
        view! { <section class="card"><p class="field-error" role="alert">{m}</p></section> }
    });
    view! {
        {new_scan}
        {message}
        <section class="card" aria-labelledby="ps-queue">
            <h2 id="ps-queue">"Running"</h2>
            {queue}
            <p><a class="btn btn-sm" href="/ui/portscan">"Refresh"</a></p>
        </section>
        <section class="card">
            <div class="table-wrap">
                <table class="device-scans">
                    <caption>"Device scans"</caption>
                    <thead><tr>
                        <th scope="col">"Device"</th><th scope="col">"Address"</th>
                        <th scope="col">"Open ports"</th>
                        <th scope="col" class="col-actions"><span class="sr-only">"Actions"</span></th>
                    </tr></thead>
                    <tbody>{devices}</tbody>
                </table>
            </div>
        </section>
        <section class="card">
            <div class="table-wrap">
                <table class="range-scans">
                    <caption>"Range scans"</caption>
                    <thead><tr>
                        <th scope="col">"Target"</th><th scope="col">"Started (UTC)"</th>
                        <th scope="col">"Status"</th><th scope="col">"Alive"</th>
                        <th scope="col">"Results"</th>
                    </tr></thead>
                    <tbody>{ranges}</tbody>
                </table>
            </div>
        </section>
    }
    .into_any()
}

// ------------------------------------------------------------ Reporting › Insight

fn insight_url(range: &str, host: Option<&str>) -> String {
    match host {
        Some(h) => format!(
            "/ui/diagnostics/networkinsight?range={range}&host={}",
            url_encode(h)
        ),
        None => format!("/ui/diagnostics/networkinsight?range={range}"),
    }
}

/// Received (above the axis) and sent (below) per bucket, as average rates.
fn traffic_chart(points: &[TrafficPoint], from: i64, to: i64, what: &str) -> AnyView {
    const W: f64 = 720.0;
    const MID: f64 = 92.0;
    const HALF: f64 = 80.0;
    let span = (to - from).max(1) as f64;
    let max = points
        .iter()
        .map(|p| p.down_bps().max(p.up_bps()))
        .max()
        .unwrap_or(0)
        .max(1);
    let bars = |sent: bool| {
        points
            .iter()
            .map(|p| {
                let v = if sent { p.up_bps() } else { p.down_bps() };
                let h = v as f64 / max as f64 * HALF;
                let x = (p.ts - from) as f64 / span * W;
                let w = (p.res as f64 / span * W).max(0.6);
                let y = if sent { MID } else { MID - h };
                format!("M{x:.1} {y:.1}h{w:.2}v{h:.1}h-{w:.2}z")
            })
            .collect::<String>()
    };
    let label = format!(
        "{what}: received above the line, sent below; peak {}",
        bps(max)
    );
    let t0 = fmt_time(u64::try_from(from).unwrap_or(0));
    let t1 = fmt_time(u64::try_from(to).unwrap_or(0));
    view! {
        <svg class="chart" viewBox="0 0 720 200" preserveAspectRatio="none" role="img" aria-label=label>
            <path class="chart-in" d=bars(false)/>
            <path class="chart-out" d=bars(true)/>
            <line class="chart-axis" x1="0" y1="92" x2="720" y2="92"/>
        </svg>
        <p class="chart-scale muted small">
            <span>{t0}</span><span>{format!("peak {}", bps(max))}</span><span>{t1}</span>
        </p>
    }
    .into_any()
}

fn top_table(
    caption: &'static str,
    key_head: &'static str,
    rows: Vec<TrafficRow>,
    link: impl Fn(&TrafficRow) -> Option<String>,
) -> AnyView {
    if rows.is_empty() {
        return view! {
            <section class="card"><h2>{caption}</h2><p class="muted">"No traffic in this range."</p></section>
        }
        .into_any();
    }
    let max = rows.iter().map(TrafficRow::total).max().unwrap_or(1).max(1);
    let body = rows
        .iter()
        .map(|r| {
            let name = if r.label.is_empty() {
                r.key.clone()
            } else {
                format!("{} ({})", r.label, r.key)
            };
            let cell = match link(r) {
                Some(href) => view! { <a href=href>{name}</a> }.into_any(),
                None => view! { <span>{name}</span> }.into_any(),
            };
            let pct = r.total() as f64 / max as f64 * 100.0;
            view! {
                <tr>
                    <td>{cell}<span class="bar" aria-hidden="true"><span style=format!("width:{pct:.1}%")></span></span></td>
                    <td class="num">{fmt_bytes(r.down)}</td>
                    <td class="num">{fmt_bytes(r.up)}</td>
                    <td class="num">{fmt_bytes(r.total())}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <section class="card">
            <h2>{caption}</h2>
            <div class="table-wrap">
                <table>
                    <thead><tr>
                        <th scope="col">{key_head}</th><th scope="col">"In"</th>
                        <th scope="col">"Out"</th><th scope="col">"Total"</th>
                    </tr></thead>
                    <tbody>{body}</tbody>
                </table>
            </div>
        </section>
    }
    .into_any()
}

fn insight_body(r: InsightReport, range: &'static str, host: Option<String>) -> AnyView {
    if !r.available {
        return view! {
            <section class="card">
                <h2>"No traffic database yet"</h2>
                <p>"Traffic accounting has not written any data. Enable it with " <code>"insight.enabled"</code>
                    "; the first figures appear within a minute."</p>
            </section>
        }
        .into_any();
    }
    let per = match r.resolution {
        60 => "minute",
        3600 => "hour",
        _ => "day",
    };
    let total_in: u64 = r.series.iter().map(|p| p.down).sum();
    let total_out: u64 = r.series.iter().map(|p| p.up).sum();
    let chart = traffic_chart(&r.series, r.from, r.to, "Traffic");
    let host_link = move |row: &TrafficRow| Some(insight_url(range, Some(&row.key)));
    match host {
        Some(h) => view! {
            <p><a href=insight_url(range, None)>"← All hosts"</a></p>
            <section class="card">
                <h2>{format!("Host {h}")}</h2>
                <p class="legend"><span class="key key-rx"></span>{format!("In {}", fmt_bytes(total_in))}
                    <span class="key key-tx"></span>{format!("Out {}", fmt_bytes(total_out))}
                    <span class="muted">{format!(" · per {per}")}</span></p>
                {chart}
            </section>
            {top_table("Top services", "Service", r.apps, |_| None)}
        }
        .into_any(),
        None => view! {
            <section class="card">
                <h2>"All local hosts"</h2>
                <p class="legend"><span class="key key-rx"></span>{format!("In {}", fmt_bytes(total_in))}
                    <span class="key key-tx"></span>{format!("Out {}", fmt_bytes(total_out))}
                    <span class="muted">{format!(" · per {per}")}</span></p>
                {chart}
            </section>
            <div class="insight-grid">
                {top_table("Top hosts", "Local host", r.hosts, host_link)}
                {top_table("Top services", "Service", r.apps, |_| None)}
                {top_table("Top remotes", "Remote address", r.remotes, |_| None)}
                {top_table("Interfaces", "Interface", r.ifaces, |_| None)}
            </div>
        }
        .into_any(),
    }
}

/// Reporting › Insight: who used the line, for what, and with whom. Server-rendered,
/// with links for the range and the per-host view.
#[component]
pub fn Insight() -> impl IntoView {
    let q = use_query_map().get_untracked();
    let (range, _, _) = crate::api::insight_range(&q.get("range").unwrap_or_default());
    let host = q
        .get("host")
        .map(|h| h.trim().to_owned())
        .filter(|h| h.parse::<std::net::IpAddr>().is_ok());
    let tabs = {
        let host = host.clone();
        INSIGHT_RANGES
            .iter()
            .map(|(k, label, _)| {
                let active = *k == range;
                view! {
                    <a class="tab" class:active=active aria-current=active.then_some("page")
                        href=insight_url(k, host.as_deref())>{*label}</a>
                }
            })
            .collect_view()
    };
    let load = move || {
        let host = host.clone();
        Suspend::new(async move {
            match insight_data(range.to_owned(), host.clone()).await {
                Ok(r) => insight_body(r, range, host),
                Err(e) => load_error(e),
            }
        })
    };
    view! {
        <nav class="tabs" aria-label="Time range">{tabs}</nav>
        <Suspense fallback=|| ()>{load}</Suspense>
    }
}

/// Reporting › Traffic: what crossed the interfaces, from the accounting database.
#[component]
pub fn Traffic() -> impl IntoView {
    let load = || {
        Suspend::new(async move {
            match insight_data("24h".to_owned(), None).await {
                Ok(r) if !r.available => view! {
                    <section class="card">
                        <h2>"Traffic"</h2>
                        <p class="muted">
                            "Traffic accounting has not written any data. Enable it with "
                            <code>"insight.enabled"</code> "."</p>
                    </section>
                }
                .into_any(),
                Ok(r) => view! {
                    <section class="card">
                        <h2>"Traffic, last 24 hours"</h2>
                        {traffic_chart(&r.series, r.from, r.to, "Traffic")}
                    </section>
                    <section class="card">
                        <h2>"Per interface"</h2>
                        {top_table("Interfaces", "Interface", r.ifaces, |_| None)}
                    </section>
                    <p class="muted small">
                        "Per host, service and remote address detail is under "
                        <a href="/ui/diagnostics/networkinsight">"Insight"</a> "."</p>
                }
                .into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    view! { <Suspense fallback=|| ()>{load}</Suspense> }
}

/// Reporting › Unbound DNS: resolver counters and blocklist state.
#[component]
pub fn UnboundOverview() -> impl IntoView {
    // The list length is a query parameter so the page stays a plain GET and
    // works without scripting.
    let top =
        leptos_router::hooks::use_query_map().with_untracked(|q| match q.get("top").as_deref() {
            Some("20") => 20,
            Some("50") => 50,
            _ => 100,
        });
    let load = move || {
        Suspend::new(async move {
            match dns_stats().await {
                Ok(stats) => view! {
                    <DnsStatsPanel top stats/>
                    <p class="muted small">
                        "Configuration is under "
                        <a href="/ui/unbound/general">"Services › Unbound DNS"</a> "."</p>
                }
                .into_any(),
                Err(e) => load_error(e),
            }
        })
    };
    let pick = move |n: usize| {
        view! {
            <a class="btn btn-sm" href=if n == 100 { "/ui/unbound/overview".to_owned() } else { format!("/ui/unbound/overview?top={n}") }
                aria-current=(n == top).then_some("page")>{n.to_string()}</a>
        }
    };
    view! {
        <div class="graph-head">
            <p class="intro">"Top queried names, the clients asking, and the most recent resolutions. Change the list length, or enable query logging under Services › Unbound DNS › Advanced to collect them."</p>
            <nav class="seg" aria-label="Rows to show">
                {pick(20)}{pick(50)}{pick(100)}
            </nav>
        </div>
        <Suspense fallback=|| ()>{load}</Suspense>
    }
}

// ------------------------------------------------------------ Hosts › one device

/// The host page's query: `?range=today|7d&page=N&q=…&edit=<name>&saved=…&error=…`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostQuery {
    /// `today` or `7d`.
    pub range: String,
    /// Domains page, from 0.
    pub page: u32,
    /// Domain search (filters the page shown).
    pub q: String,
    /// The looked-up name the service override editor is open for.
    pub edit: Option<String>,
    /// An override was just saved: `applied`, `staged` or `removed`.
    pub saved: Option<String>,
    /// The override editor's refusal.
    pub error: Option<String>,
    /// What Scan now came back with (`scan_`-prefixed keys).
    pub scan: crate::portscan::PortscanQuery,
}

impl HostQuery {
    /// The query of a host page URL.
    pub fn from_query(qm: &leptos_router::params::ParamsMap) -> Self {
        Self {
            range: if qm.get("range").as_deref() == Some("7d") {
                "7d".into()
            } else {
                "today".into()
            },
            page: qm
                .get("page")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0)
                .min(100_000),
            q: qm.get("q").unwrap_or_default(),
            edit: qm.get("edit").filter(|e| !e.is_empty()),
            saved: qm.get("saved"),
            error: qm.get("error"),
            scan: crate::portscan::PortscanQuery::from_query(|k| qm.get(&format!("scan_{k}"))),
        }
    }
}

/// A host page's data, loaded once per request: the layout's heading and the page body
/// both await it (provided as context by the layout).
#[derive(Clone)]
pub struct HostPageLoad(
    pub  futures::future::Shared<
        futures::future::BoxFuture<'static, Result<crate::actions::HostPageData, ServerFnError>>,
    >,
);

/// Starts loading the page of host `key` for query `q`.
#[cfg(feature = "ssr")]
pub fn host_page_load(key: String, q: &HostQuery) -> HostPageLoad {
    use futures::FutureExt;
    HostPageLoad(
        crate::actions::host_page(key, q.range.clone(), q.page, q.edit.clone())
            .boxed()
            .shared(),
    )
}

/// The copy of the banner shown while the dnstap feed is stale.
pub const STALE_FEED: &str = "DNS answers aren't arriving; showing lookups only.";

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Categories that count as screen time (everything but system and ads).
fn screen_time(category: &str) -> bool {
    !matches!(category, "system" | "ads_tracking")
}

/// `t` relative to `now`: `now`, `4 min ago`, `2 h ago`, `6 d ago`.
fn ago(now: i64, t: i64) -> String {
    let d = (now - t).max(0);
    match d {
        0..60 => "now".to_owned(),
        60..3_600 => format!("{} min ago", d / 60),
        3_600..86_400 => format!("{} h ago", d / 3_600),
        _ => format!("{} d ago", d / 86_400),
    }
}

/// A small category chip: its colour dot and name.
fn category_chip(key: &str) -> impl IntoView + use<> {
    let dot = format!("background:var(--{})", crate::runtime::category_token(key));
    view! {
        <span class="chip"><i class="dot" style=dot aria-hidden="true"></i>{crate::runtime::category_name(key)}</span>
    }
}

/// The URL of the host page with `range`, domains `page` and extra query text.
fn host_url(key: &str, range: &str, page: u32, extra: &str) -> String {
    let mut u = format!("{}?range={range}", crate::runtime::host_href(key));
    if page > 0 {
        u += &format!("&page={page}");
    }
    u + extra
}

/// `&q=<search>` for a non-blank search, else nothing.
fn search_param(q: &str) -> String {
    if q.trim().is_empty() {
        String::new()
    } else {
        format!("&q={}", url_encode(q))
    }
}

/// Where the service override form goes back to: the host page of `key` with its range,
/// domains page and search, every value percent-encoded (plain ASCII, safe for a Location
/// header). A key that is not an inventory key (a MAC or `id:` plus letters, digits, `:`,
/// `-`, `_`) goes back to the dashboard instead.
pub fn host_back_url(key: &str, range: &str, page: u32, q: &str) -> String {
    let key = key.trim();
    let ok = !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_'));
    if !ok {
        return "/".to_owned();
    }
    let range = if range == "7d" { "7d" } else { "today" };
    host_url(key, range, page.min(100_000), &search_param(q))
}

fn host_header(p: &crate::actions::HostPageData, range: &str) -> AnyView {
    let h = &p.host;
    let label = h.host_label.as_ref().filter(|l| !l.text().is_empty()).map(|l| {
        view! {
            <span class="host-label" class:host-label-guess=l.guess() title=l.reasons.join("\n")>
                <span class="host-kind-icon" aria-hidden="true">{l.kind_display().1}</span>{l.text()}
            </span>
        }
    });
    let mode = match h.locked_mode() {
        Some("isolated") => view! { <span class="pill pill-warn">"Isolated"</span> }.into_any(),
        Some("quarantine") => view! { <span class="pill pill-off">"Quarantine"</span> }.into_any(),
        _ => view! { <span class="pill pill-on">"Normal"</span> }.into_any(),
    };
    let seen = match h.seen(p.now).as_str() {
        s @ ("now" | "never") => s.to_owned(),
        s => format!("{s} ago"),
    };
    let tabs = [("today", "Today"), ("7d", "7 days")]
        .map(|(k, t)| {
            let current = k == range;
            view! {
                <a class="btn btn-sm" href=host_url(&h.key, k, 0, "")
                    aria-current=current.then_some("page")>{t}</a>
            }
        })
        .collect_view();
    let has_activity = p.activity.is_some();
    view! {
        <section class="card hp-wide" aria-labelledby="hp-h">
            <div class="hp-head">
                <div>
                    <h2 id="hp-h">{h.label()}</h2>
                    {label}
                    <dl class="hp-meta">
                        {h.mac.clone().map(|m| view! { <div><dt>"MAC"</dt><dd class="num">{m}</dd></div> })}
                        {h.ipv4.clone().map(|ip| view! { <div><dt>"IPv4"</dt><dd class="num">{ip}</dd></div> })}
                        {h.ipv6.first().cloned().map(|ip| view! { <div><dt>"IPv6"</dt><dd class="num">{ip}</dd></div> })}
                        {(!h.interface_name.is_empty()).then(|| view! { <div><dt>"Network"</dt><dd>{h.interface_name.clone()}</dd></div> })}
                        <div><dt>"Mode"</dt><dd>{mode}</dd></div>
                        <div><dt>"Last seen"</dt><dd>{seen}</dd></div>
                    </dl>
                </div>
                {has_activity.then(|| view! { <nav class="seg" aria-label="Time range">{tabs}</nav> })}
            </div>
        </section>
    }
    .into_any()
}

fn screen_time_card(a: &crate::api::HostActivityView) -> AnyView {
    let title = if a.range == "7d" {
        "Screen time, last 7 days"
    } else {
        "Screen time today"
    };
    let cats: Vec<_> = a
        .categories
        .iter()
        .filter(|c| screen_time(&c.category) && c.minutes > 0)
        .collect();
    let total: u32 = cats.iter().map(|c| c.minutes).sum::<u32>().max(1);
    let label = cats
        .iter()
        .map(|c| {
            format!(
                "{} {}",
                crate::runtime::category_name(&c.category),
                crate::runtime::fmt_minutes(c.minutes)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let bar = cats
        .iter()
        .map(|c| {
            let style = format!(
                "width:{:.2}%;background:var(--{})",
                f64::from(c.minutes) * 100.0 / f64::from(total),
                crate::runtime::category_token(&c.category)
            );
            view! { <i style=style></i> }
        })
        .collect_view();
    let legend = cats
        .iter()
        .map(|c| {
            let dot = format!(
                "background:var(--{})",
                crate::runtime::category_token(&c.category)
            );
            view! {
                <li><i class="dot" style=dot aria-hidden="true"></i>
                    {crate::runtime::category_name(&c.category)}
                    <b>{crate::runtime::fmt_minutes(c.minutes)}</b></li>
            }
        })
        .collect_view();
    let empty = cats.is_empty();
    view! {
        <section class="card" aria-labelledby="hp-s">
            <h2 id="hp-s">{title}</h2>
            <p class="big">{crate::runtime::fmt_minutes(a.screen_time)}</p>
            {(!empty).then(|| view! {
                <div class="sbar" role="img" aria-label=format!("Screen time by category: {label}")>{bar}</div>
                <ul class="legend-row">{legend}</ul>
            })}
            <p class="muted small">{if empty {
                "No screen time in this range. Apple/Google/Microsoft system and Ads & tracking are not counted."
            } else {
                "Apple/Google/Microsoft system and Ads & tracking are not counted."
            }}</p>
        </section>
    }
    .into_any()
}

fn services_card(a: &crate::api::HostActivityView) -> AnyView {
    let max = a
        .services
        .iter()
        .map(|s| s.minutes)
        .max()
        .unwrap_or(1)
        .max(1);
    let rows = a
        .services
        .iter()
        .map(|s| {
            let style = format!(
                "width:{:.1}%;background:var(--{})",
                f64::from(s.minutes) * 100.0 / f64::from(max),
                crate::runtime::category_token(&s.category)
            );
            view! {
                <li class="svc">
                    <span class="svc-name">{s.service.clone()}</span>
                    {category_chip(&s.category)}
                    <span class="track" aria-hidden="true"><i style=style></i></span>
                    <span class="t num">{crate::runtime::fmt_minutes(s.minutes)}</span>
                </li>
            }
        })
        .collect_view();
    let empty = a.services.is_empty();
    view! {
        <section class="card" aria-labelledby="hp-v">
            <h2 id="hp-v">"Services"</h2>
            {if empty {
                view! { <p class="muted">"No active minutes in this range."</p> }.into_any()
            } else {
                view! { <ul class="svc-list">{rows}</ul> }.into_any()
            }}
        </section>
    }
    .into_any()
}

fn timeline_card(a: &crate::api::HostActivityView) -> AnyView {
    const DAY: i64 = 86_400;
    let first = (a.from + a.utc_offset).div_euclid(DAY);
    let days = if a.range == "7d" { 7 } else { 1 };
    // cells can repeat a (day, hour): sum them, and scale by the summed cell, as drawn
    let mut sums: std::collections::BTreeMap<(i64, u8), u32> = Default::default();
    for c in &a.timeline {
        *sums.entry((c.day, c.hour)).or_default() += c.minutes;
    }
    let max = sums.values().copied().max().unwrap_or(0).max(1);
    let wd = |day: i64| WEEKDAYS[usize::try_from((day + 4).rem_euclid(7)).unwrap_or(0)];
    let mut grid = Vec::new();
    let mut table = Vec::new();
    for day in first..first + days {
        let name = wd(day);
        grid.push(view! { <span class="dl">{name}</span> }.into_any());
        let mut busy = Vec::new();
        for hour in 0..24u8 {
            let m = sums.get(&(day, hour)).copied().unwrap_or(0);
            let title = format!("{name} {hour:02}:00 — {m} min");
            if m > 0 {
                busy.push(format!("{hour:02}:00 {m} min"));
                let p = 15 + m * 85 / max;
                grid.push(
                    view! { <span class="c a" style=format!("--p:{p}%") title=title></span> }
                        .into_any(),
                );
            } else {
                grid.push(view! { <span class="c" title=title></span> }.into_any());
            }
        }
        let hours = if busy.is_empty() {
            "none".to_owned()
        } else {
            busy.join(", ")
        };
        table.push(view! { <tr><th scope="row">{name}</th><td>{hours}</td></tr> });
    }
    view! {
        <section class="card hp-wide" aria-labelledby="hp-w">
            <h2 id="hp-w">"When"</h2>
            <div class="heat" aria-hidden="true">
                {grid}
                <span></span>
                {["0", "6", "12", "18"].map(|h| view! { <span class="hl">{h}</span> })}
            </div>
            <div class="heat-scale" aria-hidden="true">"less"
                <i style="--p:15%"></i><i style="--p:40%"></i><i style="--p:70%"></i><i style="--p:100%"></i>"more"</div>
            // a table ignores the 1px box of .sr-only, so a wrapper carries it
            <div class="sr-only">
                <table>
                    <caption>"Screen time by day and hour"</caption>
                    <thead><tr><th scope="col">"Day"</th><th scope="col">"Hours with screen time"</th></tr></thead>
                    <tbody>{table}</tbody>
                </table>
            </div>
        </section>
    }
    .into_any()
}

fn domains_card(
    p: &crate::actions::HostPageData,
    a: &crate::api::HostActivityView,
    q: &HostQuery,
) -> AnyView {
    let key = p.host.key.clone();
    let range = a.range.clone();
    let now = i64::try_from(p.now).unwrap_or(0);
    let needle = q.q.trim().to_lowercase();
    let rows: Vec<_> = a
        .domains
        .iter()
        .filter(|d| {
            needle.is_empty()
                || d.qname.contains(&needle)
                || d.service.to_lowercase().contains(&needle)
        })
        .collect();
    let shown = rows.len();
    let count = if needle.is_empty() {
        format!("{shown} of {} names", thousands(u64::from(a.domains_total)))
    } else {
        format!("{shown} matching on this page")
    };
    let search_extra = if needle.is_empty() {
        String::new()
    } else {
        format!("&q={}", url_encode(&q.q))
    };
    let body = rows
        .into_iter()
        .map(|d| {
            let edit = p.can_edit.then(|| {
                let href = host_url(
                    &key,
                    &range,
                    a.page,
                    &format!("{search_extra}&edit={}", url_encode(&d.qname)),
                );
                view! {
                    <a class="btn btn-sm" href=href aria-label=format!("Set service for {}", d.qname)>"Set service"</a>
                }
            });
            let dot = format!("background:var(--{})", crate::runtime::category_token(&d.category));
            view! {
                <tr>
                    <td class="dom-name"><code>{d.qname.clone()}</code>
                        {d.blocked.then(|| view! { <span class="pill pill-off">"blocked"</span> })}
                        {d.new.then(|| view! { <span class="pill pill-info">"new"</span> })}</td>
                    <td class="dom-svc"><i class="dot" style=dot aria-hidden="true"></i>{d.service.clone()}
                        <span class="sr-only">{format!(" ({})", crate::runtime::category_name(&d.category))}</span></td>
                    <td class="num col-opt">{thousands(d.count)}</td>
                    <td class="num col-opt">{ago(now, d.first_seen)}</td>
                    <td class="num col-opt">{ago(now, d.last_seen)}</td>
                    <td class="dom-act">{edit}</td>
                </tr>
            }
        })
        .collect_view();
    let pages = a.domains_total.div_ceil(a.per_page.max(1));
    let pager = (pages > 1).then(|| {
        let prev = (a.page > 0).then(|| {
            view! { <a class="btn btn-sm" href=host_url(&key, &range, a.page - 1, &search_extra) rel="prev">"Previous"</a> }
        });
        let next = (a.page + 1 < pages).then(|| {
            view! { <a class="btn btn-sm" href=host_url(&key, &range, a.page + 1, &search_extra) rel="next">"Next"</a> }
        });
        view! {
            <nav class="pager" aria-label="Domain pages">
                <span class="muted">{format!("Page {} of {pages}", a.page + 1)}</span>
                <span class="pager-buttons">{prev}{next}</span>
            </nav>
        }
    });
    view! {
        <section class="card hp-wide" aria-labelledby="hp-d">
            <h2 id="hp-d">"Domains"</h2>
            <form method="get" action=crate::runtime::host_href(&key) class="grid-toolbar" role="search" aria-label="Search domains">
                <input type="hidden" name="range" value=range.clone()/>
                {(a.page > 0).then(|| view! { <input type="hidden" name="page" value=a.page.to_string()/> })}
                <label class="search">
                    <span class="sr-only">"Search domains"</span>
                    <input type="search" name="q" value=q.q.clone() placeholder="Search domains on this page"/>
                </label>
                <span class="muted">{count}</span>
            </form>
            {if shown == 0 {
                view! { <p class="muted">{if needle.is_empty() { "No lookups in this range." } else { "No name on this page matches." }}</p> }.into_any()
            } else {
                view! {
                    <div class="table-wrap">
                        <table class="dom">
                            <thead><tr>
                                <th scope="col">"Domain"</th>
                                <th scope="col">"Service"</th>
                                <th scope="col" class="num col-opt">"Queries"</th>
                                <th scope="col" class="num col-opt">"First seen"</th>
                                <th scope="col" class="num col-opt">"Last seen"</th>
                                <th scope="col"><span class="sr-only">"Actions"</span></th>
                            </tr></thead>
                            <tbody>{body}</tbody>
                        </table>
                    </div>
                }.into_any()
            }}
            {pager}
        </section>
    }
    .into_any()
}

/// The service override editor: a dialog with a plain form, opened by the page's URL
/// (`edit=`), so it needs no island; a line of script makes it modal when scripting is on.
fn override_dialog(
    p: &crate::actions::HostPageData,
    d: &crate::actions::OverrideDraft,
    q: &HostQuery,
) -> AnyView {
    let back = host_url(&p.host.key, &q.range, q.page, &search_param(&q.q));
    let (cancel, cancel_x, cancel_btn) = (back.clone(), back.clone(), back);
    let error = q.error.as_deref().map(|code| match code {
        "forbidden" => "You may not change service overrides.",
        "suffix" => "The suffix is a domain such as example.com.",
        "service" => "The service name is 1 to 48 characters.",
        "category" => "Pick a category.",
        _ => "The router refused the override. Check the suffix and the service name.",
    });
    let options = crate::runtime::CATEGORIES
        .iter()
        .map(|(k, name)| view! { <option value=*k selected=*k == d.category>{*name}</option> })
        .collect_view();
    // Save comes first in the form, so Enter saves rather than removes.
    view! {
        <dialog id="set-service" class="modal modal-small" open aria-labelledby="ss-title" data-cancel=cancel>
            <form method="post" action="/ui/fn/service_override">
                <div class="modal-head">
                    <h2 id="ss-title">"Set service"</h2>
                    <a class="icon-btn" href=cancel_x aria-label="Close">"✕"</a>
                </div>
                <div class="modal-body">
                    <p class="muted">"Choose what " <code>{d.qname.clone()}</code>
                        " and the other names under the suffix count as, on every device's page."</p>
                    {error.map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <input type="hidden" name="qname" value=d.qname.clone()/>
                    <input type="hidden" name="key" value=p.host.key.clone()/>
                    <input type="hidden" name="range" value=q.range.clone()/>
                    <input type="hidden" name="page" value=q.page.to_string()/>
                    <input type="hidden" name="q" value=q.q.clone()/>
                    <div class="field-stack">
                        <label for="ss-suffix">"Domain suffix"</label>
                        <input id="ss-suffix" name="suffix" type="text" required maxlength="253"
                            value=d.suffix.clone() aria-describedby="ss-suffix-help" autocapitalize="off" spellcheck="false"/>
                        <p id="ss-suffix-help" class="muted small">"Matches this domain and every name under it."</p>
                    </div>
                    <div class="field-stack">
                        <label for="ss-service">"Service"</label>
                        <input id="ss-service" name="service" type="text" required maxlength="48" autofocus
                            value=d.service.clone()/>
                    </div>
                    <div class="field-stack">
                        <label for="ss-category">"Category"</label>
                        <select id="ss-category" name="category">{options}</select>
                    </div>
                </div>
                <div class="modal-foot">
                    <button type="submit" class="btn btn-primary">"Save"</button>
                    <a class="btn" href=cancel_btn>"Cancel"</a>
                    {d.existing.then(|| view! {
                        <button type="submit" class="btn modal-foot-start" name="remove" value="1" formnovalidate>"Remove override"</button>
                    })}
                </div>
            </form>
        </dialog>
        <script inner_html="(function(){var d=document.getElementById('set-service');if(!d||!d.showModal)return;d.close();d.showModal();var i=document.getElementById('ss-service');if(i){i.focus();i.select();}d.addEventListener('cancel',function(e){e.preventDefault();location.href=d.dataset.cancel;});})();"></script>
    }
    .into_any()
}

/// The host page's Ports section (`#ports`): every port of the latest scan with what it
/// said, Scan now, and the scan history, newest first. Device text is rendered as text.
fn ports_card(d: &crate::portscan::HostPortsDetail, q: &crate::portscan::PortscanQuery) -> AnyView {
    use sensr_scan::types::{PortState, Proto};
    let state = |s: PortState| match s {
        PortState::Open => "open",
        PortState::OpenFiltered => "open|filtered",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
    };
    let scan = match (&d.ipv4, d.can_scan && !d.scanning) {
        _ if d.scanning => {
            Some(view! { <p class="muted port-scanning">"scanning…"</p> }.into_any())
        }
        (Some(ip), true) => Some(
            view! {
                <form method="post" action="/ui/fn/portscan_submit" class="scan-now">
                    <input type="hidden" name="target" value=ip.clone()/>
                    <input type="hidden" name="mac" value=d.mac.clone()/>
                    <input type="hidden" name="back" value="host"/>
                    <button type="submit" class="btn btn-sm">"Scan now"</button>
                </form>
            }
            .into_any(),
        ),
        _ => None,
    };
    let message = q.message().map(|(bad, m)| {
        if bad {
            view! { <p class="field-error" role="alert">{m}</p> }.into_any()
        } else {
            view! { <p class="notice" role="status">{m}</p> }.into_any()
        }
    });
    let table = if d.ports.is_empty() {
        let msg = if d.history.is_empty() {
            "Not scanned yet."
        } else {
            "No open ports."
        };
        view! { <p class="muted">{msg}</p> }.into_any()
    } else {
        let rows = d
            .ports
            .iter()
            .map(|p| {
                let grey = p.state != PortState::Open;
                let said = if p.state == PortState::OpenFiltered {
                    crate::runtime::OPEN_FILTERED_TIP.to_owned()
                } else {
                    crate::portscan::said(&p.ident)
                };
                view! {
                    <tr class:dimmed=grey>
                        <td class="num">{p.port}</td>
                        <td>{if p.proto == Proto::Tcp { "TCP" } else { "UDP" }}</td>
                        <td>{state(p.state)}</td>
                        <td>{p.service.clone().unwrap_or_default()}</td>
                        <td class="said">{said}</td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <div class="table-wrap">
                <table class="ports">
                    <thead><tr>
                        <th scope="col">"Port"</th><th scope="col">"Protocol"</th>
                        <th scope="col">"State"</th><th scope="col">"Service"</th>
                        <th scope="col">"What it said"</th>
                    </tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        }
        .into_any()
    };
    let history = (!d.history.is_empty()).then(|| {
        let items = d
            .history
            .iter()
            .map(|h| {
                let when = fmt_time(u64::try_from(h.finished).unwrap_or(0));
                let mut parts = vec![when, h.status.clone(), format!("{} open", h.open)];
                parts.extend(h.changes.iter().cloned());
                parts.push(format!("at {}", h.address));
                view! { <li>{parts.join(" · ")}</li> }
            })
            .collect_view();
        view! {
            <h3>"History"</h3>
            <ol class="scan-history">{items}</ol>
        }
    });
    view! {
        <section class="card hp-wide" id="ports" aria-labelledby="hp-ports">
            <h2 id="hp-ports">"Ports"</h2>
            {message}
            {scan}
            {table}
            {history}
        </section>
    }
    .into_any()
}

/// The body of a host page.
pub fn host_page_body(p: crate::actions::HostPageData, q: HostQuery) -> AnyView {
    let range = p
        .activity
        .as_ref()
        .map_or_else(|| q.range.clone(), |a| a.range.clone());
    let header = host_header(&p, &range);
    let saved = q.saved.as_deref().map(|s| {
        let msg = match s {
            "staged" => "Service override staged — Apply to take effect.",
            "removed" => "Service override removed. Names are re-attributed within a minute.",
            _ => "Service override saved. Names are re-attributed within a minute; minutes already counted keep their service.",
        };
        view! { <div class="banner banner-info hp-wide" role="status"><p>{msg}</p></div> }
    });
    let note = p.note.clone().map(|n| {
        view! { <section class="card hp-wide"><p class="muted">{n}</p></section> }
    });
    let body = p.activity.as_ref().map(|a| {
        let stale = a.feed_stale.then(|| {
            view! { <div class="banner banner-warn hp-wide" role="status"><p>{STALE_FEED}</p></div> }
        });
        if !a.available {
            return view! {
                {stale}
                <section class="card hp-wide">
                    <h2>"No DNS activity yet"</h2>
                    <p class="muted">"Per-device DNS activity is recorded by Insight once it is enabled (" <code>"insight.enabled"</code> "); the first lookups show within a minute."</p>
                </section>
            }
            .into_any();
        }
        view! {
            {stale}
            {screen_time_card(a)}
            {services_card(a)}
            {timeline_card(a)}
            {domains_card(&p, a, &q)}
        }
        .into_any()
    });
    let dialog = p.draft.as_ref().map(|d| override_dialog(&p, d, &q));
    let ports = p.ports.as_ref().map(|d| ports_card(d, &q.scan));
    view! {
        <div class="hp-grid">
            {header}
            {saved}
            {note}
            {body}
            {ports}
        </div>
        {dialog}
    }
    .into_any()
}

/// Hosts › one device: who it is and what it did (`/ui/hosts/<key>`). Server-rendered; the
/// range, search, paging and the service override editor are links and plain forms.
#[component]
pub fn HostActivityPage() -> impl IntoView {
    let key = param("mac").unwrap_or_default();
    let q = HostQuery::from_query(&use_query_map().get_untracked());
    // the layout started the load (and its heading uses it too)
    let shared = use_context::<HostPageLoad>();
    let load = move || {
        let (key, q, shared) = (key.clone(), q.clone(), shared.clone());
        Suspend::new(async move {
            let data = match shared {
                Some(l) => l.0.await,
                None => {
                    crate::actions::host_page(key, q.range.clone(), q.page, q.edit.clone()).await
                }
            };
            match data {
                Ok(p) => host_page_body(p, q),
                Err(e) => load_error(e),
            }
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
    use super::{fmt_bytes, fmt_time, url_encode};

    #[test]
    fn encodes_and_formats() {
        assert_eq!(url_encode("a b/c:1"), "a%20b%2Fc%3A1");
        assert_eq!(fmt_bytes(999), "999 B");
        assert_eq!(fmt_bytes(1_500_000), "1.5 MB");
    }

    fn render(f: impl FnOnce() -> leptos::prelude::AnyView) -> String {
        use leptos::prelude::*;
        Owner::new().with(|| f().to_html())
    }

    fn alert(sid: u32, suppressed: bool) -> crate::api::AlertRow {
        crate::api::AlertRow {
            id: 1,
            ts: 1_794_787_200_000,
            gid: 1,
            sid,
            signature: "ET SCAN Potential SSH Scan".into(),
            category: "Attempted Information Leak".into(),
            severity: 2,
            action: "allowed".into(),
            proto: "TCP".into(),
            src_ip: "2001:db8::7".into(),
            src_port: Some(40_000),
            dest_ip: "203.0.113.24".into(),
            dest_port: Some(22),
            iface: "eth0".into(),
            suppressed,
        }
    }

    #[test]
    fn alert_rows_carry_suppress_forms_and_page_links() {
        let page = crate::api::AlertPage {
            available: true,
            rows: vec![alert(2001219, false), alert(2013504, true)],
            total: 60,
            page: 1,
            per_page: 25,
        };
        let html = render(|| super::alerts_table(page, "ssh scan", ""));
        assert!(html.contains("Showing 26 to 50 of 60 alerts"), "{html}");
        assert!(html.contains("[2001:db8::7]:40000"));
        assert_eq!(html.matches("action=\"/ui/fn/ids_suppress\"").count(), 1);
        assert!(html.contains("aria-label=\"Source only: suppress sid 2001219 from 2001:db8::7\""));
        assert!(html.contains("name=\"text\" value=\"ssh scan\""), "{html}");
        assert!(html.contains("name=\"page\" value=\"1\""), "{html}");
        assert!(
            html.contains("href=\"/ui/ids/alerts?text=ssh%20scan\""),
            "previous page"
        );
        assert!(
            html.contains("href=\"/ui/ids/alerts?text=ssh%20scan&amp;page=2\""),
            "next page"
        );
        assert!(html.contains(">suppressed<"));
    }

    #[test]
    fn insight_without_a_database_says_so() {
        let html = render(|| super::insight_body(Default::default(), "24h", None));
        assert!(html.contains("No traffic database yet"));
    }

    #[test]
    fn insight_chart_and_tables() {
        use crate::api::{InsightReport, TrafficPoint, TrafficRow};
        let row = |key: &str, label: &str, up, down| TrafficRow {
            key: key.into(),
            label: label.into(),
            up,
            down,
            up_packets: 1,
            down_packets: 1,
        };
        let r = InsightReport {
            available: true,
            from: 0,
            to: 7200,
            resolution: 60,
            hosts: vec![row("192.168.1.20", "", 10, 1_000_000)],
            apps: vec![row("tcp/443", "HTTPS", 5, 500)],
            remotes: vec![],
            ifaces: vec![row("wan", "WAN", 1, 1)],
            series: vec![TrafficPoint {
                ts: 60,
                res: 60,
                up: 750,
                down: 7_500_000,
            }],
        };
        let html = render(|| super::insight_body(r, "2h", None));
        assert!(html.contains("peak 1.0 Mbit/s"), "{html}");
        assert!(
            html.contains("href=\"/ui/diagnostics/networkinsight?range=2h&amp;host=192.168.1.20\"")
        );
        assert!(html.contains("HTTPS (tcp/443)"));
        assert!(html.contains("No traffic in this range."), "empty remotes");
        assert!(html.contains("per minute"));
    }

    #[test]
    fn formats_numbers_and_rfc3339() {
        use super::{rfc3339_display, thousands};
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_284_377), "1,284,377");
        assert_eq!(
            rfc3339_display("2026-11-16T03:00:15Z"),
            "2026-11-16 03:00:15 UTC"
        );
        assert_eq!(
            rfc3339_display("2026-11-16T03:00:15.123Z"),
            "2026-11-16 03:00:15 UTC"
        );
        assert_eq!(
            rfc3339_display("2026-11-16T04:00:15+01:00"),
            "2026-11-16 04:00:15+01:00"
        );
    }

    #[test]
    fn formats_utc() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_time(1_794_787_200), "2026-11-16 00:00:00 UTC");
    }
}
