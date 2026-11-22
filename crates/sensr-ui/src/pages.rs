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
            let (status, hosts) = futures::join!(live_status(), hosts());
            match status {
                Ok(initial) => {
                    // The Hosts card is optional: an inventory error only leaves it out.
                    let hosts = hosts.ok().flatten();
                    view! { <DashboardLive initial/><HostsCard initial=hosts/> }.into_any()
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

fn alerts_url(text: &str, host: &str, page: u32) -> String {
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
    let back = alerts_url(text, host, p.page);
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
                        <input type="hidden" name="back" value=back.clone()/>
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
    let staged = q.get("staged");
    let error = q.get("error");
    let load = move || {
        let (text, host) = (text.clone(), host.clone());
        let (staged, error) = (staged.clone(), error.clone());
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
        assert!(html.contains("value=\"/ui/ids/alerts?text=ssh%20scan&amp;page=1\""));
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
