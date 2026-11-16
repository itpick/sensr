//! Pages of the routing slice, plus the generic `<SettingsForm<T>>` and `<Grid<T>>`.
//!
//! Pages are server-rendered; only the form, grid, banner and dashboard islands hydrate.

use crate::actions::{
    dns_stats, field_choices, form_load, grid_fetch, live_status, revision_diff, revisions,
};
use crate::api::{DiffLine, DnsStats};
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

/// Firewall › Aliases.
#[component]
pub fn Aliases() -> impl IntoView {
    view! { <Grid<Alias>/> }
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
pub fn DnsStatsPanel(stats: DnsStats) -> impl IntoView {
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
            view! {
                <dl class="stat-tiles" aria-label="Resolver">
                    <div><dt>"Total queries"</dt><dd id="unbound-queries">{thousands(u.queries)}</dd></div>
                    <div><dt>"Cache hits"</dt><dd>{format!("{}{pct}", thousands(u.cache_hits))}</dd></div>
                    <div><dt>"NXDOMAIN answers"</dt><dd>{thousands(u.nxdomain)}</dd></div>
                    <div><dt>"Resolver uptime"</dt><dd>{duration(u.uptime_seconds.max(0.0) as u64)}</dd></div>
                </dl>
                <p class="muted small">{format!("Sampled {}.", rfc3339_display(&u.at))}</p>
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

#[cfg(test)]
mod tests {
    use super::fmt_time;

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
