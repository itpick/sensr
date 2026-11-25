//! Component tests: render islands and chrome to HTML on the server and check structure and
//! accessibility basics (every control labelled, errors wired to fields, table semantics).

use leptos::prelude::*;
use scraper::{Html, Selector};
use sensr_ui::api::{FieldError, Pending};
use sensr_ui::form::{get_path, to_inputs};
use sensr_ui::grid::{GridQuery, run_query};
use sensr_ui::islands::{ApplyBanner, FormFields, GridIsland, SettingsFormIsland};
use sensr_ui::models::{FormId, GridId};

fn render(f: impl FnOnce() -> AnyView) -> Html {
    let owner = Owner::new();
    let html = owner.with(|| f().to_html());
    Html::parse_fragment(&html)
}

fn sel(s: &str) -> Selector {
    Selector::parse(s).unwrap()
}

/// Every form control has a visible label (`<label for>`), `aria-label`, or a wrapping label.
fn assert_all_labelled(doc: &Html, what: &str) {
    let labels: Vec<String> = doc
        .select(&sel("label[for]"))
        .filter_map(|l| l.value().attr("for").map(str::to_owned))
        .collect();
    for control in doc.select(&sel("input:not([type=hidden]), select, textarea")) {
        let v = control.value();
        let ok = v.attr("aria-label").is_some()
            || v.attr("id")
                .is_some_and(|id| labels.iter().any(|l| l == id))
            || control
                .ancestors()
                .any(|a| a.value().as_element().is_some_and(|e| e.name() == "label"));
        assert!(ok, "{what}: unlabelled control {:?}", v);
    }
}

const FORMS: [FormId; 13] = [
    FormId::SystemGeneral,
    FormId::Interface,
    FormId::SourceNatMode,
    FormId::DhcpSettings,
    FormId::UnboundGeneral,
    FormId::UnboundAdvanced,
    FormId::UnboundServeExpired,
    FormId::UnboundLogging,
    FormId::UnboundCache,
    FormId::UnboundAclDefault,
    FormId::UnboundForwarding,
    FormId::IdsSettings,
    FormId::PortscanSettings,
];

const GRIDS: [GridId; 17] = [
    GridId::Assignments,
    GridId::Aliases,
    GridId::FilterRules,
    GridId::SourceNat,
    GridId::PortForwards,
    GridId::DhcpRanges,
    GridId::StaticMaps,
    GridId::HostOverrides,
    GridId::AccessLists,
    GridId::Forwarders,
    GridId::Blocklists,
    GridId::WgInstances,
    GridId::WgPeers,
    GridId::IdsSuppressions,
    GridId::IdsUserRules,
    GridId::FirewallIsolation,
    GridId::PortscanExcludes,
];

#[test]
fn settings_forms_render_every_field_labelled() {
    let seed = sensr_ui::mock::seed();
    for form in FORMS {
        let initial = sensr_ui::adapt::form_to_view(form, &seed, &form.scope(&None)).unwrap();
        let doc = render(|| {
            view! { <SettingsFormIsland form scope=None initial choices=Default::default()/> }
                .into_any()
        });
        assert_all_labelled(&doc, &format!("{form:?}"));
        let controls = doc
            .select(&sel("form input, form select, form textarea"))
            .count();
        assert_eq!(
            controls,
            form.fields().len(),
            "{form:?}: one control per field"
        );
        assert!(doc.select(&sel("button[type=submit]")).next().is_some());
        // Help text is referenced by its input.
        for help in doc.select(&sel("p.help")) {
            let id = help.value().attr("id").unwrap();
            let referenced = doc.select(&sel("[aria-describedby]")).any(|e| {
                e.value()
                    .attr("aria-describedby")
                    .unwrap()
                    .split(' ')
                    .any(|x| x == id)
            });
            assert!(referenced, "{form:?}: help {id} not referenced");
        }
    }
}

#[test]
fn field_errors_attach_to_their_field() {
    let fields = FormId::SystemGeneral.fields();
    let doc = render(|| {
        let values = RwSignal::new(to_inputs(fields, &serde_json::json!({})));
        let errors = RwSignal::new(vec![FieldError::new("hostname", "Bad host name.")]);
        view! { <FormFields fields form_id="f".to_owned() values errors/> }.into_any()
    });
    let input = doc
        .select(&sel("#f--hostname"))
        .next()
        .expect("hostname input");
    assert_eq!(input.value().attr("aria-invalid"), Some("true"));
    let described = input.value().attr("aria-describedby").unwrap();
    assert!(described.split(' ').any(|x| x == "f--hostname-err"));
    let err = doc.select(&sel("#f--hostname-err")).next().unwrap();
    assert_eq!(err.text().collect::<String>(), "Bad host name.");
    // Other fields stay valid.
    let domain = doc.select(&sel("#f--domain")).next().unwrap();
    assert_eq!(domain.value().attr("aria-invalid"), None);
}

#[test]
fn grids_render_rows_with_table_semantics() {
    let seed = sensr_ui::mock::seed();
    for grid in GRIDS {
        let scope = grid.scope(&None);
        let store = sensr_ui::adapt::store(grid, &scope, &seed);
        let (sensr_ui::adapt::Store::Map(p) | sensr_ui::adapt::Store::Array(p)) = &store;
        let items: Vec<serde_json::Value> = match get_path(&seed, p).unwrap() {
            serde_json::Value::Object(m) => m.values().cloned().collect(),
            serde_json::Value::Array(a) => a.clone(),
            _ => unreachable!(),
        };
        let rows: Vec<_> = items
            .iter()
            .filter(|i| sensr_ui::adapt::in_scope(grid, &scope, &seed, i))
            .map(|i| sensr_ui::adapt::to_view(grid, &seed, i))
            .collect();
        let page = run_query(&rows, grid.columns(), &GridQuery::default());
        let n = page.rows.len();
        assert!(n > 0, "{grid:?}: seed has rows");
        let doc = render(|| {
            view! { <GridIsland grid scope=None initial=page label="item".to_owned() choices=Default::default()/> }.into_any()
        });
        assert_all_labelled(&doc, &format!("{grid:?}"));
        assert_eq!(doc.select(&sel("tbody tr")).count(), n, "{grid:?}");
        assert_eq!(
            doc.select(&sel("thead th[scope=col]")).count(),
            grid.columns().len() + 2,
            "{grid:?}: select + columns + actions"
        );
        for th in doc.select(&sel("thead th[aria-sort]")) {
            assert_eq!(th.value().attr("aria-sort"), Some("none"));
        }
        for b in doc.select(&sel("tbody button")) {
            assert!(
                b.value().attr("aria-label").is_some(),
                "{grid:?}: icon button without a name"
            );
        }
        assert_eq!(
            doc.select(&sel(".drag-handle")).count(),
            if grid.meta().ordered { n } else { 0 },
            "{grid:?}: reorder controls only on ordered grids"
        );
        assert!(doc.select(&sel("dialog[aria-labelledby]")).next().is_some());
    }
}

#[test]
fn apply_banner_states() {
    let clean = render(|| view! { <ApplyBanner initial=Pending::default()/> }.into_any());
    assert!(clean.select(&sel(".banner")).next().is_none());

    let alert = Pending {
        alert: Some("config.xml not imported: see import-report.txt".into()),
        ..Default::default()
    };
    let doc = render(|| view! { <ApplyBanner initial=alert/> }.into_any());
    let text: String = doc.root_element().text().collect();
    assert!(text.contains("config.xml not imported"), "{text}");

    let dirty = Pending {
        changed: vec!["firewall".into()],
        ..Default::default()
    };
    let doc = render(|| view! { <ApplyBanner initial=dirty/> }.into_any());
    let text: String = doc.root_element().text().collect();
    assert!(text.contains("You must apply the changes"));
    assert!(text.contains("Changed: firewall."));
    assert!(
        doc.select(&sel("button"))
            .any(|b| b.text().collect::<String>() == "Apply")
    );

    let probation = Pending {
        changed: vec![],
        confirm: Some(sensr_ui::api::ConfirmWindow {
            revision: 7,
            deadline: 1_060,
        }),
        now: 1_000,
        alert: None,
    };
    let doc = render(|| view! { <ApplyBanner initial=probation/> }.into_any());
    let text: String = doc.root_element().text().collect();
    assert!(text.contains("Revision 7"), "{text}");
    assert!(text.contains("in 60 s"), "{text}");
    assert!(
        doc.select(&sel("button"))
            .any(|b| b.text().collect::<String>() == "Keep changes")
    );
}

#[test]
fn menu_tree_marks_current_page() {
    use sensr_ui::app::MenuTree;
    let menu = sensr_ui::menu::build(&[]);
    let doc = render(|| view! { <MenuTree menu path="/ui/firewall/alias".to_owned()/> }.into_any());
    let current: Vec<_> = doc.select(&sel("a[aria-current=page]")).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].value().attr("href"), Some("/ui/firewall/alias"));
    let open: Vec<String> = doc
        .select(&sel("details[open] > summary"))
        .map(|s| s.text().collect::<String>())
        .collect();
    assert_eq!(open, ["Firewall"]);
    assert!(
        doc.select(&sel("nav[aria-label='Main menu']"))
            .next()
            .is_some()
    );
}

#[test]
fn blocklist_dialog_groups_curated_lists_like_opnsense() {
    let fields = GridId::Blocklists.meta().fields;
    let doc = render(|| {
        let values = RwSignal::new(to_inputs(
            fields,
            &serde_json::json!({"lists": ["hagezi-pro", "oisd-small"]}),
        ));
        let errors = RwSignal::new(vec![FieldError::new("lists", "Pick one.")]);
        view! { <FormFields fields form_id="b".to_owned() values errors/> }.into_any()
    });
    assert_all_labelled(&doc, "blocklist dialog");
    let legends: Vec<String> = doc
        .select(&sel("#b--lists fieldset > legend"))
        .map(|l| l.text().collect())
        .collect();
    assert_eq!(
        legends,
        [
            "General Blocklists",
            "HaGeZi Multi - Clean the Internet",
            "OISD Blocklists",
            "HaGeZi Targeted Lists",
            "Minimal Hardware Requirements"
        ]
    );
    let checked: Vec<&str> = doc
        .select(&sel("#b--lists input[checked]"))
        .filter_map(|i| i.value().attr("value"))
        .collect();
    assert_eq!(checked, ["hagezi-pro", "oisd-small"]);
    // The group is named by the field label and carries the error.
    let group = doc.select(&sel("#b--lists")).next().unwrap();
    assert_eq!(group.value().attr("role"), Some("group"));
    let label_id = group.value().attr("aria-labelledby").unwrap();
    let label = doc.select(&sel(&format!("#{label_id}"))).next().unwrap();
    assert_eq!(label.text().collect::<String>(), "Type of DNSBL");
    assert_eq!(group.value().attr("aria-invalid"), Some("true"));
    assert!(
        group
            .value()
            .attr("aria-describedby")
            .unwrap()
            .contains("b--lists-err")
    );
}

#[test]
fn dns_stats_panel_shows_no_data_then_figures() {
    use sensr_ui::pages::DnsStatsPanel;
    let empty = render(|| view! { <DnsStatsPanel stats=Default::default()/> }.into_any());
    assert!(empty.select(&sel("#dnsbl-no-data")).next().is_some());
    assert!(empty.select(&sel("#unbound-no-data")).next().is_some());
    assert!(empty.select(&sel("#dnsbl-blocked-note")).next().is_some());

    let doc = render(|| {
        view! { <DnsStatsPanel stats=sensr_ui::mock::simulated_dns_stats()/> }.into_any()
    });
    let text = |s: &str| {
        doc.select(&sel(s))
            .next()
            .unwrap()
            .text()
            .collect::<String>()
    };
    assert_eq!(text("#dnsbl-names"), "412,731");
    assert_eq!(text("#unbound-queries"), "1,284,377");
    let all: String = doc.root_element().text().collect();
    assert!(all.contains("Default: 238,904 names"), "{all}");
    assert!(all.contains("2026-11-16 03:00:15 UTC"));
    assert!(all.contains("HTTP 503"), "source errors are shown");
    assert!(all.contains("does not count blocked queries per blocklist"));
    // Four sources, five top names, three top clients and three recent queries.
    assert_eq!(doc.select(&sel("tbody tr")).count(), 15);
    // Each of the four tables carries its column headers.
    assert_eq!(doc.select(&sel("thead th[scope=col]")).count(), 18);
    assert!(all.contains("connectivity-check.ubuntu.com."), "{all}");
    assert!(all.contains("api.github.com."), "{all}");

    let mut off = sensr_ui::mock::simulated_dns_stats();
    if let Some(u) = off.unbound.as_mut() {
        u.log_queries = false;
    }
    let doc = render(|| view! { <DnsStatsPanel stats=off/> }.into_any());
    assert!(doc.select(&sel("#unbound-log-off")).next().is_some());

    let broken = sensr_ui::api::DnsStats {
        problems: vec!["/run/sensr-dns/unbound-stats.json: expected value".into()],
        ..Default::default()
    };
    let doc = render(|| view! { <DnsStatsPanel stats=broken/> }.into_any());
    assert!(
        doc.select(&sel("[role=alert]"))
            .any(|a| a.text().collect::<String>().contains("unbound-stats.json"))
    );
}
fn block<T>(f: futures::future::BoxFuture<'_, T>) -> T {
    futures::executor::block_on(f)
}

fn mock_runtime<T: serde::de::DeserializeOwned + Default>(
    section: sensr_ui::runtime::RuntimeSection,
) -> T {
    use sensr_ui::api::Backend;
    let m = sensr_ui::mock::MockBackend::with_clock(Box::new(|| 1_794_787_200));
    sensr_ui::runtime::parse(block(m.runtime(section)).unwrap())
}

fn text(e: scraper::ElementRef<'_>) -> String {
    e.text().collect()
}

#[test]
fn gateway_status_page_shows_badges_markers_and_groups() {
    use sensr_ui::islands::GatewaysLive;
    use sensr_ui::runtime::{GatewayState, GatewaysView, RuntimeSection};
    let mut initial: GatewaysView = mock_runtime(RuntimeSection::Gateways);
    initial.gateways[0].status = GatewayState::Down;
    initial.gateways.push(sensr_ui::runtime::GatewayRow {
        name: "LTE".into(),
        status: GatewayState::ForceDown,
        ..Default::default()
    });
    let doc = render(|| view! { <GatewaysLive initial/> }.into_any());
    let rows: Vec<_> = doc.select(&sel(".gw-table tbody tr")).collect();
    assert_eq!(rows.len(), 4);
    assert_eq!(doc.select(&sel(".gw-table thead th[scope=col]")).count(), 9);
    let row = |name: &str| {
        rows.iter()
            .find(|r| text(**r).contains(name))
            .copied()
            .unwrap()
    };
    // Colour per status: red for down, amber for latency, green for online.
    let badge = |name: &str| {
        let r = row(name);
        let b = r.select(&sel("td:last-child .pill")).next().unwrap();
        (b.value().attr("class").unwrap().to_owned(), text(b))
    };
    assert_eq!(badge("WAN_DHCP6"), ("pill pill-on".into(), "Online".into()));
    assert_eq!(
        badge("BACKUP_GW"),
        ("pill pill-warn".into(), "Latency".into())
    );
    assert_eq!(
        badge("LTE"),
        ("pill pill-off".into(), "Offline (forced)".into())
    );
    let first = text(rows[0]);
    assert!(
        first.contains("WAN_DHCP") && first.contains("Offline"),
        "{first}"
    );
    // The default gateway is marked; the backup is not.
    assert!(text(row("WAN_DHCP6")).contains("active"));
    assert!(!text(row("BACKUP_GW")).contains("active"));
    let backup = text(row("BACKUP_GW"));
    assert!(backup.contains("198.51.100.1") && backup.contains("198.51.100.53"));
    assert!(
        backup.contains(" ms") && backup.contains("2.0 %"),
        "{backup}"
    );
    // LTE has no data yet: OPNsense's placeholder.
    assert!(text(row("LTE")).contains('~'));
    // Groups with their active members.
    let groups: String = doc
        .select(&sel("[aria-labelledby=gw-groups] tbody tr"))
        .map(text)
        .collect();
    assert!(
        groups.contains("WAN_FAILOVER") && groups.contains("WAN_DHCP"),
        "{groups}"
    );
}

#[test]
fn gateway_status_page_without_monitor_says_so() {
    use sensr_ui::islands::GatewaysLive;
    let doc = render(|| view! { <GatewaysLive initial=Default::default()/> }.into_any());
    let all = text(doc.root_element());
    assert!(all.contains("No gateways are monitored."));
    assert!(all.contains("No gateway groups."));
}

#[test]
fn dashboard_gateways_widget_is_filled() {
    use sensr_ui::api::Backend;
    use sensr_ui::islands::DashboardLive;
    use sensr_ui::runtime::{GatewaysView, RuntimeSection};
    let m = sensr_ui::mock::MockBackend::with_clock(Box::new(|| 1_794_787_200));
    let mut initial = block(m.status()).unwrap();
    initial.gateways = mock_runtime::<GatewaysView>(RuntimeSection::Gateways).gateways;
    let doc = render(|| view! { <DashboardLive initial/> }.into_any());
    let items: Vec<String> = doc.select(&sel(".gw-list li")).map(text).collect();
    assert_eq!(items.len(), 3);
    assert!(items[0].contains("WAN_DHCP") && items[0].contains("(active)"));
    assert!(items[0].contains("RTT") && items[0].contains("RTTd") && items[0].contains("Loss"));
    assert!(items[2].contains("Latency") && !items[2].contains("(active)"));

    initial = block(m.status()).unwrap();
    let doc = render(|| view! { <DashboardLive initial/> }.into_any());
    assert!(text(doc.root_element()).contains("No gateway data."));
}

#[test]
fn alias_grid_shows_feed_status_with_error_badge() {
    use sensr_ui::runtime::AliasFeed;
    let seed = sensr_ui::mock::seed();
    let mut rows: Vec<_> = get_path(&seed, "firewall.aliases")
        .unwrap()
        .as_object()
        .unwrap()
        .values()
        .map(|i| sensr_ui::adapt::to_view(GridId::Aliases, &seed, i))
        .collect();
    let feeds = [
        AliasFeed {
            name: "spamhaus_drop".into(),
            kind: "url_table".into(),
            entries: 1234,
            updated_at: Some(1_794_787_200),
            ..Default::default()
        },
        AliasFeed {
            name: "nas".into(),
            error: Some("HTTP 503".into()),
            ..Default::default()
        },
    ];
    sensr_ui::adapt::add_feed_status(&mut rows, &feeds);
    let page = run_query(&rows, GridId::Aliases.columns(), &GridQuery::default());
    let doc = render(|| {
        view! { <GridIsland grid=GridId::Aliases scope=None initial=page label="alias".to_owned() choices=Default::default()/> }.into_any()
    });
    let heads: Vec<String> = doc.select(&sel("thead th[scope=col]")).map(text).collect();
    assert!(
        heads.iter().any(|h| h.trim() == "Loaded")
            && heads.iter().any(|h| h.trim() == "Last updated"),
        "{heads:?}"
    );
    let tr = |name: &str| {
        doc.select(&sel("tbody tr"))
            .find(|r| text(*r).contains(name))
            .unwrap()
    };
    let ok = text(tr("spamhaus_drop"));
    assert!(
        ok.contains("1234") && ok.contains("2026-11-16 00:00:00 UTC"),
        "{ok}"
    );
    let bad = tr("nas");
    let badge = bad.select(&sel(".pill-off")).next().expect("error badge");
    assert_eq!(badge.value().attr("title"), Some("HTTP 503"));
    assert!(text(bad).contains("never"));
    // Aliases without a feed have no badge.
    assert!(tr("web_ports").select(&sel(".pill-off")).next().is_none());
}

#[test]
fn ipv6_panel_shows_prefix_lifetimes_and_deprecated_subnets() {
    use sensr_ui::pages::Ipv6Prefixes;
    use sensr_ui::runtime::{Ipv6Status, RuntimeSection};
    let status = Ipv6Status {
        uplinks: mock_runtime(RuntimeSection::Ipv6),
        now: 1_794_787_200,
    };
    let doc = render(|| view! { <Ipv6Prefixes status/> }.into_any());
    let all = text(doc.root_element());
    assert!(all.contains("2001:db8:42::/56"), "{all}");
    assert!(all.contains("30m 0s") && all.contains("1h 30m"), "{all}");
    let rows: Vec<_> = doc.select(&sel("tbody tr")).collect();
    assert_eq!(rows.len(), 2);
    assert!(text(rows[0]).contains("2001:db8:42:1::/64") && text(rows[0]).contains("preferred"));
    assert!(text(rows[1]).contains("deprecated"));
    assert_eq!(rows[1].value().attr("class"), Some("disabled"));
    // The withdrawn /56 is listed too.
    assert!(all.contains("2001:db8:17::/56"));

    let empty = render(|| view! { <Ipv6Prefixes status=Ipv6Status::default()/> }.into_any());
    assert!(text(empty.root_element()).contains("No interface requests a delegated prefix."));
}

#[test]
fn lease_table_marks_reserved_rows_and_offers_the_rest() {
    use sensr_ui::actions::LeaseTable;
    use sensr_ui::islands::DhcpLeases;
    let leases = sensr_ui::mock::simulated_leases();
    let table = LeaseTable {
        now: 1_794_787_200,
        leases,
    };
    let doc = render(|| view! { <DhcpLeases initial=table/> }.into_any());
    let rows: Vec<_> = doc.select(&sel("tbody tr")).collect();
    assert_eq!(rows.len(), 4, "one row per lease");
    // The reserved client is marked and has nothing to press.
    assert!(text(rows[0]).contains("nas"));
    assert!(text(rows[0]).contains("static"));
    assert!(rows[0].select(&sel("button")).next().is_none());
    // A live lease without a reservation offers the button.
    assert!(text(rows[1]).contains("bench-pi"));
    let button = rows[1]
        .select(&sel("button"))
        .next()
        .expect("make-static button");
    assert_eq!(text(button), "Make static");
    // A client-id-only lease is reservable as well (Kea records no MAC for it).
    assert!(rows[2].select(&sel("button")).next().is_some());
    // The expired lease is dimmed and shows its state.
    assert_eq!(rows[3].value().attr("class"), Some("dimmed"));
    assert!(text(rows[3]).contains("expired"));
    let headers: Vec<String> = doc.select(&sel("thead th")).map(text).collect();
    assert!(headers.contains(&"MAC address".to_owned()));
}

#[test]
fn lease_table_explains_an_empty_dhcp_server() {
    use sensr_ui::actions::LeaseTable;
    use sensr_ui::islands::DhcpLeases;
    let doc = render(|| {
        view! { <DhcpLeases initial=LeaseTable { now: 0, leases: Vec::new() }/> }.into_any()
    });
    assert!(text(doc.root_element()).contains("No leases yet"));
    assert!(doc.select(&sel("tbody tr")).next().is_none());
}

const HOSTS_NOW: u64 = 1_794_787_200;

/// `hosts()` run against `m` as the signed-in backend.
fn hosts_from(m: sensr_ui::mock::MockBackend) -> Option<sensr_ui::actions::HostCard> {
    let handle: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    let owner = Owner::new();
    owner.with(|| {
        provide_context(handle);
        futures::executor::block_on(sensr_ui::actions::hosts()).unwrap()
    })
}

fn hosts_mock() -> sensr_ui::mock::MockBackend {
    sensr_ui::mock::MockBackend::with_clock(Box::new(|| HOSTS_NOW))
}

fn render_hosts(initial: Option<sensr_ui::actions::HostCard>) -> Html {
    use sensr_ui::islands::HostsCard;
    render(|| view! { <HostsCard initial/> }.into_any())
}

/// A Hosts row's name: its link's text (the cell also holds the DNS mix for screen readers).
fn name_text(td: scraper::ElementRef<'_>) -> String {
    td.select(&sel("a.host-link"))
        .next()
        .map_or_else(|| text(td), text)
        .trim()
        .to_owned()
}

/// The card's row for the host named `name`.
fn host_row<'a>(doc: &'a Html, name: &str) -> scraper::ElementRef<'a> {
    doc.select(&sel("tbody tr"))
        .find(|r| {
            r.select(&sel("td"))
                .next()
                .is_some_and(|td| name_text(td) == name)
        })
        .unwrap_or_else(|| panic!("no row for {name}"))
}

#[test]
fn hosts_card_lists_first_20_and_show_all() {
    let card = hosts_from(hosts_mock()).expect("root may see hosts");
    assert_eq!(card.list.hosts.len(), 25);
    let doc = render_hosts(Some(card));
    let title: Vec<String> = doc.select(&sel("h2")).map(text).collect();
    assert!(title.iter().any(|t| t == "Hosts (25)"), "{title:?}");
    assert_eq!(doc.select(&sel("tbody tr")).count(), 20);
    assert!(
        doc.select(&sel("button"))
            .any(|b| text(b).trim() == "Show all (25)")
    );
    let heads: Vec<String> = doc
        .select(&sel("thead th"))
        .map(|h| text(h).trim().to_owned())
        .collect();
    assert_eq!(
        heads,
        [
            "Name", "MAC", "IP", "Network", "Source", "Seen", "Today", "Mode", ""
        ]
    );
    let search = doc.select(&sel("input[type=search]")).next().unwrap();
    assert_eq!(
        search.value().attr("placeholder"),
        Some("Search name, MAC or IP")
    );
    let options: Vec<String> = doc
        .select(&sel(".grid-toolbar select option"))
        .map(text)
        .collect();
    assert_eq!(options, ["All networks", "LAN", "LAN2"]);
    assert_all_labelled(&doc, "hosts card");
}

#[test]
fn hosts_card_source_and_seen_labels() {
    let mut card = hosts_from(hosts_mock()).unwrap();
    // Never-seen hosts sort last; keep a few so they all render.
    card.list.hosts.retain(|h| {
        matches!(
            h.name.as_deref(),
            Some("printer" | "old-router" | "nas" | "bench-pi")
        ) || h.sources == ["neighbour"]
    });
    let doc = render_hosts(Some(card));
    let cells = |name: &str| -> Vec<String> {
        host_row(&doc, name)
            .select(&sel("td"))
            .map(|c| text(c).trim().to_owned())
            .collect()
    };
    let printer = cells("printer");
    assert_eq!(
        (printer[4].as_str(), printer[5].as_str()),
        ("static", "never")
    );
    let old = cells("old-router");
    assert_eq!((old[4].as_str(), old[5].as_str()), ("dynamic", "2h"));
    assert_eq!(old[3], "LAN2");
    let nas = cells("nas");
    assert_eq!((nas[4].as_str(), nas[5].as_str()), ("static", "now"));
    // A seen-only host has no name: its MAC stands in.
    let seen_row = doc
        .select(&sel("tbody tr"))
        .find(|r| {
            r.select(&sel("td"))
                .nth(4)
                .is_some_and(|c| text(c).trim() == "seen")
        })
        .expect("seen-only row");
    let seen: Vec<String> = seen_row
        .select(&sel("td"))
        .map(|c| text(c).trim().to_owned())
        .collect();
    let name = name_text(seen_row.select(&sel("td")).next().unwrap());
    assert!(seen[1].starts_with(&name), "name falls back to the MAC");
    assert_eq!(seen[4], "seen");
    // IPv6 sits on its own muted line under the IPv4.
    let ip = host_row(&doc, "nas").select(&sel("td")).nth(2).unwrap();
    assert!(text(ip).starts_with("192.168.1.20"));
    assert!(
        ip.select(&sel(".muted"))
            .next()
            .is_some_and(|m| text(m).contains(':'))
    );
}

#[test]
fn hosts_card_hidden_without_privilege() {
    let m = hosts_mock().with_privileges(&["page-sensr-status"]);
    let card = hosts_from(m);
    assert!(card.is_none());
    let doc = render_hosts(card);
    assert!(!text(doc.root_element()).contains("Hosts ("));
}

#[test]
fn hosts_card_read_only_has_no_actions() {
    let m = hosts_mock().with_privileges(&["page-all", "user-config-readonly"]);
    let card = hosts_from(m).expect("read-only users still see hosts");
    assert!(card.read_only);
    let doc = render_hosts(Some(card));
    let all = text(doc.root_element());
    assert!(all.contains("Hosts (25)"));
    assert!(!all.contains("Forget"), "{all}");
    assert!(!all.contains("Make static"));
    assert!(!all.contains("Reserved"), "{all}");
}

#[test]
fn hosts_card_reserved_row_has_no_forget() {
    let doc = render_hosts(hosts_from(hosts_mock()));
    let nas = host_row(&doc, "nas");
    assert!(
        nas.select(&sel(".host-actions button")).next().is_none(),
        "{}",
        text(nas)
    );
    let reserved = nas
        .select(&sel(".host-reserved"))
        .next()
        .expect("reserved note");
    assert_eq!(text(reserved), "Reserved");
    assert_eq!(
        reserved.value().attr("title"),
        Some("Remove the reservation on the DHCP page to forget this host")
    );
    // A leased host can be made static and forgotten.
    let pi: Vec<String> = host_row(&doc, "bench-pi")
        .select(&sel(".host-actions button"))
        .map(|b| text(b).trim().to_owned())
        .collect();
    assert_eq!(pi, ["Make static", "Forget"]);
}

#[test]
fn mock_forgets_unreserved_hosts_only() {
    use sensr_ui::api::Backend;
    let m = hosts_mock();
    assert!(
        block(m.forget_host("52:54:00:aa:bb:01".into())).is_err(),
        "nas is reserved"
    );
    assert!(block(m.forget_host("no:such:host".into())).is_err());
    block(m.forget_host("b8:27:eb:7d:4e:25".into())).unwrap();
    let card = hosts_from(m).unwrap();
    assert_eq!(card.list.hosts.len(), 24);
    assert!(
        card.list
            .hosts
            .iter()
            .all(|h| h.name.as_deref() != Some("bench-pi"))
    );
}

#[test]
fn hosts_card_empty_list_says_so() {
    let card = sensr_ui::actions::HostCard {
        list: sensr_ui::runtime::HostList {
            now: HOSTS_NOW,
            hosts: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    let doc = render_hosts(Some(card));
    let all = text(doc.root_element());
    assert!(
        all.contains("Hosts (0)") && all.contains("No hosts seen yet."),
        "{all}"
    );
    assert!(doc.select(&sel("table")).next().is_none());
}

#[test]
fn hosts_card_make_static_needs_a_lease_a_mac_and_an_ipv4() {
    let mut card = hosts_from(hosts_mock()).unwrap();
    let base = card
        .list
        .hosts
        .iter()
        .find(|h| h.name.as_deref() == Some("bench-pi"))
        .unwrap()
        .clone();
    let no_mac = sensr_ui::runtime::HostRow {
        key: "id:01aa".into(),
        mac: None,
        name: Some("no-mac".into()),
        ..base.clone()
    };
    let no_ip = sensr_ui::runtime::HostRow {
        key: "02:aa:00:00:00:01".into(),
        mac: Some("02:aa:00:00:00:01".into()),
        name: Some("no-ip".into()),
        ipv4: None,
        ..base
    };
    card.list.hosts.retain(|h| h.sources == ["neighbour"]);
    card.list.hosts.extend([no_mac, no_ip]);
    let doc = render_hosts(Some(card));
    let buttons = |r: scraper::ElementRef<'_>| -> Vec<String> {
        r.select(&sel(".host-actions button"))
            .map(|b| text(b).trim().to_owned())
            .collect()
    };
    let seen = doc
        .select(&sel("tbody tr"))
        .find(|r| {
            r.select(&sel("td"))
                .nth(4)
                .is_some_and(|c| text(c).trim() == "seen")
        })
        .expect("seen-only row");
    assert_eq!(
        buttons(seen),
        ["Forget"],
        "no lease: nothing to make static"
    );
    assert_eq!(buttons(host_row(&doc, "no-mac")), ["Forget"]);
    assert_eq!(buttons(host_row(&doc, "no-ip")), ["Forget"]);
}

#[test]
fn hosts_card_make_static_is_gone_once_staged() {
    let handle: sensr_ui::api::BackendHandle = std::sync::Arc::new(hosts_mock());
    let owner = Owner::new();
    let card = owner.with(|| {
        provide_context(handle);
        futures::executor::block_on(sensr_ui::actions::reserve_lease(
            "192.168.1.112".into(),
            Some("b8:27:eb:7d:4e:25".into()),
            None,
            "bench-pi".into(),
        ))
        .unwrap();
        futures::executor::block_on(sensr_ui::actions::hosts())
            .unwrap()
            .unwrap()
    });
    let pi = card
        .list
        .hosts
        .iter()
        .find(|h| h.name.as_deref() == Some("bench-pi"))
        .unwrap();
    assert!(pi.staged, "the staged reservation covers bench-pi");
    // others are untouched until they are staged too
    assert!(
        !card
            .list
            .hosts
            .iter()
            .any(|h| h.staged && h.name.as_deref() != Some("bench-pi"))
    );
    let doc = render_hosts(Some(card));
    let row = host_row(&doc, "bench-pi");
    let buttons: Vec<String> = row
        .select(&sel(".host-actions button"))
        .map(|b| text(b).trim().to_owned())
        .collect();
    assert_eq!(buttons, ["Forget"], "no second Make static before Apply");
    assert!(text(row).contains("staged"));
}

#[test]
fn hosts_card_filter_search_and_show_all() {
    let card = hosts_from(hosts_mock()).unwrap();
    // Everything, first 20 of 25.
    let (rows, m) = card.visible("", "", false);
    assert_eq!((rows.len(), m), (20, 25));
    let (rows, m) = card.visible("", "", true);
    assert_eq!((rows.len(), m), (25, 25));
    // LAN2 only: few enough that the card offers no Show all.
    let (rows, m) = card.visible("opt1", "", false);
    assert!(!rows.is_empty() && rows.iter().all(|h| h.interface_name == "LAN2"));
    assert_eq!(rows.len(), m);
    assert!(m <= sensr_ui::actions::HostCard::SHOWN);
    // the heading count follows the network filter, not the search
    assert_eq!(card.count_in("opt1"), m);
    assert_eq!(card.count_in(""), 25);
    assert_eq!(card.visible("opt1", "zzz-no-match", false).1, 0);
    assert_eq!(card.count_in("opt1"), m);
    let lan2 = render_hosts(Some(sensr_ui::actions::HostCard {
        list: sensr_ui::runtime::HostList {
            now: card.list.now,
            hosts: rows.into_iter().cloned().collect(),
            ..card.list.clone()
        },
        ..card.clone()
    }));
    assert!(!text(lan2.root_element()).contains("Show all"));
    // Search by MAC suffix, case-insensitive.
    let (rows, m) = card.visible("", "A5:FC", false);
    assert_eq!(m, 1);
    assert_eq!(rows[0].name.as_deref(), Some("old-router"));
    // Filter and search combine.
    assert_eq!(card.visible("lan", "old-router", false).1, 0);
}

/// The Mode cell (second to last) of a host row.
fn mode_cell<'a>(row: scraper::ElementRef<'a>) -> scraper::ElementRef<'a> {
    let cells: Vec<_> = row.select(&sel("td")).collect();
    cells[cells.len() - 2]
}

#[test]
fn host_mode_select_present_for_mac_rows() {
    let mut card = hosts_from(hosts_mock()).unwrap();
    let base = card.list.hosts[0].clone();
    card.list
        .hosts
        .retain(|h| h.name.as_deref() == Some("bench-pi"));
    card.list.hosts.push(sensr_ui::runtime::HostRow {
        key: "id:01:cc".into(),
        mac: None,
        name: Some("orphan".into()),
        mode: None,
        ..base
    });
    let doc = render_hosts(Some(card));
    let heads: Vec<String> = doc
        .select(&sel("thead th"))
        .map(|h| text(h).trim().to_owned())
        .collect();
    assert_eq!(
        heads,
        [
            "Name", "MAC", "IP", "Network", "Source", "Seen", "Today", "Mode", ""
        ]
    );
    let pi = mode_cell(host_row(&doc, "bench-pi"));
    let select = pi.select(&sel("select")).next().expect("mode select");
    assert_eq!(select.value().attr("aria-label"), Some("Mode for bench-pi"));
    let options: Vec<(String, String)> = select
        .select(&sel("option"))
        .map(|o| (o.value().attr("value").unwrap_or("").to_owned(), text(o)))
        .collect();
    assert_eq!(
        options,
        [
            ("normal".into(), "Normal".into()),
            ("isolated".into(), "Isolated".into()),
            ("quarantine".into(), "Quarantine".into()),
        ]
    );
    let selected: Vec<String> = select.select(&sel("option[selected]")).map(text).collect();
    assert_eq!(selected, ["Normal"]);
    let orphan = mode_cell(host_row(&doc, "orphan"));
    assert!(orphan.select(&sel("select")).next().is_none());
    assert_eq!(text(orphan).trim(), "—");
    assert_all_labelled(&doc, "hosts card with modes");
}

#[test]
fn host_mode_badges() {
    let card = hosts_from(hosts_mock()).unwrap();
    let mode = |name: &str| {
        card.list
            .hosts
            .iter()
            .find(|h| h.name.as_deref() == Some(name))
            .and_then(|h| h.mode.clone())
    };
    assert_eq!(mode("device-02").as_deref(), Some("isolated"));
    assert_eq!(mode("device-05").as_deref(), Some("quarantine"));
    assert_eq!(mode("bench-pi"), None);
    let doc = render_hosts(Some(card));
    // editable rows tint the select itself instead of adding a badge
    let class = |name: &str| {
        let cell = mode_cell(host_row(&doc, name));
        assert!(
            cell.select(&sel(".pill")).next().is_none(),
            "{name} has a badge"
        );
        cell.select(&sel("select"))
            .next()
            .and_then(|s| s.value().attr("class"))
            .unwrap_or("")
            .to_owned()
    };
    assert_eq!(class("device-02"), "mode-select mode-isolated");
    assert_eq!(class("device-05"), "mode-select mode-quarantine");
    assert_eq!(class("bench-pi"), "mode-select");
    let selected: Vec<String> = mode_cell(host_row(&doc, "device-05"))
        .select(&sel("option[selected]"))
        .map(text)
        .collect();
    assert_eq!(selected, ["Quarantine"]);
}

#[test]
fn host_mode_read_only_has_no_select() {
    let m = hosts_mock().with_privileges(&["page-all", "user-config-readonly"]);
    let card = hosts_from(m).unwrap();
    let doc = render_hosts(Some(card));
    for row in doc.select(&sel("tbody tr")) {
        assert!(mode_cell(row).select(&sel("select")).next().is_none());
    }
    // the badges still say which hosts are locked
    assert!(
        mode_cell(host_row(&doc, "device-02"))
            .select(&sel(".pill-warn"))
            .next()
            .is_some()
    );
    // the read-only mock refuses a change like the agent does
    use sensr_ui::api::Backend;
    let m = hosts_mock().with_privileges(&["page-all", "user-config-readonly"]);
    assert!(
        block(m.set_host_mode("b8:27:eb:7d:4e:25".into(), Some("isolated".into()), None)).is_err()
    );
}

const FOOTER_LOCKED: &str = "Same-network blocking works by redirecting the device's local traffic through the router (IPv4). It stops ordinary devices, not ones configured to bypass it.";

#[test]
fn host_mode_footer_text() {
    let card = hosts_from(hosts_mock()).unwrap();
    assert!(card.list.intercept.as_ref().is_some_and(|i| i.active));
    assert_eq!(card.arp_error, None);
    let all = text(render_hosts(Some(card.clone())).root_element());
    assert!(all.contains(FOOTER_LOCKED), "{all}");
    assert!(!all.contains("Same-network blocking is off"));
    // nobody locked: no footer
    let mut normal = card.clone();
    for h in &mut normal.list.hosts {
        h.mode = None;
    }
    let all = text(render_hosts(Some(normal)).root_element());
    assert!(!all.contains("Same-network blocking"), "{all}");
    // the interceptor could not start
    let mut broken = card;
    broken.arp_error = Some("raw socket: permission denied".into());
    let all = text(render_hosts(Some(broken)).root_element());
    assert!(all.contains(FOOTER_LOCKED));
    assert!(
        all.contains("Same-network blocking is off: raw socket: permission denied"),
        "{all}"
    );
}

#[test]
fn host_card_reads_arp_error_from_the_intercept_block() {
    let l: sensr_ui::runtime::HostList = sensr_ui::runtime::parse(serde_json::json!({
        "now": 1, "hosts": [],
        "intercept": {"active": false, "interfaces": [], "error": "no raw socket"}
    }));
    assert_eq!(
        l.intercept.and_then(|i| i.error).as_deref(),
        Some("no raw socket")
    );
}

const SELF_QUARANTINE: &str = "That's the device you're using — quarantine it from another device.";

/// Runs the `set_host_mode` server fn against `m`, the request coming from `remote`.
fn set_mode_on(
    m: sensr_ui::mock::MockBackend,
    remote: Option<&str>,
    mac: &str,
    mode: Option<&str>,
) -> (Result<String, String>, sensr_ui::actions::HostCard) {
    let handle: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    let owner = Owner::new();
    owner.with(|| {
        provide_context(handle);
        if let Some(r) = remote {
            let (mut parts, ()) = axum::http::Request::new(()).into_parts();
            let addr: std::net::SocketAddr = r.parse().unwrap();
            parts.extensions.insert(axum::extract::ConnectInfo(addr));
            provide_context(parts);
        }
        let r = futures::executor::block_on(sensr_ui::actions::set_host_mode(
            mac.into(),
            mode.map(str::to_owned),
        ))
        .map_err(|e| sensr_ui::actions::server_message(&e));
        let card = futures::executor::block_on(sensr_ui::actions::hosts())
            .unwrap()
            .unwrap();
        (r, card)
    })
}

#[test]
fn self_quarantine_refused() {
    let mac = sensr_ui::mock::MOCK_CLIENT_MAC;
    // the mock (like the agent) refuses its own client
    let (r, card) = set_mode_on(hosts_mock(), None, mac, Some("quarantine"));
    assert_eq!(r, Err(SELF_QUARANTINE.to_owned()));
    let own = card.list.hosts.iter().find(|h| h.key == mac).unwrap();
    assert_eq!(own.mode, None, "nothing changed");
    // isolating it is fine
    let (r, _) = set_mode_on(hosts_mock(), None, mac, Some("isolated"));
    assert_eq!(r.as_deref(), Ok("applied"));
    // the card's own check: the request comes from nas's address
    let (r, _) = set_mode_on(
        hosts_mock(),
        Some("192.168.1.20:50000"),
        "52:54:00:AA:BB:01",
        Some("quarantine"),
    );
    assert_eq!(r, Err(SELF_QUARANTINE.to_owned()));
    // ...also as a dual-stack listener reports it
    let (r, _) = set_mode_on(
        hosts_mock(),
        Some("[::ffff:192.168.1.20]:50000"),
        "52:54:00:aa:bb:01",
        Some("quarantine"),
    );
    assert_eq!(r, Err(SELF_QUARANTINE.to_owned()));
}

#[test]
fn host_mode_set_and_back_to_normal() {
    let (r, card) = set_mode_on(hosts_mock(), None, "b8:27:eb:7d:4e:25", Some("quarantine"));
    assert_eq!(r.as_deref(), Ok("applied"));
    let pi = |c: &sensr_ui::actions::HostCard| {
        c.list
            .hosts
            .iter()
            .find(|h| h.name.as_deref() == Some("bench-pi"))
            .unwrap()
            .mode
            .clone()
    };
    assert_eq!(pi(&card).as_deref(), Some("quarantine"));
    let (r, card) = set_mode_on(hosts_mock(), None, "02:00:00:00:00:02", None);
    assert_eq!(r.as_deref(), Ok("applied"));
    assert!(
        card.list
            .hosts
            .iter()
            .find(|h| h.name.as_deref() == Some("device-02"))
            .unwrap()
            .mode
            .is_none()
    );
    let (r, _) = set_mode_on(hosts_mock(), None, "b8:27:eb:7d:4e:25", Some("bogus"));
    assert!(r.is_err());
}

#[test]
fn host_mode_offline_row_with_the_remote_address_is_not_the_caller() {
    // old-router is offline and still lists 192.168.72.2; whoever sends from it now
    // is another device, so the card's check lets it through
    let (r, card) = set_mode_on(
        hosts_mock(),
        Some("192.168.72.2:50000"),
        "00:14:78:38:a5:fc",
        Some("quarantine"),
    );
    assert_eq!(r.as_deref(), Ok("applied"));
    let old = card
        .list
        .hosts
        .iter()
        .find(|h| h.name.as_deref() == Some("old-router"))
        .unwrap();
    assert!(!old.online);
    assert_eq!(old.mode.as_deref(), Some("quarantine"));
}

#[test]
fn host_mode_staged_shows_on_the_row() {
    use sensr_ui::api::Backend;
    let m = hosts_mock();
    // another change is staged, so a mode waits for Apply as on the agent
    block(m.set("system.hostname", serde_json::json!("fw"))).unwrap();
    let (r, card) = set_mode_on(m, None, "b8:27:eb:7d:4e:25", Some("quarantine"));
    assert_eq!(r.as_deref(), Ok("staged"));
    let pi = card
        .list
        .hosts
        .iter()
        .find(|h| h.name.as_deref() == Some("bench-pi"))
        .unwrap();
    assert_eq!(
        (pi.mode.as_deref(), pi.staged_mode.as_deref()),
        (None, Some("quarantine")),
        "in force: Normal; staged: Quarantine"
    );
    assert!(
        card.list
            .hosts
            .iter()
            .all(|h| h.staged_mode.is_none() || h.name.as_deref() == Some("bench-pi"))
    );
    let doc = render_hosts(Some(card));
    let cell = mode_cell(host_row(&doc, "bench-pi"));
    assert!(
        text(cell).contains("Staged — Apply to take effect"),
        "{}",
        text(cell)
    );
    assert!(
        cell.select(&sel(".pill")).next().is_none(),
        "not in force yet"
    );
    let selected: Vec<String> = cell.select(&sel("option[selected]")).map(text).collect();
    assert_eq!(selected, ["Quarantine"]);
    // other rows say nothing
    assert!(!text(mode_cell(host_row(&doc, "device-02"))).contains("Staged"));
}

// ------------------------------------------------------------------ traffic charts

#[test]
fn rate_formatting_scales_units() {
    use sensr_ui::chart::bps;
    assert_eq!(bps(0), "0 bit/s");
    assert_eq!(bps(950), "950 bit/s");
    assert_eq!(bps(12_300_000), "12.3 Mbit/s");
    assert_eq!(bps(1_200_000_000), "1.20 Gbit/s");
    assert_eq!(bps(64_000), "64 kbit/s");
}

#[test]
fn rate_ticks_are_nice_round_steps() {
    use sensr_ui::chart::{rate_ticks, rate_unit, tick_label};
    // Idle: still a 1 kbit/s axis.
    assert_eq!(rate_ticks(0), [0, 250, 500, 750, 1_000]);
    assert_eq!(rate_ticks(950), [0, 250, 500, 750, 1_000]);
    assert_eq!(
        rate_ticks(12_300_000),
        [0, 5_000_000, 10_000_000, 15_000_000]
    );
    assert_eq!(rate_ticks(1_001), [0, 500, 1_000, 1_500]);
    assert_eq!(
        rate_ticks(180_000_000),
        [0, 50_000_000, 100_000_000, 150_000_000, 200_000_000]
    );
    assert_eq!(
        rate_ticks(2_400_000_000),
        [0, 1_000_000_000, 2_000_000_000, 3_000_000_000]
    );
    for max in [1, 999, 1_234, 77_777, 3_000_001, 9_999_999_999] {
        let t = rate_ticks(max);
        assert!((4..=5).contains(&t.len()), "{max}: {t:?}");
        assert!(*t.last().unwrap() >= max, "{max}: {t:?}");
    }
    assert_eq!(rate_unit(1_000), (1_000, "kbit/s"));
    assert_eq!(rate_unit(15_000_000), (1_000_000, "Mbit/s"));
    assert_eq!(rate_unit(3_000_000_000), (1_000_000_000, "Gbit/s"));
    assert_eq!(rate_unit(500), (1, "bit/s"));
    let labels: Vec<String> = rate_ticks(950)
        .iter()
        .map(|v| tick_label(*v, 1_000))
        .collect();
    assert_eq!(labels, ["0", "0.25", "0.5", "0.75", "1"]);
}

#[test]
fn time_ticks_fall_on_round_local_times() {
    use sensr_ui::chart::{clock, time_ticks};
    const T: i64 = 1_794_787_200; // 00:00:00 UTC
    // Two minutes: every 30 s, none in the outer 6 %.
    assert_eq!(time_ticks(T + 2, T + 122, 0), [T + 30, T + 60, T + 90]);
    // One minute: every 15 s; ten minutes: every 2 min; one hour: every 10 min.
    assert_eq!(time_ticks(T - 59, T, 0), [T - 45, T - 30, T - 15]);
    assert_eq!(
        time_ticks(T, T + 600, 0),
        [T + 120, T + 240, T + 360, T + 480]
    );
    assert_eq!(
        time_ticks(T - 3_540, T + 60, 0),
        [T - 3_000, T - 2_400, T - 1_800, T - 1_200, T - 600]
    );
    // Aligned to local time: 5 minutes east of UTC puts six 10-minute marks in the
    // hour, too many, so quarter hours, shifted with it.
    assert_eq!(
        time_ticks(T - 3_540, T + 60, 300),
        [T - 3_000, T - 2_100, T - 1_200, T - 300]
    );
    assert!(time_ticks(T, T, 0).is_empty());
    assert_eq!(clock(T + 3_723, 0, false), "01:02");
    assert_eq!(clock(T + 3_723, 0, true), "01:02:03");
    assert_eq!(clock(T, 3_600, false), "01:00");
    assert_eq!(clock(T, -3_600, false), "23:00");
}

fn chart_samples() -> Vec<sensr_ui::chart::Sample> {
    (0..41)
        .map(|i| sensr_ui::chart::Sample {
            ts: 1_794_787_200 + 3 * i,
            rx: if i == 20 { 12_300_000 } else { 2_000_000 },
            tx: 800_000,
        })
        .collect()
}

#[test]
fn traffic_chart_renders_axes_for_a_known_series() {
    use sensr_ui::chart::TrafficChart;
    let doc = render(|| {
        view! { <TrafficChart samples=Memo::new(|_| chart_samples()) label="Traffic, test".to_owned()/> }
            .into_any()
    });
    let ys: Vec<String> = doc.select(&sel(".tc-y span")).map(text).collect();
    assert_eq!(ys, ["0", "5", "10", "15"]);
    assert_eq!(text(doc.select(&sel(".tc-unit")).next().unwrap()), "Mbit/s");
    let xs: Vec<String> = doc.select(&sel(".tc-x span")).map(text).collect();
    assert_eq!(xs, ["00:00:30", "00:01:00", "00:01:30"]);
    // One faint gridline per tick, the baseline stronger.
    assert_eq!(doc.select(&sel("svg line.tc-grid")).count(), 3);
    assert_eq!(doc.select(&sel("svg line.tc-base")).count(), 1);
    // No text inside the stretched SVG.
    let svg = doc.select(&sel("svg")).next().unwrap();
    assert_eq!(svg.value().attr("preserveAspectRatio"), Some("none"));
    assert!(svg.select(&sel("text")).next().is_none());
    // Keyboard-operable, and says what the latest sample is.
    let plot = doc.select(&sel(".tc-plot")).next().unwrap().value();
    assert_eq!(plot.attr("tabindex"), Some("0"));
    assert_eq!(plot.attr("role"), Some("slider"));
    assert_eq!(plot.attr("aria-label"), Some("Traffic, test"));
    assert_eq!(plot.attr("aria-valuemax"), Some("40"));
    assert_eq!(
        plot.attr("aria-valuetext"),
        Some("00:02:00: In 2.0 Mbit/s, Out 800 kbit/s")
    );
    // No tooltip until hovered.
    assert!(doc.select(&sel(".tc-tip")).next().is_none());

    // The name is escaped (interface descriptions are user text).
    let doc = render(|| {
        view! { <TrafficChart samples=Memo::new(|_| Vec::new()) label=r#"LAN "office" <&>"#.to_owned()/> }
            .into_any()
    });
    let plot = doc.select(&sel(".tc-plot")).next().unwrap().value();
    assert_eq!(plot.attr("aria-label"), Some(r#"LAN "office" <&>"#));
    assert_eq!(plot.attr("aria-valuetext"), Some("No samples yet"));
    assert_eq!(doc.select(&sel(".tc-y span")).count(), 5, "idle axis");
}

#[test]
fn dashboard_traffic_cards_use_the_axis_chart() {
    use sensr_ui::api::Backend;
    use sensr_ui::islands::DashboardLive;
    let m = sensr_ui::mock::MockBackend::with_clock(Box::new(|| 1_794_787_200));
    let initial = block(m.status()).unwrap();
    let n = initial.traffic.len();
    assert!(n > 0);
    assert!(initial.traffic.iter().all(|t| t.ts.len() == t.rx.len()));
    let doc = render(|| view! { <DashboardLive initial/> }.into_any());
    let charts: Vec<_> = doc.select(&sel(".traffic figure .tchart")).collect();
    assert_eq!(charts.len(), n);
    for c in &charts {
        assert!(c.select(&sel(".tc-y span")).count() >= 4);
        assert!(c.select(&sel(".tc-x span")).count() >= 3);
        let name = c
            .select(&sel(".tc-plot"))
            .next()
            .unwrap()
            .value()
            .attr("aria-label")
            .unwrap();
        assert!(name.ends_with("traffic, last two minutes"), "{name}");
    }
    assert!(
        doc.select(&sel(".spark")).next().is_none(),
        "old sparklines are gone"
    );
}

fn samples_at(ts: &[i64]) -> Vec<sensr_ui::chart::Sample> {
    ts.iter()
        .map(|t| sensr_ui::chart::Sample {
            ts: *t,
            rx: 1_000_000,
            tx: 500_000,
        })
        .collect()
}

#[test]
fn clock_jumps_and_bad_timestamps_are_contained() {
    use sensr_ui::chart::{prepare, time_ticks};
    const NOW: i64 = 1_780_000_000;
    // A 56-year span (boot in 1970, then NTP): no time axis, and no O(span) loop.
    assert!(time_ticks(100, NOW, 0).is_empty());
    assert!(time_ticks(NOW, NOW, 0).is_empty());
    assert!(time_ticks(NOW, NOW - 5, 0).is_empty());
    assert!(time_ticks(NOW - 86_400, NOW, 0).len() <= 5);
    let ts = |s: &[sensr_ui::chart::Sample]| s.iter().map(|p| p.ts).collect::<Vec<_>>();

    // Jump forward: only the samples after the jump.
    let (s, timed) = prepare(&samples_at(&[100, 103, 106, NOW, NOW + 3, NOW + 6]));
    assert!(timed);
    assert_eq!(ts(&s), [NOW, NOW + 3, NOW + 6]);
    // Backwards: only the trailing run.
    let (s, timed) = prepare(&samples_at(&[NOW, NOW + 3, NOW + 6, NOW - 500, NOW - 497]));
    assert!(timed);
    assert_eq!(ts(&s), [NOW - 500, NOW - 497]);
    // Duplicates (two viewers in one second) are kept.
    let (s, timed) = prepare(&samples_at(&[NOW, NOW + 3, NOW + 3, NOW + 6]));
    assert!(timed);
    assert_eq!(s.len(), 4);
    // A jump right before the newest sample leaves one sample: no times.
    let (s, timed) = prepare(&samples_at(&[100, 103, NOW]));
    assert!(!timed);
    assert_eq!(ts(&s), [0]);
    // No timestamps at all: evenly spaced, no times.
    let (s, timed) = prepare(&samples_at(&[0, 0, 0, 0]));
    assert!(!timed);
    assert_eq!(ts(&s), [0, 1, 2, 3]);
    assert_eq!(prepare(&[]), (Vec::new(), false));
}

#[test]
fn tooltip_stays_inside_the_plot() {
    use sensr_ui::chart::tip_left;
    // Room on the right: beside the crosshair, else on its left.
    assert_eq!(tip_left(5.0, 220.0, 120.0), 15.0);
    assert_eq!(tip_left(215.0, 220.0, 120.0), 85.0);
    // Mid-way in a small plot: centred, inside both edges.
    let l = tip_left(110.0, 220.0, 120.0);
    assert!(l >= 0.0 && l + 120.0 <= 220.0, "{l}");
    for px in [0.0, 30.0, 70.0, 150.0, 220.0] {
        let l = tip_left(px, 220.0, 150.0);
        assert!(l >= 0.0 && l + 150.0 <= 220.0, "{px}: {l}");
    }
    // Wider than the plot: pinned to its left edge, never over the rate axis.
    assert_eq!(tip_left(100.0, 220.0, 300.0), 0.0);
}

#[test]
fn chart_without_timestamps_shows_no_times() {
    use sensr_ui::api::Backend;
    use sensr_ui::chart::TrafficChart;
    use sensr_ui::islands::DashboardLive;
    let doc = render(|| {
        view! { <TrafficChart samples=Memo::new(|_| samples_at(&[0, 0, 0])) label="t".to_owned()/> }
            .into_any()
    });
    assert_eq!(doc.select(&sel(".tc-x span")).count(), 0);
    assert_eq!(
        doc.select(&sel(".tc-y span")).count(),
        5,
        "rate axis still shown"
    );
    let plot = doc.select(&sel(".tc-plot")).next().unwrap().value();
    assert_eq!(
        plot.attr("aria-valuetext"),
        Some("In 1.0 Mbit/s, Out 500 kbit/s")
    );

    // A clock jump: times only for the samples after it.
    let doc = render(|| {
        view! { <TrafficChart samples=Memo::new(|_| samples_at(&[100, 103, 1_794_787_200, 1_794_787_260])) label="t".to_owned()/> }
            .into_any()
    });
    let xs: Vec<String> = doc.select(&sel(".tc-x span")).map(text).collect();
    assert!(!xs.is_empty() && xs.len() <= 5, "{xs:?}");
    assert!(xs.iter().all(|x| x.starts_with("00:00:")), "{xs:?}");

    // An interface series with partial timestamps: that chart has no time axis.
    let m = sensr_ui::mock::MockBackend::with_clock(Box::new(|| 1_794_787_200));
    let mut initial = block(m.status()).unwrap();
    initial.traffic[0].ts.truncate(3);
    let doc = render(|| view! { <DashboardLive initial/> }.into_any());
    let charts: Vec<_> = doc.select(&sel(".traffic figure .tchart")).collect();
    assert_eq!(charts[0].select(&sel(".tc-x span")).count(), 0);
    assert!(charts[1].select(&sel(".tc-x span")).count() >= 3);
}

/// The MAC cell (second column) of a host row.
fn mac_cell<'a>(row: scraper::ElementRef<'a>) -> scraper::ElementRef<'a> {
    row.select(&sel("td")).nth(1).unwrap()
}

/// The label line in a MAC cell.
fn label_line<'a>(cell: scraper::ElementRef<'a>) -> scraper::ElementRef<'a> {
    cell.select(&sel(".host-label")).next().expect("label line")
}

/// The card with only the named hosts (the printer sorts past the first 20).
fn hosts_named(names: &[&str]) -> sensr_ui::actions::HostCard {
    let mut card = hosts_from(hosts_mock()).unwrap();
    card.list
        .hosts
        .retain(|h| h.name.as_deref().is_some_and(|n| names.contains(&n)));
    card
}

#[test]
fn host_label_line_renders() {
    let doc = render_hosts(Some(hosts_named(&["bench-pi", "nas"])));
    let cell = mac_cell(host_row(&doc, "bench-pi"));
    assert!(text(cell).starts_with("b8:27:eb:7d:4e:25"));
    let line = label_line(cell);
    let icon = line.select(&sel(".host-kind-icon")).next().unwrap();
    assert_eq!(icon.value().attr("aria-hidden"), Some("true"));
    assert_eq!(text(icon), "🗄");
    assert_eq!(
        text(line).trim_start_matches(&text(icon)).trim(),
        "Raspberry Pi · Server?"
    );
    assert!(
        line.value()
            .has_class("host-label-guess", scraper::CaseSensitivity::CaseSensitive)
    );
    let title = line.value().attr("title").unwrap();
    assert_eq!(title, "MAC maker: Raspberry Pi");
    // a confident guess is not italic
    let nas = label_line(mac_cell(host_row(&doc, "nas")));
    assert!(text(nas).ends_with("QEMU/KVM · Virtual machine"));
    assert!(
        !nas.value()
            .has_class("host-label-guess", scraper::CaseSensitivity::CaseSensitive)
    );
    assert_all_labelled(&doc, "hosts card with labels");
}

#[test]
fn host_label_private_mac_text() {
    let doc = render_hosts(Some(hosts_named(&["device-01"])));
    let line = label_line(mac_cell(host_row(&doc, "device-01")));
    let icon = text(line.select(&sel(".host-kind-icon")).next().unwrap());
    assert_eq!(
        text(line).trim_start_matches(&icon).trim(),
        "Private MAC · Phone/laptop?"
    );
}

#[test]
fn host_label_owner_not_guess() {
    let card = hosts_named(&["printer", "bench-pi"]);
    let printer = card
        .list
        .hosts
        .iter()
        .find(|h| h.name.as_deref() == Some("printer"))
        .unwrap();
    assert_eq!(printer.owner_kind.as_deref(), Some("printer"));
    assert_eq!(printer.owner_maker.as_deref(), Some("Brother"));
    assert!(!printer.staged_label);
    let doc = render_hosts(Some(card));
    let line = label_line(mac_cell(host_row(&doc, "printer")));
    assert!(text(line).ends_with("Brother · Printer"), "{}", text(line));
    assert!(
        !line
            .value()
            .has_class("host-label-guess", scraper::CaseSensitivity::CaseSensitive)
    );
    // one reason per line: the owner's first, then the guess's (as the agent does)
    assert_eq!(
        line.value().attr("title"),
        Some("Set by you\nMAC maker: Brother industries")
    );
    // the editor is closed until ✎ is pressed
    let edit = mac_cell(host_row(&doc, "printer"))
        .select(&sel("button.icon-btn.host-label-edit"))
        .next()
        .expect("edit button");
    assert_eq!(
        edit.value().attr("aria-label"),
        Some("Edit label for printer")
    );
    assert_eq!(edit.value().attr("aria-expanded"), Some("false"));
    // it carries the owner's label to fill the editor with
    assert_eq!(edit.value().attr("data-kind"), Some("printer"));
    assert_eq!(edit.value().attr("data-maker"), Some("Brother"));
    assert!(doc.select(&sel(".host-label-editor")).next().is_none());
}

#[test]
fn host_label_edit_sits_inline_after_the_label() {
    let doc = render_hosts(Some(hosts_named(&["bench-pi"])));
    let cell = mac_cell(host_row(&doc, "bench-pi"));
    let lines: Vec<_> = cell.select(&sel(".host-label-line")).collect();
    assert_eq!(lines.len(), 1, "one line under the MAC");
    let children: Vec<String> = lines[0]
        .children()
        .filter_map(|c| {
            c.value()
                .as_element()
                .map(|e| e.attr("class").unwrap_or("").to_owned())
        })
        .collect();
    assert_eq!(
        children,
        ["host-label host-label-guess", "icon-btn host-label-edit"],
        "✎ follows the label text on the same line"
    );
    assert_eq!(cell.value().attr("id"), Some("host-label-b827eb7d4e25"));
}

#[test]
fn host_actions_do_not_wrap() {
    let doc = render_hosts(Some(hosts_named(&["bench-pi"])));
    let actions = host_row(&doc, "bench-pi")
        .select(&sel("td.host-actions"))
        .next()
        .unwrap();
    assert!(actions.select(&sel("br")).next().is_none());
    let css = include_str!("../style/main.css");
    assert!(
        css.contains(".host-actions { white-space: nowrap; }"),
        "Make static and Forget stay side by side"
    );
}

#[test]
fn host_label_unknown_kind_reads_as_unknown() {
    let mut card = hosts_named(&["bench-pi", "nas"]);
    for h in &mut card.list.hosts {
        let l = h.host_label.as_mut().unwrap();
        l.kind = "toaster".into();
        if h.name.as_deref() == Some("nas") {
            l.maker = None;
        }
    }
    let doc = render_hosts(Some(card));
    let pi = label_line(mac_cell(host_row(&doc, "bench-pi")));
    assert_eq!(text(pi), "•Raspberry Pi", "just the maker, no kind or ?");
    let nas = mac_cell(host_row(&doc, "nas"));
    assert!(
        nas.select(&sel(".host-label")).next().is_none(),
        "nothing to say"
    );
    assert!(nas.select(&sel(".host-label-edit")).next().is_some());
}

#[test]
fn host_label_editor_renders_the_draft_and_busy() {
    // the card renders an open editor from its draft, so a re-render keeps what was typed
    let doc = Html::parse_fragment(&sensr_ui::islands::host_label_editor_html(
        "bench-pi",
        "camera",
        "Typed so far",
        true,
    ));
    let selected: Vec<String> = doc.select(&sel("option[selected]")).map(text).collect();
    assert_eq!(selected, ["Camera"]);
    let input = doc.select(&sel("input")).next().unwrap();
    assert_eq!(input.value().attr("value"), Some("Typed so far"));
    // a save in flight disables both buttons; Save submits the form so Enter saves
    let buttons: Vec<_> = doc.select(&sel("form button")).collect();
    assert_eq!(buttons.len(), 2);
    assert!(buttons.iter().all(|b| b.value().attr("disabled").is_some()));
    assert_eq!(buttons[0].value().attr("type"), Some("submit"));
    let idle = Html::parse_fragment(&sensr_ui::islands::host_label_editor_html(
        "x", "", "", false,
    ));
    assert!(idle.select(&sel("button[disabled]")).next().is_none());
}

#[test]
fn host_label_edit_hidden_read_only() {
    let m = hosts_mock().with_privileges(&["page-all", "user-config-readonly"]);
    let doc = render_hosts(hosts_from(m));
    assert!(
        doc.select(&sel(".host-label")).next().is_some(),
        "labels still show"
    );
    assert!(doc.select(&sel(".host-label-edit")).next().is_none());
    // the read-only mock refuses a change like the agent does
    use sensr_ui::api::Backend;
    let m = hosts_mock().with_privileges(&["page-all", "user-config-readonly"]);
    assert!(block(m.set_host_label("b8:27:eb:7d:4e:25".into(), Some("tv".into()), None)).is_err());
}

#[test]
fn host_label_editor_options() {
    let doc = Html::parse_fragment(&sensr_ui::islands::host_label_editor_html(
        "bench-pi", "", "", false,
    ));
    let select = doc.select(&sel("select")).next().unwrap();
    assert_eq!(select.value().attr("aria-label"), Some("Type for bench-pi"));
    let options: Vec<(String, String)> = select
        .select(&sel("option"))
        .map(|o| (o.value().attr("value").unwrap_or("?").to_owned(), text(o)))
        .collect();
    assert_eq!(options.len(), 15);
    assert_eq!(options[0], ("".to_owned(), "Auto".to_owned()));
    assert_eq!(options[1], ("phone".to_owned(), "Phone".to_owned()));
    assert_eq!(options[4], ("tv".to_owned(), "TV/streaming".to_owned()));
    assert_eq!(options[14], ("unknown".to_owned(), "Unknown".to_owned()));
    let selected: Vec<String> = select.select(&sel("option[selected]")).map(text).collect();
    assert_eq!(selected, ["Auto"]);
    let input = doc.select(&sel("input[type=text]")).next().unwrap();
    assert_eq!(input.value().attr("aria-label"), Some("Maker for bench-pi"));
    assert_eq!(input.value().attr("placeholder"), Some("Auto"));
    let buttons: Vec<String> = doc
        .select(&sel("form.host-label-editor button.btn.btn-sm"))
        .map(text)
        .collect();
    assert_eq!(buttons, ["Save", "Reset to auto"]);
    assert_all_labelled(&doc, "label editor");
    // filled with the owner's label
    let doc = Html::parse_fragment(&sensr_ui::islands::host_label_editor_html(
        "printer", "printer", "Brother", false,
    ));
    let selected: Vec<String> = doc.select(&sel("option[selected]")).map(text).collect();
    assert_eq!(selected, ["Printer"]);
    let input = doc.select(&sel("input[type=text]")).next().unwrap();
    assert_eq!(input.value().attr("value"), Some("Brother"));
    // names and makers come off the network: escaped, not markup
    let doc = Html::parse_fragment(&sensr_ui::islands::host_label_editor_html(
        "<b>\"x'",
        "",
        "a\"><script>&",
        false,
    ));
    assert!(doc.select(&sel("script, b")).next().is_none());
    let input = doc.select(&sel("input[type=text]")).next().unwrap();
    assert_eq!(input.value().attr("value"), Some("a\"><script>&"));
    assert_eq!(input.value().attr("aria-label"), Some("Maker for <b>\"x'"));
}

#[test]
fn host_label_mock_set_applies_and_stages() {
    use sensr_ui::api::Backend;
    let m = hosts_mock();
    const PI: &str = "b8:27:eb:7d:4e:25";
    assert_eq!(
        block(m.set_host_label(PI.into(), Some("tv".into()), Some(" Acme ".into()))).unwrap(),
        "applied"
    );
    assert!(matches!(
        block(m.set_host_label(PI.into(), Some("toaster".into()), None)),
        Err(sensr_ui::api::ApiError::Validation(_))
    ));
    let card = hosts_from(m).unwrap();
    let pi = card
        .list
        .hosts
        .iter()
        .find(|h| h.mac.as_deref() == Some(PI))
        .unwrap();
    let l = pi.host_label.as_ref().unwrap();
    assert_eq!(
        (l.text().as_str(), l.by.as_str()),
        ("Acme · TV/streaming", "owner")
    );
    assert_eq!(pi.owner_maker.as_deref(), Some("Acme"));
    assert!(!pi.staged_label);
    // with another change staged, a label waits for Apply and says so
    let m = hosts_mock();
    block(m.set_host_mode(PI.into(), Some("isolated".into()), None)).unwrap();
    block(m.set("system.hostname", serde_json::json!("other"))).unwrap();
    assert_eq!(
        block(m.set_host_label(PI.into(), Some("camera".into()), None)).unwrap(),
        "staged"
    );
    let card = hosts_from(m).unwrap();
    let pi = card
        .list
        .hosts
        .iter()
        .find(|h| h.mac.as_deref() == Some(PI))
        .unwrap();
    assert!(pi.staged_label);
    assert_eq!(
        pi.host_label.as_ref().unwrap().text(),
        "Raspberry Pi · Server?"
    );
    let doc = render_hosts(Some(card));
    let cell = mac_cell(host_row(&doc, "bench-pi"));
    assert_eq!(
        text(cell.select(&sel(".host-label-staged")).next().unwrap()),
        "Staged — Apply to take effect"
    );
    // Reset to auto removes the owner's entry
    let m = hosts_mock();
    block(m.set_host_label("00:1b:a9:44:02:7c".into(), None, None)).unwrap();
    let card = hosts_from(m).unwrap();
    let p = card
        .list
        .hosts
        .iter()
        .find(|h| h.name.as_deref() == Some("printer"))
        .unwrap();
    assert_eq!(p.host_label.as_ref().unwrap().by, "auto");
    assert_eq!(p.owner_kind, None);
}

#[test]
fn grid_q_param_prefills_search() {
    let seed = sensr_ui::mock::seed();
    let rows: Vec<serde_json::Value> =
        sensr_ui::adapt::rows(GridId::Aliases, &GridId::Aliases.scope(&None), &seed)
            .into_iter()
            .map(|r| r.view)
            .collect();
    let q = GridQuery {
        search: "web".to_owned(),
        ..Default::default()
    };
    let page = run_query(&rows, GridId::Aliases.columns(), &q);
    let doc = render(|| {
        view! {
            <GridIsland grid=GridId::Aliases scope=None initial=page label="alias".to_owned()
                choices=Default::default() search="web".to_owned()/>
        }
        .into_any()
    });
    let input = doc
        .select(&sel(".grid-toolbar input[type=search]"))
        .next()
        .unwrap();
    assert_eq!(input.value().attr("value"), Some("web"));
}

#[test]
fn hosts_card_host_param_prefills_search() {
    use sensr_ui::islands::HostsCard;
    let card = hosts_from(hosts_mock()).expect("root may see hosts");
    let mac = card.list.hosts[3].mac.clone().expect("mock host has a MAC");
    let doc = render(|| view! { <HostsCard initial=Some(card) search=mac.clone()/> }.into_any());
    let input = doc
        .select(&sel(".grid-toolbar input[type=search]"))
        .next()
        .unwrap();
    assert_eq!(input.value().attr("value"), Some(mac.as_str()));
    assert_eq!(
        doc.select(&sel("tbody tr")).count(),
        1,
        "filtered to that host"
    );
}

// ------------------------------------------------------------------ global search

#[test]
fn gsearch_renders_after_wordmark() {
    use sensr_ui::app::TopBar;
    let doc = render(|| view! { <TopBar user="root".to_owned()/> }.into_any());
    let brand = doc
        .select(&sel(".topbar > a.brand"))
        .next()
        .expect("wordmark");
    let next = brand
        .next_siblings()
        .find_map(scraper::ElementRef::wrap)
        .expect("something after the wordmark");
    let gs = if next.value().classes().any(|c| c == "gsearch") {
        next
    } else {
        next.select(&sel(".gsearch"))
            .next()
            .expect(".gsearch right after the wordmark")
    };
    let input = gs.select(&sel("input")).next().expect("search input");
    let a = input.value();
    assert_eq!(a.attr("type"), Some("search"));
    assert_eq!(a.attr("role"), Some("combobox"));
    assert_eq!(a.attr("aria-label"), Some("Search sensr"));
    assert_eq!(a.attr("aria-autocomplete"), Some("list"));
    assert_eq!(a.attr("aria-controls"), Some("gsearch-list"));
    assert_eq!(a.attr("aria-expanded"), Some("false"));
    assert_eq!(a.attr("placeholder"), Some("Search  /"));
    let list = gs.select(&sel("#gsearch-list")).next().expect("listbox");
    assert_eq!(list.value().attr("role"), Some("listbox"));
    let phone = gs
        .select(&sel("button.icon-btn[aria-label=Search]"))
        .next()
        .expect("phone magnifier");
    assert_eq!(phone.value().attr("type"), Some("button"));
    // the live region is there before any results, so screen readers pick up changes
    let live = gs
        .select(&sel("[aria-live=polite]"))
        .next()
        .expect("live region");
    assert!(live.value().classes().any(|c| c == "sr-only"));
    assert_eq!(text(live).trim(), "");
    // the search box sits on the left: everything else stays in .topbar-right
    assert!(gs.select(&sel(".topbar-right")).next().is_none());
}

#[test]
fn gsearch_absent_on_login() {
    use sensr_ui::app::App;
    // the real routes at /login, so a search box added to any shared chrome would show
    let doc = render(|| {
        provide_context(leptos_router::location::RequestUrl::new("/login"));
        view! { <App/> }.into_any()
    });
    assert!(
        doc.select(&sel(".login-card")).next().is_some(),
        "login renders"
    );
    assert!(
        doc.select(&sel(".gsearch, [role=combobox]"))
            .next()
            .is_none()
    );
}

#[test]
fn results_escape_text() {
    use sensr_ui::islands::gsearch_results;
    use sensr_ui::search::{SearchGroup, SearchHit, SearchResults};
    let evil = "<img src=x onerror=alert(1)>";
    let r = SearchResults {
        query: "img".to_owned(),
        groups: vec![SearchGroup {
            name: evil.to_owned(),
            total: 9,
            more_url: Some("/ui/firewall/alias?q=img".to_owned()),
            hits: vec![SearchHit {
                title: evil.to_owned(),
                detail: evil.to_owned(),
                url: "/ui/firewall/alias?edit=1".to_owned(),
            }],
        }],
    };
    let doc = render(|| gsearch_results(&r, Some(0)).into_any());
    assert!(doc.select(&sel("img")).next().is_none(), "no <img> element");
    let opts: Vec<_> = doc.select(&sel("[role=option]")).collect();
    assert_eq!(opts.len(), 2, "the hit and Show all");
    assert_eq!(opts[0].value().attr("id"), Some("gsearch-opt-0"));
    assert_eq!(opts[0].value().attr("aria-selected"), Some("true"));
    assert!(text(opts[0]).contains(evil), "shown as text");
    assert_eq!(opts[1].value().attr("id"), Some("gsearch-opt-1"));
    assert_eq!(text(opts[1]), "Show all (9)");
    let group = doc.select(&sel("[role=group]")).next().unwrap();
    assert_eq!(group.value().attr("aria-label"), Some(evil));
}

#[test]
fn gsearch_no_show_all_when_everything_is_shown() {
    use sensr_ui::islands::gsearch_results;
    use sensr_ui::search::{SearchGroup, SearchHit, SearchResults};
    let hit = SearchHit {
        title: "DHCPv4".to_owned(),
        detail: "Services › DHCPv4".to_owned(),
        url: "/ui/dhcpv4/lan".to_owned(),
    };
    let r = SearchResults {
        query: "dhcp".to_owned(),
        groups: vec![
            SearchGroup {
                name: "Pages".to_owned(),
                total: 1,
                more_url: None,
                hits: vec![hit.clone()],
            },
            SearchGroup {
                name: "Settings".to_owned(),
                total: 8,
                more_url: None,
                hits: vec![hit],
            },
        ],
    };
    let doc = render(|| gsearch_results(&r, None).into_any());
    let ids: Vec<_> = doc
        .select(&sel("[role=option]"))
        .map(|o| o.value().attr("id").unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["gsearch-opt-0", "gsearch-opt-1"]);
    assert!(!doc.html().contains("Show all"));
}

#[test]
fn topbar_controls_are_labelled() {
    use sensr_ui::app::TopBar;
    let doc = render(|| view! { <TopBar user="root".to_owned()/> }.into_any());
    assert_all_labelled(&doc, "top bar");
}

// ------------------------------------------------------------ per-host DNS activity

const KID_TABLET: &str = "e2:5b:7a:31:90:c4";

/// `host_page()` run against `m` as the signed-in backend.
fn host_page_from(
    m: sensr_ui::mock::MockBackend,
    key: &str,
    range: &str,
    edit: Option<&str>,
) -> sensr_ui::actions::HostPageData {
    let handle: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    let owner = Owner::new();
    owner.with(|| {
        provide_context(handle);
        futures::executor::block_on(sensr_ui::actions::host_page(
            key.into(),
            range.into(),
            0,
            edit.map(Into::into),
        ))
        .unwrap()
    })
}

fn render_host_page(p: sensr_ui::actions::HostPageData, q: sensr_ui::pages::HostQuery) -> Html {
    render(move || sensr_ui::pages::host_page_body(p, q))
}

fn host_query(range: &str) -> sensr_ui::pages::HostQuery {
    sensr_ui::pages::HostQuery {
        range: range.into(),
        ..Default::default()
    }
}

#[test]
fn host_page_renders_services_categories_timeline_domains() {
    let p = host_page_from(hosts_mock(), KID_TABLET, "today", None);
    let doc = render_host_page(p, host_query("today"));
    let h2: Vec<String> = doc.select(&sel("h2")).map(text).collect();
    assert_eq!(h2[0], "kid-tablet");
    for want in ["Screen time today", "Services", "When", "Domains"] {
        assert!(h2.iter().any(|h| h == want), "{want} in {h2:?}");
    }
    let head = text(doc.select(&sel(".hp-head")).next().unwrap());
    assert!(head.contains("Samsung · Tablet"), "{head}");
    assert!(
        head.contains(KID_TABLET) && head.contains("Normal") && head.contains("now"),
        "{head}"
    );
    // range links, the current one marked
    let current: Vec<String> = doc
        .select(&sel(".seg a[aria-current=page]"))
        .map(text)
        .collect();
    assert_eq!(current, ["Today"]);
    assert!(
        doc.select(&sel(".seg a"))
            .any(|a| a.value().attr("href") == Some(&*format!("/ui/hosts/{KID_TABLET}?range=7d")))
    );
    // headline: 2 h 47 m, without system and ads
    assert_eq!(
        text(doc.select(&sel(".big")).next().unwrap()).trim(),
        "2 h 47 m"
    );
    // services: name, category, minutes
    let services: Vec<String> = doc
        .select(&sel(".svc"))
        .map(|r| {
            r.text()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    assert_eq!(services[0], "YouTube Video 1 h 22 m", "{services:?}");
    assert!(
        services.iter().any(|s| s == "Roblox Games 48 m"),
        "{services:?}"
    );
    // categories: stacked bar segments and a legend
    let segs = doc.select(&sel(".sbar i")).count();
    assert!(segs >= 3, "{segs}");
    assert!(
        doc.select(&sel(".sbar[role=img][aria-label]"))
            .next()
            .is_some()
    );
    // timeline: one row of 24 hours today, each with a title, and a table alternative
    let cells: Vec<_> = doc.select(&sel(".heat .c")).collect();
    assert_eq!(cells.len(), 24);
    assert!(
        cells
            .iter()
            .filter_map(|c| c.value().attr("title"))
            .any(|t| t.contains(":00 — ") && t.ends_with(" min")),
        "titles"
    );
    assert!(doc.select(&sel(".sr-only table caption")).next().is_some());
    // domains: pills, Set service, paging total
    let rows: Vec<_> = doc.select(&sel("table.dom tbody tr")).collect();
    assert!(rows.len() >= 5);
    let blocked = rows
        .iter()
        .find(|r| text(**r).contains("ads.tiktok.com"))
        .unwrap();
    assert!(text(*blocked).contains("blocked"));
    let new = rows
        .iter()
        .find(|r| text(**r).contains("some-new-game-cdn.net"))
        .unwrap();
    assert!(text(*new).contains("new"));
    let set = new.select(&sel("a.btn")).next().expect("Set service");
    assert_eq!(text(set).trim(), "Set service");
    assert!(
        set.value()
            .attr("href")
            .unwrap()
            .contains("edit=some-new-game-cdn.net")
    );
    assert!(
        set.value()
            .attr("aria-label")
            .unwrap()
            .contains("some-new-game-cdn.net")
    );
    assert!(
        doc.select(&sel("input[type=search][name=q]"))
            .next()
            .is_some()
    );
    assert_all_labelled(&doc, "host page");

    // 7 days: a 7 × 24 grid
    let p = host_page_from(hosts_mock(), KID_TABLET, "7d", None);
    let doc = render_host_page(p, host_query("7d"));
    assert_eq!(doc.select(&sel(".heat .c")).count(), 7 * 24);
    assert!(
        doc.select(&sel("h2"))
            .any(|h| text(h) == "Screen time, last 7 days")
    );
    assert_all_labelled(&doc, "host page 7d");
}

#[test]
fn host_page_search_filters_and_edit_opens_the_override_dialog() {
    let p = host_page_from(
        hosts_mock(),
        KID_TABLET,
        "today",
        Some("rr3---sn-x.googlevideo.com"),
    );
    let mut q = host_query("today");
    q.q = "tiktok".into();
    q.edit = Some("rr3---sn-x.googlevideo.com".into());
    let doc = render_host_page(p, q);
    let rows: Vec<String> = doc.select(&sel("table.dom tbody tr")).map(text).collect();
    assert!(
        !rows.is_empty() && rows.iter().all(|r| r.contains("tiktok")),
        "{rows:?}"
    );
    let dialog = doc
        .select(&sel("dialog.modal[open]"))
        .next()
        .expect("dialog");
    let form = dialog.select(&sel("form[method=post]")).next().unwrap();
    assert_eq!(form.value().attr("action"), Some("/ui/fn/service_override"));
    let suffix = dialog.select(&sel("input[name=suffix]")).next().unwrap();
    // the registrable domain, not the whole name
    assert_eq!(suffix.value().attr("value"), Some("googlevideo.com"));
    let cats: Vec<String> = dialog
        .select(&sel("select[name=category] option"))
        .map(text)
        .collect();
    assert_eq!(cats.len(), 11);
    assert_eq!(cats[7], "Apple/Google/Microsoft system");
    assert_all_labelled(&doc, "override dialog");
}

#[test]
fn host_page_stale_banner() {
    let p = host_page_from(hosts_mock().with_stale_feed(), KID_TABLET, "today", None);
    let doc = render_host_page(p, host_query("today"));
    let banner = doc
        .select(&sel("[role=status].banner-warn, .banner-warn"))
        .next()
        .expect("banner");
    assert_eq!(
        text(banner).trim(),
        "DNS answers aren't arriving; showing lookups only."
    );
    let p = host_page_from(hosts_mock(), KID_TABLET, "today", None);
    let doc = render_host_page(p, host_query("today"));
    assert!(!text(doc.root_element()).contains("DNS answers aren't arriving"));
}

#[test]
fn hosts_card_links_to_host_page() {
    let card = hosts_from(hosts_mock()).unwrap();
    let doc = render_hosts(Some(card.clone()));
    let rows: Vec<_> = doc.select(&sel("tbody tr")).collect();
    assert_eq!(rows.len(), 20);
    for (r, h) in rows.iter().zip(card.visible("", "", false).0) {
        let a = r.select(&sel("td a.host-link")).next().expect("name link");
        assert_eq!(
            a.value().attr("href").unwrap(),
            sensr_ui::runtime::host_href(&h.key)
        );
        assert_eq!(text(a), h.label());
    }
    let kid = host_row(&doc, "kid-tablet");
    let a = kid.select(&sel("a.host-link")).next().unwrap();
    assert_eq!(
        a.value().attr("href"),
        Some(&*format!("/ui/hosts/{KID_TABLET}"))
    );
    assert_eq!(
        sensr_ui::runtime::host_href("id:01 ab"),
        "/ui/hosts/id:01%20ab"
    );
}

#[test]
fn hosts_card_today_minutes() {
    let card = hosts_from(hosts_mock()).unwrap();
    let doc = render_hosts(Some(card));
    let heads: Vec<String> = doc
        .select(&sel("thead th"))
        .map(|h| text(h).trim().to_owned())
        .collect();
    assert!(heads.iter().any(|h| h == "Today"), "{heads:?}");
    let today = |name: &str| {
        text(
            host_row(&doc, name)
                .select(&sel("td.host-today"))
                .next()
                .unwrap(),
        )
        .trim()
        .to_owned()
    };
    assert_eq!(today("kid-tablet"), "2 h 47 m");
    assert_eq!(today("laptop"), "5 h 38 m");
    // no screen time: nothing shown
    assert_eq!(today("7c:78:b2:10:9e:41"), "");
    assert!(
        host_row(&doc, "kid-tablet")
            .select(&sel("td.host-today .muted"))
            .next()
            .is_some()
    );
}

#[test]
fn hosts_card_row_tinted_by_dns_mix() {
    use sensr_ui::runtime::{HostRow, mix_style};
    let card = hosts_from(hosts_mock()).unwrap();
    let doc = render_hosts(Some(card.clone()));
    let kid = host_row(&doc, "kid-tablet");
    let style = kid.value().attr("style").expect("tinted");
    assert!(style.starts_with("--mix:linear-gradient(90deg,"), "{style}");
    assert!(style.contains("var(--tint-video)"), "{style}");
    let title = kid.value().attr("title").unwrap();
    assert!(title.contains("Video") && title.contains('%'), "{title}");
    // a host without DNS data stays plain
    let plain = host_row(&doc, "device-01");
    assert!(plain.value().attr("style").is_none());
    assert!(plain.value().attr("title").is_none());
    // the legend sits under the card
    let legend: Vec<String> = doc
        .select(&sel(".cat-legend li"))
        .map(|l| text(l).trim().to_owned())
        .collect();
    assert_eq!(legend.len(), 11);
    assert_eq!(legend[0], "Video");

    // stops follow the proportions: 3:1 puts the boundary at 75%
    let row = HostRow {
        dns_mix: vec![("video".into(), 3), ("games".into(), 1)],
        ..HostRow::default()
    };
    let s = mix_style(&row.dns_mix).unwrap();
    let stops: Vec<f64> = s
        .split(['(', ')', ','])
        .filter_map(|p| p.trim().strip_suffix('%'))
        .filter_map(|p| p.rsplit(' ').next()?.parse().ok())
        .collect();
    assert_eq!(stops.first(), Some(&0.0), "{s}");
    assert_eq!(stops.last(), Some(&100.0), "{s}");
    // video ends and games starts around 75%, blended over a few percent
    let video_end = stops[1];
    let games_start = stops[2];
    assert!(
        (70.0..75.0).contains(&video_end) && (75.0..80.0).contains(&games_start),
        "{s}"
    );
    assert!(s.find("--tint-video").unwrap() < s.find("--tint-games").unwrap());
    assert_eq!(mix_style(&[]), None);
    assert_eq!(mix_style(&[("video".into(), 0)]), None);
}

/// Runs a form-post server function as a browser's form post would (with the request
/// parts and response options leptos_axum gives it) and returns its Location header.
fn form_post_location<F, Fut>(m: sensr_ui::mock::MockBackend, f: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), ServerFnError>>,
{
    let handle: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    let (parts, _) = axum::http::Request::builder()
        .header("accept", "text/html")
        .body(())
        .unwrap()
        .into_parts();
    let res = leptos_axum::ResponseOptions::default();
    let owner = Owner::new();
    owner.with(|| {
        provide_context(handle);
        provide_context(parts);
        provide_context(res.clone());
        futures::executor::block_on(f()).unwrap();
    });
    let parts = res.0.read().unwrap();
    parts
        .headers
        .get("location")
        .expect("a redirect")
        .to_str()
        .expect("visible ASCII")
        .to_owned()
}

const HOSTILE: [&str; 4] = [
    "\r\nSet-Cookie: x=1",
    "é",
    "../../ui/core/password",
    "\"><script>&",
];

#[test]
fn service_override_redirect_is_rebuilt_and_safe() {
    // a refused save (bad category) and a successful one, with hostile key / q / qname
    for bad in HOSTILE {
        for category in ["toaster", "games"] {
            let loc = form_post_location(hosts_mock(), || {
                sensr_ui::actions::service_override(
                    "example.com".into(),
                    "Example".into(),
                    category.into(),
                    bad.into(),
                    bad.into(),
                    Some(bad.into()),
                    Some(3),
                    Some(bad.into()),
                    None,
                )
            });
            // not an inventory key: back to the dashboard
            let want = if category == "games" {
                "/?saved=applied"
            } else {
                ""
            };
            if category == "games" {
                assert_eq!(loc, want, "{bad:?}");
            } else {
                assert!(
                    loc.starts_with("/?edit=") && loc.ends_with("&error=category"),
                    "{bad:?}: {loc}"
                );
            }
            assert!(
                loc.starts_with('/') && !loc.starts_with("//"),
                "{bad:?}: {loc}"
            );
            assert!(!loc.contains(['\r', '\n', '"', '<', ' ']), "{bad:?}: {loc}");
            // the path is the dashboard; `..` may only appear encoded inside a query value
            assert_eq!(loc.split('?').next(), Some("/"), "{bad:?}: {loc}");
        }
    }
    // a real key keeps the page, range, page number and the encoded search
    let loc = form_post_location(hosts_mock(), || {
        sensr_ui::actions::service_override(
            "example.com".into(),
            "Example".into(),
            "toaster".into(),
            "www.example.com".into(),
            KID_TABLET.into(),
            Some("7d".into()),
            Some(2),
            Some("é <x>\r\n".into()),
            None,
        )
    });
    assert_eq!(
        loc,
        format!(
            "/ui/hosts/{KID_TABLET}?range=7d&page=2&q=%C3%A9%20%3Cx%3E%0D%0A&edit=www.example.com&error=category"
        )
    );
    let loc = form_post_location(hosts_mock(), || {
        sensr_ui::actions::service_override(
            "example.com".into(),
            "Example".into(),
            "games".into(),
            "www.example.com".into(),
            KID_TABLET.into(),
            None,
            None,
            None,
            None,
        )
    });
    assert_eq!(
        loc,
        format!("/ui/hosts/{KID_TABLET}?range=today&saved=applied")
    );
}

#[test]
fn ids_suppress_redirect_is_rebuilt_and_safe() {
    for bad in HOSTILE {
        let loc = form_post_location(sensr_ui::mock::MockBackend::new(), || {
            sensr_ui::actions::ids_suppress(
                2001219,
                1,
                "ET SCAN".into(),
                Some("not an address".into()),
                Some(bad.into()),
                Some(bad.into()),
                Some(1),
            )
        });
        assert!(loc.starts_with("/ui/ids/alerts?"), "{bad:?}: {loc}");
        assert!(loc.ends_with("&error=address"), "{bad:?}: {loc}");
        assert!(!loc.contains(['\r', '\n', '"', '<', ' ']), "{bad:?}: {loc}");
        // the hostile text only ever appears percent-encoded, as a query value
        assert!(!loc.contains("/../"), "{bad:?}: {loc}");
    }
}

#[test]
fn host_page_escapes_hostile_names() {
    use sensr_ui::actions::{HostPageData, OverrideDraft};
    use sensr_ui::api::{ActivityDomain, HostActivityView};
    const BAD: &str = "\"><script>alert(1)</script>&";
    let mut p = host_page_from(hosts_mock(), KID_TABLET, "today", None);
    let a: &mut HostActivityView = p.activity.as_mut().unwrap();
    a.domains.push(ActivityDomain {
        qname: BAD.into(),
        service: BAD.into(),
        category: "other".into(),
        count: 1,
        ..ActivityDomain::default()
    });
    p.draft = Some(OverrideDraft {
        qname: BAD.into(),
        suffix: BAD.into(),
        service: BAD.into(),
        category: "other".into(),
        existing: true,
    });
    let p: HostPageData = p;
    let html = {
        let owner = Owner::new();
        owner.with(|| sensr_ui::pages::host_page_body(p, host_query("today")).to_html())
    };
    assert!(!html.contains(BAD), "raw text reached the page");
    assert!(!html.contains("<script>alert"), "script injected");
    // text nodes escape <, > and & (a bare quote is harmless there); attributes also the quote
    let escaped = "&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;";
    let ctx: Vec<&str> = html
        .match_indices("alert(1)")
        .map(|(i, _)| &html[i.saturating_sub(70)..i + 30])
        .collect();
    // the domain and service cells, the Set service label, the dialog's text, and the
    // qname, suffix and service fields
    assert_eq!(html.matches(escaped).count(), 7, "{ctx:#?}");
    assert_eq!(
        html.matches(&format!("&quot;{escaped}\"")).count(),
        4,
        "attribute values: {ctx:#?}"
    );
    let doc = Html::parse_fragment(&html);
    let suffix = doc.select(&sel("input[name=suffix]")).next().unwrap();
    assert_eq!(suffix.value().attr("value"), Some(BAD));
    let service = doc.select(&sel("input[name=service]")).next().unwrap();
    assert_eq!(service.value().attr("value"), Some(BAD));
}

#[test]
fn wordmark_text_fits_its_box_in_any_font() {
    // a wider fallback font (Noto, DejaVu) must not clip the final "r"
    let html = leptos::prelude::view! { <sensr_ui::app::Wordmark/> }.to_html();
    assert!(html.contains("textLength=\"168\""), "{html}");
    assert!(html.contains("lengthAdjust=\"spacingAndGlyphs\""), "{html}");
}

// ------------------------------------------------------------ port scanner

/// 2026-11-25 12:00 UTC: when the seeded scans finish.
const SCAN_AT: i64 = 1_795_608_000;
const NAS: &str = "52:54:00:aa:bb:01";
const BENCH_PI: &str = "b8:27:eb:7d:4e:25";

/// The hosts mock reading the seeded scan database (kept alive by the returned directory).
fn scan_mock() -> (tempfile::TempDir, sensr_ui::mock::MockBackend) {
    let d = tempfile::tempdir().unwrap();
    sensr_ui::mock::seed_scans(d.path(), SCAN_AT).unwrap();
    let m = hosts_mock().with_scan_dir(d.path());
    (d, m)
}

/// Runs a server function with `b` as the signed-in backend.
fn as_user<T>(
    b: &sensr_ui::api::BackendHandle,
    f: impl std::future::Future<Output = Result<T, ServerFnError>>,
) -> Result<T, ServerFnError> {
    let owner = Owner::new();
    owner.with(|| {
        provide_context(b.clone());
        futures::executor::block_on(f)
    })
}

/// The ports line under a host's name, whitespace collapsed.
fn ports_line(doc: &Html, name: &str) -> Option<String> {
    host_row(doc, name)
        .select(&sel(".host-ports"))
        .next()
        .map(|p| text(p).split_whitespace().collect::<Vec<_>>().join(" "))
}

#[test]
fn hosts_line_shows_ports() {
    let (_d, m) = scan_mock();
    let mut card = hosts_from(m).unwrap();
    // the never-seen printer sorts past the first 20 rows
    card.list.hosts.retain(|h| {
        matches!(h.name.as_deref(), Some("nas" | "printer" | "laptop"))
            || h.mac.as_deref() == Some("7c:78:b2:10:9e:41")
    });
    let doc = render_hosts(Some(card));
    let line = ports_line(&doc, "nas").expect("nas has a ports line");
    assert_eq!(
        line,
        r#"22 ssh · 80 http "Synology" · 53/udp domain · scanned Nov 25 · Scan now"#
    );
    let row = host_row(&doc, "nas");
    // each port's tooltip is what it said
    let tips: Vec<_> = row
        .select(&sel(".host-ports .port-chip"))
        .map(|c| c.value().attr("title").unwrap_or_default().to_owned())
        .collect();
    assert_eq!(tips[0], "SSH-2.0-OpenSSH_9.6");
    assert!(
        tips[1].contains("Synology") && tips[1].contains("nginx"),
        "{tips:?}"
    );
    let button = row.select(&sel(".host-ports button")).next().unwrap();
    assert_eq!(text(button), "Scan now");
    assert_eq!(button.value().attr("aria-label"), Some("Scan now: nas"));
    // the date is UTC, the full time in its tooltip
    let date = row.select(&sel(".host-ports .port-date")).next().unwrap();
    assert_eq!(date.value().attr("title"), Some("2026-11-25 12:00:00 UTC"));
    // the name stays the link's text
    assert_eq!(name_text(row.select(&sel("td")).next().unwrap()), "nas");

    // open|filtered UDP is greyed, with the tooltip saying why; a partial scan says so
    let cam = doc
        .select(&sel("tbody tr"))
        .find(|r| text(*r).contains("7c:78:b2:10:9e:41"))
        .unwrap();
    let grey = cam
        .select(&sel(".port-chip.port-of"))
        .next()
        .expect("grey chip");
    assert_eq!(text(grey), "1900/udp ssdp");
    assert_eq!(
        grey.value().attr("title"),
        Some("no reply: open or filtered")
    );
    assert!(text(cam).contains("partial scan"), "{}", text(cam));
    // a device that did not answer
    assert_eq!(
        ports_line(&doc, "printer").as_deref(),
        Some("scanned Nov 25 · no response · Scan now")
    );
    // never scanned: only the button
    assert_eq!(ports_line(&doc, "laptop").as_deref(), Some("Scan now"));
}

#[test]
fn hosts_line_marks_new_port() {
    let (_d, m) = scan_mock();
    let mut card = hosts_from(m).unwrap();
    card.list
        .hosts
        .retain(|h| matches!(h.name.as_deref(), Some("bench-pi" | "device-01")));
    let doc = render_hosts(Some(card));
    assert_eq!(
        ports_line(&doc, "bench-pi").as_deref(),
        Some("22 ssh · +3389 new · scanned Nov 25 · Scan now")
    );
    // the first 8 open ports, then a link to the rest on the host page
    let line = ports_line(&doc, "device-01").unwrap();
    let row = host_row(&doc, "device-01");
    assert_eq!(row.select(&sel(".port-chip")).count(), 8, "{line}");
    let more = row.select(&sel(".host-ports a")).next().unwrap();
    assert_eq!(text(more), "+4 more");
    assert_eq!(
        more.value().attr("href"),
        Some("/ui/hosts/02:00:00:00:00:01#ports")
    );
}

#[test]
fn hosts_line_read_only_and_hidden() {
    let (_d, m) = scan_mock();
    let card = hosts_from(m.with_privileges(&["page-all", "user-config-readonly"])).unwrap();
    assert!(!card.can_scan);
    let doc = render_hosts(Some(card));
    assert_eq!(
        ports_line(&doc, "nas").as_deref(),
        Some(r#"22 ssh · 80 http "Synology" · 53/udp domain · scanned Nov 25"#)
    );
    assert!(ports_line(&doc, "laptop").is_none(), "nothing to show");

    // hosts without the port scanner privilege: no line at all
    let (_d, m) = scan_mock();
    let card = hosts_from(m.with_privileges(&["page-sensr-hosts"])).unwrap();
    assert!(card.list.hosts.iter().all(|h| h.ports.is_none()));
    let doc = render_hosts(Some(card));
    assert!(doc.select(&sel(".host-ports")).next().is_none());
}

#[test]
fn hosts_line_escapes_titles() {
    use sensr_scan::proto::JobKind;
    use sensr_scan::types::{Ident, PortRow, PortState, Proto, ScanStatus};
    const BAD: &str = "<img src=x onerror=alert(1)>";
    let d = tempfile::tempdir().unwrap();
    let s = sensr_scan::store::Store::open(&d.path().join(sensr_scan::config::DB)).unwrap();
    let job = s
        .begin_job(JobKind::Device, "192.168.1.20", Some(NAS), false, false)
        .unwrap();
    let port = PortRow {
        proto: Proto::Tcp,
        port: 80,
        state: PortState::Open,
        service: Some(BAD.into()),
        ident: Ident {
            title: Some(BAD.into()),
            banner: Some(BAD.into()),
            ..Ident::default()
        },
    };
    s.write_scan(
        job,
        "192.168.1.20".parse().unwrap(),
        Some(NAS),
        SCAN_AT - 60,
        SCAN_AT,
        ScanStatus::Complete,
        false,
        &[port],
    )
    .unwrap();
    let card = hosts_from(hosts_mock().with_scan_dir(d.path()));
    let html = {
        let owner = Owner::new();
        owner.with(|| {
            view! { <sensr_ui::islands::HostsCard initial=card/> }
                .into_any()
                .to_html()
        })
    };
    assert!(!html.contains("<img"), "markup injected");
    assert!(
        html.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{html}"
    );
    let doc = Html::parse_fragment(&html);
    let chip = host_row(&doc, "nas")
        .select(&sel(".port-chip"))
        .next()
        .unwrap();
    assert_eq!(text(chip), format!("80 {BAD} \"{BAD}\""));
    assert!(chip.value().attr("title").unwrap().contains(BAD));
}

#[test]
fn hosts_line_shows_scanning_after_scan_now() {
    use sensr_ui::actions::{ScanStart, portscan_start};
    let (_d, m) = scan_mock();
    let b: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    let r = as_user(
        &b,
        portscan_start("192.168.1.112".into(), Some(BENCH_PI.into()), false),
    )
    .unwrap();
    assert!(matches!(r, ScanStart::Started(_)), "{r:?}");
    let card = as_user(&b, sensr_ui::actions::hosts()).unwrap();
    let doc = render_hosts(card);
    // the old result stays, the date and button give way to "scanning…"
    assert_eq!(
        ports_line(&doc, "bench-pi").as_deref(),
        Some("22 ssh · +3389 new · scanning…")
    );
}

#[test]
fn portscan_actions_enforce_the_rules() {
    use sensr_ui::actions::{ScanStart, portscan_cancel, portscan_start, portscan_status};
    let (_d, m) = scan_mock();
    let b: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    // a public address needs the tick
    let r = as_user(&b, portscan_start("8.8.8.8".into(), None, false)).unwrap();
    assert_eq!(
        r,
        ScanStart::Refused("the target is not local; confirm to scan it anyway".into())
    );
    let r = as_user(&b, portscan_start("8.8.8.8".into(), None, true)).unwrap();
    assert!(matches!(r, ScanStart::Started(_)));
    let r = as_user(&b, portscan_start("192.168.1.0/16x".into(), None, false)).unwrap();
    assert!(
        matches!(&r, ScanStart::Refused(t) if t.starts_with("the target is not valid")),
        "{r:?}"
    );
    let ScanStart::Started(id) =
        as_user(&b, portscan_start("192.168.1.0/24".into(), None, false)).unwrap()
    else {
        panic!("not started");
    };
    let st = as_user(&b, portscan_status()).unwrap();
    assert!(
        st.queue
            .iter()
            .any(|q| q.job_id == id && q.target == "192.168.1.0/24")
    );
    as_user(&b, portscan_cancel(id)).unwrap();
    let st = as_user(&b, portscan_status()).unwrap();
    assert!(!st.queue.iter().any(|q| q.job_id == id));
    // a bad MAC never reaches the daemon
    assert!(
        as_user(
            &b,
            portscan_start("192.168.1.5".into(), Some("nope".into()), false)
        )
        .is_err()
    );

    // read-only callers may look but not start or cancel
    let (_d, m) = scan_mock();
    let ro: sensr_ui::api::BackendHandle =
        std::sync::Arc::new(m.with_privileges(&["page-all", "user-config-readonly"]));
    assert!(as_user(&ro, portscan_status()).is_ok());
    assert!(as_user(&ro, portscan_start("192.168.1.5".into(), None, false)).is_err());
    assert!(as_user(&ro, portscan_cancel(1)).is_err());
    // and callers without the privilege may do neither
    let (_d, m) = scan_mock();
    let none: sensr_ui::api::BackendHandle =
        std::sync::Arc::new(m.with_privileges(&["page-sensr-hosts"]));
    assert!(as_user(&none, portscan_status()).is_err());
    assert!(as_user(&none, sensr_ui::actions::portscan_page()).is_err());
    assert!(as_user(&none, portscan_start("192.168.1.5".into(), None, false)).is_err());

    // a daemon that is not there
    let (_d, m) = scan_mock();
    let down: sensr_ui::api::BackendHandle = std::sync::Arc::new(m.with_scanner_down());
    let e = as_user(&down, portscan_start("192.168.1.5".into(), None, false)).unwrap_err();
    assert_eq!(
        sensr_ui::actions::server_message(&e),
        "The port scanner is not running."
    );
    let page = as_user(&down, sensr_ui::actions::portscan_page()).unwrap();
    assert_eq!(
        page.note.as_deref(),
        Some("The port scanner is not running.")
    );
}

#[test]
fn host_page_ports_section() {
    let (_d, m) = scan_mock();
    let p = host_page_from(m, BENCH_PI, "today", None);
    let doc = render_host_page(p, host_query("today"));
    let sec = doc
        .select(&sel("section#ports"))
        .next()
        .expect("Ports section");
    assert!(text(sec).contains("Ports"));
    let rows: Vec<Vec<String>> = sec
        .select(&sel("table tbody tr"))
        .map(|r| {
            r.select(&sel("td"))
                .map(|c| text(c).trim().to_owned())
                .collect()
        })
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0][..4], ["22", "TCP", "open", "ssh"]);
    assert_eq!(rows[0][4], "SSH-2.0-OpenSSH_9.2p1");
    assert_eq!(rows[1][..4], ["3389", "TCP", "open", "ms-wbt-server"]);
    let history: Vec<String> = sec
        .select(&sel("ol.scan-history li"))
        .map(|l| text(l).split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(history.len(), 2, "{history:?}");
    assert!(history[0].starts_with("2026-11-25"), "{history:?}");
    assert!(
        history[0].contains("complete") && history[0].contains("+3389 new"),
        "{history:?}"
    );
    assert!(
        history[1].starts_with("2026-11-18") && history[1].contains("complete"),
        "{history:?}"
    );
    assert!(
        sec.select(&sel("form[action='/ui/fn/portscan_submit'] button"))
            .any(|b| text(b) == "Scan now"),
        "Scan now on the host page"
    );

    // back from Scan now: what happened, in the section
    let (_d, m) = scan_mock();
    let p = host_page_from(m, BENCH_PI, "today", None);
    let mut q = host_query("today");
    q.scan.refused = Some("excluded".into());
    let doc = render_host_page(p, q);
    let alert = doc
        .select(&sel("section#ports [role=alert]"))
        .next()
        .unwrap();
    assert_eq!(
        text(alert),
        "Not scanned: the target is on the exclude list."
    );
}

#[test]
fn portscan_page_lists_jobs() {
    let (_d, m) = scan_mock();
    let b: sensr_ui::api::BackendHandle = std::sync::Arc::new(m);
    let p = as_user(&b, sensr_ui::actions::portscan_page()).unwrap();
    assert!(p.can_scan && p.note.is_none());
    let q = sensr_ui::portscan::PortscanQuery::default();
    let doc = render(|| sensr_ui::pages::portscan_body(p, &q));
    assert!(
        doc.select(&sel(
            "form[action='/ui/fn/portscan_submit'] input[name=target]"
        ))
        .next()
        .is_some()
    );
    assert!(
        doc.select(&sel("form input[type=checkbox][name=public_ok]"))
            .next()
            .is_some()
    );
    let all = text(doc.root_element());
    assert!(all.contains("12 of 254 alive"), "{all}");
    assert!(
        doc.select(&sel("button")).any(|b| text(b) == "Cancel"),
        "the running job can be cancelled"
    );
    let caption = |t: &str| {
        doc.select(&sel("table"))
            .find(|tb| tb.select(&sel("caption")).any(|c| text(c) == t))
            .unwrap_or_else(|| panic!("no {t} table"))
    };
    let devices = caption("Device scans");
    assert!(text(devices).contains("nas"));
    assert!(text(devices).contains("+3389 new"));
    let ranges = caption("Range scans");
    assert!(text(ranges).contains("192.168.1.0/24"), "{}", text(ranges));
    assert!(text(ranges).contains("Printer setup"), "{}", text(ranges));
    assert_all_labelled(&doc, "port scanner page");

    // read-only: results without the forms
    let (_d, m) = scan_mock();
    let ro: sensr_ui::api::BackendHandle =
        std::sync::Arc::new(m.with_privileges(&["page-all", "user-config-readonly"]));
    let p = as_user(&ro, sensr_ui::actions::portscan_page()).unwrap();
    assert!(!p.can_scan);
    let q = sensr_ui::portscan::PortscanQuery::default();
    let doc = render(|| sensr_ui::pages::portscan_body(p, &q));
    assert!(doc.select(&sel("input[name=target]")).next().is_none());
    assert!(!text(doc.root_element()).contains("Scan now"));
    assert!(text(doc.root_element()).contains("12 of 254 alive"));
}

#[test]
fn portscan_menu_entry() {
    let menu = sensr_ui::menu::build(&[]);
    let services = menu.iter().find(|m| m.id == "Services").unwrap();
    let item = services
        .children
        .iter()
        .find(|c| c.id == "Portscan")
        .expect("Services › Port Scanner");
    assert_eq!(item.label, "Port Scanner");
    assert_eq!(item.url.as_deref(), Some("/ui/portscan"));
    assert_eq!(
        sensr_ui::models::FormId::PortscanSettings.page_url(),
        "/ui/portscan"
    );
}

#[test]
fn portscan_forms_redirect_with_codes_only() {
    use sensr_ui::actions::{portscan_cancel_form, portscan_submit};
    use sensr_ui::portscan::PortscanQuery;
    let post = |m, target: &str, public: bool| {
        let t = target.to_owned();
        form_post_location(m, move || {
            portscan_submit(t, None, public.then(|| "on".to_owned()), None)
        })
    };
    let (_d, m) = scan_mock();
    let loc = post(m, "8.8.8.8", false);
    assert_eq!(loc, "/ui/portscan?refused=public&target=8.8.8.8");
    let (_d, m) = scan_mock();
    let loc = post(m, "192.168.1.0/24", false);
    assert!(loc.starts_with("/ui/portscan?started="), "{loc}");
    assert!(loc.ends_with("&target=192.168.1.0%2F24"), "{loc}");
    let (_d, m) = scan_mock();
    assert_eq!(
        post(m, "10.0.0.0/8", true),
        "/ui/portscan?refused=too_large&addresses=16777216&max=4096&target=10.0.0.0%2F8"
    );
    // hostile text is never echoed: only a target that parses travels back
    for bad in HOSTILE {
        let (_d, m) = scan_mock();
        let loc = post(m, bad, false);
        assert_eq!(loc, "/ui/portscan?refused=invalid", "{bad:?}");
    }
    let (_d, m) = scan_mock();
    assert_eq!(
        post(m.with_scanner_down(), "192.168.1.5", false),
        "/ui/portscan?error=not_running&target=192.168.1.5"
    );
    let (_d, m) = scan_mock();
    assert_eq!(
        post(
            m.with_privileges(&["page-all", "user-config-readonly"]),
            "192.168.1.5",
            false
        ),
        "/ui/portscan?error=forbidden&target=192.168.1.5"
    );
    let (_d, m) = scan_mock();
    assert_eq!(
        form_post_location(m, || portscan_cancel_form(7)),
        "/ui/portscan?cancelled=7"
    );
    let (_d, m) = scan_mock();
    let ro = m.with_privileges(&["page-all", "user-config-readonly"]);
    assert_eq!(
        form_post_location(ro, || portscan_cancel_form(7)),
        "/ui/portscan?error=forbidden"
    );

    // Scan now on a host page goes back there, keys prefixed (the page has its own error)
    let (_d, m) = scan_mock();
    let loc = form_post_location(m, || {
        portscan_submit(
            "192.168.1.112".into(),
            Some(BENCH_PI.to_uppercase()),
            None,
            Some("host".into()),
        )
    });
    assert!(
        loc.starts_with(&format!("/ui/hosts/{BENCH_PI}?scan_started=")),
        "{loc}"
    );
    assert!(loc.ends_with("&scan_target=192.168.1.112#ports"), "{loc}");

    // what the page makes of the codes
    let q = |pairs: &[(&str, &str)]| {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        PortscanQuery::from_query(|k| pairs.iter().find(|p| p.0 == k).map(|p| p.1.clone()))
    };
    assert_eq!(
        q(&[("refused", "public"), ("target", "8.8.8.8")]).message(),
        Some((
            true,
            "Not scanned: the target is not local; confirm to scan it anyway.".into()
        ))
    );
    assert_eq!(
        q(&[
            ("refused", "too_large"),
            ("addresses", "8192"),
            ("max", "4096")
        ])
        .message(),
        Some((
            true,
            "Not scanned: 8192 addresses is more than the 4096 allowed.".into()
        ))
    );
    assert_eq!(
        q(&[("started", "12"), ("target", "192.168.1.0/24")]).message(),
        Some((false, "Scan of 192.168.1.0/24 queued (job 12).".into()))
    );
    // a target that does not parse is dropped, not shown
    let hostile = q(&[("started", "12"), ("target", "<b>owned</b>")]);
    assert_eq!(hostile.target, "");
    assert_eq!(
        hostile.message(),
        Some((false, "Scan queued (job 12).".into()))
    );
    assert_eq!(
        q(&[("error", "not_running")]).message(),
        Some((true, "The port scanner is not running.".into()))
    );
    assert_eq!(q(&[]).message(), None);
}
