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

const FORMS: [FormId; 12] = [
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
];

const GRIDS: [GridId; 16] = [
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

/// The card's row for the host named `name`.
fn host_row<'a>(doc: &'a Html, name: &str) -> scraper::ElementRef<'a> {
    doc.select(&sel("tbody tr"))
        .find(|r| {
            r.select(&sel("td"))
                .next()
                .is_some_and(|td| text(td).trim() == name)
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
        ["Name", "MAC", "IP", "Network", "Source", "Seen", "Mode", ""]
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
    let seen = doc
        .select(&sel("tbody tr"))
        .find(|r| {
            r.select(&sel("td"))
                .nth(4)
                .is_some_and(|c| text(c).trim() == "seen")
        })
        .expect("seen-only row");
    let seen: Vec<String> = seen
        .select(&sel("td"))
        .map(|c| text(c).trim().to_owned())
        .collect();
    assert_eq!(seen[0], seen[1], "name falls back to the MAC");
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
    assert!(!all.contains("remove the reservation on the DHCP page"));
}

#[test]
fn hosts_card_reserved_row_has_no_forget() {
    let doc = render_hosts(hosts_from(hosts_mock()));
    let nas = host_row(&doc, "nas");
    assert!(nas.select(&sel("button")).next().is_none(), "{}", text(nas));
    assert!(text(nas).contains("remove the reservation on the DHCP page to forget this host"));
    // A leased host can be made static and forgotten.
    let pi: Vec<String> = host_row(&doc, "bench-pi")
        .select(&sel("button"))
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
        r.select(&sel("button"))
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
        .select(&sel("button"))
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
        ["Name", "MAC", "IP", "Network", "Source", "Seen", "Mode", ""]
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
    let badge = |name: &str| {
        mode_cell(host_row(&doc, name))
            .select(&sel(".pill"))
            .next()
            .map(|b| (b.value().attr("class").unwrap_or("").to_owned(), text(b)))
    };
    let (class, label) = badge("device-02").expect("isolated badge");
    assert!(class.split(' ').any(|c| c == "pill-warn"), "{class}");
    assert_eq!(label, "Isolated");
    let (class, label) = badge("device-05").expect("quarantine badge");
    assert!(class.split(' ').any(|c| c == "pill-off"), "{class}");
    assert_eq!(label, "Quarantine");
    assert!(badge("bench-pi").is_none(), "Normal has no badge");
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
